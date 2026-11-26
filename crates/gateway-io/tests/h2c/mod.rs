//! A small cleartext HTTP/2 client for the tests: prior knowledge, one
//! request per connection, frames written by hand and responses read with
//! h2-net's HPACK decoder.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use h2_net::hpack::{Decoder, HeaderList};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// What came back for stream 1.
#[derive(Debug, Default)]
pub struct Answer {
    /// The `:status`, when a response came.
    pub status: Option<u16>,
    /// The response fields.
    pub fields: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
    /// The stream was reset (`RST_STREAM`), with this code.
    pub reset: Option<u32>,
    /// The connection was ended (`GOAWAY`), with this code.
    pub goaway: Option<u32>,
    /// Whether any HTTP/2 frame came back at all.
    pub spoke_h2: bool,
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut f = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, kind, flags];
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// A field as an HPACK literal without indexing, new name, no Huffman.
fn literal(out: &mut Vec<u8>, name: &str, value: &str) {
    assert!(name.len() < 127 && value.len() < 127);
    out.push(0x00);
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
}

/// Sends one request on stream 1 (`method`, `path`, and `fields`, which may
/// hold `:protocol`) and reads until its answer ends, the stream is reset,
/// or the connection goes.
pub fn request(addr: SocketAddr, method: &str, path: &str, fields: &[(&str, &str)]) -> Answer {
    let s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("timeout");
    request_over(s, "http", method, path, fields)
}

/// As `request`, on a stream already open (TLS, say), with this `:scheme`.
/// A read timeout on the stream keeps the loop turning.
pub fn request_over<S: Read + Write>(
    mut s: S,
    scheme: &str,
    method: &str,
    path: &str,
    fields: &[(&str, &str)],
) -> Answer {
    let mut block = Vec::new();
    literal(&mut block, ":method", method);
    literal(&mut block, ":scheme", scheme);
    literal(&mut block, ":authority", "localhost");
    literal(&mut block, ":path", path);
    for (n, v) in fields {
        literal(&mut block, n, v);
    }
    // CONNECT opens a stream that stays open; anything else ends with its
    // headers.
    let end_stream = if method == "CONNECT" { 0 } else { 0x1 };
    let mut out = PREFACE.to_vec();
    out.extend(frame(0x4, 0, 0, &[]));
    out.extend(frame(0x1, 0x4 | end_stream, 1, &block));
    s.write_all(&out).expect("write");

    let mut answer = Answer::default();
    let mut buf = Vec::new();
    let mut decoder = Decoder::new(4096);
    let until = Instant::now() + Duration::from_secs(10);
    let mut chunk = [0u8; 16 * 1024];
    while Instant::now() < until {
        // Every whole frame in the buffer.
        while buf.len() >= 9 {
            let len =
                (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let (kind, flags) = (buf[3], buf[4]);
            let stream = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff;
            let payload = buf[9..9 + len].to_vec();
            buf.drain(..9 + len);
            answer.spoke_h2 = true;
            match kind {
                // SETTINGS: acknowledge the server's.
                0x4 if flags & 0x1 == 0 => {
                    let _ = s.write_all(&frame(0x4, 0x1, 0, &[]));
                }
                // HEADERS on stream 1.
                0x1 if stream == 1 => {
                    let mut fragment = &payload[..];
                    if flags & 0x8 != 0 {
                        let pad = usize::from(fragment[0]);
                        fragment = &fragment[1..fragment.len() - pad];
                    }
                    if flags & 0x20 != 0 {
                        fragment = &fragment[5..];
                    }
                    let mut list = HeaderList::new(64 * 1024);
                    decoder.decode(fragment, &mut list).expect("hpack");
                    for f in list.iter() {
                        let name = String::from_utf8_lossy(f.name).into_owned();
                        let value = String::from_utf8_lossy(f.value).into_owned();
                        if name == ":status" {
                            answer.status = value.parse().ok();
                        } else {
                            answer.fields.push((name, value));
                        }
                    }
                    if flags & 0x1 != 0 {
                        return answer;
                    }
                }
                // DATA on stream 1.
                0x0 if stream == 1 => {
                    answer.body.extend_from_slice(&payload);
                    if flags & 0x1 != 0 {
                        return answer;
                    }
                }
                // RST_STREAM on stream 1.
                0x3 if stream == 1 => {
                    answer.reset = Some(u32::from_be_bytes([
                        payload[0], payload[1], payload[2], payload[3],
                    ]));
                    return answer;
                }
                // GOAWAY.
                0x7 => {
                    answer.goaway = Some(u32::from_be_bytes([
                        payload[4], payload[5], payload[6], payload[7],
                    ]));
                    return answer;
                }
                _ => {}
            }
        }
        match s.read(&mut chunk) {
            Ok(0) => return answer,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return answer,
        }
    }
    answer
}

/// The status of an HTTP/1.1 `GET path` with these extra fields; 0 when no
/// status line came.
pub fn http1_status(addr: SocketAddr, path: &str, fields: &str) -> u16 {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let _ = s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{fields}Connection: close\r\n\r\n")
            .as_bytes(),
    );
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf)
        .get(9..12)
        .and_then(|t| t.parse().ok())
        .unwrap_or(0)
}
