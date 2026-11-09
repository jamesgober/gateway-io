//! The data of one in-flight request: the slot a passport carries.
//!
//! Every buffer in a slot is created once, at boot, and reused: a request
//! copies its head into buffers that already have capacity, and returning the
//! slot to the pool wipes the used part and keeps the capacity.

use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use id_forge::ulid::Ulid;

use crate::identity::Identity;

/// Zeroes `bytes` before the buffer is reused.
///
/// A vectorized fill (memset speed), then an opaque read so the compiler must
/// keep the stores: the buffer stays allocated and reachable, so they are
/// never dead. This is what crypt-io's `wipe` does without its `zeroize`
/// feature; zeroize's per-byte volatile writes measured about ten times slower
/// on a 64 KiB body, and the passport wipes every request it carries.
#[inline]
pub(crate) fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    std::hint::black_box(&*bytes);
}

/// A request id: a ULID, time ordered and unique within the process.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct RequestId(pub Ulid);

impl RequestId {
    /// A fresh id.
    #[inline]
    #[must_use]
    pub fn new() -> RequestId {
        RequestId(Ulid::new())
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RequestId({})", self.0)
    }
}

/// A profile: what a listener's connections are (site, admin, api, ...). One byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct ProfileId(pub u8);

/// A service tag: which service answers a profile's requests. One byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct ServiceTag(pub u8);

/// A priority lane: 0 is the most important. One byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Lane(pub u8);

impl Default for Lane {
    fn default() -> Lane {
        Lane(4)
    }
}

/// Where a slot lives in the pool: its worker's shelf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Home {
    pub(crate) worker: u16,
}

/// The facts of the trip, written once when the passport is taken.
#[derive(Clone, Copy, Debug)]
pub struct Trip {
    /// The request id.
    pub id: RequestId,
    /// The transport's connection id.
    pub conn: u64,
    /// The request's number on its connection (1 for the first).
    pub seq: u32,
    /// The worker that owns the connection.
    pub worker: u16,
    /// The listener's profile.
    pub profile: ProfileId,
    /// The service the profile names.
    pub service: ServiceTag,
    /// The priority lane.
    pub lane: Lane,
    /// The real client address, after ingress normalization (`None` when unknown).
    pub client: Option<IpAddr>,
    /// When the first byte of the head arrived.
    pub arrived: Instant,
    /// When the request must be answered.
    pub deadline: Instant,
    /// The bouncer's tag for this request: revocable at any checkpoint.
    pub ticket: u64,
}

impl Trip {
    /// A trip with every field at its empty value, for a slot not in use.
    #[must_use]
    pub fn empty() -> Trip {
        let now = Instant::now();
        Trip {
            id: RequestId::default(),
            conn: 0,
            seq: 0,
            worker: 0,
            profile: ProfileId(0),
            service: ServiceTag(0),
            lane: Lane::default(),
            client: None,
            arrived: now,
            deadline: now,
            ticket: 0,
        }
    }
}

/// A byte range inside one of the slot's buffers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Span {
    start: u32,
    end: u32,
}

impl Span {
    #[inline]
    fn of<'b>(&self, bytes: &'b [u8]) -> &'b [u8] {
        bytes
            .get(self.start as usize..self.end as usize)
            .unwrap_or(&[])
    }
}

/// Appends `part` to `buf` and returns where it went. Lengths are bounded by the
/// head limits long before they reach `u32::MAX`; a longer buffer saturates and
/// reads back as empty, never as the wrong bytes.
#[inline]
fn push(buf: &mut Vec<u8>, part: &[u8]) -> Span {
    let start = u32::try_from(buf.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(part);
    let end = u32::try_from(buf.len()).unwrap_or(u32::MAX);
    Span { start, end }
}

/// A request head copied into the slot: method, target, version, and fields,
/// as spans into one reused buffer.
pub struct Head {
    bytes: Vec<u8>,
    method: Span,
    target: Span,
    version_minor: u8,
    fields: Vec<(Span, Span)>,
}

impl Head {
    pub(crate) fn with_capacity(bytes: usize, fields: usize) -> Head {
        Head {
            bytes: Vec::with_capacity(bytes),
            method: Span::default(),
            target: Span::default(),
            version_minor: 1,
            fields: Vec::with_capacity(fields),
        }
    }

    /// Starts a head: the request line. Clears anything left from before.
    pub fn set_line(&mut self, method: &str, target: &str, version_minor: u8) {
        self.bytes.clear();
        self.fields.clear();
        self.method = push(&mut self.bytes, method.as_bytes());
        self.target = push(&mut self.bytes, target.as_bytes());
        self.version_minor = version_minor;
    }

    /// Adds one field, in arrival order.
    #[inline]
    pub fn push_field(&mut self, name: &str, value: &[u8]) {
        let n = push(&mut self.bytes, name.as_bytes());
        let v = push(&mut self.bytes, value);
        self.fields.push((n, v));
    }

    /// The method, as received (`GET`, `POST`, ...).
    #[must_use]
    pub fn method(&self) -> &str {
        std::str::from_utf8(self.method.of(&self.bytes)).unwrap_or("")
    }

    /// The request target, exactly as received.
    #[must_use]
    pub fn target(&self) -> &str {
        std::str::from_utf8(self.target.of(&self.bytes)).unwrap_or("")
    }

    /// The path part of the target (percent-encoding kept).
    #[must_use]
    pub fn path(&self) -> &str {
        let t = self.target();
        t.split_once('?').map_or(t, |(p, _)| p)
    }

    /// The query, without the `?`.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.target().split_once('?').map(|(_, q)| q)
    }

    /// The minor version of HTTP/1.x.
    #[must_use]
    pub fn version_minor(&self) -> u8 {
        self.version_minor
    }

    /// The first field with this name (ASCII case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.fields.iter().find_map(|(n, v)| {
            n.of(&self.bytes)
                .eq_ignore_ascii_case(name.as_bytes())
                .then(|| v.of(&self.bytes))
        })
    }

    /// The first field with this name, if it is valid UTF-8.
    #[must_use]
    pub fn header_str(&self, name: &str) -> Option<&str> {
        self.header(name).and_then(|v| std::str::from_utf8(v).ok())
    }

    /// Every field in arrival order.
    pub fn fields(&self) -> impl ExactSizeIterator<Item = (&[u8], &[u8])> + '_ {
        self.fields
            .iter()
            .map(|(n, v)| (n.of(&self.bytes), v.of(&self.bytes)))
    }

    /// How many fields the head has.
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// The bytes the head occupies in the slot.
    #[must_use]
    pub fn len_bytes(&self) -> usize {
        self.bytes.len()
    }

    /// `GET` or `HEAD`.
    #[must_use]
    pub fn is_get_or_head(&self) -> bool {
        matches!(self.method(), "GET" | "HEAD")
    }

    fn wipe(&mut self) {
        wipe(&mut self.bytes);
        self.bytes.clear();
        self.fields.clear();
        self.method = Span::default();
        self.target = Span::default();
    }
}

impl fmt::Debug for Head {
    // Field values may carry credentials: only names are shown.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<_> = self
            .fields
            .iter()
            .map(|(n, _)| String::from_utf8_lossy(n.of(&self.bytes)))
            .collect();
        f.debug_struct("Head")
            .field("method", &self.method())
            .field("target", &self.target())
            .field("fields", &names)
            .finish()
    }
}

/// Why a reply was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyKind {
    /// Nothing written yet.
    Empty,
    /// Content from a cleared passport.
    Answer,
    /// A refusal: fixed body, no content.
    Refusal,
    /// Bytes from the core's guest output cache.
    Cached,
    /// An external service wrote the reply on the protocol's own types; the
    /// passport carries none.
    HandedOff,
}

/// The way out: status, fields, body. Reused across requests.
pub struct Reply {
    status: u16,
    bytes: Vec<u8>,
    fields: Vec<(Span, Span)>,
    body: Vec<u8>,
    close: bool,
    retry_after: Option<Duration>,
    kind: ReplyKind,
}

impl Reply {
    pub(crate) fn with_capacity(fields: usize, body: usize) -> Reply {
        Reply {
            status: 200,
            bytes: Vec::with_capacity(fields * 48),
            fields: Vec::with_capacity(fields),
            body: Vec::with_capacity(body),
            close: false,
            retry_after: None,
            kind: ReplyKind::Empty,
        }
    }

    /// Sets the status (default 200).
    pub fn status(&mut self, status: u16) -> &mut Self {
        self.status = status;
        self.kind = ReplyKind::Answer;
        self
    }

    /// Adds a field. The encoder refuses invalid names and values (the client
    /// then gets a 500), so nothing malformed reaches the wire.
    pub fn header(&mut self, name: &str, value: impl AsRef<[u8]>) -> &mut Self {
        let n = push(&mut self.bytes, name.as_bytes());
        let v = push(&mut self.bytes, value.as_ref());
        self.fields.push((n, v));
        self.kind = ReplyKind::Answer;
        self
    }

    /// Appends to the body.
    pub fn body(&mut self, bytes: &[u8]) -> &mut Self {
        self.body.extend_from_slice(bytes);
        self.kind = ReplyKind::Answer;
        self
    }

    /// A plain text reply.
    pub fn text(&mut self, status: u16, text: &str) -> &mut Self {
        self.status(status)
            .header("content-type", "text/plain; charset=utf-8")
            .body(text.as_bytes())
    }

    /// An HTML reply.
    pub fn html(&mut self, status: u16, html: &str) -> &mut Self {
        self.status(status)
            .header("content-type", "text/html; charset=utf-8")
            .body(html.as_bytes())
    }

    /// Ends the connection after this reply.
    pub fn close(&mut self) -> &mut Self {
        self.close = true;
        self
    }

    /// The status written.
    #[must_use]
    pub fn status_code(&self) -> u16 {
        self.status
    }

    /// Every field written, in order.
    pub fn fields(&self) -> impl ExactSizeIterator<Item = (&[u8], &[u8])> + '_ {
        self.fields
            .iter()
            .map(|(n, v)| (n.of(&self.bytes), v.of(&self.bytes)))
    }

    /// The body written.
    #[must_use]
    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }

    /// Whether the connection closes after this reply.
    #[must_use]
    pub fn closes(&self) -> bool {
        self.close
    }

    /// `Retry-After`, for refusals that set it.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    /// Why the reply was written.
    #[must_use]
    pub fn kind(&self) -> ReplyKind {
        self.kind
    }

    pub(crate) fn mark_handed_off(&mut self) {
        self.kind = ReplyKind::HandedOff;
    }

    /// Replaces whatever was written with a refusal: wiped, then a fixed body.
    pub(crate) fn refuse(&mut self, refusal: Refusal) {
        self.wipe();
        self.status = refusal.status;
        self.close = refusal.close;
        self.retry_after = refusal.retry_after;
        self.kind = ReplyKind::Refusal;
        let n = push(&mut self.bytes, b"content-type");
        let v = push(&mut self.bytes, b"text/plain; charset=utf-8");
        self.fields.push((n, v));
        self.body
            .extend_from_slice(refusal_text(refusal.status).as_bytes());
    }

    fn wipe(&mut self) {
        wipe(&mut self.bytes);
        wipe(&mut self.body);
        self.bytes.clear();
        self.body.clear();
        self.fields.clear();
        self.status = 200;
        self.close = false;
        self.retry_after = None;
        self.kind = ReplyKind::Empty;
    }
}

impl fmt::Debug for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reply")
            .field("status", &self.status)
            .field("fields", &self.fields.len())
            .field("body_len", &self.body.len())
            .field("kind", &self.kind)
            .finish()
    }
}

/// A refusal: a status, and what the client should do next. The body is fixed
/// per status and never says why (the reason goes to the log).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The status, 400 to 599.
    pub status: u16,
    /// `Retry-After`, for 429 and 503.
    pub retry_after: Option<Duration>,
    /// End the connection after the refusal.
    pub close: bool,
}

impl Refusal {
    /// A refusal with this status that keeps the connection.
    #[must_use]
    pub const fn status(status: u16) -> Refusal {
        Refusal {
            status,
            retry_after: None,
            close: false,
        }
    }

    /// The same refusal, ending the connection.
    #[must_use]
    pub const fn closing(mut self) -> Refusal {
        self.close = true;
        self
    }

    /// The same refusal, with `Retry-After`.
    #[must_use]
    pub const fn retry_after(mut self, after: Duration) -> Refusal {
        self.retry_after = Some(after);
        self
    }
}

/// The fixed refusal text for a status.
#[must_use]
pub fn refusal_text(status: u16) -> &'static str {
    match status {
        400 => "400 Bad Request\n",
        401 => "401 Unauthorized\n",
        403 => "403 Forbidden\n",
        404 => "404 Not Found\n",
        405 => "405 Method Not Allowed\n",
        408 => "408 Request Timeout\n",
        413 => "413 Content Too Large\n",
        414 => "414 URI Too Long\n",
        429 => "429 Too Many Requests\n",
        431 => "431 Request Header Fields Too Large\n",
        503 => "503 Service Unavailable\n",
        _ => "500 Internal Server Error\n",
    }
}

/// What customs stamped on the head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inspection {
    /// The rule set that passed it (customs' own numbering).
    pub rules: u16,
}

/// What authorization stamped: the rule that passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessStamp {
    /// The rule's id.
    pub rule: u32,
}

/// Sizes a slot is created with. Buffers that grow past their size keep the
/// larger capacity up to `retain`, then shrink back on return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotSizes {
    /// Head bytes.
    pub head: usize,
    /// Head fields.
    pub fields: usize,
    /// Request body bytes.
    pub body: usize,
    /// Reply body bytes.
    pub reply: usize,
    /// The largest capacity a buffer keeps between requests.
    pub retain: usize,
}

impl Default for SlotSizes {
    fn default() -> SlotSizes {
        SlotSizes {
            head: 2048,
            fields: 32,
            body: 0,
            reply: 4096,
            retain: 64 * 1024,
        }
    }
}

/// The data of one in-flight request.
pub struct Slot {
    pub(crate) home: Home,
    pub(crate) trip: Trip,
    pub(crate) head: Head,
    pub(crate) body: Vec<u8>,
    pub(crate) inspected: Option<Inspection>,
    pub(crate) identity: Option<Identity>,
    pub(crate) access: Option<AccessStamp>,
    pub(crate) reply: Reply,
    /// A `Set-Cookie` value authentication asks the response to carry (for
    /// example clearing a dead session cookie), on answers and refusals alike.
    pub(crate) auth_cookie: Vec<u8>,
}

impl Slot {
    pub(crate) fn new(worker: u16, sizes: &SlotSizes) -> Slot {
        Slot {
            home: Home { worker },
            trip: Trip::empty(),
            head: Head::with_capacity(sizes.head, sizes.fields),
            body: Vec::with_capacity(sizes.body),
            inspected: None,
            identity: None,
            access: None,
            reply: Reply::with_capacity(8, sizes.reply),
            auth_cookie: Vec::with_capacity(128),
        }
    }

    /// Wipes what the request used and resets every stamp. Capacity is kept up
    /// to `retain`.
    pub(crate) fn wipe(&mut self, retain: usize) {
        self.head.wipe();
        wipe(&mut self.body);
        self.body.clear();
        self.reply.wipe();
        self.inspected = None;
        self.identity = None;
        self.access = None;
        wipe(&mut self.auth_cookie);
        self.auth_cookie.clear();
        self.trip = Trip {
            ticket: 0,
            client: None,
            ..self.trip
        };
        if self.body.capacity() > retain {
            self.body.shrink_to(retain);
        }
        if self.reply.body.capacity() > retain {
            self.reply.body.shrink_to(retain);
        }
        if self.head.bytes.capacity() > retain {
            self.head.bytes.shrink_to(retain);
        }
    }
}

impl fmt::Debug for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Slot")
            .field("trip", &self.trip)
            .field("head", &self.head)
            .field("body_len", &self.body.len())
            .field("inspected", &self.inspected)
            .field("identity", &self.identity)
            .field("access", &self.access)
            .field("reply", &self.reply)
            .finish()
    }
}
