// Start shim for hosts whose application setup runs Node apps only (cPanel's
// "Setup Node.js App", Phusion Passenger). It starts the wasp binary beside
// it on a free loopback port and passes every request through, adding the
// client to X-Forwarded-For. No dependencies: Node's own http module.
//
// Environment: WASP_BIN (default ./wasp), WASP_CONFIG (default ./wasp.conf),
// WASP_ADMIN_PASSWORD (optional, passed on). Passenger sets PORT.
'use strict';

const http = require('http');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');

const here = __dirname;
const bin = process.env.WASP_BIN || path.join(here, 'wasp');
const config = process.env.WASP_CONFIG || path.join(here, 'wasp.conf');

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.unref();
    s.on('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

async function main() {
  const inner = await freePort();
  // wasp reads PORT: it listens on 127.0.0.1:<inner> and trusts only the
  // loopback front end (this shim) for client addresses.
  const child = spawn(bin, [], {
    cwd: here,
    stdio: 'inherit',
    env: { ...process.env, PORT: String(inner), WASP_CONFIG: config },
  });
  child.on('exit', (code, signal) => process.exit(code === null ? (signal ? 1 : 0) : code));
  for (const sig of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
    process.on(sig, () => child.kill(sig));
  }

  const server = http.createServer((req, res) => {
    const headers = { ...req.headers };
    const peer = req.socket.remoteAddress || '';
    headers['x-forwarded-for'] = headers['x-forwarded-for']
      ? `${headers['x-forwarded-for']}, ${peer}`
      : peer;
    const upstream = http.request(
      { host: '127.0.0.1', port: inner, method: req.method, path: req.url, headers },
      (up) => {
        res.writeHead(up.statusCode || 502, up.rawHeaders);
        up.pipe(res);
      },
    );
    upstream.on('error', () => {
      // wasp is still starting, or stopped: a plain 502, nothing else.
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
      }
      res.end('502 Bad Gateway\n');
    });
    req.pipe(upstream);
  });
  server.listen(process.env.PORT || 3000);
}

main().catch((e) => {
  console.error(`wasp shim: ${e.message}`);
  process.exit(1);
});
