// Start shim for hosts whose application setup runs Node apps only (cPanel's
// "Setup Node.js App", Phusion Passenger). It starts the wasp binary beside
// it on a Unix socket in run/ and passes every request through, adding the
// client to X-Forwarded-For. No dependencies: Node's own http module.
//
// Why a socket: any account on a shared server can open a loopback port, and
// wasp believes the client address its front end names. run/ is this
// account's alone (mode 0700), the socket is too (0600), and wasp closes any
// connection from another user before reading a byte.
//
// Environment: WASP_BIN (default ./wasp), WASP_CONFIG (default ./wasp.conf),
// WASP_ADMIN_PASSWORD (passed on), WASP_SOCKET (default ./run/wasp.sock; a
// socket's path is at most about 100 bytes, so set a shorter one if the
// application folder is deep), WASP_STOP_TIMEOUT (seconds a stop may take
// before wasp is killed, default 20), WASP_START_TIMEOUT (seconds wasp may
// take to open its socket, default 60). Passenger sets PORT, for this shim
// only.
//
// Starting: the shim listens only once wasp accepts connections, so the
// request that woke the app is answered by wasp, not with a 502.
//
// Stopping: Passenger stops a Node app by closing its standard input and
// emitting 'exit' on PhusionPassenger; signals work too. Each one asks wasp
// for a clean stop (SIGTERM, and its standard input closes), waits for it to
// exit, and then exits with its code. wasp also stops by itself if this
// shim dies first: its standard input is a pipe held by this process.
'use strict';

const fs = require('fs');
const http = require('http');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');

const here = __dirname;
const bin = process.env.WASP_BIN || path.join(here, 'wasp');
const config = process.env.WASP_CONFIG || path.join(here, 'wasp.conf');
const stopTimeout = Number(process.env.WASP_STOP_TIMEOUT) || 20;
const startTimeout = Number(process.env.WASP_START_TIMEOUT) || 60;
const socket = process.env.WASP_SOCKET || path.join(here, 'run', 'wasp.sock');

// Resolves once something accepts connections on the socket.
function accepting(deadline) {
  return new Promise((resolve, reject) => {
    const attempt = () => {
      const s = net.connect({ path: socket });
      s.once('connect', () => {
        s.destroy();
        resolve();
      });
      s.once('error', () => {
        s.destroy();
        if (Date.now() >= deadline) {
          reject(new Error(`wasp did not open its socket within ${startTimeout}s`));
        } else {
          setTimeout(attempt, 100);
        }
      });
    };
    attempt();
  });
}

// The socket's folder, this account's alone.
function socketFolder() {
  if (Buffer.byteLength(socket) > 100) {
    throw new Error(`the socket path ${socket} is too long: set WASP_SOCKET to a shorter one`);
  }
  const dir = path.dirname(socket);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
}

async function main() {
  socketFolder();
  // wasp reads WASP_SOCKET: it listens on that socket, lets only this user
  // connect, and believes the client this shim names. PORT is Passenger's,
  // for this shim, so wasp does not get it.
  const env = { ...process.env, WASP_SOCKET: socket, WASP_CONFIG: config };
  delete env.PORT;
  const child = spawn(bin, [], {
    cwd: here,
    stdio: ['pipe', 'inherit', 'inherit'],
    env,
  });
  let server = null;
  let exited = false;
  child.on('exit', (code, signal) => {
    exited = true;
    process.exit(code === null ? (signal ? 1 : 0) : code);
  });
  child.on('error', (e) => {
    console.error(`wasp shim: cannot start ${bin}: ${e.message}`);
    process.exit(1);
  });
  // Never leave wasp behind, however this process ends.
  process.on('exit', () => {
    if (!exited) child.kill('SIGKILL');
  });

  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    if (server && server.listening) server.close();
    child.stdin.end();
    child.kill('SIGTERM');
    setTimeout(() => child.kill('SIGKILL'), stopTimeout * 1000).unref();
  };
  for (const sig of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
    process.on(sig, stop);
  }
  // With a listener here, Passenger's loader waits for this process to exit
  // instead of exiting at once (which would leave wasp running).
  if (typeof PhusionPassenger !== 'undefined') {
    PhusionPassenger.on('exit', stop);
  }

  server = http.createServer((req, res) => {
    const headers = { ...req.headers };
    const peer = req.socket.remoteAddress || '';
    headers['x-forwarded-for'] = headers['x-forwarded-for']
      ? `${headers['x-forwarded-for']}, ${peer}`
      : peer;
    // A request with no body can be sent again: one refused while wasp is
    // restarting its listener is retried for up to two seconds.
    const resend = req.method === 'GET' || req.method === 'HEAD';
    const until = Date.now() + 2000;
    const send = () => {
      const upstream = http.request(
        { socketPath: socket, method: req.method, path: req.url, headers },
        (up) => {
          res.writeHead(up.statusCode || 502, up.rawHeaders);
          up.pipe(res);
        },
      );
      upstream.on('error', (e) => {
        const down = e.code === 'ECONNREFUSED' || e.code === 'ENOENT';
        if (resend && down && !stopping && Date.now() < until) {
          setTimeout(send, 100);
          return;
        }
        // wasp is stopped or failing: a plain 502, nothing else.
        if (!res.headersSent) {
          res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
        }
        res.end('502 Bad Gateway\n');
      });
      if (resend) upstream.end();
      else req.pipe(upstream);
    };
    send();
  });
  await accepting(Date.now() + startTimeout * 1000);
  if (!stopping) server.listen(process.env.PORT || 3000);
}

main().catch((e) => {
  console.error(`wasp shim: ${e.message}`);
  process.exit(1);
});
