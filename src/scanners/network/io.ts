import dgram from "node:dgram";
import net from "node:net";

export const DEFAULT_TIMEOUT_MS = 3000;

export class ProbeTimeout extends Error {
  constructor(what: string, ms: number) {
    super(`${what} timed out after ${ms} ms`);
  }
}

/**
 * Open a non-blocking TCP connection, send `hello` (optional), and accumulate bytes until
 * `done(buffer)` returns true, the peer closes, or the deadline passes. Connect and read
 * phases each get an explicit timeout; the socket is always destroyed.
 */
export function tcpExchange(
  host: string,
  port: number,
  opts: { hello?: Uint8Array | ((received: Buffer) => Uint8Array | undefined); done: (buf: Buffer) => boolean; timeoutMs?: number; maxBytes?: number },
): Promise<Buffer> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = opts.maxBytes ?? 256 * 1024;
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host, port });
    let buf = Buffer.alloc(0);
    let settled = false;
    let sentLate = false;
    const finish = (err?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(connectTimer);
      clearTimeout(readTimer);
      sock.destroy();
      if (err && !buf.length) reject(err);
      else resolve(buf);
    };
    const connectTimer = setTimeout(() => finish(new ProbeTimeout(`connect ${host}:${port}`, timeoutMs)), timeoutMs);
    let readTimer: NodeJS.Timeout | undefined;
    sock.once("connect", () => {
      clearTimeout(connectTimer);
      readTimer = setTimeout(() => finish(new ProbeTimeout(`read ${host}:${port}`, timeoutMs)), timeoutMs);
      if (opts.hello instanceof Uint8Array) sock.write(opts.hello);
    });
    sock.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (typeof opts.hello === "function" && !sentLate) {
        const out = opts.hello(buf);
        if (out) {
          sentLate = true;
          sock.write(out);
        }
      }
      if (buf.length >= maxBytes || opts.done(buf)) finish();
    });
    sock.once("error", (e) => finish(e));
    sock.once("close", () => finish(new Error(`connection closed by ${host}:${port}`)));
  });
}

/** Single UDP request/response with a receive deadline (UDP has no connect phase). */
export function udpExchange(host: string, port: number, payload: Uint8Array, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket(net.isIPv6(host) ? "udp6" : "udp4");
    const timer = setTimeout(() => {
      sock.close();
      reject(new ProbeTimeout(`udp ${host}:${port}`, timeoutMs));
    }, timeoutMs);
    sock.once("message", (msg) => {
      clearTimeout(timer);
      sock.close();
      resolve(msg);
    });
    sock.once("error", (e) => {
      clearTimeout(timer);
      sock.close();
      reject(e);
    });
    sock.send(payload, port, host);
  });
}
