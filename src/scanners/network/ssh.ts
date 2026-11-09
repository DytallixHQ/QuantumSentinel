// SSH KEXINIT probe (RFC 4253 7.1). Reads the server's algorithm lists; no key exchange is performed.
import { tcpExchange } from "./io.ts";

export interface SshKexInit {
  banner: string;
  kex: string[];
  hostKey: string[];
  encC2S: string[];
  encS2C: string[];
  macC2S: string[];
  macS2C: string[];
}

const CLIENT_BANNER = "SSH-2.0-QuantumSentinel_probe\r\n";

function findBanner(buf: Buffer): { banner: string; rest: Buffer } | null {
  let p = 0;
  while (p < buf.length) {
    const nl = buf.indexOf(0x0a, p);
    if (nl < 0) return null;
    const line = buf.subarray(p, nl).toString("latin1").replace(/\r$/, "");
    if (line.startsWith("SSH-")) return { banner: line, rest: buf.subarray(nl + 1) };
    p = nl + 1; // RFC 4253 allows pre-banner lines
  }
  return null;
}

/** Parse an SSH binary packet carrying SSH_MSG_KEXINIT. */
export function parseKexInitPacket(pkt: Uint8Array): Omit<SshKexInit, "banner"> | null {
  if (pkt.length < 6) return null;
  const dv = new DataView(pkt.buffer, pkt.byteOffset, pkt.byteLength);
  const len = dv.getUint32(0);
  if (len + 4 > pkt.length) return null;
  const pad = pkt[4];
  const payload = pkt.subarray(5, 4 + len - pad);
  if (payload[0] !== 20) throw new Error(`expected KEXINIT, got message ${payload[0]}`);
  let p = 17; // msg byte + 16-byte cookie
  const lists: string[][] = [];
  const pv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  for (let i = 0; i < 10; i++) {
    const n = pv.getUint32(p);
    const s = new TextDecoder().decode(payload.subarray(p + 4, p + 4 + n));
    lists.push(s ? s.split(",") : []);
    p += 4 + n;
  }
  return { kex: lists[0], hostKey: lists[1], encC2S: lists[2], encS2C: lists[3], macC2S: lists[4], macS2C: lists[5] };
}

export function interpretSsh(buf: Buffer): SshKexInit | null {
  const b = findBanner(buf);
  if (!b) return null;
  try {
    const k = parseKexInitPacket(b.rest);
    return k ? { banner: b.banner, ...k } : null;
  } catch {
    return null;
  }
}

export async function probeSsh(host: string, port = 22, timeoutMs?: number): Promise<SshKexInit> {
  const buf = await tcpExchange(host, port, {
    hello: (received) => (findBanner(received) ? new Uint8Array(Buffer.from(CLIENT_BANNER)) : undefined),
    done: (b) => interpretSsh(b) !== null,
    timeoutMs,
  });
  const r = interpretSsh(buf);
  if (!r) throw new Error(`no SSH KEXINIT from ${host}:${port}`);
  return r;
}
