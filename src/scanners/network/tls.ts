// Raw TLS 1.2/1.3 ClientHello probe. No handshake is completed and no application data is sent.
import { randomBytes } from "node:crypto";
import { tcpExchange } from "./io.ts";

export const HRR_RANDOM = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c";

export const PROBE_GROUPS_PQ_FIRST = [0x11ec, 0x11eb, 0x11ed, 0x0201, 0x0202, 0x001d, 0x0017, 0x0018, 0x0019, 0x001e, 0x0100, 0x0101];
export const PROBE_GROUPS_CLASSICAL = [0x001d, 0x0017, 0x0018, 0x0019, 0x001e, 0x0100, 0x0101];
const TLS13_SUITES = [0x1301, 0x1302, 0x1303];
const TLS12_SUITES = [0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9, 0xc013, 0xc014, 0xc009, 0xc00a, 0x009e, 0x009f, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a];
const SIG_ALGS = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807, 0x0808, 0x0401, 0x0501, 0x0601, 0x0904, 0x0905, 0x0906];

const u16 = (n: number) => [(n >> 8) & 0xff, n & 0xff];
const u24 = (n: number) => [(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
const vec16 = (b: number[]) => [...u16(b.length), ...b];
const ext = (type: number, body: number[]) => [...u16(type), ...vec16(body)];

export interface ClientHelloOptions {
  serverName?: string;
  maxVersion: "1.2" | "1.3";
  groups?: number[];
  random?: Uint8Array; // injectable for golden tests
  shares?: number[]; // groups to send key shares for (supported: 0x11ec, 0x0201, 0x001d)
}

/**
 * Throwaway key share bytes. ML-KEM-768 encapsulation keys are all-zero coefficients plus a random seed:
 * validly encoded (every coefficient < q) and never used, because the handshake is abandoned after ServerHello.
 */
function keyShareBytes(group: number): number[] | undefined {
  const mlkem768 = () => [...new Array(1152).fill(0), ...randomBytes(32)];
  if (group === 0x11ec) return [...mlkem768(), ...randomBytes(32)];
  if (group === 0x0201) return mlkem768();
  if (group === 0x001d) return [...randomBytes(32)];
  return undefined;
}

export const PROBE_GROUPS_PURE_MLKEM = [0x0201, 0x0202, 0x0200];

export function buildClientHello(o: ClientHelloOptions): Uint8Array {
  const groups = o.groups ?? PROBE_GROUPS_PQ_FIRST;
  const random = [...(o.random ?? randomBytes(32))];
  const sessionId = o.maxVersion === "1.3" ? random.slice(0, 32).map((b) => b ^ 0x5a) : [];
  const suites = o.maxVersion === "1.3" ? [...TLS13_SUITES, ...TLS12_SUITES] : TLS12_SUITES;
  const exts: number[] = [];
  if (o.serverName) {
    const name = [...Buffer.from(o.serverName, "ascii")];
    exts.push(...ext(0x0000, vec16([0x00, ...vec16(name)])));
  }
  exts.push(...ext(0x000a, vec16(groups.flatMap(u16))));
  exts.push(...ext(0x000b, [1, 0])); // ec_point_formats: uncompressed
  exts.push(...ext(0x000d, vec16(SIG_ALGS.flatMap(u16))));
  exts.push(...ext(0xff01, [0])); // renegotiation_info
  if (o.maxVersion === "1.3") {
    exts.push(...ext(0x002b, [4, ...u16(0x0304), ...u16(0x0303)]));
    exts.push(...ext(0x002d, [1, 1])); // psk_key_exchange_modes: psk_dhe_ke
    // Key shares (default: X25519MLKEM768 when offered, plus X25519). Servers that only switch to a PQ group when the
    // client already sent its share (e.g. OpenSSL 3.5 tuple preference) would otherwise be under-reported.
    const shareGroups = o.shares ?? (groups.includes(0x11ec) ? [0x11ec, 0x001d] : [0x001d]);
    const shares = shareGroups.flatMap((grp) => {
      const k = keyShareBytes(grp);
      return k ? [...u16(grp), ...vec16(k)] : [];
    });
    exts.push(...ext(0x0033, vec16(shares)));
  }
  const body = [...u16(0x0303), ...random, sessionId.length, ...sessionId, ...vec16(suites.flatMap(u16)), 1, 0, ...vec16(exts)];
  const hs = [0x01, ...u24(body.length), ...body];
  return new Uint8Array([0x16, 0x03, 0x01, ...u16(hs.length), ...hs]);
}

export interface TlsProbeResult {
  version?: "TLS1.3" | "TLS1.2" | "TLS1.1" | "TLS1.0";
  cipherSuite?: number;
  /** Group the server selected (ServerHello key_share) or requested (HelloRetryRequest). */
  group?: number;
  helloRetry: boolean;
  /** TLS 1.2 only: named curve from ServerKeyExchange. */
  ske?: { curveType: number; group?: number };
  certificates: Uint8Array[]; // TLS 1.2 only (TLS 1.3 certificates are encrypted)
  alert?: { level: number; description: number };
  complete: boolean;
}

interface HsMsg {
  type: number;
  body: Uint8Array;
}

/** Split TLS records and reassemble handshake messages (plaintext portion only). */
export function parseServerFlight(buf: Uint8Array): { messages: HsMsg[]; alert?: { level: number; description: number }; sawCcsOrAppData: boolean } {
  let p = 0;
  const hs: number[] = [];
  let alert: { level: number; description: number } | undefined;
  let sawCcsOrAppData = false;
  while (p + 5 <= buf.length) {
    const type = buf[p];
    const len = (buf[p + 3] << 8) | buf[p + 4];
    if (p + 5 + len > buf.length) break;
    const frag = buf.subarray(p + 5, p + 5 + len);
    if (type === 22 && !sawCcsOrAppData) hs.push(...frag);
    else if (type === 21 && frag.length >= 2) alert = { level: frag[0], description: frag[1] };
    else if (type === 20 || type === 23) sawCcsOrAppData = true;
    p += 5 + len;
  }
  const messages: HsMsg[] = [];
  let q = 0;
  while (q + 4 <= hs.length) {
    const len = (hs[q + 1] << 16) | (hs[q + 2] << 8) | hs[q + 3];
    if (q + 4 + len > hs.length) break;
    messages.push({ type: hs[q], body: Uint8Array.from(hs.slice(q + 4, q + 4 + len)) });
    q += 4 + len;
  }
  return { messages, alert, sawCcsOrAppData };
}

const VERSIONS: Record<number, TlsProbeResult["version"]> = { 0x0304: "TLS1.3", 0x0303: "TLS1.2", 0x0302: "TLS1.1", 0x0301: "TLS1.0" };

export function parseServerHello(body: Uint8Array): Pick<TlsProbeResult, "version" | "cipherSuite" | "group" | "helloRetry"> {
  let p = 0;
  const legacy = (body[p] << 8) | body[p + 1];
  p += 2;
  const random = Buffer.from(body.subarray(p, p + 32)).toString("hex");
  p += 32;
  p += 1 + body[p]; // session id
  const cipherSuite = (body[p] << 8) | body[p + 1];
  p += 3; // suite + compression
  let version = VERSIONS[legacy];
  let group: number | undefined;
  const helloRetry = random === HRR_RANDOM;
  if (p + 2 <= body.length) {
    const end = p + 2 + ((body[p] << 8) | body[p + 1]);
    p += 2;
    while (p + 4 <= end) {
      const type = (body[p] << 8) | body[p + 1];
      const len = (body[p + 2] << 8) | body[p + 3];
      const d = body.subarray(p + 4, p + 4 + len);
      if (type === 0x002b && len >= 2) version = VERSIONS[(d[0] << 8) | d[1]];
      if (type === 0x0033 && len >= 2) group = (d[0] << 8) | d[1];
      p += 4 + len;
    }
  }
  return { version, cipherSuite, group, helloRetry };
}

export function parseCertificateMsg(body: Uint8Array): Uint8Array[] {
  const certs: Uint8Array[] = [];
  const total = (body[0] << 16) | (body[1] << 8) | body[2];
  let p = 3;
  while (p + 3 <= 3 + total && p + 3 <= body.length) {
    const len = (body[p] << 16) | (body[p + 1] << 8) | body[p + 2];
    certs.push(body.subarray(p + 3, p + 3 + len));
    p += 3 + len;
  }
  return certs;
}

/** Interpret a captured server flight (unit-testable with recorded bytes). */
export function interpretFlight(buf: Uint8Array): TlsProbeResult {
  const { messages, alert } = parseServerFlight(buf);
  const out: TlsProbeResult = { helloRetry: false, certificates: [], alert, complete: false };
  for (const m of messages) {
    if (m.type === 2) Object.assign(out, parseServerHello(m.body));
    else if (m.type === 11) out.certificates = parseCertificateMsg(m.body);
    else if (m.type === 12 && m.body.length >= 3) out.ske = { curveType: m.body[0], group: m.body[0] === 3 ? (m.body[1] << 8) | m.body[2] : undefined };
    else if (m.type === 14) out.complete = true;
  }
  if (out.version === "TLS1.3" && out.cipherSuite !== undefined) out.complete = true;
  return out;
}

function flightDone(buf: Buffer): boolean {
  const r = parseServerFlight(buf);
  if (r.alert || r.sawCcsOrAppData) return true;
  return r.messages.some((m) => m.type === 14 || (m.type === 2 && (m.body.length > 40 && parseServerHello(m.body).version === "TLS1.3")));
}

export async function probeTls(host: string, port: number, opts: { serverName?: string; maxVersion?: "1.2" | "1.3"; groups?: number[]; shares?: number[]; timeoutMs?: number } = {}): Promise<TlsProbeResult> {
  const hello = buildClientHello({ serverName: opts.serverName ?? (/^[\d.:]+$/.test(host) ? undefined : host), maxVersion: opts.maxVersion ?? "1.3", groups: opts.groups, shares: opts.shares });
  const buf = await tcpExchange(host, port, { hello, done: flightDone, timeoutMs: opts.timeoutMs });
  return interpretFlight(buf);
}
