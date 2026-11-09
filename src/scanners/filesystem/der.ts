// Minimal strict DER reader (definite lengths only). Enough for X.509, SPKI, PKCS#8 headers and PKCS#12 structure.

export interface Tlv {
  tag: number;
  constructed: boolean;
  start: number; // offset of tag byte
  valueStart: number;
  end: number; // exclusive
  buf: Uint8Array;
}

export class DerError extends Error {}

export function readTlv(buf: Uint8Array, offset = 0, limit = buf.length): Tlv {
  if (offset + 2 > limit) throw new DerError("truncated TLV header");
  const tag = buf[offset];
  if ((tag & 0x1f) === 0x1f) throw new DerError("high-tag-number form unsupported");
  let len = buf[offset + 1];
  let p = offset + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0) throw new DerError("indefinite length not allowed in DER");
    if (n > 4) throw new DerError("length too large");
    if (p + n > limit) throw new DerError("truncated length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p + i];
    p += n;
  }
  if (p + len > limit) throw new DerError("TLV exceeds buffer");
  return { tag, constructed: (tag & 0x20) !== 0, start: offset, valueStart: p, end: p + len, buf };
}

export function children(t: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let p = t.valueStart;
  while (p < t.end) {
    const c = readTlv(t.buf, p, t.end);
    out.push(c);
    p = c.end;
  }
  return out;
}

export function value(t: Tlv): Uint8Array {
  return t.buf.subarray(t.valueStart, t.end);
}

export function raw(t: Tlv): Uint8Array {
  return t.buf.subarray(t.start, t.end);
}

export function decodeOid(t: Tlv): string {
  if (t.tag !== 0x06) throw new DerError(`expected OID, got tag 0x${t.tag.toString(16)}`);
  const v = value(t);
  if (!v.length) throw new DerError("empty OID");
  const parts: number[] = [];
  let acc = 0;
  for (let i = 0; i < v.length; i++) {
    acc = acc * 128 + (v[i] & 0x7f);
    if (!(v[i] & 0x80)) {
      if (!parts.length) {
        const first = acc < 80 ? Math.floor(acc / 40) : 2;
        parts.push(first, acc - first * 40);
      } else parts.push(acc);
      acc = 0;
    }
  }
  return parts.join(".");
}

export function decodeInteger(t: Tlv): bigint {
  const v = value(t);
  let n = 0n;
  for (const b of v) n = (n << 8n) | BigInt(b);
  if (v.length && v[0] & 0x80) n -= 1n << BigInt(v.length * 8);
  return n;
}

/** Bit length of an unsigned INTEGER (e.g. an RSA modulus) without materializing it. */
export function integerBitLength(t: Tlv): number {
  const v = value(t);
  let i = 0;
  while (i < v.length - 1 && v[i] === 0) i++;
  const lead = v[i];
  return (v.length - i - 1) * 8 + (lead ? 32 - Math.clz32(lead) : 0);
}

export function decodeString(t: Tlv): string {
  return new TextDecoder().decode(value(t));
}

/** Decode GeneralizedTime / UTCTime to ISO-8601. */
export function decodeTime(t: Tlv): string {
  const s = decodeString(t);
  const m = t.tag === 0x17 ? s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/) : s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/);
  if (!m) return s;
  const year = t.tag === 0x17 ? (Number(m[1]) >= 50 ? 1900 : 2000) + Number(m[1]) : Number(m[1]);
  return `${String(year).padStart(4, "0")}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6] ?? "00"}Z`;
}

/** Parse a DER blob; returns null when it is not exactly one well-formed TLV. */
export function tryParseDer(buf: Uint8Array): Tlv | null {
  try {
    const t = readTlv(buf, 0);
    return t.end === buf.length ? t : null;
  } catch {
    return null;
  }
}

export interface PemBlock {
  label: string;
  der: Uint8Array;
  headers: boolean; // legacy encrypted PEM ("Proc-Type: 4,ENCRYPTED")
}

export function parsePem(text: string): PemBlock[] {
  const out: PemBlock[] = [];
  const re = /-----BEGIN ([A-Z0-9 #]+)-----([\s\S]*?)-----END \1-----/g;
  for (let m; (m = re.exec(text)); ) {
    const body = m[2];
    const headers = /Proc-Type:/i.test(body);
    const b64 = body.split(/\r?\n/).filter((l) => l && !l.includes(":")).join("").replace(/\s+/g, "");
    out.push({ label: m[1], der: new Uint8Array(Buffer.from(b64, "base64")), headers });
  }
  return out;
}
