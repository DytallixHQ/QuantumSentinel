// Content sniffers for keystores, OpenPGP and full-disk-encryption headers.
// All parsers are read-only over public structure; encrypted bags/keys are never decrypted.
import { children, decodeOid, readTlv, tryParseDer, value } from "./der.ts";

export type ContentType =
  | "pem" | "x509-der" | "spki-der" | "pkcs8-der" | "pkcs12" | "jks" | "jceks"
  | "openpgp" | "luks1" | "luks2" | "bitlocker" | "high-entropy" | "other";

export function shannonEntropy(buf: Uint8Array): number {
  if (!buf.length) return 0;
  const counts = new Uint32Array(256);
  for (const b of buf) counts[b]++;
  let h = 0;
  for (const c of counts) {
    if (!c) continue;
    const p = c / buf.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export const ENTROPY_THRESHOLD = 7.5;
const LUKS_MAGIC = [0x4c, 0x55, 0x4b, 0x53, 0xba, 0xbe];
const OID_PKCS7_DATA = "1.2.840.113549.1.7.1";
const OID_PKCS7_ENCRYPTED = "1.2.840.113549.1.7.6";

function startsWith(buf: Uint8Array, magic: number[], at = 0): boolean {
  return magic.every((b, i) => buf[at + i] === b);
}

/** Sniff content type from bytes only; file extensions are never consulted. */
export function sniff(buf: Uint8Array): ContentType {
  if (buf.length >= 4) {
    const m = (buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3]) >>> 0;
    if (m === 0xfeedfeed) return "jks";
    if (m === 0xcececece) return "jceks";
  }
  if (startsWith(buf, LUKS_MAGIC)) {
    const ver = (buf[6] << 8) | buf[7];
    return ver === 2 ? "luks2" : "luks1";
  }
  if (buf.length > 11 && new TextDecoder().decode(buf.subarray(3, 11)) === "-FVE-FS-") return "bitlocker";
  const head = new TextDecoder("latin1").decode(buf.subarray(0, Math.min(buf.length, 4096)));
  if (head.includes("-----BEGIN ")) return head.includes("PGP ") ? "openpgp" : "pem";
  const der = buf[0] === 0x30 ? tryParseDer(buf) : null;
  if (der) {
    try {
      const f = children(der);
      if (f[0]?.tag === 0x02 && f.length >= 2 && f[1].tag === 0x30) {
        const v = value(f[0]);
        if (v.length === 1 && v[0] === 3 && children(f[1])[0]?.tag === 0x06 && decodeOid(children(f[1])[0]) === OID_PKCS7_DATA) return "pkcs12";
        if (v.length === 1 && (v[0] === 0 || v[0] === 1) && f[2]?.tag === 0x04) return "pkcs8-der";
      }
      if (f[0]?.tag === 0x30 && f[1]?.tag === 0x30 && f[2]?.tag === 0x03) return "x509-der";
      if (f.length === 2 && f[0].tag === 0x30 && f[1].tag === 0x03) return "spki-der";
    } catch {
      /* fall through */
    }
  }
  if (isOpenPgpBinary(buf)) return "openpgp";
  if (shannonEntropy(buf.subarray(0, 65536)) >= ENTROPY_THRESHOLD) return "high-entropy";
  return "other";
}

// ---------------------------------------------------------------- OpenPGP (RFC 9580)

export interface PgpPacket {
  tag: number;
  version?: number;
  algorithmId?: number;
  algorithm?: string;
  keyId?: string;
}

const PGP_ALGS: Record<number, string> = {
  1: "RSA", 2: "RSA", 3: "RSA", 16: "ElGamal", 17: "DSA", 18: "ECDH", 19: "ECDSA", 22: "EdDSA",
  25: "X25519", 26: "X448", 27: "Ed25519", 28: "Ed448",
  // draft-ietf-openpgp-pqc
  30: "ML-DSA-65+Ed25519", 31: "ML-DSA-87+Ed448", 35: "ML-KEM-768+X25519", 36: "ML-KEM-1024+X448",
};

function isOpenPgpBinary(buf: Uint8Array): boolean {
  if (buf.length < 3 || !(buf[0] & 0x80)) return false;
  try {
    const pkts = parsePgpPackets(buf, 4);
    return pkts.length > 0 && pkts.every((p) => [1, 2, 3, 5, 6, 7, 8, 11, 13, 14, 18, 20].includes(p.tag)) && pkts.some((p) => p.algorithm !== undefined);
  } catch {
    return false;
  }
}

export function dearmor(text: string): Uint8Array {
  const m = text.match(/-----BEGIN PGP [A-Z ]+-----\r?\n([\s\S]*?)-----END PGP/);
  if (!m) return new Uint8Array();
  const lines = m[1].split(/\r?\n/);
  const blank = lines.findIndex((l) => l.trim() === "");
  const body = (blank >= 0 ? lines.slice(blank + 1) : lines).filter((l) => !l.startsWith("=")).join("");
  return new Uint8Array(Buffer.from(body, "base64"));
}

/** Walk packet headers; inspects Tag 1 (PKESK) and Tag 6/14 (public keys) only. */
export function parsePgpPackets(buf: Uint8Array, maxPackets = 64): PgpPacket[] {
  const out: PgpPacket[] = [];
  let p = 0;
  while (p < buf.length && out.length < maxPackets) {
    const h = buf[p];
    if (!(h & 0x80)) throw new Error("bad packet header");
    let tag: number;
    let len: number;
    if (h & 0x40) {
      tag = h & 0x3f;
      const b0 = buf[p + 1];
      if (b0 < 192) { len = b0; p += 2; }
      else if (b0 < 224) { len = ((b0 - 192) << 8) + buf[p + 2] + 192; p += 3; }
      else if (b0 === 255) { len = (buf[p + 2] << 24 | buf[p + 3] << 16 | buf[p + 4] << 8 | buf[p + 5]) >>> 0; p += 6; }
      else throw new Error("partial body lengths unsupported");
    } else {
      tag = (h >> 2) & 0x0f;
      const lt = h & 3;
      if (lt === 0) { len = buf[p + 1]; p += 2; }
      else if (lt === 1) { len = (buf[p + 1] << 8) | buf[p + 2]; p += 3; }
      else if (lt === 2) { len = (buf[p + 1] << 24 | buf[p + 2] << 16 | buf[p + 3] << 8 | buf[p + 4]) >>> 0; p += 5; }
      else { len = buf.length - p - 1; p += 1; }
    }
    if (p + len > buf.length) throw new Error("packet exceeds buffer");
    const body = buf.subarray(p, p + len);
    const pkt: PgpPacket = { tag };
    if (tag === 1 && body.length >= 10) {
      pkt.version = body[0];
      if (body[0] === 3) {
        pkt.keyId = Buffer.from(body.subarray(1, 9)).toString("hex");
        pkt.algorithmId = body[9];
      } else if (body[0] === 6) {
        const fpLen = body[1];
        pkt.algorithmId = body[2 + fpLen];
      }
    } else if ((tag === 6 || tag === 14) && body.length >= 6) {
      pkt.version = body[0];
      pkt.algorithmId = body[0] === 3 ? body[7] : body[5];
    }
    if (pkt.algorithmId !== undefined) pkt.algorithm = PGP_ALGS[pkt.algorithmId] ?? `pgp-alg-${pkt.algorithmId}`;
    out.push(pkt);
    p += len;
  }
  return out;
}

// ---------------------------------------------------------------- Java KeyStore

export interface JksEntry {
  alias: string;
  kind: "private-key" | "trusted-cert" | "secret-key";
  certs: Uint8Array[]; // DER certificates (public)
}

/** Parse JKS/JCEKS entries. Protected private-key blobs are skipped, never decrypted. */
export function parseJks(buf: Uint8Array): JksEntry[] {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let p = 8;
  const count = dv.getUint32(p);
  p += 4;
  const utf = () => {
    const n = dv.getUint16(p);
    const s = new TextDecoder().decode(buf.subarray(p + 2, p + 2 + n));
    p += 2 + n;
    return s;
  };
  const cert = () => {
    utf(); // certificate type, e.g. "X.509"
    const n = dv.getUint32(p);
    const der = buf.subarray(p + 4, p + 4 + n);
    p += 4 + n;
    return der;
  };
  const out: JksEntry[] = [];
  for (let i = 0; i < Math.min(count, 1024); i++) {
    const tag = dv.getUint32(p);
    p += 4;
    const alias = utf();
    p += 8; // timestamp
    if (tag === 1) {
      const n = dv.getUint32(p);
      p += 4 + n; // EncryptedPrivateKeyInfo: skipped
      const chain = dv.getUint32(p);
      p += 4;
      const certs: Uint8Array[] = [];
      for (let c = 0; c < Math.min(chain, 32); c++) certs.push(cert());
      out.push({ alias, kind: "private-key", certs });
    } else if (tag === 2) {
      out.push({ alias, kind: "trusted-cert", certs: [cert()] });
    } else {
      // JCEKS sealed secret key (Java serialization): record and stop; offsets are not recoverable.
      out.push({ alias, kind: "secret-key", certs: [] });
      break;
    }
  }
  return out;
}

// ---------------------------------------------------------------- PKCS#12

export interface P12Summary {
  certs: Uint8Array[]; // from unencrypted CertBags only
  shroudedKeyBags: number;
  plainKeyBags: number;
  encryptedContentOids: string[]; // algorithms protecting EncryptedData content
  shroudedKeyOids: string[];
  macDigestOid?: string;
}

const OID_CERT_BAG = "1.2.840.113549.1.12.10.1.3";
const OID_KEY_BAG = "1.2.840.113549.1.12.10.1.1";
const OID_SHROUDED_KEY_BAG = "1.2.840.113549.1.12.10.1.2";
const OID_X509_CERT = "1.2.840.113549.1.9.22.1";
const OID_PBES2 = "1.2.840.113549.1.5.13";

function pbeAlgorithm(algId: ReturnType<typeof readTlv>): string {
  const [oidT, params] = children(algId);
  const oid = decodeOid(oidT);
  if (oid === OID_PBES2 && params) return decodeOid(children(children(params)[1])[0]);
  return oid;
}

/** Walk a PFX without a password: unencrypted bags are read; encrypted ones are counted with their algorithm. */
export function parsePkcs12(buf: Uint8Array): P12Summary {
  const pfx = children(readTlv(buf, 0));
  const authSafeCi = children(pfx[1]);
  if (decodeOid(authSafeCi[0]) !== OID_PKCS7_DATA) throw new Error("unsupported PFX authSafe (public-key integrity mode)");
  const octet = children(authSafeCi[1])[0];
  const safes = children(readTlv(value(octet), 0));
  const out: P12Summary = { certs: [], shroudedKeyBags: 0, plainKeyBags: 0, encryptedContentOids: [], shroudedKeyOids: [] };
  for (const ci of safes) {
    const [typeT, content] = children(ci);
    const type = decodeOid(typeT);
    if (type === OID_PKCS7_ENCRYPTED) {
      const encData = children(children(content)[0]);
      const eci = children(encData[1]);
      out.encryptedContentOids.push(pbeAlgorithm(eci[1]));
      continue;
    }
    if (type !== OID_PKCS7_DATA) continue;
    const bags = children(readTlv(value(children(content)[0]), 0));
    for (const bag of bags) {
      const [bagIdT, bagVal] = children(bag);
      const bagId = decodeOid(bagIdT);
      const inner = children(bagVal)[0];
      if (bagId === OID_CERT_BAG) {
        const [certIdT, certVal] = children(inner);
        if (decodeOid(certIdT) === OID_X509_CERT) out.certs.push(value(children(certVal)[0]));
      } else if (bagId === OID_SHROUDED_KEY_BAG) {
        out.shroudedKeyBags++;
        out.shroudedKeyOids.push(pbeAlgorithm(children(inner)[0]));
      } else if (bagId === OID_KEY_BAG) {
        out.plainKeyBags++;
      }
    }
  }
  if (pfx[2]) {
    const digestInfo = children(children(pfx[2])[0]);
    out.macDigestOid = decodeOid(children(digestInfo[0])[0]);
  }
  return out;
}

// ---------------------------------------------------------------- LUKS / BitLocker

export interface VolumeInfo {
  format: "LUKS1" | "LUKS2" | "BitLocker";
  cipher?: string; // e.g. "aes-xts-plain64"
  keyBits?: number; // effective cipher key bits (XTS halves the stored key)
  hash?: string;
}

function cstr(buf: Uint8Array, at: number, n: number): string {
  const s = buf.subarray(at, at + n);
  const z = s.indexOf(0);
  return new TextDecoder().decode(z >= 0 ? s.subarray(0, z) : s);
}

export function parseLuks(buf: Uint8Array): VolumeInfo {
  const ver = (buf[6] << 8) | buf[7];
  if (ver === 1) {
    const cipher = `${cstr(buf, 8, 32)}-${cstr(buf, 40, 32)}`;
    const keyBytes = new DataView(buf.buffer, buf.byteOffset).getUint32(108);
    const xts = /xts/i.test(cipher);
    return { format: "LUKS1", cipher, keyBits: (keyBytes * 8) / (xts ? 2 : 1), hash: cstr(buf, 72, 32) };
  }
  // LUKS2: 4096-byte binary header, then JSON metadata area.
  const end = buf.indexOf(0, 4096);
  const json = JSON.parse(new TextDecoder().decode(buf.subarray(4096, end > 0 ? end : undefined)));
  const seg = Object.values(json.segments ?? {})[0] as { encryption?: string } | undefined;
  const ks = Object.values(json.keyslots ?? {})[0] as { key_size?: number } | undefined;
  const cipher = seg?.encryption;
  const xts = /xts/i.test(cipher ?? "");
  return { format: "LUKS2", cipher, keyBits: ks?.key_size ? (ks.key_size * 8) / (xts ? 2 : 1) : undefined, hash: cstr(buf, 72, 32) || undefined };
}

const BITLOCKER_METHODS: Record<number, { cipher: string; keyBits: number }> = {
  0x8000: { cipher: "aes-cbc-diffuser", keyBits: 128 },
  0x8001: { cipher: "aes-cbc-diffuser", keyBits: 256 },
  0x8002: { cipher: "aes-cbc", keyBits: 128 },
  0x8003: { cipher: "aes-cbc", keyBits: 256 },
  0x8004: { cipher: "aes-xts", keyBits: 128 },
  0x8005: { cipher: "aes-xts", keyBits: 256 },
};

/** Reads the encryption method from the first FVE metadata block when it is inside `buf`. */
export function parseBitLocker(buf: Uint8Array): VolumeInfo {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  if (buf.length >= 0xb8) {
    const off = Number(dv.getBigUint64(0xb0, true));
    if (off > 0 && off + 102 <= buf.length && cstr(buf, off, 8) === "-FVE-FS-") {
      const method = dv.getUint16(off + 64 + 36, true);
      const m = BITLOCKER_METHODS[method];
      if (m) return { format: "BitLocker", ...m };
    }
  }
  return { format: "BitLocker" };
}
