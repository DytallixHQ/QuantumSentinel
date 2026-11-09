import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { CURVE_OIDS, OID_REGISTRY } from "../../engine/classifier/registry.ts";
import { children, decodeOid, decodeString, decodeTime, integerBitLength, raw, readTlv, value, type Tlv } from "./der.ts";

export interface KeyInfo {
  oid: string;
  algorithm: string; // registry name or "OID x.y.z"
  keySize?: number;
  curve?: string;
  spkiSha256?: string; // fingerprint of the SubjectPublicKeyInfo DER
}

export interface CertInfo {
  derSha256: string;
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  signatureOid: string;
  publicKey: KeyInfo;
}

const sha256 = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

const NAME_ATTRS: Record<string, string> = { "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU", "1.2.840.113549.1.9.1": "E" };

export function decodeName(t: Tlv): string {
  const parts: string[] = [];
  for (const rdn of children(t)) {
    for (const atv of children(rdn)) {
      const [oidT, valT] = children(atv);
      const oid = decodeOid(oidT);
      parts.push(`${NAME_ATTRS[oid] ?? oid}=${decodeString(valT)}`);
    }
  }
  return parts.join(", ");
}

function algName(oid: string): string {
  return OID_REGISTRY[oid]?.name ?? `OID ${oid}`;
}

/** Parse SubjectPublicKeyInfo. Reads only public parameters (modulus length, curve, prime size). */
export function parseSpki(spki: Tlv): KeyInfo {
  const [algId, bits] = children(spki);
  const algParts = children(algId);
  const oid = decodeOid(algParts[0]);
  const params = algParts[1];
  const info: KeyInfo = { oid, algorithm: algName(oid), spkiSha256: sha256(raw(spki)) };
  if (oid === "1.2.840.10045.2.1" && params?.tag === 0x06) {
    const c = decodeOid(params);
    info.curve = CURVE_OIDS[c] ?? c;
  } else if (oid === "1.2.840.113549.1.1.1" || oid === "1.2.840.113549.1.1.10") {
    const bitVal = value(bits);
    const inner = readTlv(bitVal, 1); // skip unused-bits byte
    info.keySize = integerBitLength(children(inner)[0]);
  } else if ((oid === "1.2.840.10040.4.1" || oid === "1.2.840.10046.2.1" || oid === "1.2.840.113549.1.3.1") && params?.tag === 0x30) {
    info.keySize = integerBitLength(children(params)[0]); // p
  }
  return info;
}

export function parseCertificate(der: Uint8Array): CertInfo {
  const cert = readTlv(der, 0);
  const [tbs, sigAlg] = children(cert);
  const f = children(tbs);
  let i = 0;
  if (f[0].tag === 0xa0) i++; // explicit version
  const serial = f[i++];
  i++; // inner signature AlgorithmIdentifier (must equal outer)
  const issuer = f[i++];
  const validity = children(f[i++]);
  const subject = f[i++];
  const spki = f[i++];
  return {
    derSha256: sha256(raw(cert)),
    subject: decodeName(subject),
    issuer: decodeName(issuer),
    serialNumber: Buffer.from(value(serial)).toString("hex"),
    notBefore: decodeTime(validity[0]),
    notAfter: decodeTime(validity[1]),
    signatureOid: decodeOid(children(sigAlg)[0]),
    publicKey: parseSpki(spki),
  };
}

export interface PrivateKeyInfo {
  /** Public key derived from the private key; the private key itself is never retained. */
  publicKey?: KeyInfo;
  oid?: string;
  algorithm: string;
  curve?: string;
  encrypted: boolean;
  encryptionOid?: string; // PBES2 encryption scheme for EncryptedPrivateKeyInfo
}

/**
 * Inspect a private key container. Only the AlgorithmIdentifier is read from the DER;
 * the key octets are passed straight to OpenSSL to derive the SPKI and then dropped.
 */
export function inspectPrivateKey(der: Uint8Array, label: string): PrivateKeyInfo {
  if (label === "ENCRYPTED PRIVATE KEY") {
    const [algId] = children(readTlv(der, 0));
    const [kdfOid, params] = children(algId);
    let encryptionOid: string | undefined;
    if (decodeOid(kdfOid) === "1.2.840.113549.1.5.13" && params) {
      const [, encScheme] = children(params);
      encryptionOid = decodeOid(children(encScheme)[0]);
    } else encryptionOid = decodeOid(kdfOid);
    return { algorithm: "encrypted", encrypted: true, encryptionOid };
  }
  let oid: string | undefined;
  let curve: string | undefined;
  if (label === "PRIVATE KEY") {
    const f = children(readTlv(der, 0));
    const alg = children(f[1]);
    oid = decodeOid(alg[0]);
    if (alg[1]?.tag === 0x06) curve = CURVE_OIDS[decodeOid(alg[1])] ?? decodeOid(alg[1]);
  } else if (label === "RSA PRIVATE KEY") oid = "1.2.840.113549.1.1.1";
  else if (label === "EC PRIVATE KEY") oid = "1.2.840.10045.2.1";
  else if (label === "DSA PRIVATE KEY") oid = "1.2.840.10040.4.1";
  let publicKey: KeyInfo | undefined;
  try {
    const type = label === "PRIVATE KEY" ? "pkcs8" : label === "RSA PRIVATE KEY" ? "pkcs1" : label === "EC PRIVATE KEY" ? "sec1" : undefined;
    if (type) {
      const priv = createPrivateKey({ key: Buffer.from(der), format: "der", type });
      const spki = createPublicKey(priv).export({ format: "der", type: "spki" });
      publicKey = parseSpki(readTlv(new Uint8Array(spki), 0));
    }
  } catch {
    // Unsupported key type in this OpenSSL build; keep OID-only metadata.
  }
  return { publicKey, oid, algorithm: oid ? algName(oid) : "unknown", curve: publicKey?.curve ?? curve, encrypted: false };
}
