import { canonicalPrimitiveId } from "../../core/graph/graph.ts";
import type { CryptoPrimitive, Evidence } from "../../core/graph/types.ts";
import { classifyAlgorithm, type AlgorithmInput, type Classification } from "./classify.ts";

type Entry = Omit<AlgorithmInput, "oid">;

/** X.509 / PKCS OIDs: public-key and signature algorithms, curves. */
export const OID_REGISTRY: Record<string, Entry> = {
  "1.2.840.113549.1.1.1": { name: "RSA", usage: "public-key" },
  "1.2.840.113549.1.1.5": { name: "SHA1withRSA", usage: "signature" },
  "1.2.840.113549.1.1.10": { name: "RSASSA-PSS", usage: "signature" },
  "1.2.840.113549.1.1.11": { name: "SHA256withRSA", usage: "signature" },
  "1.2.840.113549.1.1.12": { name: "SHA384withRSA", usage: "signature" },
  "1.2.840.113549.1.1.13": { name: "SHA512withRSA", usage: "signature" },
  "1.2.840.113549.1.1.7": { name: "RSAES-OAEP", usage: "encryption" },
  "1.2.840.10045.2.1": { name: "EC", usage: "public-key" },
  "1.2.840.10045.4.1": { name: "ECDSA", usage: "signature" },
  "1.2.840.10045.4.3.2": { name: "ECDSA", usage: "signature" },
  "1.2.840.10045.4.3.3": { name: "ECDSA", usage: "signature" },
  "1.2.840.10045.4.3.4": { name: "ECDSA", usage: "signature" },
  "1.2.840.10040.4.1": { name: "DSA", usage: "public-key" },
  "1.2.840.10040.4.3": { name: "DSA", usage: "signature" },
  "1.2.840.10046.2.1": { name: "DH", usage: "key-exchange" },
  "1.2.840.113549.1.3.1": { name: "DH", usage: "key-exchange" },
  "1.3.101.110": { name: "X25519", usage: "key-exchange" },
  "1.3.101.111": { name: "X448", usage: "key-exchange" },
  "1.3.101.112": { name: "Ed25519", usage: "signature" },
  "1.3.101.113": { name: "Ed448", usage: "signature" },
  "2.16.840.1.101.3.4.3.17": { name: "ML-DSA-44", usage: "signature" },
  "2.16.840.1.101.3.4.3.18": { name: "ML-DSA-65", usage: "signature" },
  "2.16.840.1.101.3.4.3.19": { name: "ML-DSA-87", usage: "signature" },
  "2.16.840.1.101.3.4.3.20": { name: "SLH-DSA-SHA2-128s", usage: "signature" },
  "2.16.840.1.101.3.4.3.21": { name: "SLH-DSA-SHA2-128f", usage: "signature" },
  "2.16.840.1.101.3.4.3.22": { name: "SLH-DSA-SHA2-192s", usage: "signature" },
  "2.16.840.1.101.3.4.3.23": { name: "SLH-DSA-SHA2-192f", usage: "signature" },
  "2.16.840.1.101.3.4.3.24": { name: "SLH-DSA-SHA2-256s", usage: "signature" },
  "2.16.840.1.101.3.4.3.25": { name: "SLH-DSA-SHA2-256f", usage: "signature" },
  "2.16.840.1.101.3.4.3.26": { name: "SLH-DSA-SHAKE-128s", usage: "signature" },
  "2.16.840.1.101.3.4.3.27": { name: "SLH-DSA-SHAKE-128f", usage: "signature" },
  "2.16.840.1.101.3.4.3.28": { name: "SLH-DSA-SHAKE-192s", usage: "signature" },
  "2.16.840.1.101.3.4.3.29": { name: "SLH-DSA-SHAKE-192f", usage: "signature" },
  "2.16.840.1.101.3.4.3.30": { name: "SLH-DSA-SHAKE-256s", usage: "signature" },
  "2.16.840.1.101.3.4.3.31": { name: "SLH-DSA-SHAKE-256f", usage: "signature" },
  "2.16.840.1.101.3.4.4.1": { name: "ML-KEM-512", usage: "key-exchange" },
  "2.16.840.1.101.3.4.4.2": { name: "ML-KEM-768", usage: "key-exchange" },
  "2.16.840.1.101.3.4.4.3": { name: "ML-KEM-1024", usage: "key-exchange" },
  "1.2.840.113549.1.9.16.3.17": { name: "LMS", usage: "signature" }, // id-alg-hss-lms-hashsig
  "1.3.6.1.5.5.7.6.34": { name: "XMSS", usage: "signature" },
  "1.3.6.1.5.5.7.6.35": { name: "XMSSMT", usage: "signature" },
  "1.2.156.10197.1.301": { name: "SM2", usage: "signature" },
  // Symmetric / PBE (seen in PKCS#8 encryption and PKCS#12 bags)
  "2.16.840.1.101.3.4.1.2": { name: "AES-128-CBC", usage: "encryption" },
  "2.16.840.1.101.3.4.1.22": { name: "AES-192-CBC", usage: "encryption" },
  "2.16.840.1.101.3.4.1.42": { name: "AES-256-CBC", usage: "encryption" },
  "1.2.840.113549.3.7": { name: "3DES", usage: "encryption" },
  "1.2.840.113549.1.12.1.3": { name: "3DES", usage: "encryption" }, // pbeWithSHAAnd3-KeyTripleDES-CBC
  "1.2.840.113549.1.12.1.6": { name: "RC2", usage: "encryption" }, // pbeWithSHAAnd40BitRC2-CBC
  "1.3.14.3.2.26": { name: "SHA-1", usage: "hash" },
  "2.16.840.1.101.3.4.2.1": { name: "SHA-256", usage: "hash" },
  "2.16.840.1.101.3.4.2.2": { name: "SHA-384", usage: "hash" },
  "2.16.840.1.101.3.4.2.3": { name: "SHA-512", usage: "hash" },
};

export const CURVE_OIDS: Record<string, string> = {
  "1.2.840.10045.3.1.7": "P-256",
  "1.3.132.0.34": "P-384",
  "1.3.132.0.35": "P-521",
  "1.3.132.0.10": "secp256k1",
  "1.3.36.3.3.2.8.1.1.7": "brainpoolP256r1",
  "1.3.36.3.3.2.8.1.1.11": "brainpoolP384r1",
  "1.3.36.3.3.2.8.1.1.13": "brainpoolP512r1",
};

/** TLS NamedGroup code points (IANA TLS Supported Groups). */
export const TLS_GROUPS: Record<number, Entry & { label: string }> = {
  0x0017: { label: "secp256r1", name: "ECDH", curve: "P-256", usage: "key-exchange" },
  0x0018: { label: "secp384r1", name: "ECDH", curve: "P-384", usage: "key-exchange" },
  0x0019: { label: "secp521r1", name: "ECDH", curve: "P-521", usage: "key-exchange" },
  0x001d: { label: "x25519", name: "X25519", usage: "key-exchange" },
  0x001e: { label: "x448", name: "X448", usage: "key-exchange" },
  0x0100: { label: "ffdhe2048", name: "FFDH", keySize: 2048, usage: "key-exchange" },
  0x0101: { label: "ffdhe3072", name: "FFDH", keySize: 3072, usage: "key-exchange" },
  0x0102: { label: "ffdhe4096", name: "FFDH", keySize: 4096, usage: "key-exchange" },
  0x0200: { label: "MLKEM512", name: "ML-KEM-512", usage: "key-exchange" },
  0x0201: { label: "MLKEM768", name: "ML-KEM-768", usage: "key-exchange" },
  0x0202: { label: "MLKEM1024", name: "ML-KEM-1024", usage: "key-exchange" },
  0x11eb: { label: "SecP256r1MLKEM768", name: "SecP256r1MLKEM768", usage: "key-exchange" },
  0x11ec: { label: "X25519MLKEM768", name: "X25519MLKEM768", usage: "key-exchange" },
  0x11ed: { label: "SecP384r1MLKEM1024", name: "SecP384r1MLKEM1024", usage: "key-exchange" },
  0x6399: { label: "X25519Kyber768Draft00", name: "X25519Kyber768", usage: "key-exchange" },
};

export interface TlsSuite {
  name: string;
  kex?: string; // undefined for TLS 1.3 suites (group negotiated separately)
  auth?: string;
  cipher: string;
  mac: string;
}

/** Subset of IANA TLS cipher suites seen in practice. */
export const TLS_CIPHER_SUITES: Record<number, TlsSuite> = {
  0x1301: { name: "TLS_AES_128_GCM_SHA256", cipher: "AES-128-GCM", mac: "SHA-256" },
  0x1302: { name: "TLS_AES_256_GCM_SHA384", cipher: "AES-256-GCM", mac: "SHA-384" },
  0x1303: { name: "TLS_CHACHA20_POLY1305_SHA256", cipher: "CHACHA20-POLY1305", mac: "SHA-256" },
  0xc02b: { name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", kex: "ECDHE", auth: "ECDSA", cipher: "AES-128-GCM", mac: "SHA-256" },
  0xc02c: { name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", kex: "ECDHE", auth: "ECDSA", cipher: "AES-256-GCM", mac: "SHA-384" },
  0xc02f: { name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", kex: "ECDHE", auth: "RSA", cipher: "AES-128-GCM", mac: "SHA-256" },
  0xc030: { name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", kex: "ECDHE", auth: "RSA", cipher: "AES-256-GCM", mac: "SHA-384" },
  0xcca8: { name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", kex: "ECDHE", auth: "RSA", cipher: "CHACHA20-POLY1305", mac: "SHA-256" },
  0xcca9: { name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", kex: "ECDHE", auth: "ECDSA", cipher: "CHACHA20-POLY1305", mac: "SHA-256" },
  0xc013: { name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", kex: "ECDHE", auth: "RSA", cipher: "AES-128-CBC", mac: "SHA-1" },
  0xc014: { name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", kex: "ECDHE", auth: "RSA", cipher: "AES-256-CBC", mac: "SHA-1" },
  0xc009: { name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", kex: "ECDHE", auth: "ECDSA", cipher: "AES-128-CBC", mac: "SHA-1" },
  0xc00a: { name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", kex: "ECDHE", auth: "ECDSA", cipher: "AES-256-CBC", mac: "SHA-1" },
  0x009e: { name: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", kex: "DHE", auth: "RSA", cipher: "AES-128-GCM", mac: "SHA-256" },
  0x009f: { name: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", kex: "DHE", auth: "RSA", cipher: "AES-256-GCM", mac: "SHA-384" },
  0x009c: { name: "TLS_RSA_WITH_AES_128_GCM_SHA256", kex: "RSA", auth: "RSA", cipher: "AES-128-GCM", mac: "SHA-256" },
  0x009d: { name: "TLS_RSA_WITH_AES_256_GCM_SHA384", kex: "RSA", auth: "RSA", cipher: "AES-256-GCM", mac: "SHA-384" },
  0x002f: { name: "TLS_RSA_WITH_AES_128_CBC_SHA", kex: "RSA", auth: "RSA", cipher: "AES-128-CBC", mac: "SHA-1" },
  0x0035: { name: "TLS_RSA_WITH_AES_256_CBC_SHA", kex: "RSA", auth: "RSA", cipher: "AES-256-CBC", mac: "SHA-1" },
  0x000a: { name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", kex: "RSA", auth: "RSA", cipher: "3DES", mac: "SHA-1" },
  0x0005: { name: "TLS_RSA_WITH_RC4_128_SHA", kex: "RSA", auth: "RSA", cipher: "RC4", mac: "SHA-1" },
};

/** SSH algorithm names (RFC 4253, 5656, 8709, 8731, 9142, draft-ietf-sshm-mlkem-hybrid-kex). */
export const SSH_ALGORITHMS: Record<string, Entry> = {
  "curve25519-sha256": { name: "X25519", usage: "key-exchange" },
  "curve25519-sha256@libssh.org": { name: "X25519", usage: "key-exchange" },
  "curve448-sha512": { name: "X448", usage: "key-exchange" },
  "ecdh-sha2-nistp256": { name: "ECDH", curve: "P-256", usage: "key-exchange" },
  "ecdh-sha2-nistp384": { name: "ECDH", curve: "P-384", usage: "key-exchange" },
  "ecdh-sha2-nistp521": { name: "ECDH", curve: "P-521", usage: "key-exchange" },
  "diffie-hellman-group1-sha1": { name: "FFDH", keySize: 1024, usage: "key-exchange" },
  "diffie-hellman-group14-sha1": { name: "FFDH", keySize: 2048, usage: "key-exchange" },
  "diffie-hellman-group14-sha256": { name: "FFDH", keySize: 2048, usage: "key-exchange" },
  "diffie-hellman-group16-sha512": { name: "FFDH", keySize: 4096, usage: "key-exchange" },
  "diffie-hellman-group18-sha512": { name: "FFDH", keySize: 8192, usage: "key-exchange" },
  "diffie-hellman-group-exchange-sha256": { name: "FFDH", usage: "key-exchange" },
  "diffie-hellman-group-exchange-sha1": { name: "FFDH", usage: "key-exchange" },
  "sntrup761x25519-sha512": { name: "sntrup761x25519", usage: "key-exchange" },
  "sntrup761x25519-sha512@openssh.com": { name: "sntrup761x25519", usage: "key-exchange" },
  "mlkem768x25519-sha256": { name: "MLKEM768x25519", usage: "key-exchange" },
  "mlkem768nistp256-sha256": { name: "MLKEM768nistp256", usage: "key-exchange" },
  "mlkem1024nistp384-sha384": { name: "MLKEM1024nistp384", usage: "key-exchange" },
  "ssh-ed25519": { name: "Ed25519", usage: "signature" },
  "ssh-ed448": { name: "Ed448", usage: "signature" },
  "ecdsa-sha2-nistp256": { name: "ECDSA", curve: "P-256", usage: "signature" },
  "ecdsa-sha2-nistp384": { name: "ECDSA", curve: "P-384", usage: "signature" },
  "ecdsa-sha2-nistp521": { name: "ECDSA", curve: "P-521", usage: "signature" },
  "rsa-sha2-256": { name: "RSA", usage: "signature" },
  "rsa-sha2-512": { name: "RSA", usage: "signature" },
  "ssh-rsa": { name: "RSA", usage: "signature" },
  "ssh-dss": { name: "DSA", keySize: 1024, usage: "signature" },
  "aes128-ctr": { name: "AES-128-CTR", usage: "encryption" },
  "aes192-ctr": { name: "AES-192-CTR", usage: "encryption" },
  "aes256-ctr": { name: "AES-256-CTR", usage: "encryption" },
  "aes128-gcm@openssh.com": { name: "AES-128-GCM", usage: "encryption" },
  "aes256-gcm@openssh.com": { name: "AES-256-GCM", usage: "encryption" },
  "chacha20-poly1305@openssh.com": { name: "CHACHA20-POLY1305", usage: "encryption" },
  "aes128-cbc": { name: "AES-128-CBC", usage: "encryption" },
  "aes256-cbc": { name: "AES-256-CBC", usage: "encryption" },
  "3des-cbc": { name: "3DES", usage: "encryption" },
  "blowfish-cbc": { name: "Blowfish", usage: "encryption" },
  arcfour: { name: "RC4", usage: "encryption" },
};

/** IKEv2 transform IDs (RFC 7296 / IANA), keyed by `${type}:${id}`. Key length from attribute 14. */
export const IKE_TRANSFORMS: Record<string, Entry & { label: string }> = {
  "1:3": { label: "ENCR_3DES", name: "3DES", usage: "encryption" },
  "1:7": { label: "ENCR_BLOWFISH", name: "Blowfish", usage: "encryption" },
  "1:12": { label: "ENCR_AES_CBC", name: "AES-CBC", usage: "encryption" },
  "1:13": { label: "ENCR_AES_CTR", name: "AES-CTR", usage: "encryption" },
  "1:20": { label: "ENCR_AES_GCM_16", name: "AES-GCM", usage: "encryption" },
  "1:28": { label: "ENCR_CHACHA20_POLY1305", name: "CHACHA20-POLY1305", usage: "encryption" },
  "2:2": { label: "PRF_HMAC_SHA1", name: "HMAC-SHA-1", usage: "kdf" },
  "2:5": { label: "PRF_HMAC_SHA2_256", name: "HMAC-SHA-256", usage: "kdf" },
  "2:6": { label: "PRF_HMAC_SHA2_384", name: "HMAC-SHA-384", usage: "kdf" },
  "2:7": { label: "PRF_HMAC_SHA2_512", name: "HMAC-SHA-512", usage: "kdf" },
  "3:2": { label: "AUTH_HMAC_SHA1_96", name: "HMAC-SHA-1", usage: "mac" },
  "3:12": { label: "AUTH_HMAC_SHA2_256_128", name: "HMAC-SHA-256", usage: "mac" },
  "3:13": { label: "AUTH_HMAC_SHA2_384_192", name: "HMAC-SHA-384", usage: "mac" },
  "3:14": { label: "AUTH_HMAC_SHA2_512_256", name: "HMAC-SHA-512", usage: "mac" },
  "4:2": { label: "MODP_1024", name: "FFDH", keySize: 1024, usage: "key-exchange" },
  "4:5": { label: "MODP_1536", name: "FFDH", keySize: 1536, usage: "key-exchange" },
  "4:14": { label: "MODP_2048", name: "FFDH", keySize: 2048, usage: "key-exchange" },
  "4:15": { label: "MODP_3072", name: "FFDH", keySize: 3072, usage: "key-exchange" },
  "4:16": { label: "MODP_4096", name: "FFDH", keySize: 4096, usage: "key-exchange" },
  "4:19": { label: "ECP_256", name: "ECDH", curve: "P-256", usage: "key-exchange" },
  "4:20": { label: "ECP_384", name: "ECDH", curve: "P-384", usage: "key-exchange" },
  "4:21": { label: "ECP_521", name: "ECDH", curve: "P-521", usage: "key-exchange" },
  "4:31": { label: "CURVE25519", name: "X25519", usage: "key-exchange" },
  "4:32": { label: "CURVE448", name: "X448", usage: "key-exchange" },
  "4:35": { label: "ML_KEM_512", name: "ML-KEM-512", usage: "key-exchange" },
  "4:36": { label: "ML_KEM_768", name: "ML-KEM-768", usage: "key-exchange" },
  "4:37": { label: "ML_KEM_1024", name: "ML-KEM-1024", usage: "key-exchange" },
};

/** AWS KMS KeySpec values. */
export const AWS_KMS_KEY_SPECS: Record<string, Entry> = {
  RSA_2048: { name: "RSA", keySize: 2048 },
  RSA_3072: { name: "RSA", keySize: 3072 },
  RSA_4096: { name: "RSA", keySize: 4096 },
  ECC_NIST_P256: { name: "EC", curve: "P-256" },
  ECC_NIST_P384: { name: "EC", curve: "P-384" },
  ECC_NIST_P521: { name: "EC", curve: "P-521" },
  ECC_SECG_P256K1: { name: "EC", curve: "secp256k1" },
  ECC_NIST_EDWARDS25519: { name: "Ed25519" },
  SYMMETRIC_DEFAULT: { name: "AES-256-GCM", keySize: 256 },
  HMAC_224: { name: "HMAC-SHA-224" },
  HMAC_256: { name: "HMAC-SHA-256" },
  HMAC_384: { name: "HMAC-SHA-384" },
  HMAC_512: { name: "HMAC-SHA-512" },
  SM2: { name: "SM2" },
  ML_DSA_44: { name: "ML-DSA-44" },
  ML_DSA_65: { name: "ML-DSA-65" },
  ML_DSA_87: { name: "ML-DSA-87" },
};

export function classifyOid(oid: string, extra: Partial<AlgorithmInput> = {}): Classification {
  const e = OID_REGISTRY[oid];
  if (!e) return classifyAlgorithm({ name: `OID ${oid}`, oid, ...extra });
  return classifyAlgorithm({ ...e, ...extra, oid });
}

export function classifyTlsGroup(id: number): Classification & { label: string } {
  const g = TLS_GROUPS[id];
  if (!g) return { ...classifyAlgorithm({ name: `tls-group-0x${id.toString(16).padStart(4, "0")}`, usage: "key-exchange" }), label: `0x${id.toString(16)}` };
  return { ...classifyAlgorithm(g), label: g.label };
}

export function classifySsh(name: string, usage?: string): Classification {
  const e = SSH_ALGORITHMS[name];
  if (e) return classifyAlgorithm(e);
  return classifyAlgorithm({ name: name.replace(/@.*$/, ""), usage });
}

export function classifyIkeTransform(type: number, id: number, keyLength?: number): Classification & { label: string } {
  const e = IKE_TRANSFORMS[`${type}:${id}`];
  if (!e) return { ...classifyAlgorithm({ name: `ike-${type}-${id}` }), label: `TRANSFORM_${type}_${id}` };
  const name = keyLength && e.name.startsWith("AES") ? e.name.replace("AES", `AES-${keyLength}`) : e.name;
  return { ...classifyAlgorithm({ ...e, name }), label: e.label };
}

/** Build a canonical, deduplicated CryptoPrimitive vertex from a classification. */
export function primitiveVertex(c: Classification, evidence: Evidence[]): CryptoPrimitive {
  const canonicalId = canonicalPrimitiveId(c.algorithm, c.curve, c.keySize, c.usage);
  return {
    id: `prim:${canonicalId.slice(0, 32)}`,
    kind: "CryptoPrimitive",
    label: c.algorithm,
    canonicalId,
    algorithm: c.algorithm,
    family: c.family,
    keySize: c.keySize,
    curve: c.curve,
    oid: c.oid,
    usage: c.usage,
    primitive: c.primitive,
    status: c.status,
    classicalSecurityLevel: c.classicalSecurityLevel,
    nistQuantumSecurityLevel: c.nistQuantumSecurityLevel,
    parameterSet: c.parameterSet,
    classicallyBroken: c.classicallyBroken,
    evidence,
  };
}

const LEGACY_LABEL: Record<string, string> = {
  VULNERABLE_SHOR: "SHOR-CRITICAL",
  DEGRADED_GROVER: "DEPRECATED",
  HYBRID: "HYBRID",
  SAFE_PQC: "QUANTUM-SAFE",
  UNKNOWN: "UNKNOWN",
};

/** Map graph status onto server/riskEngine.js labels so dashboard and CBOM agree. */
export function toLegacyClassification(status: string): string {
  return LEGACY_LABEL[status] ?? "UNKNOWN";
}
