import type { CdxPrimitive, QuantumStatus } from "../../core/graph/types.ts";

export interface AlgorithmInput {
  name: string; // free-form algorithm name (registry lookups normalize first)
  keySize?: number; // modulus bits for RSA/DH/DSA, key bits for symmetric
  curve?: string;
  usage?: string;
  oid?: string;
}

export interface Classification {
  algorithm: string;
  family?: string; // CycloneDX algorithmFamiliesEnum value, when one applies
  primitive: CdxPrimitive;
  usage: string;
  keySize?: number;
  curve?: string;
  oid?: string;
  parameterSet?: string;
  status: QuantumStatus;
  classicalSecurityLevel?: number;
  nistQuantumSecurityLevel?: number;
  classicallyBroken?: boolean;
  rationale: string;
}

/** Bits of classical security for finite-field / RSA moduli (NIST SP 800-57 Pt.1 Table 2). */
export function ffcIfcSecurityBits(modulusBits: number): number {
  if (modulusBits >= 15360) return 256;
  if (modulusBits >= 7680) return 192;
  if (modulusBits >= 3072) return 128;
  if (modulusBits >= 2048) return 112;
  if (modulusBits >= 1024) return 80;
  return Math.max(0, Math.floor(modulusBits / 16));
}

const CURVE_BITS: Record<string, number> = {
  "P-256": 128, "P-384": 192, "P-521": 256, secp256k1: 128,
  X25519: 128, Ed25519: 128, X448: 224, Ed448: 224,
  brainpoolP256r1: 128, brainpoolP384r1: 192, brainpoolP512r1: 256, SM2: 128,
};

export function normalizeCurve(curve: string | undefined): string | undefined {
  if (!curve) return undefined;
  const c = curve.replace(/[_\s]/g, "").toLowerCase();
  if (/^(p-?256|prime256v1|secp256r1|nistp256|eccnistp256)$/.test(c)) return "P-256";
  if (/^(p-?384|secp384r1|nistp384|eccnistp384)$/.test(c)) return "P-384";
  if (/^(p-?521|secp521r1|nistp521|eccnistp521)$/.test(c)) return "P-521";
  if (/^(p-?256k|secp256k1|eccsecgp256k1)$/.test(c)) return "secp256k1";
  if (c === "x25519" || c === "curve25519") return "X25519";
  if (c === "x448" || c === "curve448") return "X448";
  if (c === "ed25519") return "Ed25519";
  if (c === "ed448") return "Ed448";
  return curve;
}

interface PqcParams {
  family: string;
  level: number; // NIST category
  classical: number;
  primitive: CdxPrimitive;
}

const PQC: Array<[RegExp, (m: RegExpMatchArray) => PqcParams & { name: string }]> = [
  [/^(ML-?KEM|KYBER)-?(512|768|1024)$/i, (m) => ({ name: `ML-KEM-${m[2]}`, family: "ML-KEM", primitive: "kem", ...({ 512: { level: 1, classical: 128 }, 768: { level: 3, classical: 192 }, 1024: { level: 5, classical: 256 } } as const)[m[2] as "512"] })],
  [/^(ML-?DSA|DILITHIUM)-?(44|65|87|2|3|5)$/i, (m) => {
    const p = ({ "44": 44, "2": 44, "65": 65, "3": 65, "87": 87, "5": 87 } as const)[m[2] as "44"];
    const lv = ({ 44: { level: 2, classical: 128 }, 65: { level: 3, classical: 192 }, 87: { level: 5, classical: 256 } } as const)[p];
    return { name: `ML-DSA-${p}`, family: "ML-DSA", primitive: "signature", ...lv };
  }],
  [/^(SLH-?DSA|SPHINCS\+?)-?(SHA2|SHAKE)-?(128|192|256)([sf])$/i, (m) => {
    const bits = Number(m[3]);
    return { name: `SLH-DSA-${m[2].toUpperCase()}-${bits}${m[4].toLowerCase()}`, family: "SLH-DSA", primitive: "signature", level: bits === 128 ? 1 : bits === 192 ? 3 : 5, classical: bits };
  }],
  [/^(FALCON|FN-?DSA)-?(512|1024)$/i, (m) => ({ name: `Falcon-${m[2]}`, family: "Falcon", primitive: "signature", level: m[2] === "512" ? 1 : 5, classical: m[2] === "512" ? 128 : 256 })],
];

const PQC_LOOSE = /^(ML-?KEM|KYBER|ML-?DSA|DILITHIUM|SLH-?DSA|SPHINCS|FALCON|FN-?DSA|LMS|HSS|XMSS|XMSSMT|FRODO|HQC|MCELIECE|CLASSIC-?MCELIECE|SNTRUP\d*|NTRU)/i;

// Hybrid: a classical KEX/sig component combined with a PQC one, in either order.
const HYBRID = /(X25519|X448|SECP?\d{3}R1|P-?\d{3}|NISTP\d{3}|ECDH|ECDSA|RSA|ED25519|ED448|FFDH|MODP).*(MLKEM|ML-KEM|KYBER|SNTRUP|MLDSA|ML-DSA)|(MLKEM|ML-KEM|KYBER|SNTRUP|MLDSA|ML-DSA).*(X25519|X448|SECP?\d{3}R1|P-?\d{3}|NISTP\d{3}|ECDH|ECDSA|RSA|ED25519|ED448|FFDH|MODP)/i;

function pqcLevelFromName(name: string): number | undefined {
  const m = name.match(/(?:MLKEM|ML-KEM|KYBER)-?(512|768|1024)/i);
  if (m) return ({ "512": 1, "768": 3, "1024": 5 } as Record<string, number>)[m[1]];
  const d = name.match(/(?:MLDSA|ML-DSA)-?(44|65|87)/i);
  if (d) return ({ "44": 2, "65": 3, "87": 5 } as Record<string, number>)[d[1]];
  if (/SNTRUP761/i.test(name)) return 1;
  return undefined;
}

function symmetric(name: string, keySize: number | undefined, usage: string): Classification | null {
  const n = name.toUpperCase().replace(/[_\s]/g, "-");
  const base = { usage, rationale: "" };
  let m = n.match(/^AES(?:-?(128|192|256))?(?:-?(GCM|CBC|CTR|CCM|XTS|ECB|OFB|CFB|SIV|GCM96|GCM-?16))?/);
  if (m) {
    let bits = m[1] ? Number(m[1]) : keySize;
    if (m[2] === "XTS" && bits && keySize && keySize === bits * 2) bits = keySize / 2;
    const status: QuantumStatus = bits === undefined ? "UNKNOWN" : bits < 192 ? "DEGRADED_GROVER" : "SAFE_PQC";
    return {
      ...base, algorithm: bits ? `AES-${bits}${m[2] ? "-" + m[2].replace(/-?16|96/, "") : ""}` : "AES", family: "AES",
      primitive: m[2] === "GCM" || m[2] === "CCM" || m[2]?.startsWith("GCM") ? "ae" : "block-cipher", keySize: bits, status,
      classicalSecurityLevel: bits, nistQuantumSecurityLevel: bits === 128 ? 1 : bits === 192 ? 3 : bits === 256 ? 5 : undefined,
      rationale: bits === undefined ? "AES key size not observed" : bits < 192 ? `Grover halves AES-${bits} to ~${bits / 2}-bit effective strength` : `AES-${bits} retains >= ${bits / 2}-bit strength under Grover`,
    };
  }
  if (/^(3DES|TDES|DES-?EDE3?|TRIPLE-?DES|DES-CBC3)/.test(n)) {
    return { ...base, algorithm: "3DES", family: "3DES", primitive: "block-cipher", keySize: 168, status: "DEGRADED_GROVER", classicalSecurityLevel: 112, nistQuantumSecurityLevel: 0, classicallyBroken: true, rationale: "64-bit block (Sweet32) and Grover-degraded key; deprecated by NIST" };
  }
  if (/^DES(-|$)/.test(n)) {
    return { ...base, algorithm: "DES", family: "DES", primitive: "block-cipher", keySize: 56, status: "DEGRADED_GROVER", classicalSecurityLevel: 56, nistQuantumSecurityLevel: 0, classicallyBroken: true, rationale: "56-bit key is classically brute-forceable" };
  }
  if (/^(BLOWFISH|BF-)/.test(n)) {
    return { ...base, algorithm: "Blowfish", family: "Blowfish", primitive: "block-cipher", keySize, status: "DEGRADED_GROVER", nistQuantumSecurityLevel: 0, rationale: "64-bit block cipher; Grover-degraded and deprecated" };
  }
  if (/^(RC4|ARCFOUR)/.test(n)) {
    return { ...base, algorithm: "RC4", family: "RC4", primitive: "stream-cipher", keySize, status: "DEGRADED_GROVER", nistQuantumSecurityLevel: 0, classicallyBroken: true, rationale: "RC4 is classically broken" };
  }
  if (/^CHACHA20/.test(n)) {
    return { ...base, algorithm: n.includes("POLY1305") ? "ChaCha20-Poly1305" : "ChaCha20", family: "ChaCha20", primitive: n.includes("POLY1305") ? "ae" : "stream-cipher", keySize: 256, status: "SAFE_PQC", classicalSecurityLevel: 256, nistQuantumSecurityLevel: 5, rationale: "256-bit key retains 128-bit strength under Grover" };
  }
  m = n.match(/^CAMELLIA-?(128|192|256)/);
  if (m) {
    const bits = Number(m[1]);
    return { ...base, algorithm: `CAMELLIA-${bits}`, family: "CAMELLIA", primitive: "block-cipher", keySize: bits, status: bits < 192 ? "DEGRADED_GROVER" : "SAFE_PQC", classicalSecurityLevel: bits, rationale: "Symmetric cipher; Grover halves effective key strength" };
  }
  return null;
}

function hash(name: string, usage: string): Classification | null {
  const n = name.toUpperCase().replace(/[_\s]/g, "-");
  const isHmac = /^HMAC-?/.test(n);
  const core = n.replace(/^HMAC-?/, "");
  const tbl: Array<[RegExp, string, string, number, number | undefined, boolean]> = [
    // pattern, name, family, output bits, NIST quantum category, broken
    [/^MD5$/, "MD5", "MD5", 128, 0, true],
    [/^SHA-?1$/, "SHA-1", "SHA-1", 160, 0, true],
    [/^SHA-?(2-?)?224$/, "SHA-224", "SHA-2", 224, 1, false],
    [/^SHA-?(2-?)?256$/, "SHA-256", "SHA-2", 256, 2, false],
    [/^SHA-?(2-?)?384$/, "SHA-384", "SHA-2", 384, 4, false],
    [/^SHA-?(2-?)?512$/, "SHA-512", "SHA-2", 512, 5, false],
    [/^SHA3-?256$/, "SHA3-256", "SHA-3", 256, 2, false],
    [/^SHA3-?384$/, "SHA3-384", "SHA-3", 384, 4, false],
    [/^SHA3-?512$/, "SHA3-512", "SHA-3", 512, 5, false],
  ];
  for (const [re, alg, family, bits, lvl, broken] of tbl) {
    if (!re.test(core)) continue;
    const status: QuantumStatus = broken ? "DEGRADED_GROVER" : "SAFE_PQC";
    return {
      algorithm: isHmac ? `HMAC-${alg}` : alg, family: isHmac ? "HMAC" : family, primitive: isHmac ? "mac" : "hash", usage,
      status, classicalSecurityLevel: isHmac ? bits : bits / 2, nistQuantumSecurityLevel: lvl, classicallyBroken: broken || undefined,
      rationale: broken ? `${alg} collisions are classically practical` : `${alg} output size withstands Grover/BHT at NIST category ${lvl}`,
    };
  }
  return null;
}

/** Core heuristic classifier. Registry lookups (OID, TLS, SSH, IKE, KMS) normalize into this. */
export function classifyAlgorithm(input: AlgorithmInput): Classification {
  const usage = input.usage ?? "unknown";
  const raw = input.name.trim();
  const n = raw.toUpperCase().replace(/_/g, "-");
  const curve = normalizeCurve(input.curve);
  const common = { usage, oid: input.oid };

  for (const [re, build] of PQC) {
    const m = raw.match(re);
    if (m) {
      const p = build(m);
      return { ...common, algorithm: p.name, family: p.family === "Falcon" ? undefined : p.family, parameterSet: p.name.split("-").slice(p.family === "SLH-DSA" ? 2 : -1).join("-"), primitive: p.primitive, status: "SAFE_PQC", classicalSecurityLevel: p.classical, nistQuantumSecurityLevel: p.level, rationale: `${p.name} is a NIST post-quantum algorithm (category ${p.level})` };
    }
  }

  if (HYBRID.test(n.replace(/-/g, ""))) {
    const lvl = pqcLevelFromName(n.replace(/-/g, ""));
    const isSig = /MLDSA|ML-DSA/.test(n);
    return { ...common, algorithm: raw, primitive: isSig ? "signature" : "combiner", curve, status: "HYBRID", classicalSecurityLevel: 128, nistQuantumSecurityLevel: lvl, rationale: "Hybrid scheme: confidentiality holds while either the classical or the lattice component is unbroken" };
  }

  if (PQC_LOOSE.test(n)) {
    const family = /^(LMS|HSS)/.test(n) ? "LMS" : /^XMSS/.test(n) ? "XMSS" : /^(ML-?KEM|KYBER)/.test(n) ? "ML-KEM" : /^(ML-?DSA|DILITHIUM)/.test(n) ? "ML-DSA" : /^(SLH|SPHINCS)/.test(n) ? "SLH-DSA" : undefined;
    const kem = /KEM|KYBER|FRODO|HQC|MCELIECE|NTRU/.test(n);
    return { ...common, algorithm: raw, family, primitive: kem ? "kem" : "signature", status: "SAFE_PQC", rationale: "Post-quantum algorithm family (parameter set not observed)" };
  }

  const sym = symmetric(raw, input.keySize, usage);
  if (sym) return { ...sym, oid: input.oid };
  const h = hash(raw, usage);
  if (h) return { ...h, oid: input.oid };

  // Shor-vulnerable public-key algorithms.
  const shor = (algorithm: string, family: string | undefined, primitive: CdxPrimitive, classical: number | undefined, extra: Partial<Classification> = {}): Classification => ({
    ...common, algorithm, family, primitive, status: "VULNERABLE_SHOR", classicalSecurityLevel: classical, nistQuantumSecurityLevel: 0,
    rationale: `${algorithm} is broken by Shor's algorithm on a cryptographically relevant quantum computer`, ...extra,
  });
  if (/^(RSA|RSASSA|RSAES|SHA\d*-?WITH-?RSA|RSA-?SHA|RSA-?PSS|SSH-RSA|RSA-SHA2)/.test(n) || n === "RSA-ENCRYPTION") {
    const fam = /PSS/.test(n) ? "RSASSA-PSS" : /OAEP/.test(n) ? "RSAES-OAEP" : usage === "signature" ? "RSASSA-PKCS1" : undefined;
    const ks = input.keySize;
    return shor(ks ? `RSA-${ks}` : "RSA", fam, usage === "signature" ? "signature" : usage === "key-exchange" ? "key-agree" : "pke", ks ? ffcIfcSecurityBits(ks) : undefined, { keySize: ks, classicallyBroken: ks !== undefined && ks < 2048 ? true : undefined });
  }
  if (/^(ED25519|ED448|EDDSA|SSH-ED25519|SSH-ED448)$/.test(n)) {
    const c = /448/.test(n) ? "Ed448" : "Ed25519";
    return shor(c, "EdDSA", "signature", CURVE_BITS[c], { curve: c });
  }
  if (/^(X25519|X448|CURVE25519|CURVE448)/.test(n)) {
    const c = /448/.test(n) ? "X448" : "X25519";
    return shor(c, "ECDH", "key-agree", CURVE_BITS[c], { curve: c });
  }
  if (/ECDSA|ECDSA-WITH|EC-?PUBLIC-?KEY|^EC$|^ECC/.test(n) && usage !== "key-exchange") {
    return shor(curve ? `ECDSA-${curve}` : "ECDSA", "ECDSA", "signature", curve ? CURVE_BITS[curve] : undefined, { curve });
  }
  if (/^(ECDHE?|ECDH-|SECP\d+R1|P-?\d{3}$)|^EC$|ECC/.test(n)) {
    const c = curve ?? normalizeCurve(raw.replace(/^ECDHE?-?/i, ""));
    return shor(c && CURVE_BITS[c] ? `ECDH-${c}` : "ECDH", "ECDH", "key-agree", c ? CURVE_BITS[c] : undefined, { curve: c && CURVE_BITS[c] ? c : undefined });
  }
  if (/^(DHE?|FFDHE?|DIFFIE-?HELLMAN|MODP|DH-)/.test(n)) {
    const ks = input.keySize;
    return shor(ks ? `FFDH-${ks}` : "FFDH", "FFDH", "key-agree", ks ? ffcIfcSecurityBits(ks) : undefined, { keySize: ks, classicallyBroken: ks !== undefined && ks < 2048 ? true : undefined });
  }
  if (/^(DSA|SSH-DSS|DSS)/.test(n)) return shor(input.keySize ? `DSA-${input.keySize}` : "DSA", "DSA", "signature", input.keySize ? ffcIfcSecurityBits(input.keySize) : undefined, { keySize: input.keySize });
  if (/^(ELGAMAL)/.test(n)) return shor("ElGamal", "ElGamal", "pke", input.keySize ? ffcIfcSecurityBits(input.keySize) : undefined, { keySize: input.keySize });
  if (/^SM2/.test(n)) return shor("SM2", "SM2", "signature", 128);

  return { ...common, algorithm: raw, primitive: "unknown", status: "UNKNOWN", keySize: input.keySize, curve, rationale: "Algorithm not in registry; review manually" };
}
