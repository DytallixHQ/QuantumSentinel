// Shared helpers that turn parsed crypto observations into deduplicated vertices and edges.
import { classifyAlgorithm, type AlgorithmInput, type Classification } from "../../engine/classifier/classify.ts";
import { classifyOid, primitiveVertex } from "../../engine/classifier/registry.ts";
import type { CertInfo, KeyInfo } from "../../scanners/filesystem/x509.ts";
import type { CryptoGraph } from "./graph.ts";
import type { CryptoMaterial, EdgeType, Evidence } from "./types.ts";

export function addPrimitive(g: CryptoGraph, c: Classification, evidence: Evidence[]): string {
  return g.addVertex(primitiveVertex(c, evidence)).id;
}

export function addAlgorithm(g: CryptoGraph, input: AlgorithmInput, evidence: Evidence[]): string {
  return addPrimitive(g, classifyAlgorithm(input), evidence);
}

export function link(g: CryptoGraph, from: string, type: EdgeType, to: string, attrs?: Record<string, string | number | boolean>): void {
  g.addEdge(from, type, to, attrs);
}

/** Classify a public key's algorithm (key usage depends on the algorithm, not on where it was found). */
export function classifyKey(k: KeyInfo): Classification {
  const usage = /^(X25519|X448|ML-KEM|DH)/.test(k.algorithm) ? "key-exchange" : k.algorithm === "RSA" ? "public-key" : "signature";
  return classifyOid(k.oid, { keySize: k.keySize, curve: k.curve, usage, ...(k.algorithm === "EC" ? { name: "ECDSA" } : {}) });
}

/** Public key vertex, deduplicated by SPKI fingerprint. */
export function addPublicKey(g: CryptoGraph, k: KeyInfo, evidence: Evidence[], materialType: CryptoMaterial["materialType"] = "public-key"): string {
  const prim = addPrimitive(g, classifyKey(k), evidence);
  if (!k.spkiSha256) return prim;
  const id = `spki:${k.spkiSha256}`;
  g.addVertex<CryptoMaterial>({
    id, kind: "CryptoMaterial", label: `${classifyKey(k).algorithm} public key`, materialType,
    fingerprintSha256: k.spkiSha256, format: "SubjectPublicKeyInfo", evidence,
  });
  link(g, id, "ENCRYPTED_WITH", prim);
  return id;
}

/** Certificate vertex, deduplicated by SHA-256 of the DER certificate. */
export function addCertificate(g: CryptoGraph, c: CertInfo, evidence: Evidence[]): string {
  const id = `cert:${c.derSha256}`;
  g.addVertex<CryptoMaterial>({
    id, kind: "CryptoMaterial", label: c.subject || id, materialType: "certificate",
    fingerprintSha256: c.derSha256, subject: c.subject, issuer: c.issuer, serialNumber: c.serialNumber,
    notBefore: c.notBefore, notAfter: c.notAfter, format: "X.509", evidence,
  });
  const keyPrim = addPrimitive(g, classifyKey(c.publicKey), evidence);
  link(g, id, "ENCRYPTED_WITH", keyPrim);
  // The signature algorithm that issued this certificate. For RSA signatures the issuer's key size is unknown here.
  const sig = classifyOid(c.signatureOid, { usage: "signature", ...(c.signatureOid.startsWith("1.2.840.10045.4") ? { name: "ECDSA" } : {}) });
  link(g, addPrimitive(g, sig, evidence), "SIGNS", id);
  return id;
}

/** Link issuer -> subject certificates found together in a chain. */
export function linkChain(g: CryptoGraph, chain: Array<{ id: string; info: CertInfo }>): void {
  for (const child of chain) {
    const parent = chain.find((p) => p.id !== child.id && p.info.subject === child.info.issuer);
    if (parent) link(g, parent.id, "SIGNS", child.id);
  }
}
