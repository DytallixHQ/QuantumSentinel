import { randomUUID } from "node:crypto";
import type { CryptoGraph } from "../core/graph/graph.ts";
import type { CryptoMaterial, CryptoPrimitive, Evidence, NetworkEndpoint, Vertex } from "../core/graph/types.ts";
import type { RiskResult } from "../engine/risk/mosca.ts";

// Values allowed by cryptography-defs.schema.json algorithmFamiliesEnum (subset we emit).
const CDX_FAMILIES = new Set([
  "3DES", "AES", "Blowfish", "CAMELLIA", "ChaCha20", "DES", "DSA", "ECDH", "ECDSA", "EdDSA", "ElGamal", "FFDH",
  "HMAC", "LMS", "MD5", "ML-DSA", "ML-KEM", "RC2", "RC4", "RSAES-OAEP", "RSAES-PKCS1", "RSASSA-PKCS1", "RSASSA-PSS",
  "SHA-1", "SHA-2", "SHA-3", "SLH-DSA", "SM2", "XMSS",
]);

const CDX_CURVES: Record<string, string> = {
  "P-256": "nist/P-256", "P-384": "nist/P-384", "P-521": "nist/P-521", secp256k1: "secg/secp256k1",
  X25519: "other/Curve25519", X448: "other/Curve448", Ed25519: "other/Ed25519", Ed448: "other/Ed448",
  brainpoolP256r1: "brainpool/brainpoolP256r1", brainpoolP384r1: "brainpool/brainpoolP384r1", brainpoolP512r1: "brainpool/brainpoolP512r1",
};

const USAGE_FUNCTIONS: Record<string, string[]> = {
  signature: ["sign", "verify"],
  "key-exchange": ["keygen", "encapsulate", "decapsulate"],
  encryption: ["encrypt", "decrypt"],
  "public-key": ["verify", "encrypt"],
  hash: ["digest"],
  mac: ["tag"],
  kdf: ["keyderive"],
};

type Json = Record<string, unknown>;

export interface CbomOptions {
  risk?: RiskResult[];
  toolVersion?: string;
  timestamp?: string; // injectable for deterministic output
  serialNumber?: string; // urn:uuid:...
}

function occurrences(evidence: Evidence[]): Json | undefined {
  if (!evidence.length) return undefined;
  const seen = new Set<string>();
  const occ: Json[] = [];
  for (const e of evidence) {
    const loc = `${e.source}:${e.locator}`;
    if (seen.has(loc)) continue;
    seen.add(loc);
    occ.push({ location: loc, ...(e.detail ? { additionalContext: e.detail } : {}) });
  }
  return { occurrences: occ };
}

function prop(name: string, value: unknown): Json | null {
  if (value === undefined || value === null || value === "") return null;
  return { name: `quantumsentinel:${name}`, value: String(value) };
}

function compact<T>(items: (T | null | undefined)[]): T[] {
  return items.filter((x): x is T => x !== null && x !== undefined);
}

function primitiveComponent(p: CryptoPrimitive): Json {
  const curve = p.curve ? CDX_CURVES[p.curve] : undefined;
  const algorithmProperties: Json = {
    primitive: p.primitive,
    ...(p.family && CDX_FAMILIES.has(p.family) ? { algorithmFamily: p.family } : {}),
    ...(p.parameterSet ? { parameterSetIdentifier: p.parameterSet } : p.keySize ? { parameterSetIdentifier: String(p.keySize) } : {}),
    ...(curve ? { ellipticCurve: curve } : {}),
    executionEnvironment: "unknown",
    implementationPlatform: "unknown",
    cryptoFunctions: USAGE_FUNCTIONS[p.usage] ?? ["unknown"],
    ...(p.classicalSecurityLevel !== undefined ? { classicalSecurityLevel: p.classicalSecurityLevel } : {}),
    ...(p.nistQuantumSecurityLevel !== undefined ? { nistQuantumSecurityLevel: p.nistQuantumSecurityLevel } : {}),
  };
  return {
    type: "cryptographic-asset",
    "bom-ref": p.id,
    name: p.algorithm,
    cryptoProperties: { assetType: "algorithm", algorithmProperties, ...(p.oid ? { oid: p.oid } : {}) },
    properties: compact([
      prop("quantumStatus", p.status),
      prop("usage", p.usage),
      prop("canonicalId", p.canonicalId),
      prop("classicallyBroken", p.classicallyBroken),
    ]),
  };
}

function materialComponent(g: CryptoGraph, m: CryptoMaterial): Json {
  const related: Json[] = [];
  for (const e of g.outgoing(m.id, ["ENCRYPTED_WITH"])) related.push({ type: "publicKey", ref: e.to });
  for (const e of g.incoming(m.id, ["SIGNS"])) {
    const src = g.get(e.from);
    related.push({ type: src?.kind === "CryptoPrimitive" ? "signature" : "issuer", ref: e.from });
  }
  const fp = m.fingerprintSha256 ? { alg: "SHA-256", content: m.fingerprintSha256 } : undefined;
  if (m.materialType === "certificate") {
    return {
      type: "cryptographic-asset",
      "bom-ref": m.id,
      name: m.subject ?? m.label,
      cryptoProperties: {
        assetType: "certificate",
        certificateProperties: {
          ...(m.serialNumber ? { serialNumber: m.serialNumber } : {}),
          ...(m.subject ? { subjectName: m.subject } : {}),
          ...(m.issuer ? { issuerName: m.issuer } : {}),
          ...(m.notBefore ? { notValidBefore: m.notBefore } : {}),
          ...(m.notAfter ? { notValidAfter: m.notAfter } : {}),
          certificateFormat: "X.509",
          ...(fp ? { fingerprint: fp } : {}),
          ...(related.length ? { relatedCryptographicAssets: related } : {}),
        },
      },
    };
  }
  const type = m.materialType === "public-key" ? "public-key" : m.materialType === "private-key-ref" ? "private-key" : m.materialType === "secret-key-ref" ? "secret-key" : "key";
  const algorithmRef = g.outgoing(m.id, ["ENCRYPTED_WITH"])[0]?.to;
  const size = algorithmRef ? (g.get(algorithmRef) as CryptoPrimitive | undefined)?.keySize : undefined;
  return {
    type: "cryptographic-asset",
    "bom-ref": m.id,
    name: m.label,
    cryptoProperties: {
      assetType: "related-crypto-material",
      relatedCryptoMaterialProperties: {
        type,
        id: m.id,
        ...(m.keyState ? { state: m.keyState } : {}),
        ...(algorithmRef ? { algorithmRef } : {}),
        ...(size ? { size } : {}),
        ...(m.format ? { format: m.format } : {}),
        ...(fp ? { fingerprint: fp } : {}),
        ...(related.length ? { relatedCryptographicAssets: related } : {}),
      },
    },
  };
}

function protocolComponent(g: CryptoGraph, v: NetworkEndpoint): Json {
  const refs = g.outgoing(v.id, ["ENCRYPTED_WITH"]).map((e) => e.to);
  const suites = g.outgoing(v.id, ["ENCRYPTED_WITH"])
    .filter((e) => typeof e.attrs?.cipherSuite === "string")
    .map((e) => ({ name: String(e.attrs!.cipherSuite), algorithms: [e.to], ...(e.attrs?.suiteId ? { identifiers: [String(e.attrs.suiteId)] } : {}) }));
  const type = v.protocol === "TLS" ? "tls" : v.protocol === "SSH" ? "ssh" : v.protocol === "IKEv2" ? "ike" : "other";
  return {
    type: "cryptographic-asset",
    "bom-ref": v.id,
    name: `${v.protocol} ${v.host}:${v.port}`,
    cryptoProperties: {
      assetType: "protocol",
      protocolProperties: {
        type,
        ...(v.protocolVersion ? { version: v.protocolVersion } : {}),
        ...(suites.length ? { cipherSuites: suites } : {}),
        ...(refs.length ? { cryptoRefArray: refs } : {}),
      },
    },
    properties: compact([prop("host", v.host), prop("ip", v.ip), prop("port", v.port), prop("posture", v.posture), prop("domain", v.domain), prop("supportedGroups", v.supportedGroups?.join(",")), prop("classicalFallback", v.classicalFallback)]),
  };
}

function genericComponent(v: Vertex): Json {
  if (v.kind === "FileAsset") {
    return { type: "file", "bom-ref": v.id, name: v.path, properties: compact([prop("contentType", v.contentType), prop("mountPoint", v.mountPoint), prop("fsType", v.fsType), prop("bucket", v.bucket), prop("owner", v.owner), prop("entropy", v.entropy)]) };
  }
  if (v.kind === "CodeAsset") {
    return { type: "file", "bom-ref": v.id, name: v.filePath, properties: compact([prop("repoUrl", v.repoUrl), prop("branch", v.branch), prop("commit", v.commit), prop("line", v.line), prop("astLocation", v.astLocation)]) };
  }
  return { type: "application", "bom-ref": v.id, name: v.label, ...(v.kind === "ServiceGroup" && v.description ? { description: v.description } : {}) };
}

/** Build a CycloneDX 1.7 CBOM from the graph. Holds only public data by construction. */
export function buildCycloneDxCbom(g: CryptoGraph, opts: CbomOptions = {}): Json {
  const risk = new Map((opts.risk ?? []).map((r) => [r.id, r]));
  const { vertices } = g.toJSON();
  const components = vertices.map((v) => {
    let c: Json;
    if (v.kind === "CryptoPrimitive") c = primitiveComponent(v);
    else if (v.kind === "CryptoMaterial") c = materialComponent(g, v);
    else if (v.kind === "NetworkEndpoint") c = protocolComponent(g, v);
    else c = genericComponent(v);
    const ev = occurrences(v.evidence);
    if (ev) c.evidence = ev;
    const r = risk.get(v.id);
    const edgeProps = groupEdges(g, v.id);
    const props = [
      ...((c.properties as Json[] | undefined) ?? []),
      ...edgeProps,
      ...(r ? compact([prop("risk.score", r.score), prop("risk.status", r.status), prop("risk.exposure", r.exposure), prop("risk.criticality", r.criticality), prop("risk.moscaGapYears", r.moscaGapYears)]) : []),
    ];
    if (props.length) c.properties = props;
    else delete c.properties;
    return c;
  });
  const dependencies = vertices.map((v) => ({
    ref: v.id,
    dependsOn: [...new Set(g.outgoing(v.id).map((e) => e.to))].sort(),
  }));
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.7",
    serialNumber: opts.serialNumber ?? `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: opts.timestamp ?? new Date().toISOString(),
      tools: { components: [{ type: "application", name: "QuantumSentinel", ...(opts.toolVersion ? { version: opts.toolVersion } : {}) }] },
      properties: [{ name: "quantumsentinel:graph", value: `vertices=${g.size.vertices};edges=${g.size.edges}` }],
    },
    components,
    dependencies,
  };
}

// CycloneDX dependencies are untyped, so edge types are kept as component properties.
function groupEdges(g: CryptoGraph, id: string): Json[] {
  const byType = new Map<string, string[]>();
  for (const e of g.outgoing(id)) {
    if (!byType.has(e.type)) byType.set(e.type, []);
    byType.get(e.type)!.push(e.to);
  }
  return [...byType.entries()].sort().map(([t, refs]) => ({ name: `quantumsentinel:edge:${t}`, value: refs.sort().join(",") }));
}
