// Attributed Cryptographic Graph G = (V, E, alpha, beta).
// alpha: vertex attributes (per-kind records below); beta: edge attributes.

export type QuantumStatus =
  | "SAFE_PQC" // post-quantum primitive, or symmetric/hash with >= 192-bit key / output (Grover-resistant)
  | "HYBRID" // classical + lattice combiner (e.g. X25519MLKEM768)
  | "DEGRADED_GROVER" // symmetric/hash weakened by Grover, or classically weak legacy cipher
  | "VULNERABLE_SHOR" // broken by Shor (RSA, ECC, DH, DSA, EdDSA)
  | "UNKNOWN";

export type CdxPrimitive =
  | "signature" | "kem" | "key-agree" | "pke" | "block-cipher" | "stream-cipher"
  | "ae" | "hash" | "mac" | "kdf" | "combiner" | "other" | "unknown";

export type Exposure = "external" | "internal" | "unknown";

export interface Evidence {
  source: "network" | "filesystem" | "cloud" | "code" | "config";
  locator: string; // host:port, file path, key ARN, repo path:line
  detail?: string; // short human description, never secret material
  observedAt: string; // ISO-8601
}

/** Risk inputs that may be set on any vertex; defaults come from RiskConfig. */
export interface RiskInputs {
  criticality?: number; // C(v) in [1, 10]
  exposureFactor?: number; // E(v) in [0.1, 1.0]
  retentionYears?: number; // T_retention(v): how long data must stay confidential
  migrationYears?: number; // T_migration(v): how long migration will take
  trustYears?: number; // T_trust(v): how long signatures made or relied on here must stay unforgeable (TNFL)
}

interface VertexBase<K extends string> extends RiskInputs {
  id: string;
  kind: K;
  label: string;
  evidence: Evidence[];
}

export interface NetworkEndpoint extends VertexBase<"NetworkEndpoint"> {
  host: string;
  ip?: string;
  port: number;
  protocol: "TLS" | "SSH" | "IKEv2" | "TCP" | "OTHER";
  domain?: string;
  posture: Exposure;
  protocolVersion?: string;
  /** Groups / KEX methods the endpoint was observed to accept (beyond the negotiated one). */
  supportedGroups?: string[];
  /** A PQ/hybrid option is available but classical-only clients are still accepted. */
  classicalFallback?: boolean;
}

export interface FileAsset extends VertexBase<"FileAsset"> {
  path: string;
  mountPoint?: string;
  fsType?: string;
  bucket?: string;
  owner?: string;
  contentType?: string; // sniffed content type, never the extension
  entropy?: number;
}

export interface CodeAsset extends VertexBase<"CodeAsset"> {
  repoUrl: string;
  branch?: string;
  commit?: string;
  filePath: string;
  line?: number;
  astLocation?: string;
}

export interface CryptoPrimitive extends VertexBase<"CryptoPrimitive"> {
  /** SHA-256(alg || curve/modulus || key_size || usage), hex. */
  canonicalId: string;
  algorithm: string; // canonical name, e.g. "RSA", "ECDSA", "ML-KEM-768", "X25519MLKEM768"
  family?: string;
  keySize?: number;
  curve?: string;
  oid?: string;
  usage: string; // "signature" | "key-exchange" | "encryption" | "hash" | ...
  primitive: CdxPrimitive;
  status: QuantumStatus;
  classicalSecurityLevel?: number;
  nistQuantumSecurityLevel?: number;
  parameterSet?: string;
  classicallyBroken?: boolean;
}

/**
 * A concrete certificate or public key, deduplicated by fingerprint
 * (SHA-256 of the DER certificate, or SHA-256 of the SubjectPublicKeyInfo).
 * Holds only public data. Private keys are represented by their derived SPKI.
 */
export interface CryptoMaterial extends VertexBase<"CryptoMaterial"> {
  materialType: "certificate" | "public-key" | "private-key-ref" | "key-metadata" | "secret-key-ref";
  fingerprintSha256?: string;
  subject?: string;
  issuer?: string;
  serialNumber?: string;
  notBefore?: string;
  notAfter?: string;
  format?: string; // X.509, PKCS#8, JKS, KMS, ...
  keyState?: "active" | "suspended" | "deactivated" | "pre-activation" | "destroyed" | "compromised";
}

/** Logical grouping (cluster, application, business service). */
export interface ServiceGroup extends VertexBase<"ServiceGroup"> {
  description?: string;
}

export type Vertex = NetworkEndpoint | FileAsset | CodeAsset | CryptoPrimitive | CryptoMaterial | ServiceGroup;
export type VertexKind = Vertex["kind"];

/**
 * Edge semantics (direction = from -> to):
 * - TERMINATES_AT:  backend endpoint -> front (proxy / LB) that terminates its crypto
 * - ENCRYPTED_WITH: endpoint/file/material -> primitive protecting or used by it
 * - CONTAINS_KEY:   endpoint/file/cloud store -> certificate/key it holds or presents
 * - SIGNS:          issuer certificate or signature primitive -> signed certificate
 * - MOUNTS:         endpoint/file (host) -> mounted volume / file asset
 * - DEPENDS_ON:     dependent -> dependency (group -> member, code -> primitive)
 */
export type EdgeType = "TERMINATES_AT" | "ENCRYPTED_WITH" | "CONTAINS_KEY" | "SIGNS" | "MOUNTS" | "DEPENDS_ON";

export interface Edge {
  from: string;
  to: string;
  type: EdgeType;
  attrs?: Record<string, string | number | boolean>;
  evidence?: Evidence[];
}
