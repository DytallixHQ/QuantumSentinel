// Read-only KMS metadata ingestors. Only list/describe/get-metadata operations are called;
// no Encrypt/Decrypt/Sign/Export/GetPublicKey-to-disk, and public key bytes returned by
// Azure/Vault are reduced to a size and never stored.
import { addPrimitive, link } from "../../core/graph/builders.ts";
import { CryptoGraph } from "../../core/graph/graph.ts";
import type { CryptoMaterial, Evidence, RiskInputs, ServiceGroup } from "../../core/graph/types.ts";
import { classifyAlgorithm, type Classification } from "../../engine/classifier/classify.ts";
import { AWS_KMS_KEY_SPECS } from "../../engine/classifier/registry.ts";

export interface CloudKeyRecord {
  provider: "aws-kms" | "azure-key-vault" | "hashicorp-vault" | "gcp-kms";
  keyId: string; // ARN / key URL / mount+name
  name: string;
  classification: Classification;
  operations: string[];
  state?: CryptoMaterial["keyState"];
  createdAt?: string;
}

// ------------------------------------------------------------------ AWS KMS

/** Subset of @aws-sdk/client-kms `KMS` (aggregated client) used here. */
export interface AwsKmsLike {
  listKeys(input: { Marker?: string; Limit?: number }): Promise<{ Keys?: Array<{ KeyId?: string; KeyArn?: string }>; NextMarker?: string; Truncated?: boolean }>;
  describeKey(input: { KeyId: string }): Promise<{ KeyMetadata?: { KeyId?: string; Arn?: string; KeySpec?: string; KeyUsage?: string; KeyState?: string; CreationDate?: Date | string; EncryptionAlgorithms?: string[]; SigningAlgorithms?: string[]; KeyAgreementAlgorithms?: string[]; Description?: string } }>;
}

const AWS_STATE: Record<string, CryptoMaterial["keyState"]> = { Enabled: "active", Disabled: "suspended", PendingDeletion: "deactivated", PendingImport: "pre-activation", Unavailable: "suspended" };

export async function listAwsKmsKeys(client: AwsKmsLike, maxKeys = 1000): Promise<CloudKeyRecord[]> {
  const out: CloudKeyRecord[] = [];
  let marker: string | undefined;
  do {
    const page = await client.listKeys({ Marker: marker, Limit: 100 });
    for (const k of page.Keys ?? []) {
      if (!k.KeyId || out.length >= maxKeys) continue;
      const md = (await client.describeKey({ KeyId: k.KeyId })).KeyMetadata ?? {};
      const spec = md.KeySpec ?? "UNKNOWN";
      const entry = AWS_KMS_KEY_SPECS[spec] ?? { name: spec };
      const usage = md.KeyUsage === "SIGN_VERIFY" ? "signature" : md.KeyUsage === "KEY_AGREEMENT" ? "key-exchange" : md.KeyUsage === "GENERATE_VERIFY_MAC" ? "mac" : "encryption";
      out.push({
        provider: "aws-kms",
        keyId: md.Arn ?? k.KeyArn ?? k.KeyId,
        name: md.Description || k.KeyId,
        classification: classifyAlgorithm({ ...entry, usage }),
        operations: [...(md.EncryptionAlgorithms ?? []), ...(md.SigningAlgorithms ?? []), ...(md.KeyAgreementAlgorithms ?? [])],
        state: md.KeyState ? AWS_STATE[md.KeyState] : undefined,
        createdAt: md.CreationDate ? new Date(md.CreationDate).toISOString() : undefined,
      });
    }
    marker = page.Truncated ? page.NextMarker : undefined;
  } while (marker && out.length < maxKeys);
  return out;
}

// ------------------------------------------------------------------ Azure Key Vault

/** Subset of @azure/keyvault-keys `KeyClient`. */
export interface AzureKeyClientLike {
  vaultUrl: string;
  listPropertiesOfKeys(): AsyncIterable<{ name: string; enabled?: boolean; createdOn?: Date }>;
  getKey(name: string): Promise<{ id?: string; name: string; keyType?: string; keyOperations?: string[]; key?: { kty?: string; crv?: string; n?: Uint8Array } ; properties?: { enabled?: boolean; createdOn?: Date } }>;
}

export async function listAzureKeys(client: AzureKeyClientLike, maxKeys = 1000): Promise<CloudKeyRecord[]> {
  const out: CloudKeyRecord[] = [];
  for await (const p of client.listPropertiesOfKeys()) {
    if (out.length >= maxKeys) break;
    const k = await client.getKey(p.name);
    const kty = (k.keyType ?? k.key?.kty ?? "").replace(/-HSM$/, "");
    const ops = k.keyOperations ?? [];
    const usage = ops.some((o) => o === "sign" || o === "verify") ? "signature" : "encryption";
    // Only the modulus *length* is kept; the public modulus itself is discarded.
    const keySize = k.key?.n ? k.key.n.length * 8 : undefined;
    const name = kty === "RSA" ? "RSA" : kty === "EC" ? (usage === "signature" ? "ECDSA" : "ECDH") : kty === "oct" ? "AES" : kty;
    out.push({
      provider: "azure-key-vault",
      keyId: k.id ?? `${client.vaultUrl}/keys/${k.name}`,
      name: k.name,
      classification: classifyAlgorithm({ name, keySize: kty === "oct" ? undefined : keySize, curve: k.key?.crv, usage }),
      operations: ops,
      state: (k.properties?.enabled ?? p.enabled) === false ? "suspended" : "active",
      createdAt: (k.properties?.createdOn ?? p.createdOn)?.toISOString(),
    });
  }
  return out;
}

// ------------------------------------------------------------------ HashiCorp Vault (Transit)

export type FetchLike = (url: string, init: { method: string; headers: Record<string, string> }) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

const VAULT_TYPES: Record<string, { name: string; keySize?: number; curve?: string; usage: string }> = {
  "aes128-gcm96": { name: "AES-128-GCM", usage: "encryption" },
  "aes256-gcm96": { name: "AES-256-GCM", usage: "encryption" },
  "chacha20-poly1305": { name: "CHACHA20-POLY1305", usage: "encryption" },
  ed25519: { name: "Ed25519", usage: "signature" },
  "ecdsa-p256": { name: "ECDSA", curve: "P-256", usage: "signature" },
  "ecdsa-p384": { name: "ECDSA", curve: "P-384", usage: "signature" },
  "ecdsa-p521": { name: "ECDSA", curve: "P-521", usage: "signature" },
  "rsa-2048": { name: "RSA", keySize: 2048, usage: "signature" },
  "rsa-3072": { name: "RSA", keySize: 3072, usage: "signature" },
  "rsa-4096": { name: "RSA", keySize: 4096, usage: "signature" },
  hmac: { name: "HMAC-SHA-256", usage: "mac" },
  "ml-dsa": { name: "ML-DSA", usage: "signature" },
  "slh-dsa": { name: "SLH-DSA", usage: "signature" },
};

export async function listVaultTransitKeys(opts: { address: string; token: string; mount?: string; namespace?: string; fetch?: FetchLike; maxKeys?: number }): Promise<CloudKeyRecord[]> {
  const f = opts.fetch ?? (globalThis.fetch as unknown as FetchLike);
  const mount = (opts.mount ?? "transit").replace(/^\/|\/$/g, "");
  const base = opts.address.replace(/\/$/, "");
  const headers: Record<string, string> = { "X-Vault-Token": opts.token, ...(opts.namespace ? { "X-Vault-Namespace": opts.namespace } : {}) };
  const list = await f(`${base}/v1/${mount}/keys`, { method: "LIST", headers });
  if (list.status === 404) return [];
  if (!list.ok) throw new Error(`vault LIST ${mount}/keys failed: HTTP ${list.status}`);
  const names = ((await list.json()) as { data?: { keys?: string[] } }).data?.keys ?? [];
  const out: CloudKeyRecord[] = [];
  for (const name of names.slice(0, opts.maxKeys ?? 1000)) {
    const r = await f(`${base}/v1/${mount}/keys/${encodeURIComponent(name)}`, { method: "GET", headers });
    if (!r.ok) continue;
    const d = ((await r.json()) as { data?: { type?: string; exportable?: boolean; deletion_allowed?: boolean; supports_encryption?: boolean; supports_signing?: boolean; parameter_set?: string } }).data ?? {};
    const t = d.type ?? "unknown";
    const entry = VAULT_TYPES[t] ?? { name: t, usage: "unknown" };
    const pqName = (t === "ml-dsa" || t === "slh-dsa") && d.parameter_set ? `${entry.name}-${d.parameter_set}` : entry.name;
    out.push({
      provider: "hashicorp-vault",
      keyId: `${base}/v1/${mount}/keys/${name}`,
      name,
      classification: classifyAlgorithm({ ...entry, name: pqName }),
      operations: [d.supports_encryption ? "encrypt" : "", d.supports_signing ? "sign" : "", d.exportable ? "exportable" : ""].filter(Boolean),
      state: "active",
    });
  }
  return out;
}

// ------------------------------------------------------------------ Google Cloud KMS

/**
 * Map a Cloud KMS CryptoKeyVersionAlgorithm to the classifier.
 * https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions#CryptoKeyVersionAlgorithm
 */
export function gcpAlgorithm(alg: string): { name: string; keySize?: number; curve?: string; usage: string } {
  const a = alg.toUpperCase();
  if (a === "GOOGLE_SYMMETRIC_ENCRYPTION") return { name: "AES-256-GCM", usage: "encryption" };
  if (a === "EXTERNAL_SYMMETRIC_ENCRYPTION") return { name: "external-symmetric", usage: "encryption" };
  let m = a.match(/^AES_(128|256)_(GCM|CBC|CTR)$/);
  if (m) return { name: `AES-${m[1]}-${m[2]}`, usage: "encryption" };
  m = a.match(/^RSA_(SIGN|DECRYPT)_[A-Z0-9_]*?(2048|3072|4096)/);
  if (m) return { name: m[1] === "SIGN" && a.includes("PSS") ? "RSASSA-PSS" : "RSA", keySize: Number(m[2]), usage: m[1] === "SIGN" ? "signature" : "encryption" };
  m = a.match(/^EC_SIGN_(P256|P384|SECP256K1)_/);
  if (m) return { name: "EC", curve: ({ P256: "P-256", P384: "P-384", SECP256K1: "secp256k1" } as Record<string, string>)[m[1]], usage: "signature" };
  if (a === "EC_SIGN_ED25519") return { name: "Ed25519", usage: "signature" };
  m = a.match(/^HMAC_(SHA1|SHA224|SHA256|SHA384|SHA512)$/);
  if (m) return { name: `HMAC-${m[1].replace("SHA", "SHA-")}`, usage: "mac" };
  m = a.match(/^PQ_SIGN_ML_DSA_(44|65|87)/);
  if (m) return { name: `ML-DSA-${m[1]}`, usage: "signature" };
  m = a.match(/SLH_DSA_(SHA2|SHAKE)_(128|192|256)([SF])/);
  if (m) return { name: `SLH-DSA-${m[1]}-${m[2]}${m[3].toLowerCase()}`, usage: "signature" };
  m = a.match(/^ML_KEM_(512|768|1024)$/);
  if (m) return { name: `ML-KEM-${m[1]}`, usage: "key-exchange" };
  if (a === "KEM_XWING") return { name: "X-Wing (X25519+ML-KEM-768)", usage: "key-exchange" };
  return { name: alg, usage: "unknown" };
}

const GCP_STATE: Record<string, CryptoMaterial["keyState"]> = {
  ENABLED: "active", DISABLED: "suspended", DESTROYED: "destroyed", DESTROY_SCHEDULED: "deactivated",
  PENDING_GENERATION: "pre-activation", PENDING_IMPORT: "pre-activation", PENDING_EXTERNAL_DESTRUCTION: "deactivated",
};

interface GcpCryptoKey {
  name: string;
  purpose?: string;
  createTime?: string;
  primary?: { state?: string; algorithm?: string; protectionLevel?: string };
  versionTemplate?: { algorithm?: string; protectionLevel?: string };
}

/**
 * Lists key rings and crypto keys with GET calls only (role roles/cloudkms.viewer is enough).
 * Never calls versions, getPublicKey, or any crypto operation. Locations default to all
 * locations the project reports.
 */
export async function listGcpKmsKeys(opts: { project: string; token: string; locations?: string[]; fetch?: FetchLike; maxKeys?: number }): Promise<CloudKeyRecord[]> {
  const f = opts.fetch ?? (globalThis.fetch as unknown as FetchLike);
  const base = "https://cloudkms.googleapis.com/v1";
  const headers = { Authorization: `Bearer ${opts.token}` };
  const max = opts.maxKeys ?? 1000;
  const getAll = async <T>(url: string, field: string): Promise<T[]> => {
    const out: T[] = [];
    let page: string | undefined;
    do {
      const r = await f(`${url}${url.includes("?") ? "&" : "?"}pageSize=1000${page ? `&pageToken=${encodeURIComponent(page)}` : ""}`, { method: "GET", headers });
      if (!r.ok) throw new Error(`GCP KMS GET ${url.replace(base, "")} failed: HTTP ${r.status}`);
      const body = (await r.json()) as Record<string, unknown>;
      out.push(...((body[field] as T[] | undefined) ?? []));
      page = body.nextPageToken as string | undefined;
    } while (page && out.length < max);
    return out;
  };
  const project = encodeURIComponent(opts.project);
  const locations = opts.locations ?? (await getAll<{ locationId: string }>(`${base}/projects/${project}/locations`, "locations")).map((l) => l.locationId);
  const out: CloudKeyRecord[] = [];
  for (const loc of locations) {
    if (out.length >= max) break;
    const rings = await getAll<{ name: string }>(`${base}/projects/${project}/locations/${encodeURIComponent(loc)}/keyRings`, "keyRings");
    for (const ring of rings) {
      for (const k of await getAll<GcpCryptoKey>(`${base}/${ring.name}/cryptoKeys`, "cryptoKeys")) {
        if (out.length >= max) break;
        const alg = k.primary?.algorithm ?? k.versionTemplate?.algorithm ?? "UNKNOWN";
        const entry = gcpAlgorithm(alg);
        out.push({
          provider: "gcp-kms",
          keyId: k.name,
          name: k.name.split("/").pop() ?? k.name,
          classification: classifyAlgorithm(entry),
          operations: [k.purpose, k.primary?.protectionLevel ?? k.versionTemplate?.protectionLevel].filter((x): x is string => Boolean(x)),
          state: k.primary?.state ? GCP_STATE[k.primary.state] : undefined,
          createdAt: k.createTime,
        });
      }
    }
  }
  return out;
}

// ------------------------------------------------------------------ graph

export function ingestCloudKeys(records: CloudKeyRecord[], opts: { now?: string; risk?: RiskInputs } = {}): CryptoGraph {
  const g = new CryptoGraph();
  const now = opts.now ?? new Date().toISOString();
  for (const r of records) {
    const ev: Evidence[] = [{ source: "cloud", locator: r.keyId, detail: `${r.provider} key metadata`, observedAt: now }];
    const storeId = `cloud:${r.provider}`;
    g.addVertex<ServiceGroup>({ id: storeId, kind: "ServiceGroup", label: r.provider, description: "Key management service", evidence: [], ...opts.risk });
    const keyId = `kms:${r.keyId}`;
    g.addVertex<CryptoMaterial>({ id: keyId, kind: "CryptoMaterial", label: `${r.provider} key ${r.name}`, materialType: "key-metadata", format: r.provider, keyState: r.state, evidence: ev });
    link(g, keyId, "ENCRYPTED_WITH", addPrimitive(g, r.classification, ev), r.operations.length ? { operations: r.operations.join(",") } : undefined);
    link(g, storeId, "CONTAINS_KEY", keyId);
  }
  return g;
}
