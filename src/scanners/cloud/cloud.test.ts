import assert from "node:assert/strict";
import test from "node:test";
import type { CryptoMaterial, CryptoPrimitive } from "../../core/graph/types.ts";
import { gcpAlgorithm, ingestCloudKeys, listAwsKmsKeys, listAzureKeys, listGcpKmsKeys, listVaultTransitKeys, type AwsKmsLike, type AzureKeyClientLike, type FetchLike } from "./index.ts";

const ARN = (id: string) => `arn:aws:kms:us-east-1:111122223333:key/${id}`;

/** Mock of @aws-sdk/client-kms with two pages; records every call to prove only read-only operations are used. */
function mockKms(calls: string[]): AwsKmsLike {
  const meta: Record<string, object> = {
    k1: { KeyId: "k1", Arn: ARN("k1"), KeySpec: "RSA_2048", KeyUsage: "SIGN_VERIFY", KeyState: "Enabled", SigningAlgorithms: ["RSASSA_PSS_SHA_256"], CreationDate: new Date("2024-01-02T00:00:00Z") },
    k2: { KeyId: "k2", Arn: ARN("k2"), KeySpec: "SYMMETRIC_DEFAULT", KeyUsage: "ENCRYPT_DECRYPT", KeyState: "Enabled", EncryptionAlgorithms: ["SYMMETRIC_DEFAULT"] },
    k3: { KeyId: "k3", Arn: ARN("k3"), KeySpec: "ML_DSA_65", KeyUsage: "SIGN_VERIFY", KeyState: "Disabled", SigningAlgorithms: ["ML_DSA_SHAKE_256"] },
    k4: { KeyId: "k4", Arn: ARN("k4"), KeySpec: "ECC_NIST_P256", KeyUsage: "KEY_AGREEMENT", KeyState: "PendingDeletion", KeyAgreementAlgorithms: ["ECDH"] },
  };
  return {
    async listKeys({ Marker }) {
      calls.push(`listKeys:${Marker ?? ""}`);
      return Marker ? { Keys: [{ KeyId: "k3" }, { KeyId: "k4" }], Truncated: false } : { Keys: [{ KeyId: "k1" }, { KeyId: "k2" }], Truncated: true, NextMarker: "page2" };
    },
    async describeKey({ KeyId }) {
      calls.push(`describeKey:${KeyId}`);
      return { KeyMetadata: meta[KeyId] };
    },
  };
}

test("AWS KMS: paginates, maps KeySpec, uses only ListKeys/DescribeKey", async () => {
  const calls: string[] = [];
  const keys = await listAwsKmsKeys(mockKms(calls));
  assert.deepEqual(calls.map((c) => c.split(":")[0]).filter((c, i, a) => a.indexOf(c) === i).sort(), ["describeKey", "listKeys"]);
  const by = Object.fromEntries(keys.map((k) => [k.keyId.split("/").pop(), k]));
  assert.equal(by.k1.classification.algorithm, "RSA-2048");
  assert.equal(by.k1.classification.status, "VULNERABLE_SHOR");
  assert.equal(by.k1.createdAt, "2024-01-02T00:00:00.000Z");
  assert.equal(by.k2.classification.status, "SAFE_PQC");
  assert.equal(by.k3.classification.algorithm, "ML-DSA-65");
  assert.equal(by.k3.state, "suspended");
  assert.equal(by.k4.classification.algorithm, "ECDH-P-256");
  assert.equal(by.k4.state, "deactivated");
});

test("Azure Key Vault: modulus length kept, modulus discarded", async () => {
  const n = new Uint8Array(384).fill(0xab); // 3072-bit public modulus
  const client: AzureKeyClientLike = {
    vaultUrl: "https://vault.test.invalid",
    async *listPropertiesOfKeys() {
      yield { name: "rsa-signer", enabled: true };
      yield { name: "ec-wrap", enabled: false };
    },
    async getKey(name) {
      return name === "rsa-signer"
        ? { id: "https://vault.test.invalid/keys/rsa-signer/1", name, keyType: "RSA-HSM", keyOperations: ["sign", "verify"], key: { kty: "RSA-HSM", n } }
        : { name, keyType: "EC", keyOperations: ["wrapKey"], key: { kty: "EC", crv: "P-384" } };
    },
  };
  const keys = await listAzureKeys(client);
  assert.equal(keys[0].classification.algorithm, "RSA-3072");
  assert.equal(keys[1].classification.algorithm, "ECDH-P-384");
  assert.equal(keys[1].state, "suspended");
  assert.ok(!JSON.stringify(keys).includes("abababab"), "public modulus not retained");
});

test("HashiCorp Vault transit: LIST + read, token only in header", async () => {
  const seen: Array<{ url: string; method: string; headers: Record<string, string> }> = [];
  const fetch: FetchLike = async (url, init) => {
    seen.push({ url, ...init });
    const body = url.endsWith("/keys")
      ? { data: { keys: ["legacy", "modern", "pq"] } }
      : { data: { legacy: { type: "rsa-2048", supports_signing: true }, modern: { type: "aes256-gcm96", supports_encryption: true }, pq: { type: "ml-dsa", parameter_set: "87", supports_signing: true } }[url.split("/").pop()!] };
    return { ok: true, status: 200, json: async () => body };
  };
  const keys = await listVaultTransitKeys({ address: "https://vault.test.invalid:8200/", token: "s.secret-token", fetch });
  assert.deepEqual(seen.map((s) => s.method), ["LIST", "GET", "GET", "GET"]);
  assert.ok(seen.every((s) => !s.url.includes("secret-token") && s.headers["X-Vault-Token"] === "s.secret-token"));
  assert.deepEqual(keys.map((k) => k.classification.algorithm), ["RSA-2048", "AES-256-GCM", "ML-DSA-87"]);
  assert.ok(!JSON.stringify(keys).includes("secret-token"));
});

test("cloud keys become key-metadata vertices under a provider group", async () => {
  const g = ingestCloudKeys(await listAwsKmsKeys(mockKms([])), { now: "2026-11-09T00:00:00Z" });
  const mats = g.allVertices("CryptoMaterial") as CryptoMaterial[];
  assert.equal(mats.length, 4);
  assert.ok(mats.every((m) => m.materialType === "key-metadata"));
  assert.equal(g.outgoing("cloud:aws-kms", ["CONTAINS_KEY"]).length, 4);
  assert.ok((g.allVertices("CryptoPrimitive") as CryptoPrimitive[]).some((p) => p.status === "SAFE_PQC"));
});

test("GCP algorithm names map to the classifier", () => {
  const cases: Array<[string, string]> = [
    ["GOOGLE_SYMMETRIC_ENCRYPTION", "AES-256-GCM"], ["AES_128_GCM", "AES-128-GCM"], ["RSA_SIGN_PSS_2048_SHA256", "RSASSA-PSS"],
    ["RSA_DECRYPT_OAEP_3072_SHA256", "RSA"], ["EC_SIGN_SECP256K1_SHA256", "EC"], ["EC_SIGN_ED25519", "Ed25519"], ["HMAC_SHA256", "HMAC-SHA-256"],
    ["PQ_SIGN_ML_DSA_65", "ML-DSA-65"], ["PQ_SIGN_SLH_DSA_SHA2_128S", "SLH-DSA-SHA2-128s"], ["ML_KEM_768", "ML-KEM-768"], ["KEM_XWING", "X-Wing (X25519+ML-KEM-768)"],
  ];
  for (const [alg, name] of cases) assert.equal(gcpAlgorithm(alg).name, name, alg);
  assert.equal(gcpAlgorithm("RSA_DECRYPT_OAEP_3072_SHA256").keySize, 3072);
  assert.equal(gcpAlgorithm("EC_SIGN_SECP256K1_SHA256").curve, "secp256k1");
});

test("GCP Cloud KMS: locations, key rings, pagination; GET-only and token only in the header", async () => {
  const seen: Array<{ url: string; method: string; headers: Record<string, string> }> = [];
  const P = "projects/acme";
  const pages: Record<string, unknown> = {
    [`${P}/locations`]: { locations: [{ locationId: "global" }, { locationId: "us-west1" }] },
    [`${P}/locations/global/keyRings`]: { keyRings: [{ name: `${P}/locations/global/keyRings/app` }] },
    [`${P}/locations/us-west1/keyRings`]: {},
    [`${P}/locations/global/keyRings/app/cryptoKeys`]: { cryptoKeys: [
      { name: `${P}/locations/global/keyRings/app/cryptoKeys/data`, purpose: "ENCRYPT_DECRYPT", primary: { state: "ENABLED", algorithm: "GOOGLE_SYMMETRIC_ENCRYPTION", protectionLevel: "HSM" } },
      { name: `${P}/locations/global/keyRings/app/cryptoKeys/wallet`, purpose: "ASYMMETRIC_SIGN", versionTemplate: { algorithm: "EC_SIGN_SECP256K1_SHA256" } },
    ], nextPageToken: "p2" },
    [`${P}/locations/global/keyRings/app/cryptoKeys#p2`]: { cryptoKeys: [
      { name: `${P}/locations/global/keyRings/app/cryptoKeys/pq-sign`, purpose: "ASYMMETRIC_SIGN", primary: { state: "ENABLED", algorithm: "PQ_SIGN_ML_DSA_65" } },
      { name: `${P}/locations/global/keyRings/app/cryptoKeys/kem`, purpose: "KEY_ENCAPSULATION", primary: { state: "DESTROY_SCHEDULED", algorithm: "KEM_XWING" } },
    ] },
  };
  const fetch: FetchLike = async (url, init) => {
    seen.push({ url, ...init });
    const u = new URL(url);
    const key = u.pathname.replace(/^\/v1\//, "") + (u.searchParams.get("pageToken") ? `#${u.searchParams.get("pageToken")}` : "");
    const body = pages[key];
    return { ok: body !== undefined, status: body === undefined ? 404 : 200, json: async () => body };
  };
  const keys = await listGcpKmsKeys({ project: "acme", token: "ya29.secret", fetch });
  assert.ok(seen.every((r) => r.method === "GET" && r.headers.Authorization === "Bearer ya29.secret" && !r.url.includes("ya29")));
  assert.ok(seen.every((r) => !/cryptoKeyVersions|publicKey|:encrypt|:sign|:decrypt/.test(r.url)), "metadata only");
  const by = Object.fromEntries(keys.map((k) => [k.name, k]));
  assert.deepEqual(Object.keys(by).sort(), ["data", "kem", "pq-sign", "wallet"]);
  assert.equal(by.data.classification.status, "SAFE_PQC");
  assert.deepEqual(by.data.operations, ["ENCRYPT_DECRYPT", "HSM"]);
  assert.equal(by.wallet.classification.algorithm, "ECDSA-secp256k1");
  assert.equal(by.wallet.classification.status, "VULNERABLE_SHOR");
  assert.equal(by["pq-sign"].classification.status, "SAFE_PQC");
  assert.equal(by.kem.classification.status, "HYBRID");
  assert.equal(by.kem.state, "deactivated");
  assert.ok(!JSON.stringify(keys).includes("ya29"));
});

test("GCP Cloud KMS: explicit locations skip the location listing; HTTP errors surface", async () => {
  const urls: string[] = [];
  const fetch: FetchLike = async (url) => {
    urls.push(url);
    return { ok: false, status: 403, json: async () => ({}) };
  };
  await assert.rejects(listGcpKmsKeys({ project: "acme", token: "t", locations: ["global"], fetch }), /HTTP 403/);
  assert.ok(!urls.some((u) => /\/locations\?/.test(u)));
});
