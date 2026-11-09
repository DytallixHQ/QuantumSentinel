import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { CryptoGraph } from "../../core/graph/graph.ts";
import type { CryptoMaterial, CryptoPrimitive, FileAsset } from "../../core/graph/types.ts";
import { parsePgpPackets, shannonEntropy, sniff } from "./containers.ts";
import { parsePem } from "./der.ts";
import { ingestBuffer, scanFilesystem } from "./index.ts";
import { writeKeyFixtures } from "./keyFixtures.ts";
import { parseCertificate } from "./x509.ts";

const FIX = path.resolve(import.meta.dirname, "../../../test-fixtures/graph");
const NOW = "2026-11-09T00:00:00Z";
const fx = async (name: string) => new Uint8Array(await readFile(path.join(FIX, name)));
const prims = (g: CryptoGraph) => g.allVertices("CryptoPrimitive") as CryptoPrimitive[];
const ingest = (buf: Uint8Array, name = "/x/" + Math.random()) => {
  const g = new CryptoGraph();
  const type = ingestBuffer(g, buf, { path: name }, NOW);
  return { g, type };
};

// ---------------------------------------------------------------- synthetic binary fixtures

function jks(certDer: Uint8Array): Uint8Array {
  const b: number[] = [0xfe, 0xed, 0xfe, 0xed, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2];
  const utf = (s: string) => [0, s.length, ...Buffer.from(s)];
  b.push(...utf("root"), ...new Array(8).fill(0), ...utf("X.509"));
  b.push((certDer.length >>> 24) & 255, (certDer.length >>> 16) & 255, (certDer.length >>> 8) & 255, certDer.length & 255, ...certDer);
  b.push(...new Array(20).fill(0)); // SHA-1 integrity digest
  return new Uint8Array(b);
}

function luks1(): Uint8Array {
  const b = new Uint8Array(4096);
  b.set([0x4c, 0x55, 0x4b, 0x53, 0xba, 0xbe, 0, 1]);
  b.set(Buffer.from("aes"), 8);
  b.set(Buffer.from("xts-plain64"), 40);
  b.set(Buffer.from("sha256"), 72);
  new DataView(b.buffer).setUint32(108, 64); // 512-bit XTS key = AES-256
  return b;
}

function luks2(): Uint8Array {
  const json = JSON.stringify({ keyslots: { "0": { type: "luks2", key_size: 32 } }, segments: { "0": { type: "crypt", encryption: "aes-xts-plain64" } } });
  const b = new Uint8Array(4096 + 12288);
  b.set([0x4c, 0x55, 0x4b, 0x53, 0xba, 0xbe, 0, 2]);
  b.set(Buffer.from("sha256"), 72);
  b.set(Buffer.from(json), 4096);
  return b; // 32-byte XTS key = AES-128
}

function bitlocker(method: number): Uint8Array {
  const b = new Uint8Array(0x3000);
  b.set([0xeb, 0x58, 0x90], 0);
  b.set(Buffer.from("-FVE-FS-"), 3);
  const dv = new DataView(b.buffer);
  dv.setBigUint64(0xb0, 0x2000n, true);
  b.set(Buffer.from("-FVE-FS-"), 0x2000);
  dv.setUint16(0x2000 + 64 + 36, method, true);
  return b;
}

function pgpPkesk(alg: number): Uint8Array {
  const body = [3, 1, 2, 3, 4, 5, 6, 7, 8, alg, ...randomBytes(40)];
  return new Uint8Array([0xc1, body.length, ...body]); // new-format Tag 1
}

// ---------------------------------------------------------------- tests

test("X.509 parser extracts algorithms, sizes and names from DER", async () => {
  const ca = parseCertificate(parsePem(new TextDecoder().decode(await fx("ca-rsa4096.pem")))[0].der);
  assert.equal(ca.publicKey.algorithm, "RSA");
  assert.equal(ca.publicKey.keySize, 4096);
  assert.equal(ca.signatureOid, "1.2.840.113549.1.1.11");
  assert.match(ca.subject, /CN=QS Test Root CA/);
  const leaf = parseCertificate(await fx("leaf-ec-p256.der"));
  assert.equal(leaf.publicKey.curve, "P-256");
  assert.equal(leaf.issuer, ca.subject);
  const pq = parseCertificate(parsePem(new TextDecoder().decode(await fx("mldsa65-selfsigned.pem")))[0].der);
  assert.equal(pq.publicKey.algorithm, "ML-DSA-65");
  assert.equal(pq.signatureOid, "2.16.840.1.101.3.4.3.18");
});

test("content sniffing ignores extensions", async () => {
  assert.equal(sniff(await fx("leaf-ec-p256.der")), "x509-der");
  assert.equal(sniff(await fx("bundle.p12")), "pkcs12");
  assert.equal(sniff(await fx("chain.pem")), "pem");
  assert.equal(sniff(jks(await fx("leaf-ec-p256.der"))), "jks");
  assert.equal(sniff(luks1()), "luks1");
  assert.equal(sniff(luks2()), "luks2");
  assert.equal(sniff(bitlocker(0x8004)), "bitlocker");
  assert.equal(sniff(pgpPkesk(1)), "openpgp");
  assert.equal(sniff(new Uint8Array(randomBytes(65536))), "high-entropy");
  assert.equal(sniff(new TextEncoder().encode("hello world ".repeat(100))), "other");
});

test("entropy threshold", () => {
  assert.ok(shannonEntropy(new Uint8Array(randomBytes(65536))) >= 7.5);
  assert.ok(shannonEntropy(new Uint8Array(4096)) < 1);
});

test("PEM chain: certificates, keys, and issuer SIGNS edge", async () => {
  const { g } = ingest(await fx("chain.pem"));
  const certs = g.allVertices("CryptoMaterial") as CryptoMaterial[];
  assert.equal(certs.length, 2);
  const leaf = certs.find((c) => c.subject?.includes("proxy"))!;
  const root = certs.find((c) => c.subject?.includes("Root"))!;
  assert.ok(g.outgoing(root.id, ["SIGNS"]).some((e) => e.to === leaf.id), "root SIGNS leaf");
  const statuses = prims(g).map((p) => `${p.algorithm}:${p.status}`).sort();
  assert.ok(statuses.includes("ECDSA-P-256:VULNERABLE_SHOR"));
  assert.ok(statuses.includes("RSA-4096:VULNERABLE_SHOR"));
});

test("PKCS#8: unencrypted key is reduced to its SPKI; encrypted key records only its PBES2 cipher", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "qs-keys-"));
  const keys = await writeKeyFixtures(dir);
  await rm(dir, { recursive: true, force: true });
  const enc8 = (s: string) => new TextEncoder().encode(s);
  const ed = ingest(enc8(keys["ed25519-private.pem"])).g;
  const m = ed.allVertices("CryptoMaterial") as CryptoMaterial[];
  assert.equal(m.length, 1);
  assert.equal(m[0].materialType, "private-key-ref");
  assert.match(m[0].id, /^spki:[0-9a-f]{64}$/);
  assert.equal(prims(ed)[0].algorithm, "Ed25519");

  const enc = ingest(enc8(keys["rsa3072-encrypted.pem"])).g;
  const p = prims(enc);
  assert.deepEqual(p.map((x) => x.algorithm), ["AES-256-CBC"]);
  assert.equal(p[0].status, "SAFE_PQC");
});

test("PKCS#12: plaintext cert bag parsed, shrouded key counted, never decrypted", async () => {
  const { g, type } = ingest(await fx("bundle.p12"));
  assert.equal(type, "pkcs12");
  const mats = g.allVertices("CryptoMaterial") as CryptoMaterial[];
  assert.ok(mats.some((m) => m.materialType === "certificate" && m.subject?.includes("proxy")));
  assert.ok(mats.some((m) => m.materialType === "private-key-ref" && m.format === "PKCS#12"));
  assert.ok(prims(g).some((p) => p.algorithm === "AES-256-CBC"));
  assert.ok(prims(g).some((p) => p.algorithm === "SHA-256"));
});

test("JKS trusted cert entry", async () => {
  const { g } = ingest(jks(await fx("leaf-ec-p256.der")));
  assert.equal((g.allVertices("CryptoMaterial") as CryptoMaterial[])[0].materialType, "certificate");
});

test("LUKS1/LUKS2/BitLocker headers yield the volume cipher and key size", () => {
  const algs = (buf: Uint8Array) => prims(ingest(buf).g).map((p) => `${p.algorithm}:${p.status}`).sort();
  assert.deepEqual(algs(luks1()), ["AES-256-XTS:SAFE_PQC", "SHA-256:SAFE_PQC"]);
  assert.deepEqual(algs(luks2()), ["AES-128-XTS:DEGRADED_GROVER", "SHA-256:SAFE_PQC"]);
  assert.deepEqual(algs(bitlocker(0x8004)), ["AES-128-XTS:DEGRADED_GROVER"]);
  assert.deepEqual(algs(bitlocker(0x8003)), ["AES-256-CBC:SAFE_PQC"]);
  const f = ingest(luks1()).g.allVertices("FileAsset")[0] as FileAsset;
  assert.equal(f.fsType, "LUKS1");
});

test("OpenPGP Tag 1 PKESK algorithms", () => {
  assert.equal(parsePgpPackets(pgpPkesk(1))[0].algorithm, "RSA");
  assert.equal(prims(ingest(pgpPkesk(18)).g)[0].status, "VULNERABLE_SHOR");
  assert.equal(prims(ingest(pgpPkesk(35)).g)[0].status, "HYBRID");
});

test("directory scan dedups the same certificate across PEM, DER, PKCS#12 and JKS", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "qs-fs-"));
  try {
    for (const [i, f] of ["chain.pem", "leaf-ec-p256.pem", "leaf-ec-p256.der", "bundle.p12", "ec-p256-public.pem"].entries()) await writeFile(path.join(dir, `blob${i}`), await fx(f));
    await writeFile(path.join(dir, "store"), jks(await fx("leaf-ec-p256.der")));
    await writeFile(path.join(dir, "notes.txt"), "nothing here");
    const g = await scanFilesystem([{ path: dir, criticality: 6 }], { now: () => NOW });
    const certs = (g.allVertices("CryptoMaterial") as CryptoMaterial[]).filter((m) => m.materialType === "certificate");
    assert.equal(certs.length, 2, "leaf + root, deduplicated by DER hash");
    const leaf = certs.find((c) => c.subject?.includes("proxy"))!;
    assert.equal(new Set(leaf.evidence.map((e) => e.locator)).size, 5, "leaf evidence from every container");
    assert.equal(g.incoming(leaf.id, ["CONTAINS_KEY"]).length, 5);
    // The bare SPKI and the leaf certificate share one ECDSA-P-256 primitive.
    assert.equal(prims(g).filter((p) => p.algorithm === "ECDSA-P-256").length, 1);
    assert.ok((g.allVertices("FileAsset") as FileAsset[]).every((f) => f.criticality === 6));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("zero secret leakage: no private key bytes reach the graph", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "qs-leak-"));
  try {
    const keys = await writeKeyFixtures(dir);
    await writeFile(path.join(dir, "bundle.p12"), await fx("bundle.p12"));
    const g = await scanFilesystem([{ path: dir }], { now: () => NOW });
    const out = JSON.stringify(g.toJSON());
    for (const [f, pem] of Object.entries(keys)) {
      const der = parsePem(pem)[0].der;
      const b64 = Buffer.from(der).toString("base64");
      for (let i = 0; i + 24 <= b64.length; i += 24) assert.ok(!out.includes(b64.slice(i, i + 24)), `${f} base64 chunk leaked`);
      const hex = Buffer.from(der).toString("hex");
      // The private scalar sits at the end of the DER; make sure no 16-byte window of it appears as hex.
      for (let i = hex.length - 64; i + 32 <= hex.length; i += 8) assert.ok(!out.includes(hex.slice(i, i + 32)), `${f} hex leaked`);
    }
    assert.ok(!/PRIVATE KEY-----/.test(out));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
