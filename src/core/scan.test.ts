import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { Ajv } from "ajv";
import { buildCycloneDxCbom } from "../exporters/cyclonedx.ts";
import type { AwsKmsLike } from "../scanners/cloud/index.ts";
import { parseCertificate } from "../scanners/filesystem/x509.ts";
import { parsePem } from "../scanners/filesystem/der.ts";
import { writeKeyFixtures } from "../scanners/filesystem/keyFixtures.ts";
import type { CodeAsset, CryptoPrimitive, NetworkEndpoint } from "./graph/types.ts";
import type { NetworkProbes } from "../scanners/network/index.ts";
import type { TlsProbeResult } from "../scanners/network/tls.ts";
import { runGraphCli } from "./cliGraph.ts";
import { runGraphScan, validateTargets, type TargetsConfig } from "./scan.ts";

const ROOT = path.resolve(import.meta.dirname, "../..");
const FIX = path.join(ROOT, "test-fixtures");
const NOW = () => "2026-11-09T00:00:00Z";
let KEYDIR = "";
let CODEDIR = "";
let KEYS: Record<string, string> = {};
test.before(async () => {
  KEYDIR = await mkdtemp(path.join(os.tmpdir(), "qs-e2e-keys-"));
  KEYS = await writeKeyFixtures(KEYDIR);
  CODEDIR = await mkdtemp(path.join(os.tmpdir(), "qs-e2e-code-"));
  await writeFile(path.join(CODEDIR, "auth.js"), 'const token = jwt.sign(payload, key, { algorithm: "RS256" });\n');
  await writeFile(path.join(CODEDIR, "tls.go"), "curve := elliptic.P256() // prime256v1 key exchange\nkem := mlkem.ML-KEM-768 // handshake kem\n");
  await writeFile(path.join(CODEDIR, "README.md"), "We plan to drop RSA eventually.\n");
});
test.after(async () => {
  await rm(KEYDIR, { recursive: true, force: true });
  await rm(CODEDIR, { recursive: true, force: true });
});
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- free-form CycloneDX JSON, validated against the schema
type Comp = Record<string, any>;

async function validator() {
  const load = async (f: string) => JSON.parse(await readFile(path.join(FIX, "cyclonedx", f), "utf8"));
  const ajv = new Ajv({ strict: false, validateFormats: false, allErrors: true });
  for (const f of ["spdx.schema.json", "jsf-0.82.schema.json", "cryptography-defs.schema.json"]) ajv.addSchema(await load(f));
  return ajv.compile(await load("bom-1.7.schema.json"));
}

async function mockProbes(): Promise<NetworkProbes> {
  const chain = parsePem(await readFile(path.join(FIX, "graph/chain.pem"), "utf8")).map((b) => b.der);
  const results: Record<string, TlsProbeResult> = {
    "proxy.test.invalid": { version: "TLS1.2", cipherSuite: 0xc02f, ske: { curveType: 3, group: 0x0017 }, helloRetry: false, certificates: chain, complete: true },
    "edge.test.invalid": { version: "TLS1.3", cipherSuite: 0x1302, group: 0x11ec, helloRetry: false, certificates: [], complete: true },
  };
  return {
    // edge prefers hybrid but still accepts classical-only clients; neither host supports pure ML-KEM.
    tls: async (host, _port, o) => {
      if (o.groups && !o.groups.includes(0x11ec)) {
        return host === "edge.test.invalid" && o.groups.includes(0x001d)
          ? { ...results[host], group: 0x001d }
          : { helloRetry: false, certificates: [], alert: { level: 2, description: 40 }, complete: false };
      }
      return results[host];
    },
    tlsChain: async () => chain, // same leaf as proxy: must dedup
    ssh: async () => ({ banner: "SSH-2.0-test", kex: ["mlkem768x25519-sha256", "curve25519-sha256"], hostKey: ["ssh-ed25519"], encC2S: ["aes256-gcm@openssh.com"], encS2C: ["aes256-gcm@openssh.com"], macC2S: [], macS2C: [] }),
    ike: async () => ({ accepted: [{ type: 1, id: 20, keyLength: 256 }, { type: 2, id: 7 }, { type: 4, id: 36 }] }),
  };
}

const kms: AwsKmsLike = {
  listKeys: async () => ({ Keys: [{ KeyId: "k1" }] }),
  describeKey: async () => ({ KeyMetadata: { Arn: "arn:aws:kms:us-east-1:111122223333:key/k1", KeySpec: "RSA_4096", KeyUsage: "ENCRYPT_DECRYPT", KeyState: "Enabled" } }),
};

function config(): TargetsConfig {
  return {
    authorization: { confirmed: true, owner: "fixture" },
    network: [
      { id: "proxy", host: "proxy.test.invalid", protocol: "tls", posture: "external", criticality: 6 },
      { id: "edge", host: "edge.test.invalid", protocol: "tls", posture: "external" },
      { id: "bastion", host: "bastion.test.invalid", protocol: "ssh", posture: "internal" },
      { id: "vpn", host: "vpn.test.invalid", protocol: "ikev2", posture: "external" },
      { id: "db", host: "10.0.0.5", port: 5432, protocol: "tcp", posture: "internal", criticality: 9, retentionYears: 10 },
    ],
    filesystem: [{ path: "graph" }, { path: KEYDIR }],
    code: [{ path: CODEDIR, repoUrl: "https://example.test.invalid/orders.git", commit: "abc123" }],
    cloud: { awsKms: { region: "us-east-1" } },
    groups: [{ id: "payments", label: "Payments cluster", members: ["db", "proxy"], criticality: 10 }],
    relations: [{ from: "db", type: "TERMINATES_AT", to: "proxy" }],
    risk: { qDayYear: 2033, currentYear: 2026 },
  };
}

test("targets validation enforces authorization and bounds", () => {
  assert.match(validateTargets({ network: [{ host: "a", protocol: "tls" }] }).join(), /authorization/);
  assert.deepEqual(validateTargets({ network: [{ host: "db", protocol: "tcp" }] }), [], "declared-only endpoints need no authorization");
  assert.match(validateTargets({ authorization: { confirmed: true }, network: [{ host: "10.0.0.0/24", protocol: "tls" }] }).join(), /not a range/);
  assert.match(validateTargets({ relations: [{ from: "a", type: "OWNS" as never, to: "b" }] }).join(), /relations\[0\]/);
  assert.match(validateTargets({ groups: [{ id: "g", members: [], criticality: 11 }] }).join(), /criticality/);
});

test("end-to-end graph scan: dedup across modalities, propagation, valid CycloneDX 1.7 CBOM", async () => {
  const res = await runGraphScan(config(), FIX, { probes: await mockProbes(), aws: async () => kms, now: NOW });
  assert.deepEqual(res.errors, []);
  const g = res.graph;

  // The proxy leaf certificate was seen over TLS, over the TLS 1.3 chain fetch, and in five fixture files: one vertex.
  const leafDer = parsePem(await readFile(path.join(FIX, "graph/leaf-ec-p256.pem"), "utf8"))[0].der;
  const leafId = `cert:${parseCertificate(leafDer).derSha256}`;
  const leaf = g.get(leafId)!;
  const sources = new Set(leaf.evidence.map((e) => e.source));
  assert.deepEqual([...sources].sort(), ["filesystem", "network"]);
  assert.ok(g.incoming(leafId, ["CONTAINS_KEY"]).some((e) => e.from === "proxy"));
  assert.ok(g.incoming(leafId, ["CONTAINS_KEY"]).some((e) => e.from === "edge"));

  const risk = new Map(res.risk.map((r) => [r.id, r]));
  assert.equal(risk.get("db")!.status, "VULNERABLE_SHOR", "plaintext DB inherits proxy's classical ECDHE");
  assert.equal(risk.get("db")!.exposure, 1);
  assert.equal(risk.get("db")!.score, 9 * 1 * 1 * (10 + 3 - 7));
  assert.equal(risk.get("payments")!.score, 10 * 1 * 1 * (10 + 3 - 7));
  assert.equal(risk.get("edge")!.status, "HYBRID");
  assert.equal(risk.get("edge")!.score, 0);
  const edge = g.get("edge") as NetworkEndpoint;
  assert.deepEqual(edge.supportedGroups, ["X25519MLKEM768", "x25519"]);
  assert.equal(edge.classicalFallback, true);
  assert.ok(risk.get("edge")!.drivers.some((d) => /classical fallback/.test(d)));
  assert.equal((g.get("proxy") as NetworkEndpoint).classicalFallback, undefined, "TLS 1.2 endpoint is not group-probed");
  // SSH is rated like TLS: by the best option a PQ-capable client gets, with fallback flagged.
  assert.equal(risk.get("bastion")!.status, "HYBRID");
  assert.equal((g.get("bastion") as NetworkEndpoint).classicalFallback, true);

  // Code ingestor (default repository rule set via dynamic import).
  const code = g.allVertices("CodeAsset") as CodeAsset[];
  const codeStatus = (file: string) => code.filter((c) => c.filePath === file).flatMap((c) => g.outgoing(c.id, ["DEPENDS_ON"]).map((e) => (g.get(e.to) as CryptoPrimitive).status));
  assert.deepEqual(codeStatus("auth.js"), ["VULNERABLE_SHOR"]);
  assert.ok(codeStatus("tls.go").includes("VULNERABLE_SHOR"));
  assert.ok(codeStatus("tls.go").includes("SAFE_PQC"));
  assert.deepEqual(codeStatus("README.md"), [], "documentation mentions are not usage");
  assert.ok(code.every((c) => c.repoUrl === "https://example.test.invalid/orders.git" && c.commit === "abc123"));
  assert.equal(risk.get("vpn")!.status, "SAFE_PQC");
  assert.equal(res.risk[0].id, "payments", "cluster is the top risk");

  const cbom = buildCycloneDxCbom(g, { risk: res.risk, timestamp: NOW(), serialNumber: "urn:uuid:00000000-0000-4000-8000-000000000000", toolVersion: "test" });
  const validate = await validator();
  assert.ok(validate(cbom), JSON.stringify(validate.errors?.slice(0, 5), null, 2));

  const comps = cbom.components as Comp[];
  assert.ok(comps.every((c) => c["bom-ref"]));
  const types = new Set(comps.filter((c) => c.type === "cryptographic-asset").map((c) => c.cryptoProperties.assetType));
  assert.deepEqual([...types].sort(), ["algorithm", "certificate", "protocol", "related-crypto-material"]);
  const hybrid = comps.find((c) => c.name === "X25519MLKEM768")!;
  assert.equal(hybrid.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel, 3);
  assert.ok(hybrid.properties.some((p: { name: string; value: string }) => p.name === "quantumsentinel:quantumStatus" && p.value === "HYBRID"));
  const rsa2048 = comps.find((c) => c.name === "RSA-2048")!;
  assert.equal(rsa2048.cryptoProperties.algorithmProperties.classicalSecurityLevel, 112);
  assert.equal(rsa2048.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel, 0);
  const proxyComp = comps.find((c) => c["bom-ref"] === "proxy")!;
  assert.equal(proxyComp.cryptoProperties.protocolProperties.type, "tls");
  assert.equal(proxyComp.cryptoProperties.protocolProperties.cipherSuites[0].name, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");

  const deps = cbom.dependencies as Array<{ ref: string; dependsOn: string[] }>;
  assert.equal(deps.length, comps.length);
  assert.deepEqual(deps.find((d) => d.ref === "payments")!.dependsOn, ["db", "proxy"]);
  assert.ok(deps.find((d) => d.ref === "db")!.dependsOn.includes("proxy"));
  const refs = new Set(comps.map((c) => c["bom-ref"]));
  assert.ok(deps.every((d) => d.dependsOn.every((r) => refs.has(r))), "no dangling dependency refs");

  // Zero secret leakage in the exported document.
  const text = JSON.stringify(cbom);
  assert.ok(!text.includes("-----BEGIN"), "no PEM armor in CBOM");
  for (const pem of Object.values(KEYS)) {
    const b64 = Buffer.from(parsePem(pem)[0].der).toString("base64");
    for (let i = 0; i + 24 <= b64.length; i += 24) assert.ok(!text.includes(b64.slice(i, i + 24)));
  }
});

test("CBOM output is deterministic for a fixed timestamp and serial", async () => {
  const run = async () => {
    const r = await runGraphScan(config(), FIX, { probes: await mockProbes(), aws: async () => kms, now: NOW });
    return JSON.stringify(buildCycloneDxCbom(r.graph, { risk: r.risk, timestamp: NOW(), serialNumber: "urn:uuid:00000000-0000-4000-8000-000000000000" }));
  };
  assert.equal(await run(), await run());
});

test("CLI: scan --graph --targets --export-cbom", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "qs-cli-"));
  try {
    const cfg = { ...config(), filesystem: [{ path: path.join(FIX, "graph") }], code: [] };
    const targets = path.join(dir, "targets.json");
    await writeFile(targets, JSON.stringify(cfg));
    const out: string[] = [];
    const code = await runGraphCli(["--graph", "--targets", targets, "--export-cbom", path.join(dir, "out/cbom.json"), "--output", path.join(dir, "graph.json"), "--html", path.join(dir, "report.html"), "--client", "Fixture Corp"], {
      probes: await mockProbes(), aws: async () => kms, now: NOW, stdout: (s) => out.push(s),
    });
    assert.equal(code, 0);
    const text = out.join("");
    assert.match(text, /CBOM \(CycloneDX 1\.7\)/);
    assert.match(text, /Top Mosca\/HNDL risk \(assets[^\n]*\n\s+60\.0\s+VULNERABLE_SHOR\s+payments/);
    assert.ok(!/cert:/.test(text), "certificates are not listed in the asset summary");
    const cbom = JSON.parse(await readFile(path.join(dir, "out/cbom.json"), "utf8"));
    assert.equal(cbom.specVersion, "1.7");
    assert.ok((await validator())(cbom));
    const html = await readFile(path.join(dir, "report.html"), "utf8");
    assert.match(html, /Fixture Corp/);
    assert.match(html, /Migration plan/);
    assert.ok(!html.includes("-----BEGIN"));
    const graph = JSON.parse(await readFile(path.join(dir, "graph.json"), "utf8"));
    assert.ok(graph.vertices.length > 10 && graph.risk.length > 0);
    await assert.rejects(runGraphCli(["--graph"]), /--targets/);
    await assert.rejects(runGraphCli(["--graph", "--targets", targets, "--bogus"]), /unknown graph-mode option/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("cloud connector failures are reported, not fatal", async () => {
  const res = await runGraphScan({ cloud: { vault: { address: "https://vault.test.invalid" }, awsKms: { region: "us-east-1" } } }, FIX, {
    env: {}, aws: async () => { throw new Error("no credentials"); }, now: NOW,
  });
  assert.equal(res.errors.length, 2);
  assert.match(res.errors.map((e) => e.error).join(), /VAULT_TOKEN/);
});
