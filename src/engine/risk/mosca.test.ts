import assert from "node:assert/strict";
import test from "node:test";
import { addAlgorithm } from "../../core/graph/builders.ts";
import { CryptoGraph } from "../../core/graph/graph.ts";
import type { NetworkEndpoint, ServiceGroup } from "../../core/graph/types.ts";
import { moscaScore, moscaUncertain, resolveRiskConfig, scoreGraph } from "./mosca.ts";

const cfg = resolveRiskConfig({ qDayYear: 2033, currentYear: 2026, asOf: "2026-01-01T00:00:00Z" });
const ev = [{ source: "config" as const, locator: "test", observedAt: "2026-01-01T00:00:00Z" }];
const ep = (id: string, protocol: NetworkEndpoint["protocol"], posture: NetworkEndpoint["posture"], extra: Partial<NetworkEndpoint> = {}): NetworkEndpoint =>
  ({ id, kind: "NetworkEndpoint", label: id, host: id, port: 1, protocol, posture, evidence: ev, ...extra });

test("Mosca: Q-Day year is converted to years remaining", () => {
  // 7 years until 2033; retention 5 + migration 3 = 8 -> gap 1.
  assert.deepEqual(moscaScore(8, 1, 1, 5, 3, cfg), { score: 8, gap: 1 });
  // Within the window: no risk.
  assert.equal(moscaScore(10, 1, 1, 2, 2, cfg).score, 0);
  // Inputs are clamped to C in [1,10], E in [0.1,1].
  assert.equal(moscaScore(50, 5, 1, 10, 5, cfg).score, 10 * 1 * 8);
  assert.equal(moscaScore(0, 0, 1, 10, 5, cfg).score, 1 * 0.1 * 8);
  // Configurable Q-Day.
  assert.equal(moscaScore(1, 1, 1, 5, 3, resolveRiskConfig({ qDayYear: 2040, currentYear: 2026 })).score, 0);
});

function propagationGraph(proxyKex: string) {
  const g = new CryptoGraph();
  g.addVertex(ep("db", "TCP", "internal", { criticality: 9, retentionYears: 10, migrationYears: 3 }));
  g.addVertex(ep("proxy", "TLS", "external", { criticality: 4 }));
  g.addVertex<ServiceGroup>({ id: "cluster", kind: "ServiceGroup", label: "payments", evidence: ev, criticality: 10 });
  g.addEdge("proxy", "ENCRYPTED_WITH", addAlgorithm(g, { name: proxyKex, usage: "key-exchange" }, ev));
  g.addEdge("proxy", "ENCRYPTED_WITH", addAlgorithm(g, { name: "AES-256-GCM", usage: "encryption" }, ev));
  g.addEdge("db", "TERMINATES_AT", "proxy");
  g.addEdge("cluster", "DEPENDS_ON", "db");
  return g;
}

test("unencrypted internal DB behind a classical external proxy inherits Shor exposure, and so does its cluster", () => {
  const r = new Map(scoreGraph(propagationGraph("X25519"), cfg).map((x) => [x.id, x]));
  const db = r.get("db")!;
  assert.equal(db.status, "VULNERABLE_SHOR");
  assert.equal(db.exposure, 1.0, "exposure propagated from external proxy");
  assert.equal(db.score, 9 * 1 * 1 * (10 + 3 - 7));
  assert.ok(db.drivers.some((d) => d.includes("TERMINATES_AT proxy")));
  const cluster = r.get("cluster")!;
  assert.equal(cluster.status, "VULNERABLE_SHOR");
  assert.equal(cluster.exposure, 1.0);
  assert.equal(cluster.score, 10 * 1 * 1 * (10 + 3 - 7), "cluster takes member retention and its own criticality");
  assert.ok(r.get("proxy")!.score < db.score, "proxy alone has lower criticality and default retention");
});

test("the same topology behind a hybrid PQC proxy scores zero", () => {
  const r = new Map(scoreGraph(propagationGraph("X25519MLKEM768"), cfg).map((x) => [x.id, x]));
  assert.equal(r.get("db")!.status, "HYBRID");
  assert.equal(r.get("db")!.score, 0);
  assert.equal(r.get("cluster")!.score, 0);
});

test("plaintext endpoint with no terminator scores at full weight", () => {
  const g = new CryptoGraph();
  g.addVertex(ep("telnet", "TCP", "external", { retentionYears: 10 }));
  const [r] = scoreGraph(g, cfg);
  assert.equal(r.status, "PLAINTEXT");
  assert.equal(r.score, 5 * 1 * 1 * (10 + 3 - 7));
});

test("confidentiality primitives drive HNDL status; signature-only weakness does not mask a PQ key exchange", () => {
  const g = new CryptoGraph();
  g.addVertex(ep("svc", "TLS", "external", { retentionYears: 20 }));
  g.addEdge("svc", "ENCRYPTED_WITH", addAlgorithm(g, { name: "X25519MLKEM768", usage: "key-exchange" }, ev));
  g.addEdge("svc", "ENCRYPTED_WITH", addAlgorithm(g, { name: "ECDSA", curve: "P-256", usage: "signature" }, ev));
  const [r] = scoreGraph(g, cfg);
  assert.equal(r.status, "HYBRID");
  assert.equal(r.score, 0);
});

test("DEPENDS_ON cycles terminate", () => {
  const g = new CryptoGraph();
  g.addVertex<ServiceGroup>({ id: "a", kind: "ServiceGroup", label: "a", evidence: ev });
  g.addVertex<ServiceGroup>({ id: "b", kind: "ServiceGroup", label: "b", evidence: ev });
  g.addEdge("a", "DEPENDS_ON", "b");
  g.addEdge("b", "DEPENDS_ON", "a");
  assert.equal(scoreGraph(g, cfg).length, 2);
});

// ---------------------------------------------------------------- Trust now, forge later

import type { CryptoMaterial } from "../../core/graph/types.ts";

function cert(g: CryptoGraph, id: string, keyAlg: { name: string; curve?: string; keySize?: number; usage: string }, sigAlg: string, notAfter: string, selfSigned = false): string {
  g.addVertex<CryptoMaterial>({ id, kind: "CryptoMaterial", label: id, materialType: "certificate", subject: `CN=${id}`, issuer: selfSigned ? `CN=${id}` : "CN=root", notAfter, evidence: ev });
  g.addEdge(id, "ENCRYPTED_WITH", addAlgorithm(g, keyAlg, ev));
  g.addEdge(addAlgorithm(g, { name: sigAlg, usage: "signature" }, ev), "SIGNS", id);
  return id;
}

function hybridEndpointWithChain(rootKey: string, rootSig: string, leafKey: string, leafSig: string) {
  const g = new CryptoGraph();
  g.addVertex(ep("web", "TLS", "external"));
  g.addEdge("web", "ENCRYPTED_WITH", addAlgorithm(g, { name: "X25519MLKEM768", usage: "key-exchange" }, ev));
  g.addEdge("web", "ENCRYPTED_WITH", addAlgorithm(g, { name: "AES-256-GCM", usage: "encryption" }, ev));
  const root = cert(g, "root", { name: rootKey, keySize: 4096, usage: "public-key" }, rootSig, "2040-01-01T00:00:00Z", true);
  const leaf = cert(g, "leaf", { name: leafKey, curve: "P-256", usage: "signature" }, leafSig, "2026-04-01T00:00:00Z");
  g.addEdge("root", "SIGNS", leaf);
  g.addEdge("web", "CONTAINS_KEY", leaf);
  g.addEdge("web", "CONTAINS_KEY", root);
  return g;
}

test("TNFL: hybrid key exchange (HNDL 0) but a classical root trusted past Q-Day is a forgery risk", () => {
  const r = new Map(scoreGraph(hybridEndpointWithChain("RSA", "SHA256withRSA", "ECDSA", "SHA256withRSA"), cfg).map((x) => [x.id, x]));
  const web = r.get("web")!;
  assert.equal(web.score, 0, "HNDL is covered by hybrid key exchange");
  assert.equal(web.tnfl.status, "VULNERABLE_SHOR");
  assert.equal(web.tnfl.trustYears, 14, "root valid until 2040");
  assert.equal(web.tnfl.score, 5 * 1 * 1 * (14 + 3 - 7));
  assert.equal(web.primaryThreat, "TNFL");
  assert.equal(web.combinedScore, web.tnfl.score);
  assert.ok(web.tnfl.drivers.some((d) => /trust anchor/.test(d)));
  assert.match(web.tnfl.drivers[0], /root/, "the longest-trusted item is listed first");
  // The root certificate itself is ranked, with the exposure of the endpoint that presents it.
  assert.equal(r.get("root")!.tnfl.score, 5 * 1 * 1 * 10);
  assert.equal(r.get("leaf")!.tnfl.score, 0, "a leaf expiring in months is not a TNFL risk on its own");
  assert.equal(r.get("root")!.score, 0, "certificates carry no HNDL score");
  assert.equal(r.get("root")!.primaryThreat, "TNFL");
});

test("TNFL: an ML-DSA chain is not forgeable", () => {
  const r = new Map(scoreGraph(hybridEndpointWithChain("ML-DSA-87", "ML-DSA-87", "ML-DSA-65", "ML-DSA-87"), cfg).map((x) => [x.id, x]));
  assert.equal(r.get("web")!.tnfl.status, "SAFE_PQC");
  assert.equal(r.get("web")!.tnfl.score, 0);
  assert.equal(r.get("web")!.primaryThreat, "none");
});

test("TNFL: signing keys without a validity period use trustYears (KMS, code signing, SSH host keys)", () => {
  const g = new CryptoGraph();
  g.addVertex<ServiceGroup>({ id: "cloud:aws-kms", kind: "ServiceGroup", label: "aws-kms", evidence: ev });
  g.addVertex<CryptoMaterial>({ id: "kms:release-signer", kind: "CryptoMaterial", label: "release signer", materialType: "key-metadata", trustYears: 15, evidence: ev });
  g.addEdge("kms:release-signer", "ENCRYPTED_WITH", addAlgorithm(g, { name: "RSA", keySize: 3072, usage: "signature" }, ev));
  g.addEdge("cloud:aws-kms", "CONTAINS_KEY", "kms:release-signer");
  g.addVertex<CryptoMaterial>({ id: "kms:data", kind: "CryptoMaterial", label: "data key", materialType: "key-metadata", trustYears: 15, evidence: ev });
  g.addEdge("kms:data", "ENCRYPTED_WITH", addAlgorithm(g, { name: "AES-256-GCM", usage: "encryption" }, ev));
  g.addVertex({ id: "code:sign.js:3", kind: "CodeAsset", label: "sign.js:3", repoUrl: "r", filePath: "sign.js", line: 3, evidence: ev });
  g.addEdge("code:sign.js:3", "DEPENDS_ON", addAlgorithm(g, { name: "ECDSA", curve: "P-256", usage: "signature" }, ev));
  g.addVertex(ep("bastion", "SSH", "internal"));
  g.addEdge("bastion", "ENCRYPTED_WITH", addAlgorithm(g, { name: "ssh-ed25519", usage: "signature" }, ev));
  const r = new Map(scoreGraph(g, resolveRiskConfig({ qDayYear: 2033, currentYear: 2026, asOf: "2026-01-01T00:00:00Z", defaults: { trustYears: 10 } })).map((x) => [x.id, x]));
  assert.equal(r.get("kms:release-signer")!.tnfl.trustYears, 15);
  assert.ok(r.get("kms:release-signer")!.tnfl.score > 0);
  assert.equal(r.get("kms:data")!.tnfl.status, undefined, "symmetric keys have no forgery risk");
  assert.equal(r.get("cloud:aws-kms")!.tnfl.status, "VULNERABLE_SHOR", "provider group inherits its signing keys");
  assert.equal(r.get("code:sign.js:3")!.tnfl.trustYears, 10);
  assert.equal(r.get("code:sign.js:3")!.primaryThreat, "TNFL");
  assert.equal(r.get("bastion")!.tnfl.status, "VULNERABLE_SHOR");
  assert.equal(r.get("bastion")!.tnfl.score, 5 * 0.3 * 1 * (10 + 3 - 7));
});

test("ranking uses max(HNDL, TNFL)", () => {
  const g = hybridEndpointWithChain("RSA", "SHA256withRSA", "ECDSA", "SHA256withRSA");
  g.addVertex(ep("legacy", "TCP", "internal"));
  const ranked = scoreGraph(g, cfg);
  for (let i = 1; i < ranked.length; i++) assert.ok(ranked[i - 1].combinedScore >= ranked[i].combinedScore);
});

function dependencyCycle(order: string[]) {
  const g = new CryptoGraph();
  const add: Record<string, () => void> = {
    a: () => g.addVertex<ServiceGroup>({ id: "a", kind: "ServiceGroup", label: "a", evidence: ev, criticality: 8 }),
    b: () => g.addVertex<ServiceGroup>({ id: "b", kind: "ServiceGroup", label: "b", evidence: ev, criticality: 8 }),
    db: () => g.addVertex(ep("db", "TLS", "external", { retentionYears: 10 })),
  };
  for (const k of order) add[k]();
  g.addEdge("db", "ENCRYPTED_WITH", addAlgorithm(g, { name: "X25519", usage: "key-exchange" }, ev));
  g.addEdge("a", "DEPENDS_ON", "db");
  g.addEdge("a", "DEPENDS_ON", "b");
  g.addEdge("b", "DEPENDS_ON", "a");
  return new Map(scoreGraph(g, cfg).map((r) => [r.id, r]));
}

test("dependency cycle: scores do not depend on vertex order", () => {
  const x = dependencyCycle(["a", "b", "db"]);
  const y = dependencyCycle(["b", "a", "db"]);
  for (const id of ["a", "b", "db"]) assert.equal(x.get(id)!.score, y.get(id)!.score, id);
  // b reaches db through a: it inherits the Shor exposure (before the fix it scored 2 when a came first).
  assert.equal(x.get("b")!.status, "VULNERABLE_SHOR");
  assert.equal(x.get("b")!.score, x.get("a")!.score);
});

test("uncertain Q-Day: probability and expected exposure years (paper worked example)", () => {
  const d = resolveRiskConfig({
    currentYear: 2026,
    qDayDistribution: [{ year: 2034, p: 0.2 }, { year: 2038, p: 0.4 }, { year: 2046, p: 0.3 }],
  });
  const r = moscaUncertain(21, d);
  assert.ok(Math.abs(r.probability - 0.9) < 1e-12);
  assert.ok(Math.abs(r.exposureYears - 6.5) < 1e-12);
  // Strict inequality: Q-Day exactly at c does not count.
  assert.ok(Math.abs(moscaUncertain(20, d).probability - 0.6) < 1e-12);
  assert.equal(moscaUncertain(2, d).probability, 0);
});

test("uncertain Q-Day: no distribution reduces to the point estimate hinge", () => {
  // 7 years to 2033.
  assert.deepEqual(moscaUncertain(8, cfg), { probability: 1, exposureYears: 1 });
  assert.deepEqual(moscaUncertain(7, cfg), { probability: 0, exposureYears: 0 });
});

test("uncertain Q-Day: invalid distributions are refused", () => {
  assert.throws(() => moscaUncertain(5, resolveRiskConfig({ currentYear: 2026, qDayDistribution: [{ year: 2030, p: 0.7 }, { year: 2031, p: 0.7 }] })));
  assert.throws(() => moscaUncertain(5, resolveRiskConfig({ currentYear: 2026, qDayDistribution: [{ year: 2030, p: -0.1 }] })));
});

test("uncertain Q-Day: score keeps the point estimate; normalizedScore is in [0,1]", () => {
  const withDist = resolveRiskConfig({
    qDayYear: 2033, currentYear: 2026, asOf: "2026-01-01T00:00:00Z",
    qDayDistribution: [{ year: 2030, p: 0.5 }, { year: 2040, p: 0.5 }],
  });
  const a = new Map(scoreGraph(propagationGraph("X25519"), cfg).map((x) => [x.id, x]));
  const b = new Map(scoreGraph(propagationGraph("X25519"), withDist).map((x) => [x.id, x]));
  for (const [id, r] of a) {
    assert.equal(b.get(id)!.score, r.score, id);
    assert.ok(b.get(id)!.normalizedScore >= 0 && b.get(id)!.normalizedScore <= 1, id);
  }
  // db: retention 10 + migration 3 = 13 years; Q-Day in 4 years (p .5) or 14 (p .5) -> probability 0.5.
  assert.equal(b.get("db")!.probability, 0.5);
  assert.equal(b.get("db")!.exposureYears, 0.5 * 9);
  assert.equal(b.get("db")!.normalizedScore, 0.9 * 1 * 1 * 0.5);
});
