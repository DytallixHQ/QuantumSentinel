import assert from "node:assert/strict";
import test from "node:test";
import { addAlgorithm } from "../../core/graph/builders.ts";
import { CryptoGraph } from "../../core/graph/graph.ts";
import type { NetworkEndpoint, ServiceGroup } from "../../core/graph/types.ts";
import { moscaScore, resolveRiskConfig, scoreGraph } from "./mosca.ts";

const cfg = resolveRiskConfig({ qDayYear: 2033, currentYear: 2026 });
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
