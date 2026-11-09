import assert from "node:assert/strict";
import test from "node:test";
import { canonicalPrimitiveId, CryptoGraph } from "./graph.ts";
import type { NetworkEndpoint, ServiceGroup } from "./types.ts";

const ev = (locator: string) => [{ source: "network" as const, locator, observedAt: "2026-01-01T00:00:00Z" }];
const ep = (id: string, extra: Partial<NetworkEndpoint> = {}): NetworkEndpoint => ({ id, kind: "NetworkEndpoint", label: id, host: id, port: 443, protocol: "TLS", posture: "external", evidence: ev(id), ...extra });

test("canonical primitive ID is deterministic and parameter-sensitive", () => {
  assert.equal(canonicalPrimitiveId("RSA", undefined, 2048, "signature"), canonicalPrimitiveId("rsa", undefined, 2048, "signature"));
  assert.notEqual(canonicalPrimitiveId("RSA", undefined, 2048, "signature"), canonicalPrimitiveId("RSA", undefined, 4096, "signature"));
  assert.notEqual(canonicalPrimitiveId("ECDSA", "P-256", undefined, "signature"), canonicalPrimitiveId("ECDSA", "P-384", undefined, "signature"));
  assert.match(canonicalPrimitiveId("AES-128", undefined, 128, "encryption"), /^[0-9a-f]{64}$/);
});

test("duplicate vertices merge evidence and keep the highest risk inputs", () => {
  const g = new CryptoGraph();
  g.addVertex(ep("a", { criticality: 3 }));
  g.addVertex({ ...ep("a", { criticality: 7 }), evidence: ev("a-other") });
  g.addVertex(ep("a"));
  const v = g.get("a")!;
  assert.equal(v.evidence.length, 2);
  assert.equal(v.criticality, 7);
  assert.equal(g.size.vertices, 1);
});

test("kind conflicts are rejected", () => {
  const g = new CryptoGraph();
  g.addVertex(ep("x"));
  assert.throws(() => g.addVertex<ServiceGroup>({ id: "x", kind: "ServiceGroup", label: "x", evidence: [] }), /kind conflict/);
});

test("edges are deduplicated and indexed in both directions", () => {
  const g = new CryptoGraph();
  ["a", "b", "c"].forEach((id) => g.addVertex(ep(id)));
  g.addEdge("a", "TERMINATES_AT", "b");
  g.addEdge("a", "TERMINATES_AT", "b");
  g.addEdge("b", "DEPENDS_ON", "c");
  assert.equal(g.size.edges, 2);
  assert.deepEqual(g.outgoing("a").map((e) => e.to), ["b"]);
  assert.deepEqual(g.incoming("b").map((e) => e.from), ["a"]);
  assert.deepEqual(g.incoming("c", ["TERMINATES_AT"]), []);
  assert.throws(() => g.addEdge("a", "SIGNS", "missing"), /target missing/);
});

test("reachable() traverses with direction, type filter, and cycles", () => {
  const g = new CryptoGraph();
  ["a", "b", "c", "d"].forEach((id) => g.addVertex(ep(id)));
  g.addEdge("a", "DEPENDS_ON", "b");
  g.addEdge("b", "DEPENDS_ON", "c");
  g.addEdge("c", "DEPENDS_ON", "a"); // cycle
  g.addEdge("c", "SIGNS", "d");
  assert.deepEqual(g.reachable("a"), ["b", "c", "d"]);
  assert.deepEqual(g.reachable("a", "out", ["DEPENDS_ON"]), ["b", "c"]);
  assert.deepEqual(g.reachable("d", "in"), ["c", "b", "a"]);
  assert.deepEqual(g.reachable("a", "out", undefined, 1), ["b"]);
});

test("merge and toJSON are order-independent", () => {
  const g1 = new CryptoGraph();
  const g2 = new CryptoGraph();
  g1.addVertex(ep("b"));
  g1.addVertex(ep("a"));
  g1.addEdge("a", "TERMINATES_AT", "b");
  g2.addVertex(ep("a"));
  g2.addVertex(ep("b"));
  g2.addEdge("a", "TERMINATES_AT", "b");
  assert.deepEqual(new CryptoGraph().merge(g1).toJSON(), new CryptoGraph().merge(g2).toJSON());
});
