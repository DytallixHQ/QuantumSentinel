import assert from "node:assert/strict";
import test from "node:test";
import { addAlgorithm } from "../core/graph/builders.ts";
import { CryptoGraph } from "../core/graph/graph.ts";
import type { NetworkEndpoint, ServiceGroup } from "../core/graph/types.ts";
import { resolveRiskConfig, scoreGraph } from "../engine/risk/mosca.ts";
import { buildHtmlReport, recommend } from "./htmlReport.ts";

const cfg = resolveRiskConfig({ qDayYear: 2033, currentYear: 2026 });
const ev = [{ source: "config" as const, locator: "t", observedAt: "2026-11-09T00:00:00Z" }];
const ep = (id: string, protocol: NetworkEndpoint["protocol"], posture: NetworkEndpoint["posture"], extra: Partial<NetworkEndpoint> = {}): NetworkEndpoint =>
  ({ id, kind: "NetworkEndpoint", label: id, host: `${id}.test.invalid`, port: 443, protocol, posture, evidence: ev, ...extra });

function graph() {
  const g = new CryptoGraph();
  g.addVertex(ep("db", "TCP", "internal", { criticality: 9, retentionYears: 10 }));
  g.addVertex(ep("proxy", "TLS", "external", { protocolVersion: "TLS1.2" }));
  g.addVertex(ep("edge", "TLS", "external", { classicalFallback: true, supportedGroups: ["X25519MLKEM768", "x25519"] }));
  g.addVertex(ep("bastion", "SSH", "internal"));
  g.addVertex<ServiceGroup>({ id: "payments", kind: "ServiceGroup", label: "Payments <cluster>", evidence: ev, criticality: 10 });
  g.addEdge("proxy", "ENCRYPTED_WITH", addAlgorithm(g, { name: "X25519", usage: "key-exchange" }, ev));
  g.addEdge("proxy", "ENCRYPTED_WITH", addAlgorithm(g, { name: "3DES", usage: "encryption" }, ev));
  g.addEdge("edge", "ENCRYPTED_WITH", addAlgorithm(g, { name: "X25519MLKEM768", usage: "key-exchange" }, ev));
  g.addEdge("bastion", "ENCRYPTED_WITH", addAlgorithm(g, { name: "curve25519-sha256", usage: "key-exchange" }, ev));
  g.addEdge("db", "TERMINATES_AT", "proxy");
  g.addEdge("payments", "DEPENDS_ON", "db");
  return g;
}

test("recommendations follow observed crypto", () => {
  const g = graph();
  const r = new Map(scoreGraph(g, cfg).map((x) => [x.id, x]));
  const proxy = recommend(g, g.get("proxy")!, r.get("proxy")!).join(" ");
  assert.match(proxy, /classically broken.*3DES/);
  assert.match(proxy, /X25519MLKEM768/);
  assert.match(recommend(g, g.get("bastion")!, r.get("bastion")!).join(" "), /mlkem768x25519-sha256/);
  assert.match(recommend(g, g.get("edge")!, r.get("edge")!).join(" "), /Classical-only clients/);
});

test("HTML report: summary, ordered plan, escaping, no external resources", () => {
  const g = graph();
  const risk = scoreGraph(g, cfg);
  const html = buildHtmlReport(g, { risk, riskConfig: cfg, client: "Acme & Co", generatedAt: "2026-11-09T00:00:00Z", errors: [{ target: "vpn:1.2.3.4", error: "timed out" }] });
  assert.match(html, /^<!doctype html>/);
  assert.match(html, /Acme &amp; Co/);
  assert.match(html, /Payments &lt;cluster&gt;/);
  assert.ok(!html.includes("<cluster>"));
  assert.match(html, /Executive summary/);
  assert.match(html, /7 years away/);
  assert.ok(html.indexOf("Payments &lt;cluster&gt;") < html.indexOf(">bastion<"), "plan ordered by score");
  assert.match(html, /Coverage gaps[\s\S]*timed out/);
  assert.match(html, /X25519MLKEM768, x25519/);
  assert.match(html, /Endpoints with PQC<\/div><div class="n">1\/4/);
  assert.ok(!/<script|src=["']http|href=["']http/i.test(html), "self-contained, no scripts or remote assets; no call to action by default");
});

test("HTML report with nothing at risk", () => {
  const g = new CryptoGraph();
  g.addVertex(ep("edge", "TLS", "external"));
  g.addEdge("edge", "ENCRYPTED_WITH", addAlgorithm(g, { name: "X25519MLKEM768", usage: "key-exchange" }, ev));
  const html = buildHtmlReport(g, { risk: scoreGraph(g, cfg), riskConfig: cfg });
  assert.match(html, /No assessed asset exceeds the Mosca threshold/);
});

test("HTML report call to action is opt-in and https-only", () => {
  const g = graph();
  const risk = scoreGraph(g, cfg);
  const cta = { heading: "Assess <all>", text: "t", url: "https://www.dytallix.com/contact?topic=QuantumSentinel", label: "Discuss" };
  const html = buildHtmlReport(g, { risk, riskConfig: cfg, cta });
  assert.match(html, /<div class="cta"><h2>Assess &lt;all&gt;<\/h2>/);
  assert.match(html, /href="https:\/\/www\.dytallix\.com\/contact\?topic=QuantumSentinel"/);
  assert.ok(!/<script/i.test(html));
  assert.ok(!buildHtmlReport(g, { risk, riskConfig: cfg, cta: { ...cta, url: "javascript:alert(1)" } }).includes('class="cta"'));
});
