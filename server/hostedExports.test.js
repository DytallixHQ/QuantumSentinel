import assert from "node:assert/strict";
import test from "node:test";
import { attachExports, buildDomainExports, buildFindingsExports, exportsSupported } from "./hostedExports.js";

const skip = !exportsSupported() && "graph engine needs Node >= 22.18";
const NOW = "2026-11-09T00:00:00Z";

test("attachExports never fails or blocks the scan", async () => {
  const base = { ok: true };
  assert.deepEqual(await attachExports(base, async () => { throw new Error("boom"); }), base);
  assert.deepEqual(await attachExports(base, async () => null), base);
  assert.deepEqual(await attachExports(base, () => new Promise(() => {}), 20), base);
  assert.deepEqual(await attachExports(base, async () => ({ cbom: {} })), { ok: true, exports: { cbom: {} } });
});

test("domain exports probe the validated address with SNI and build a CBOM + report", { skip }, async () => {
  const calls = [];
  const probes = {
    tls: async (host, port, o) => {
      calls.push({ host, port, serverName: o.serverName, groups: o.groups });
      if (o.groups && !o.groups.includes(0x11ec)) return { version: "TLS1.3", cipherSuite: 0x1302, group: 0x001d, helloRetry: false, certificates: [], complete: true };
      return { version: "TLS1.3", cipherSuite: 0x1302, group: 0x11ec, helloRetry: false, certificates: [], complete: true };
    },
    tlsChain: async () => [],
    ssh: async () => { throw new Error("unused"); },
    ike: async () => { throw new Error("unused"); },
  };
  const report = { scan: { target: "example.com", assessedAddress: "93.184.216.34", ports: [443] } };
  const out = await buildDomainExports(report, { probes, now: NOW });
  assert.ok(calls.length >= 1 && calls.every((c) => c.host === "93.184.216.34" && c.serverName === "example.com"), "no DNS re-resolution");
  assert.equal(out.cbom.specVersion, "1.7");
  assert.ok(out.cbom.components.some((c) => c.name === "X25519MLKEM768"));
  assert.match(out.reportHtml, /Post-Quantum Readiness: example\.com/);
  assert.match(out.reportHtml, /X25519MLKEM768, x25519/);
});

test("findings exports exclude documentation and keep only metadata", { skip }, async () => {
  const report = { findings: [
    { matchedValue: "RS256", confidence: "high", usage: "signature-or-trust", evidence: { file: "auth.js", line: 3, excerpt: "secret" } },
    { matchedValue: "RSA", confidence: "documentation-reference", usage: "usage-unverified", evidence: { file: "README.md", line: 1 } },
  ] };
  const out = await buildFindingsExports(report, { repoUrl: "https://github.com/a/b.git", label: "a/b", now: NOW });
  const files = out.cbom.components.filter((c) => c.type === "file").map((c) => c.name);
  assert.deepEqual(files, ["auth.js"]);
  assert.ok(!JSON.stringify(out).includes("excerpt"));
  assert.match(out.reportHtml, /a\/b/);
});

test("returns null when the engine is unavailable or input is incomplete", async () => {
  assert.equal(await buildDomainExports({ scan: {} }), null);
  assert.equal(await buildFindingsExports({}), null);
});
