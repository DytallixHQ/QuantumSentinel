import assert from "node:assert/strict";
import test from "node:test";

import { calculateWebsiteReadinessScore, isPublicAddress, normalizeDomainScanInput, scanDomain } from "./domainScanner.js";

test("domain scan validates bounded TLS targets", () => {
  assert.deepEqual(normalizeDomainScanInput("Example.COM", [443, 443, 993]), { hostname: "example.com", ports: [443, 993] });
  assert.throws(() => normalizeDomainScanInput("https://example.com", [443]), /hostname/);
  assert.throws(() => normalizeDomainScanInput("example.com", [22]), /allowlist/);
});

test("domain scan rejects private and reserved network addresses", async () => {
  assert.equal(isPublicAddress("93.184.216.34"), true);
  assert.equal(isPublicAddress("127.0.0.1"), false);
  assert.equal(isPublicAddress("10.0.0.1"), false);
  assert.equal(isPublicAddress("2001:db8::1"), false);
  assert.equal(isPublicAddress("64:ff9b::a9fe:a9fe"), false);
  assert.equal(isPublicAddress("64:ff9b:1::a9fe:a9fe"), false);
  assert.equal(isPublicAddress("2002:a9fe:a9fe::"), false);
  assert.equal(isPublicAddress("2001:0000:4136:e378:8000:63bf:3fff:fdd2"), false);
  assert.equal(isPublicAddress("fec0::1"), false);

  await assert.rejects(
    scanDomain("internal.example", {
      resolver: { resolve4: async () => ["127.0.0.1"], resolve6: async () => [] },
      probe: async () => assert.fail("private target must not be probed"),
    }),
    /private, reserved, or non-routable/,
  );
});

test("domain scan produces DNS, service, evidence, and score output", async () => {
  const report = await scanDomain("example.com", {
    ports: [443, 993],
    resolver: { resolve4: async () => ["93.184.216.34"], resolve6: async () => ["2606:2800:220:1:248:1893:25c8:1946"] },
    probe: async ({ host, port }) => port === 443 ? {
      status: "completed", target: { host, port }, result: {
        protocol: { name: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", perfectForwardSecrecy: true, keyExchange: { type: "ECDH", name: "X25519", size: 253 } },
        certificate: { algorithm: "RSA-2048", expiresAt: "2030-01-01" },
        classification: { quantumVulnerable: true, notes: [] },
      },
    } : { status: "failed", target: { host, port }, error: "connection refused" },
  });
  assert.equal(report.scan.kind, "domain");
  assert.deepEqual(report.scan.addresses.ipv4, ["93.184.216.34"]);
  assert.equal(report.scan.assessedAddress, "93.184.216.34");
  assert.match(report.limitations.join(" "), /assessed only 93\.184\.216\.34/);
  assert.equal(report.summary.servicesObserved, 1);
  assert.equal(report.summary.servicesFailed, 1);
  assert.equal(report.findings[0].classification, "shor-vulnerable-public-key");
  assert.equal(report.score.readinessScore, 40);
  assert.equal(report.score.rating, "Migration required");
  assert.equal(report.score.breakdown.length, 6);
  assert.deepEqual(report.score.breakdown.map((item) => item.score), [0, 0, 15, 10, 10, 5]);
  assert.ok(report.score.breakdown.every((item) => item.action));
  assert.match(report.score.breakdown.find((item) => item.id === "key-exchange").action, /X25519MLKEM768/);
  assert.match(report.score.breakdown.find((item) => item.id === "forward-secrecy").meaning, /does not stop future quantum decryption/);
  assert.match(report.interpretation.internalInference, /do not establish/);
});

test("website readiness score differentiates transport and certificate evidence", () => {
  const current = {
    status: "completed", target: { host: "strong.example", port: 443 }, result: {
      protocol: { name: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", perfectForwardSecrecy: true, keyExchange: { type: "ECDH", name: "X25519", size: 253 } },
      certificate: { algorithm: "EC-prime256v1", expiresAt: "2030-01-01" },
    },
  };
  const weaker = {
    status: "completed", target: { host: "weaker.example", port: 443 }, result: {
      protocol: { name: "TLSv1.2", cipher: "TLS_AES_128_GCM_SHA256", perfectForwardSecrecy: false, keyExchange: { type: "ECDH", name: "prime256v1", size: 256 } },
      certificate: { algorithm: "RSA-2048", expiresAt: "2026-09-20" },
    },
  };
  const now = Date.parse("2026-09-01T00:00:00Z");
  const currentScore = calculateWebsiteReadinessScore([current], { now });
  const weakerScore = calculateWebsiteReadinessScore([weaker], { now });
  assert.equal(currentScore.readinessScore, 40);
  assert.equal(weakerScore.readinessScore, 20);
  assert.equal(weakerScore.breakdown.find((item) => item.id === "certificate").status, "review");
  assert.ok(currentScore.readinessScore > weakerScore.readinessScore);

  const expired = structuredClone(current);
  expired.result.certificate.expiresAt = "2026-08-31T23:59:59Z";
  const expiredFactor = calculateWebsiteReadinessScore([expired], { now }).breakdown.find((item) => item.id === "certificate");
  assert.equal(expiredFactor.score, 0);
  assert.equal(expiredFactor.status, "risk");
  assert.equal(expiredFactor.observation, "Expired less than 1 day ago");
});

test("website readiness score reports unassessed when no service completes", () => {
  const score = calculateWebsiteReadinessScore([{ status: "failed", target: { host: "offline.example", port: 443 }, error: "timeout" }]);
  assert.equal(score.readinessScore, 0);
  assert.equal(score.rating, "Not assessed");
  assert.equal(score.assessmentStatus, "unassessed");
  assert.deepEqual(score.breakdown, []);
});

test("missing TLS 1.3 group is filled by the key-exchange probe on the validated address and scored", async () => {
  const seen = [];
  const report = await scanDomain("example.com", {
    resolver: { resolve4: async () => ["93.184.216.34"], resolve6: async () => [] },
    probe: async ({ host, port }) => ({
      id: "j", status: "completed", target: { mode: "tls", host, port },
      result: { protocol: { name: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", perfectForwardSecrecy: true, keyExchange: { type: null, name: null, size: null } }, certificate: { algorithm: "ECDSA P-256", expiresAt: "Jan 1 00:00:00 2099 GMT" }, classification: { quantumVulnerable: true, notes: [] } },
    }),
    keyExchangeProbe: async (host, port, serverName) => { seen.push([host, port, serverName]); return "X25519MLKEM768"; },
  });
  assert.deepEqual(seen, [["93.184.216.34", 443, "example.com"]]);
  assert.equal(report.services[0].result.protocol.keyExchange.name, "X25519MLKEM768");
  const kex = report.score.breakdown.find((item) => item.id === "key-exchange" || /key exchange/i.test(item.label ?? item.name ?? ""));
  assert.equal(kex.score, 30);
});
