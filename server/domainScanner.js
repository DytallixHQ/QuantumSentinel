import { resolve4, resolve6 } from "node:dns/promises";
import { BlockList, isIP } from "node:net";

import { createProbeJob } from "./probeEngine.js";

export const DEFAULT_DOMAIN_PORTS = [443];
export const ALLOWED_DOMAIN_PORTS = [443, 465, 636, 853, 993, 995, 8443, 9443];
const MAX_DOMAIN_PORTS = 8;

const NON_PUBLIC_IPV4_ADDRESSES = new BlockList();
const NON_PUBLIC_IPV6_ADDRESSES = new BlockList();
for (const [address, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
]) {
  NON_PUBLIC_IPV4_ADDRESSES.addSubnet(address, prefix, "ipv4");
}
for (const [address, prefix] of [
  ["::", 128],
  ["::1", 128],
  ["::ffff:0:0", 96],
  ["64:ff9b::", 96],
  ["64:ff9b:1::", 48],
  ["100::", 64],
  ["2001::", 32],
  ["2001:2::", 48],
  ["2001:10::", 28],
  ["2001:20::", 28],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["fc00::", 7],
  ["fe80::", 10],
  ["fec0::", 10],
  ["ff00::", 8],
]) {
  NON_PUBLIC_IPV6_ADDRESSES.addSubnet(address, prefix, "ipv6");
}

function validHostname(hostname) {
  if (typeof hostname !== "string" || hostname.length > 253 || hostname.includes("/") || hostname.includes(":")) return false;
  return hostname.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
}

export function normalizeDomainScanInput(domain, ports = DEFAULT_DOMAIN_PORTS) {
  const hostname = String(domain ?? "").trim().toLowerCase().replace(/\.$/, "");
  if (!validHostname(hostname)) throw new Error("domain must be a hostname without a URL, path, or port");
  if (!Array.isArray(ports) || ports.length === 0 || ports.length > MAX_DOMAIN_PORTS) throw new Error(`domain scans require 1-${MAX_DOMAIN_PORTS} ports`);
  const normalizedPorts = [...new Set(ports.map(Number))];
  if (normalizedPorts.some((port) => !ALLOWED_DOMAIN_PORTS.includes(port))) {
    throw new Error(`ports must be selected from the bounded TLS allowlist: ${ALLOWED_DOMAIN_PORTS.join(", ")}`);
  }
  return { hostname, ports: normalizedPorts };
}

async function resolveAddresses(hostname, resolver = { resolve4, resolve6 }) {
  const [ipv4, ipv6] = await Promise.all([
    resolver.resolve4(hostname).catch(() => []),
    resolver.resolve6(hostname).catch(() => []),
  ]);
  return { ipv4: [...new Set(ipv4)], ipv6: [...new Set(ipv6)] };
}

export function isPublicAddress(address) {
  const family = isIP(address);
  if (family === 4) return !NON_PUBLIC_IPV4_ADDRESSES.check(address, "ipv4");
  if (family === 6) {
    if (address.toLowerCase().startsWith("::ffff:")) return false;
    return !NON_PUBLIC_IPV6_ADDRESSES.check(address, "ipv6");
  }
  return false;
}

function requirePublicAddresses(addresses) {
  const resolved = [...addresses.ipv4, ...addresses.ipv6];
  if (resolved.length === 0) {
    const error = new Error("domain did not resolve to an IP address");
    error.statusCode = 502;
    throw error;
  }

  if (resolved.some((address) => !isPublicAddress(address))) {
    const error = new Error("domain resolves to a private, reserved, or non-routable address");
    error.statusCode = 400;
    throw error;
  }

  return resolved;
}

function findingFromJob(domain, job) {
  if (job.status !== "completed" || !job.result) return null;
  const classification = job.result.classification ?? {};
  const certificate = job.result.certificate ?? {};
  const expired = (classification.notes ?? []).some((note) => /expired/i.test(note));
  const vulnerable = classification.quantumVulnerable === true;
  const observedAlgorithm = certificate.algorithm ?? "Unknown";
  const informational = !vulnerable && !expired;
  return {
    id: `domain-${domain}-${job.target.port}`,
    ruleId: expired ? "expired-public-certificate" : vulnerable ? "tls-classical-public-key" : "tls-posture-observation",
    algorithm: observedAlgorithm,
    matchedValue: observedAlgorithm,
    classification: expired ? "deprecated" : vulnerable ? "shor-vulnerable-public-key" : /ML-KEM|ML-DSA|HYBRID/i.test(observedAlgorithm) ? "pqc" : "externally-observed",
    severity: expired ? "CRITICAL" : vulnerable ? "HIGH" : "INFO",
    confidence: "confirmed",
    usage: "public-tls-service",
    evidence: {
      file: `${domain}:${job.target.port}`,
      line: 0,
      excerpt: `${job.result.protocol?.name ?? "TLS"} · ${job.result.protocol?.cipher ?? "unknown cipher"} · ${observedAlgorithm}`,
      endpoint: domain,
      port: job.target.port,
      certificate,
      protocol: job.result.protocol,
    },
    rationale: expired
      ? "The publicly observed certificate is expired."
      : vulnerable
        ? "The publicly observed TLS certificate relies on Shor-vulnerable public-key cryptography."
        : "A public TLS service was observed; its complete certificate chain and server-side architecture may require additional verification.",
    recommendation: informational
      ? "Retain as external evidence and validate certificate-chain, negotiation, fallback, and origin-service boundaries"
      : "Plan a standards-aligned hybrid or post-quantum migration and validate the complete certificate and service trust path",
  };
}

function readinessRating(score) {
  if (score >= 80) return "Quantum-ready";
  if (score >= 50) return "Transition underway";
  return "Migration required";
}

function factor(id, label, score, maxScore, status, observation, meaning, action) {
  return { id, label, score, maxScore, status, observation, meaning, action };
}

function publicKeyFactor(certificate = {}) {
  const algorithm = String(certificate.algorithm ?? "Unknown");
  if (/ML-DSA|SLH-DSA|SPHINCS/i.test(algorithm)) {
    return factor("public-key", "Website identity", 30, 30, "strong", algorithm,
      "The certificate uses post-quantum or hybrid identity protection.",
      "Confirm that the complete certificate chain uses approved algorithms and cannot fall back to classical-only identity.");
  }
  if (/RSA|ECDSA|ECDH|EC-|X25519|X448|P-?256|P-?384|P-?521|prime256v1/i.test(algorithm)) {
    return factor("public-key", "Website identity", 0, 30, "risk", algorithm,
      "The certificate uses a classical identity key. A future quantum computer could recover that key and impersonate the website.",
      "Record the certificate provider, renewal owner, and migration trigger. Replace the identity algorithm when browsers and certificate authorities support an approved post-quantum option.");
  }
  return factor("public-key", "Website identity", 0, 30, "review", algorithm,
    "The scanner could not identify the certificate identity algorithm.",
    "Inspect the complete certificate chain and record each identity algorithm.");
}

function keyExchangeFactor(protocol = {}) {
  const key = protocol.keyExchange ?? {};
  const observation = [key.type, key.name, key.size ? `${key.size}-bit` : null].filter(Boolean).join(" · ") || "Not reported";
  if (/ML-?KEM|KYBER|HYBRID/i.test(observation)) {
    return factor("key-exchange", "Connection key exchange", 30, 30, "strong", observation,
      "This connection negotiated hybrid or post-quantum key exchange. This reduces the risk that a future quantum computer can decrypt recorded traffic.",
      "Keep hybrid key exchange enabled. Test fallback paths so supported clients cannot be forced to use classical key exchange.");
  }
  if (/ECDH|DH|X25519|X448|EC/i.test(observation)) {
    return factor("key-exchange", "Connection key exchange", 0, 30, "risk", observation,
      "This connection used classical key exchange. An attacker could record the traffic now and decrypt it after a future quantum break.",
      "Enable hybrid X25519MLKEM768 on the website edge. Verify that supported clients negotiate it.");
  }
  return factor("key-exchange", "Connection key exchange", 0, 30, "review", observation,
    "The scanner could not identify the negotiated key exchange.",
    "Test the website with an ML-KEM-capable TLS probe and confirm the negotiated key exchange.");
}

function protocolFactor(protocol = {}) {
  const name = String(protocol.name ?? "Unknown");
  if (/TLSv?1\.3/i.test(name)) return factor("protocol", "Connection protocol", 15, 15, "strong", name,
    "TLS 1.3 removes obsolete protocol features. Quantum protection still depends on the negotiated key exchange.",
    "Keep TLS 1.3 enabled. Pair it with hybrid ML-KEM key exchange.");
  if (/TLSv?1\.2/i.test(name)) return factor("protocol", "Connection protocol", 10, 15, "review", name,
    "TLS 1.2 permits legacy cipher suites and configurations that TLS 1.3 removes. It does not provide quantum protection by itself.",
    "Move supported clients to TLS 1.3. Test compatibility before you disable TLS 1.2.");
  return factor("protocol", "Connection protocol", 0, 15, "risk", name,
    "The connection used an obsolete protocol, or the scanner could not identify it.",
    "Require TLS 1.3 and confirm the change with a new scan.");
}

function forwardSecrecyFactor(protocol = {}) {
  if (protocol.perfectForwardSecrecy === true) {
    return factor("forward-secrecy", "Forward secrecy", 10, 10, "strong", "Present",
      "Forward secrecy limits damage if the server's long-term key is stolen. It does not stop future quantum decryption of recorded sessions that used classical key exchange.",
      "Keep forward secrecy enabled. Add hybrid ML-KEM to protect recorded traffic from future quantum decryption.");
  }
  return factor("forward-secrecy", "Forward secrecy", 0, 10, "risk", "Not observed",
    "A stolen server key could expose past traffic. This is separate from the quantum risk in classical key exchange.",
    "Enable TLS 1.3 or ECDHE now. Then add hybrid ML-KEM key exchange.");
}

function cipherFactor(protocol = {}) {
  const cipher = String(protocol.cipher ?? "Unknown");
  if (/AES[_-]?256|CHACHA20/i.test(cipher)) return factor("data-encryption", "Data encryption", 10, 10, "strong", cipher,
    "The cipher uses a 256-bit symmetric key. It retains more security margin against quantum search than a 128-bit key.",
    "Keep the 256-bit data cipher enabled. Complete the identity and key-exchange migration separately.");
  if (/AES[_-]?128/i.test(cipher)) return factor("data-encryption", "Data encryption", 8, 10, "review", cipher,
    "AES-128 protects data today but has less margin against future quantum search than AES-256.",
    "Use AES-256 where data must remain confidential for many years. Confirm performance and client support first.");
  if (/3DES|DES|RC4|NULL/i.test(cipher)) return factor("data-encryption", "Data encryption", 0, 10, "risk", cipher,
    "The data cipher is obsolete and creates a security risk today.",
    "Disable this cipher. Use AES-GCM or ChaCha20-Poly1305 through TLS 1.3.");
  return factor("data-encryption", "Data encryption", 0, 10, "review", cipher,
    "The scanner could not confirm the data cipher strength.",
    "Inspect the enabled cipher policy and confirm the negotiated cipher with a new scan.");
}

function certificateFactor(certificate = {}, now = Date.now()) {
  const expiresAt = certificate.expiresAt ?? null;
  const expiresTimestamp = Date.parse(expiresAt);
  if (!Number.isFinite(expiresTimestamp)) return factor("certificate", "Certificate expiration", 0, 5, "review", "Expiration unknown",
    "The scanner could not confirm the certificate expiration date.",
    "Inspect the certificate chain and confirm the expiration and renewal settings.");
  if (expiresTimestamp <= now) {
    const fullDaysExpired = Math.floor((now - expiresTimestamp) / 86_400_000);
    const observation = fullDaysExpired === 0 ? "Expired less than 1 day ago" : `Expired ${fullDaysExpired} days ago`;
    return factor("certificate", "Certificate expiration", 0, 5, "risk", observation,
      "The certificate is expired. Browsers cannot rely on it for current website identity.",
      "Replace the certificate now. Confirm automated renewal before you restore service.");
  }
  const daysRemaining = Math.ceil((expiresTimestamp - now) / 86_400_000);
  const observation = `${daysRemaining} days remaining`;
  if (daysRemaining <= 30) return factor("certificate", "Certificate expiration", 2, 5, "review", observation,
    "The certificate expires within 30 days.",
    "Renew the certificate before it expires. Confirm that automated renewal works.");
  return factor("certificate", "Certificate expiration", 5, 5, "strong", observation,
    "The certificate has not expired. This does not confirm its trust chain or make its identity algorithm quantum-safe.",
    "Keep automated renewal active. Plan the post-quantum identity migration separately.");
}

function serviceReadiness(job, now) {
  const protocol = job.result?.protocol ?? {};
  const certificate = job.result?.certificate ?? {};
  const breakdown = [
    publicKeyFactor(certificate),
    keyExchangeFactor(protocol),
    protocolFactor(protocol),
    forwardSecrecyFactor(protocol),
    cipherFactor(protocol),
    certificateFactor(certificate, now),
  ];
  const readinessScore = breakdown.reduce((sum, item) => sum + item.score, 0);
  return {
    endpoint: `${job.target.host}:${job.target.port}`,
    readinessScore,
    rating: readinessRating(readinessScore),
    breakdown,
  };
}

export function calculateWebsiteReadinessScore(jobs, { now = Date.now() } = {}) {
  const assessedServices = jobs
    .filter((job) => job.status === "completed" && job.result)
    .map((job) => serviceReadiness(job, now));
  if (!assessedServices.length) {
    return {
      readinessScore: 0,
      rating: "Not assessed",
      assessmentStatus: "unassessed",
      assessedEndpoint: null,
      breakdown: [],
      method: "No public TLS service completed, so QuantumSentinel could not calculate a website readiness score.",
    };
  }
  const lowest = assessedServices.toSorted((left, right) => left.readinessScore - right.readinessScore)[0];
  return {
    readinessScore: lowest.readinessScore,
    rating: lowest.rating,
    assessmentStatus: "assessed",
    assessedEndpoint: lowest.endpoint,
    breakdown: lowest.breakdown,
    serviceScores: assessedServices.map(({ endpoint, readinessScore, rating }) => ({ endpoint, readinessScore, rating })),
    method: "100 weighted points: website identity 30, connection key exchange 30, connection protocol 15, forward secrecy 10, data encryption 10, and certificate status 5. Multiple services use the lowest observed score.",
  };
}

/** Negotiated TLS group via the graph engine's raw ClientHello (needs Node >= 22.18); null otherwise. */
export async function defaultKeyExchangeProbe(host, port, serverName) {
  if (!process.features?.typescript) return null;
  const [{ probeTls }, { classifyTlsGroup }] = await Promise.all([
    import("../src/scanners/network/tls.ts"),
    import("../src/engine/classifier/registry.ts"),
  ]);
  const result = await probeTls(host, port, { serverName, maxVersion: "1.3", timeoutMs: 3_000 });
  return result.group === undefined ? null : classifyTlsGroup(result.group).label;
}

export async function scanDomain(domain, options = {}) {
  const { hostname, ports } = normalizeDomainScanInput(domain, options.ports);
  const startedAt = new Date().toISOString();
  const addresses = await resolveAddresses(hostname, options.resolver);
  const resolved = requirePublicAddresses(addresses);
  const connectHost = resolved[0];
  const jobs = [];
  for (const port of ports) {
    jobs.push(await (options.probe ?? createProbeJob)(
      { mode: "tls", host: hostname, port, timeoutMs: options.timeoutMs ?? 5_000 },
      { connectHost, servername: hostname },
    ));
  }
  // Node's TLS client does not report the TLS 1.3 group. Fill it in with one raw ClientHello probe
  // against the same validated address (no DNS re-resolution).
  const keyExchangeProbe = options.keyExchangeProbe ?? (options.probe ? null : defaultKeyExchangeProbe);
  if (keyExchangeProbe) {
    for (const job of jobs) {
      const protocol = job.status === "completed" ? job.result?.protocol : null;
      if (!protocol || protocol.keyExchange?.name) continue;
      const name = await keyExchangeProbe(connectHost, job.target.port, hostname).catch(() => null);
      if (name) protocol.keyExchange = { type: null, name, size: null, source: "clienthello-probe" };
    }
  }
  const findings = jobs.map((job) => findingFromJob(hostname, job)).filter(Boolean);
  const completedAt = new Date().toISOString();
  const failedServices = jobs.filter((job) => job.status !== "completed").map((job) => ({ port: job.target.port, error: job.error }));
  const byClassification = {};
  const bySeverity = {};
  for (const finding of findings) {
    byClassification[finding.classification] = (byClassification[finding.classification] ?? 0) + 1;
    bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;
  }
  return {
    schemaVersion: "1.0.0",
    scanner: { name: "QuantumSentinel External Q-Day Scanner", version: "0.1.0" },
    scan: { target: hostname, targetName: hostname, kind: "domain", startedAt, completedAt, filesScanned: jobs.length, bytesScanned: 0, ports, addresses, assessedAddress: connectHost, failedServices },
    score: calculateWebsiteReadinessScore(jobs),
    summary: { totalFindings: findings.length, servicesRequested: ports.length, servicesObserved: jobs.length - failedServices.length, servicesFailed: failedServices.length, byClassification, bySeverity },
    findings,
    services: jobs,
    interpretation: {
      externallyObserved: "The report describes cryptography negotiated or presented by the scanned public edge at the recorded time.",
      internalInference: "Public-edge findings do not establish the cryptographic posture of origin servers, internal networks, data stores, identity systems, software signing, backups, devices, or third parties.",
      warrantedNextStep: "Confirmed classical public-key exposure raises the priority of an authorized internal cryptographic inventory and migration assessment.",
    },
    limitations: [
      "This is an authorized, externally observable cryptographic posture assessment, not a penetration test or general web-vulnerability scan.",
      "A CDN, proxy, load balancer, or hosted edge may conceal the origin service and internal cryptographic dependencies.",
      `This scan assessed only ${connectHost}, the first public address returned by DNS. Other active edge addresses can have different configurations.`,
      "The scan does not prove support for every TLS group or fallback path and does not inspect application vulnerabilities.",
      "A high readiness score is not a certification, audit opinion, or guarantee of quantum safety.",
    ],
  };
}
