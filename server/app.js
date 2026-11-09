import http from "node:http";
import { BlockList, isIP } from "node:net";

import { createProbeJob, getProbeJob, listProbeJobs } from "./probeEngine.js";
import {
  createMonitorScheduler,
  createMonitorPolicy,
  getMonitorHealth,
  getMonitorPolicy,
  listMonitorRuns,
  listMonitorPolicies,
  runMonitorPolicy,
  updateMonitorPolicy,
} from "./probeScheduler.js";
import { buildReport, listReportTypes } from "./reporting.js";
import { scanDomain } from "./domainScanner.js";
import { attachExports, buildDomainExports, buildFindingsExports } from "./hostedExports.js";
import { persistRepositoryScan } from "./repositoryScanPersistence.js";
import { normalizePublicGitHubRepositorySource, runRepositoryScan } from "./repositoryScanRunner.js";
import { scanUploadedFile } from "./repositoryScanner.js";
import { createPublicNetworkSessionStore, readBearerToken } from "./publicNetworkSessions.js";
import { analyzeAsset, detectAssetDrift, findingsFromAnalysis } from "./riskEngine.js";

const ALLOWED_ORIGIN = String(process.env.QS_ALLOWED_ORIGIN ?? "*").trim() || "*";
const JSON_HEADERS = {
  "access-control-allow-origin": ALLOWED_ORIGIN,
  "access-control-allow-methods": "GET, POST, PATCH, OPTIONS",
  "access-control-allow-headers": "content-type, accept, authorization",
  "cache-control": "no-store",
  "content-type": "application/json; charset=utf-8",
  "x-content-type-options": "nosniff",
};

const TERMINAL_FINDING_STATUSES = new Set(["accepted_risk", "remediated", "closed"]);
const REPORT_EXPORT_ROLES = new Set(["auditor", "approver", "admin"]);
const APPROVER_ROLES = new Set(["approver", "admin"]);
const MAX_JSON_BODY_BYTES = 1_000_000;
const TRUSTED_PROXY_IPV4 = new BlockList();
const TRUSTED_PROXY_IPV6 = new BlockList();
for (const [address, prefix] of [["127.0.0.0", 8], ["10.0.0.0", 8], ["172.16.0.0", 12], ["192.168.0.0", 16]]) {
  TRUSTED_PROXY_IPV4.addSubnet(address, prefix, "ipv4");
}
for (const [address, prefix] of [["::1", 128], ["fc00::", 7]]) {
  TRUSTED_PROXY_IPV6.addSubnet(address, prefix, "ipv6");
}

const SSE_HEADERS = {
  "access-control-allow-origin": ALLOWED_ORIGIN,
  "cache-control": "no-cache",
  connection: "keep-alive",
  "content-type": "text/event-stream; charset=utf-8",
};

function average(items, field) {
  if (!items.length) return 0;
  return Math.floor(items.reduce((sum, item) => sum + Number(item[field] || 0), 0) / items.length);
}

function countBy(items, field, value) {
  return items.filter((item) => item[field] === value).length;
}

function alertSeverity(severity) {
  const value = String(severity ?? "INFO").toUpperCase();
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(value) ? value : "INFO";
}

function findingToAlert(finding) {
  return {
    id: `finding-alert-${finding.id}`,
    ts: finding.observedAt ?? finding.createdAt ?? finding.updatedAt ?? null,
    sev: alertSeverity(finding.severity),
    type: finding.type ?? "CRYPTO_FINDING",
    msg: finding.title ?? finding.description ?? "Cryptographic finding requires review",
    asset: finding.asset?.hostname ?? finding.assetName ?? finding.assetId ?? "portfolio",
    findingId: finding.id,
    source: finding.source ?? "finding",
  };
}

async function activeAlerts(datastore) {
  if (!datastore) return [];
  const findings = await datastore.listFindings();
  return findings
    .filter((finding) => !TERMINAL_FINDING_STATUSES.has(String(finding.status ?? "").toLowerCase()))
    .filter((finding) => alertSeverity(finding.severity) !== "INFO")
    .filter((finding) => ["tls-probe", "risk-engine", "risk-recompute"].includes(finding.source ?? ""))
    .map(findingToAlert)
    .toSorted((left, right) => String(right.ts ?? "").localeCompare(String(left.ts ?? "")));
}

export function deriveSummary({
  assets = [],
  alerts = [],
  compliance = [],
  trends = [],
} = {}) {
  const latest = trends.at(-1) ?? { risk: 0, safe: 0 };
  const first = trends[0] ?? { risk: 0, safe: 0 };

  return {
    assets: {
      total: assets.length,
      critical: countBy(assets, "prio", "CRITICAL"),
      high: countBy(assets, "prio", "HIGH"),
      medium: countBy(assets, "prio", "MEDIUM"),
      monitor: countBy(assets, "prio", "MONITOR"),
      shorCritical: countBy(assets, "cls", "SHOR-CRITICAL"),
      quantumSafe: countBy(assets, "cls", "QUANTUM-SAFE"),
      hybrid: countBy(assets, "cls", "HYBRID"),
      deprecated: countBy(assets, "cls", "DEPRECATED"),
      noPfs: assets.filter((asset) => !asset.pfs).length,
      averageRisk: average(assets, "risk"),
    },
    alerts: {
      total: alerts.length,
      critical: countBy(alerts, "sev", "CRITICAL"),
      high: countBy(alerts, "sev", "HIGH"),
      medium: countBy(alerts, "sev", "MEDIUM"),
      info: countBy(alerts, "sev", "INFO"),
    },
    compliance: {
      averagePct: average(compliance, "pct"),
      red: countBy(compliance, "status", "RED"),
      amber: countBy(compliance, "status", "AMBER"),
      green: countBy(compliance, "status", "GREEN"),
    },
    trends: {
      latestRisk: latest.risk,
      latestSafe: latest.safe,
      riskDelta: latest.risk - first.risk,
      safeDelta: latest.safe - first.safe,
    },
  };
}

function toCbomEntry(asset) {
  return {
    componentId: `asset-${asset.id}`,
    assetId: asset.id,
    hostname: asset.hostname,
    assetType: asset.type,
    networkSegment: asset.segment,
    cryptography: {
      algorithm: asset.algo,
      protocol: asset.proto,
      classification: asset.cls,
      perfectForwardSecrecy: asset.pfs,
      certificateExpiration: asset.cert_exp,
    },
    risk: {
      hndl: asset.hndl,
      tnfl: asset.tnfl,
      score: asset.risk,
      priority: asset.prio,
    },
    migration: {
      target: asset.migration,
      complexity: asset.complexity,
      hardwareRefreshRequired: asset.migration === "REQUIRES HW REFRESH",
    },
  };
}

export function buildCbom(assets = []) {
  const data = assets.map(toCbomEntry);
  const migrationTargets = {};

  for (const asset of assets) {
    migrationTargets[asset.migration] = (migrationTargets[asset.migration] ?? 0) + 1;
  }

  return {
    data,
    count: data.length,
    summary: {
      totalComponents: data.length,
      vulnerableComponents: assets.filter((asset) => !["QUANTUM-SAFE", "QUANTUM-RESISTANT", "PQC", "HYBRID"].includes(asset.cls)).length,
      pfsEnabled: assets.filter((asset) => asset.pfs).length,
      requiresHardwareRefresh: assets.filter((asset) => asset.migration === "REQUIRES HW REFRESH").length,
      migrationTargets,
    },
  };
}

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, JSON_HEADERS);
  response.end(JSON.stringify(payload));
}

function sendCollection(response, data) {
  sendJson(response, 200, { data, count: data.length });
}

function sendMaybeFound(response, data, message) {
  if (!data) {
    sendJson(response, 404, { error: message });
    return false;
  }

  sendJson(response, 200, { data });
  return true;
}

async function createAuditEvent(datastore, event) {
  if (!datastore) return null;
  return datastore.createAuditEvent(event);
}

function jsonError(message, statusCode = 400) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function headerValue(request, name) {
  if (typeof request.headers?.get === "function") {
    return request.headers.get(name) ?? request.headers.get(name.toLowerCase());
  }
  return request.headers?.[name.toLowerCase()] ?? request.headers?.[name];
}

function getRequestRole(request) {
  return String(headerValue(request, "x-qs-role") ?? "analyst").trim().toLowerCase() || "analyst";
}

function getRequestActor(request, payload = {}) {
  return String(
    payload.actor
    ?? payload.author
    ?? payload.createdBy
    ?? payload.requestedBy
    ?? headerValue(request, "x-qs-actor")
    ?? "system",
  );
}

function forbidden(message) {
  return jsonError(message, 403);
}

function hasRole(request, roles) {
  return roles.has(getRequestRole(request));
}

async function requireApprovedAction(datastore, approvalId, {
  entityType,
  entityId,
  action,
  alternateActions = [],
  message,
}) {
  if (!approvalId || !datastore) {
    throw forbidden(message);
  }

  const approval = await datastore.getApprovalRequest(approvalId);
  const allowedActions = new Set([action, ...alternateActions]);

  if (
    !approval
    || approval.status !== "approved"
    || approval.entityType !== entityType
    || String(approval.entityId) !== String(entityId)
    || !allowedActions.has(approval.action)
  ) {
    throw forbidden(message);
  }

  return approval;
}

function readJsonBody(request) {
  const rawContentLength = headerValue(request, "content-length");
  if (rawContentLength != null) {
    const contentLength = Number(rawContentLength);
    if (!Number.isSafeInteger(contentLength) || contentLength < 0) {
      return Promise.reject(jsonError("Invalid Content-Length header"));
    }
    if (contentLength > MAX_JSON_BODY_BYTES) {
      return Promise.reject(jsonError("Request body too large", 413));
    }
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    let body = "";
    const settle = (fn, value) => {
      if (settled) return;
      settled = true;
      fn(value);
    };

    request.setEncoding("utf8");

    request.on("data", (chunk) => {
      if (settled) return;

      body += chunk;
      if (body.length > MAX_JSON_BODY_BYTES) {
        settle(reject, jsonError("Request body too large", 413));
        body = "";
      }
    });

    request.on("end", () => {
      if (!body.trim()) {
        settle(resolve, {});
        return;
      }

      try {
        settle(resolve, JSON.parse(body));
      } catch {
        settle(reject, jsonError("Invalid JSON body"));
      }
    });

    request.on("error", (error) => settle(reject, error));
  });
}

function isTrustedProxyPeer(address) {
  if (isIP(address) === 4) return TRUSTED_PROXY_IPV4.check(address, "ipv4");
  if (isIP(address) === 6) {
    if (address.toLowerCase().startsWith("::ffff:")) {
      const mappedAddress = address.slice("::ffff:".length);
      return isIP(mappedAddress) === 4 && TRUSTED_PROXY_IPV4.check(mappedAddress, "ipv4");
    }
    return TRUSTED_PROXY_IPV6.check(address, "ipv6");
  }
  return false;
}

export function publicClientId(request) {
  const remoteAddress = request.socket?.remoteAddress ?? "unknown";
  if (isTrustedProxyPeer(remoteAddress)) {
    const forwarded = String(headerValue(request, "x-real-ip") ?? "").trim();
    if (isIP(forwarded)) return forwarded;
  }
  return remoteAddress;
}

function createRateLimiter({ limit, windowMs }) {
  const entries = new Map();
  let nextCleanupAt = 0;
  return (key) => {
    const now = Date.now();
    if (now >= nextCleanupAt) {
      for (const [entryKey, entry] of entries) {
        if (entry.expiresAt <= now) entries.delete(entryKey);
      }
      nextCleanupAt = now + windowMs;
    }
    const current = entries.get(key);
    if (!current || current.expiresAt <= now) {
      entries.set(key, { count: 1, expiresAt: now + windowMs });
      return true;
    }
    if (current.count >= limit) return false;
    current.count += 1;
    return true;
  };
}

function handleEvents(request, response) {
  response.writeHead(200, SSE_HEADERS);
  response.write(`event: summary\ndata: ${JSON.stringify(deriveSummary({ assets: [], alerts: [], compliance: [], trends: [] }))}\n\n`);

  const interval = setInterval(() => {
    response.write(`event: heartbeat\ndata: ${JSON.stringify({ at: new Date().toISOString() })}\n\n`);
  }, 15_000);

  request.on("close", () => {
    clearInterval(interval);
  });
}

function probePersistenceReason(job) {
  if (job.mode === "tls") return "tls-observation";
  if (job.mode === "discovery") return "discovery-observation";
  return job.status ?? "observation";
}

function probeSeverity(classification = {}) {
  const priority = String(classification.priority ?? "").toUpperCase();
  if (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(priority)) return priority;
  return classification.quantumVulnerable ? "HIGH" : "INFO";
}

function probeFindingType(classification = {}) {
  if (classification.label === "DEPRECATED") return "CRYPTO_DEPRECATED";
  if (classification.quantumVulnerable) return "HNDL";
  return "CRYPTO_OBSERVATION";
}

function stableKeyPart(value) {
  return String(value ?? "unknown").trim().toLowerCase().replace(/[^a-z0-9_.:-]+/g, "-");
}

function tlsDedupeKey(job, classification = {}) {
  return [
    "tls",
    job.target?.assetId ?? "portfolio",
    job.target?.host ?? "endpoint",
    job.target?.port ?? "443",
    job.result?.certificate?.fingerprint256 ?? job.result?.certificate?.fingerprint ?? "no-fingerprint",
    classification.label ?? "UNKNOWN",
  ].map(stableKeyPart).join(":");
}

function riskDedupeKey(assetId, finding) {
  return [
    "risk",
    assetId ?? "portfolio",
    finding.type ?? "GENERAL",
    finding.title ?? finding.description ?? "finding",
  ].map(stableKeyPart).join(":");
}

function mergeUnique(left = [], right = [], keyFn = (value) => JSON.stringify(value)) {
  const seen = new Set();
  const merged = [];
  for (const item of [...left, ...right]) {
    const key = keyFn(item);
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push(item);
  }
  return merged;
}

function recurrenceForNewFinding(job, observedAt) {
  return {
    count: 1,
    firstObservedAt: observedAt,
    lastObservedAt: observedAt,
    probeIds: job?.id ? [job.id] : [],
    fingerprints: job?.result?.certificate?.fingerprint256 ? [job.result.certificate.fingerprint256] : [],
  };
}

function recurrencePatch(existing, incoming, job, observedAt) {
  const previous = existing.evidence?.recurrence ?? {};
  const incomingRecurrence = incoming.evidence?.recurrence ?? {};
  return {
    count: Number(previous.count ?? 1) + 1,
    firstObservedAt: previous.firstObservedAt ?? incomingRecurrence.firstObservedAt ?? existing.observedAt ?? observedAt,
    lastObservedAt: observedAt,
    probeIds: mergeUnique(previous.probeIds, [job?.id].filter(Boolean), String),
    fingerprints: mergeUnique(
      previous.fingerprints,
      [job?.result?.certificate?.fingerprint256].filter(Boolean),
      String,
    ),
  };
}

function reobservedStatus(existing) {
  if (existing.status === "remediated" || existing.status === "closed") return "open";
  return existing.status;
}

async function createTlsProbeEvidenceEvent(datastore, job) {
  if (!datastore || job.mode !== "tls" || job.status !== "completed" || !job.result) return null;

  return datastore.createAuditEvent({
    action: "probe.tls_evidence_archived",
    entityType: "probe-job",
    entityId: job.id,
    summary: `${job.target?.host ?? "TLS endpoint"} TLS probe evidence archived`,
    after: {
      probeId: job.id,
      target: job.target ?? null,
      protocol: job.result.protocol ?? null,
      certificate: job.result.certificate ?? null,
      classification: job.result.classification ?? null,
    },
    metadata: {
      evidenceKind: "tls-probe",
      mode: job.mode,
      status: job.status,
      assetId: job.target?.assetId ?? null,
      host: job.target?.host ?? null,
      port: job.target?.port ?? null,
      fingerprint256: job.result.certificate?.fingerprint256 ?? null,
      classification: job.result.classification?.label ?? null,
    },
    correlationId: job.id,
  });
}

function directProbeFindings(job, assetId, evidenceEvent = null) {
  if (!job.result || job.mode !== "tls") return [];
  const classification = job.result.classification ?? {};
  const findings = Array.isArray(job.result.findings) ? job.result.findings : [];
  const observedAt = job.result.observedAt ?? job.completedAt;
  const dedupeKey = tlsDedupeKey(job, classification);

  return [{
    assetId,
    severity: probeSeverity(classification),
    type: probeFindingType(classification),
    title: `${job.target?.host ?? "TLS endpoint"} cryptographic posture requires review`,
    description: findings.join("; ") || "TLS probe observed cryptographic posture that requires review.",
    evidence: {
      probeId: job.id,
      target: job.target,
      protocol: job.result.protocol ?? null,
      certificate: job.result.certificate ?? null,
      classification,
      dedupeKey,
      recurrence: recurrenceForNewFinding(job, observedAt),
      evidenceRefs: [
        { kind: "probe-job", id: job.id, label: `${job.target?.host ?? "TLS endpoint"} TLS probe` },
        ...(evidenceEvent ? [{
          kind: "audit-event",
          id: evidenceEvent.id,
          label: "TLS probe evidence archive event",
          hash: evidenceEvent.hash,
        }] : []),
      ],
    },
    source: "tls-probe",
    observedAt,
  }];
}

async function upsertFindingObservation(datastore, finding, job, {
  direct = false,
} = {}) {
  const dedupeKey = finding.evidence?.dedupeKey;
  if (!dedupeKey) {
    const saved = await datastore.createFinding(finding);
    return { saved, created: true };
  }

  const existing = (await datastore.listFindings({ source: finding.source }))
    .find((candidate) => candidate.evidence?.dedupeKey === dedupeKey);

  if (!existing) {
    const saved = await datastore.createFinding(finding);
    return { saved, created: true };
  }

  const observedAt = finding.observedAt ?? job?.result?.observedAt ?? job?.completedAt;
  const recurrence = recurrencePatch(existing, finding, job, observedAt);
  const evidenceRefs = mergeUnique(
    existing.evidence?.evidenceRefs,
    finding.evidence?.evidenceRefs,
    (ref) => `${ref.kind ?? "ref"}:${ref.id ?? ref.hash ?? JSON.stringify(ref)}`,
  );

  const saved = await datastore.updateFinding(existing.id, {
    severity: finding.severity,
    type: finding.type,
    title: finding.title,
    description: finding.description,
    source: finding.source,
    observedAt,
    status: reobservedStatus(existing),
    evidence: {
      ...existing.evidence,
      ...finding.evidence,
      evidenceRefs,
      recurrence,
    },
    note: direct
      ? `Reobserved by TLS probe ${job?.id ?? "unknown"}; recurrence count ${recurrence.count}.`
      : `Reobserved by risk analysis for probe ${job?.id ?? "unknown"}; recurrence count ${recurrence.count}.`,
    author: "system",
  });

  return { saved, created: false };
}

export async function persistProbeResult(datastore, job, { recordJob = true } = {}) {
  if (!datastore) {
    return {
      probeJobId: job?.id ?? null,
      evidenceCount: 0,
      evidenceRefs: [],
      findingCount: 0,
      findingIds: [],
      directFindingIds: [],
      riskFindingIds: [],
    };
  }

  if (recordJob) await datastore.createProbeJob(job);
  const persistence = {
    probeJobId: job.id,
    evidenceCount: 0,
    evidenceRefs: [],
    findingCount: 0,
    findingIds: [],
    directFindingIds: [],
    riskFindingIds: [],
  };

  if (job.status === "completed") {
    if (["discovery", "device"].includes(job.mode)) {
      const completedObservations = (job.result?.observations || []).filter(
        (observation) => observation.status === "completed" && observation.reachability?.tcp,
      );
      for (const observation of completedObservations) {
        const nested = await persistProbeResult(datastore, {
          id: `${job.id}:${observation.host}:${observation.port}`,
          mode: "tls",
          status: "completed",
          createdAt: job.createdAt,
          updatedAt: job.updatedAt,
          completedAt: job.completedAt,
          target: { host: observation.host, port: observation.port },
          result: observation,
          error: null,
        }, { recordJob: false });
        persistence.evidenceCount += nested.evidenceCount;
        persistence.evidenceRefs.push(...nested.evidenceRefs);
        persistence.findingIds.push(...nested.findingIds);
        persistence.directFindingIds.push(...nested.directFindingIds);
        persistence.riskFindingIds.push(...nested.riskFindingIds);
      }
      persistence.evidenceRefs = mergeUnique(
        persistence.evidenceRefs,
        [],
        (ref) => `${ref.kind}:${ref.id ?? ref.hash}`,
      );
      persistence.findingIds = mergeUnique(persistence.findingIds, [], String);
      persistence.directFindingIds = mergeUnique(persistence.directFindingIds, [], String);
      persistence.riskFindingIds = mergeUnique(persistence.riskFindingIds, [], String);
      persistence.findingCount = persistence.findingIds.length;
      return persistence;
    }

    let assetForAnalysis = job;
    let assetId = job.target?.assetId ?? null;

    if (assetId == null && job.mode === "tls" && job.target?.host) {
      const assets = await datastore.listAssets();
      const existing = assets.find((asset) => asset.hostname === job.target.host);
      assetId = existing?.id ?? Math.max(0, ...assets.map((asset) => Number(asset.id) || 0)) + 1;
    }

    if (assetId != null) {
      assetForAnalysis = await datastore.upsertAssetFromProbe({
        ...job,
        id: assetId,
        target: { ...job.target, assetId },
      }, {
        reason: probePersistenceReason(job),
      });
    }

    const evidenceEvent = await createTlsProbeEvidenceEvent(datastore, job);
    if (evidenceEvent) {
      persistence.evidenceCount += 1;
      persistence.evidenceRefs.push({
        kind: "audit-event",
        id: evidenceEvent.id,
        label: "TLS probe evidence archive event",
        hash: evidenceEvent.hash,
      });
    }

    for (const finding of directProbeFindings(job, assetId, evidenceEvent)) {
      const { saved } = await upsertFindingObservation(datastore, finding, job, { direct: true });
      persistence.findingIds.push(saved.id);
      persistence.directFindingIds.push(saved.id);
    }

    const analysis = analyzeAsset(assetForAnalysis);
    if (assetId != null) {
      assetForAnalysis = await datastore.upsertAsset({
        ...assetForAnalysis,
        hndl: analysis.scores.hndl,
        tnfl: analysis.scores.tnfl,
        risk: analysis.scores.risk,
        prio: analysis.priority,
        migration: analysis.remediation?.target ?? assetForAnalysis.migration,
      }, {
        source: "risk-engine",
        reason: "probe-risk-analysis",
        observedAt: job.result?.observedAt ?? job.completedAt,
      });
    }
    for (const finding of findingsFromAnalysis(assetForAnalysis, analysis)) {
      const observedAt = job.result?.observedAt ?? job.completedAt;
      const { saved } = await upsertFindingObservation(datastore, {
        evidence: {
          dedupeKey: riskDedupeKey(assetId, finding),
          recurrence: recurrenceForNewFinding(job, observedAt),
          evidenceRefs: [
            { kind: "probe-job", id: job.id, label: `${job.target?.host ?? "Probe"} risk analysis source` },
          ],
        },
        assetId,
        ...finding,
        source: "risk-engine",
        observedAt,
      }, job);
      persistence.findingIds.push(saved.id);
      persistence.riskFindingIds.push(saved.id);
    }
  }

  persistence.findingCount = persistence.findingIds.length;
  return persistence;
}

export async function backfillProbeAssets(datastore) {
  if (!datastore) return { promoted: 0 };
  const [jobs, assets] = await Promise.all([datastore.listProbeJobs(), datastore.listAssets()]);
  const knownHosts = new Set(assets.map((asset) => asset.hostname).filter(Boolean));
  let promoted = 0;

  for (const job of jobs) {
    if (job.status !== "completed" || !["discovery", "device"].includes(job.mode)) continue;
    for (const observation of job.result?.observations || []) {
      if (observation.status !== "completed" || !observation.reachability?.tcp || knownHosts.has(observation.host)) continue;
      await persistProbeResult(datastore, {
        id: `${job.id}:${observation.host}:${observation.port}`,
        mode: "tls",
        status: "completed",
        createdAt: job.createdAt,
        updatedAt: job.updatedAt,
        completedAt: job.completedAt,
        target: { host: observation.host, port: observation.port },
        result: observation,
        error: null,
      }, { recordJob: false });
      knownHosts.add(observation.host);
      promoted += 1;
    }
  }
  return { promoted };
}

async function analyzeAssetById(datastore, id) {
  const asset = datastore
    ? await datastore.getAsset(id)
    : null;

  if (!asset) return null;

  const history = datastore ? await datastore.listAssetHistory(id) : [];
  const findings = datastore ? await datastore.listFindings({ assetId: id }) : [];
  const drift = detectAssetDrift(history);
  const analysis = analyzeAsset(asset);

  return {
    asset,
    analysis,
    drift,
    findings,
  };
}

async function analyzePortfolioDrift(datastore) {
  const assets = datastore ? await datastore.listAssets() : [];
  const results = [];

  for (const asset of assets) {
    const history = datastore ? await datastore.listAssetHistory(asset.id) : [];
    const drift = detectAssetDrift(history);
    if (drift.driftDetected) {
      results.push({
        asset: {
          id: asset.id,
          hostname: asset.hostname,
          ip: asset.ip,
          type: asset.type,
          segment: asset.segment,
        },
        ...drift,
      });
    }
  }

  return {
    driftDetected: results.length > 0,
    count: results.length,
    assets: results,
  };
}

async function recomputeRisk(datastore, { assetId = null, persist = true } = {}) {
  const assets = assetId == null
    ? (datastore ? await datastore.listAssets() : [])
    : [datastore ? await datastore.getAsset(assetId) : null].filter(Boolean);

  if (assetId != null && assets.length === 0) return null;

  const analyses = [];
  const createdFindings = [];

  for (const asset of assets) {
    const analysis = analyzeAsset(asset);
    const findings = findingsFromAnalysis(asset, analysis);
    analyses.push({ asset, analysis, findings });

    if (datastore && persist) {
      for (const finding of findings) {
        createdFindings.push(await datastore.createFinding({
          assetId: asset.id,
          ...finding,
          source: "risk-recompute",
        }));
      }
    }
  }

  return {
    analyses,
    createdFindings,
  };
}

export function createApiServer({
  datastore = null,
  scheduler = null,
  schedulerOptions = {},
  publicDomainScanner = scanDomain,
  publicScanLimitPerMinute = Number.parseInt(process.env.QS_PUBLIC_SCAN_LIMIT_PER_MINUTE ?? "5", 10),
  publicRepositoryScanner = runRepositoryScan,
  publicRepositoryScanLimitPerMinute = Number.parseInt(process.env.QS_PUBLIC_REPOSITORY_SCAN_LIMIT_PER_MINUTE ?? "2", 10),
  publicRepositoryScanConcurrency = Number.parseInt(process.env.QS_PUBLIC_REPOSITORY_SCAN_CONCURRENCY ?? "1", 10),
  publicFileScanner = scanUploadedFile,
  publicFileScanLimitPerMinute = Number.parseInt(process.env.QS_PUBLIC_FILE_SCAN_LIMIT_PER_MINUTE ?? "5", 10),
  publicNetworkSessionLimitPerMinute = Number.parseInt(process.env.QS_PUBLIC_NETWORK_SESSION_LIMIT_PER_MINUTE ?? "2", 10),
  publicNetworkConnectLimitPerMinute = Number.parseInt(process.env.QS_PUBLIC_NETWORK_CONNECT_LIMIT_PER_MINUTE ?? "10", 10),
  publicNetworkResultLimitPerMinute = Number.parseInt(process.env.QS_PUBLIC_NETWORK_RESULT_LIMIT_PER_MINUTE ?? "10", 10),
  publicNetworkSessions = createPublicNetworkSessionStore(),
  publicExports = process.env.QS_PUBLIC_EXPORTS === "0"
    ? { domain: async () => null, findings: async () => null }
    : { domain: buildDomainExports, findings: buildFindingsExports },
} = {}) {
  const schedulerRuntime = scheduler ?? createMonitorScheduler({
    datastore,
    persistProbeResult,
    ...schedulerOptions,
  });
  const allowPublicScan = createRateLimiter({
    limit: Number.isInteger(publicScanLimitPerMinute) && publicScanLimitPerMinute > 0 ? publicScanLimitPerMinute : 5,
    windowMs: 60_000,
  });
  const allowPublicRepositoryScan = createRateLimiter({
    limit: Number.isInteger(publicRepositoryScanLimitPerMinute) && publicRepositoryScanLimitPerMinute > 0 ? publicRepositoryScanLimitPerMinute : 2,
    windowMs: 60_000,
  });
  const allowPublicFileScan = createRateLimiter({
    limit: Number.isInteger(publicFileScanLimitPerMinute) && publicFileScanLimitPerMinute > 0 ? publicFileScanLimitPerMinute : 5,
    windowMs: 60_000,
  });
  const allowPublicNetworkSession = createRateLimiter({
    limit: Number.isInteger(publicNetworkSessionLimitPerMinute) && publicNetworkSessionLimitPerMinute > 0 ? publicNetworkSessionLimitPerMinute : 2,
    windowMs: 60_000,
  });
  const allowPublicNetworkConnect = createRateLimiter({
    limit: Number.isInteger(publicNetworkConnectLimitPerMinute) && publicNetworkConnectLimitPerMinute > 0 ? publicNetworkConnectLimitPerMinute : 10,
    windowMs: 60_000,
  });
  const allowPublicNetworkResult = createRateLimiter({
    limit: Number.isInteger(publicNetworkResultLimitPerMinute) && publicNetworkResultLimitPerMinute > 0 ? publicNetworkResultLimitPerMinute : 10,
    windowMs: 60_000,
  });
  const publicRepositoryConcurrency = Number.isInteger(publicRepositoryScanConcurrency) && publicRepositoryScanConcurrency > 0
    ? publicRepositoryScanConcurrency
    : 1;
  let publicRepositoryScansInFlight = 0;

  const server = http.createServer(async (request, response) => {
    if (request.method === "OPTIONS") {
      response.writeHead(204, JSON_HEADERS);
      response.end();
      return;
    }

    const url = new URL(request.url, "http://127.0.0.1");
    const publicNetworkMatch = /^\/api\/public\/network-scans\/([0-9a-f-]+)(\/results)?$/.exec(url.pathname);

    try {
      if (request.method === "POST" && url.pathname === "/api/public/file-scans") {
        const payload = await readJsonBody(request);
        if (payload.authorized !== true) {
          sendJson(response, 400, { error: "authorized must be true before an uploaded file can be scanned" });
          return;
        }
        if (!allowPublicFileScan(publicClientId(request))) {
          sendJson(response, 429, { error: "Public file scan rate limit exceeded. Try again later." });
          return;
        }
        const report = await publicFileScanner({ filename: payload.filename, content: payload.content }, {
          maxFileBytes: 512 * 1024,
          maxFindings: 250,
          maxLines: 50_000,
        });
        sendJson(response, 200, { data: await attachExports(report, () => publicExports.findings(report, { label: String(payload.filename ?? "file").slice(0, 120) })) });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/public/network-scans") {
        const payload = await readJsonBody(request);
        if (payload.authorized !== true) {
          sendJson(response, 400, { error: "authorized must be true before a network scan session can be created" });
          return;
        }
        if (!allowPublicNetworkSession(publicClientId(request))) {
          sendJson(response, 429, { error: "Public network session rate limit exceeded. Try again later." });
          return;
        }
        sendJson(response, 201, {
          data: publicNetworkSessions.create(payload, { clientKey: publicClientId(request) }),
        });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/public/network-scans/connect") {
        const payload = await readJsonBody(request);
        if (!allowPublicNetworkConnect(publicClientId(request))) {
          sendJson(response, 429, { error: "Network connector rate limit exceeded. Try again later." });
          return;
        }
        sendJson(response, 200, { data: publicNetworkSessions.connect(payload.deviceCode) });
        return;
      }

      if (request.method === "GET" && publicNetworkMatch && !publicNetworkMatch[2]) {
        sendJson(response, 200, { data: publicNetworkSessions.get(publicNetworkMatch[1], readBearerToken(request)) });
        return;
      }

      if (request.method === "POST" && publicNetworkMatch?.[2] === "/results") {
        if (!allowPublicNetworkResult(publicClientId(request))) {
          sendJson(response, 429, { error: "Network scan result rate limit exceeded. Try again later." });
          return;
        }
        const payload = await readJsonBody(request);
        const job = payload.job ?? payload.result ?? payload.data;
        sendJson(response, 200, { data: publicNetworkSessions.submit(publicNetworkMatch[1], readBearerToken(request), job) });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/public/domain-scans") {
        const payload = await readJsonBody(request);
        if (payload.authorized !== true) {
          sendJson(response, 400, { error: "authorized must be true before a public scan can run" });
          return;
        }
        if (!allowPublicScan(publicClientId(request))) {
          sendJson(response, 429, { error: "Public scan rate limit exceeded. Try again later." });
          return;
        }

        const report = await publicDomainScanner(payload.domain, {
          ports: [443],
          timeoutMs: 5_000,
        });
        sendJson(response, 200, { data: await attachExports(report, () => publicExports.domain(report)) });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/public/repository-scans") {
        const payload = await readJsonBody(request);
        if (payload.authorized !== true) {
          sendJson(response, 400, { error: "authorized must be true before a public repository scan can run" });
          return;
        }
        const source = normalizePublicGitHubRepositorySource(payload.repository ?? payload.url);
        if (!allowPublicRepositoryScan(publicClientId(request))) {
          sendJson(response, 429, { error: "Public repository scan rate limit exceeded. Try again later." });
          return;
        }
        if (publicRepositoryScansInFlight >= publicRepositoryConcurrency) {
          sendJson(response, 503, { error: "The public repository scanner is busy. Try again shortly." });
          return;
        }

        publicRepositoryScansInFlight += 1;
        try {
          const report = await publicRepositoryScanner(source.cloneUrl, {
            maxFiles: 1_000,
            maxFileBytes: 512 * 1024,
            maxTotalBytes: 10 * 1024 * 1024,
            maxFindings: 500,
            maxCheckoutBytes: 64 * 1024 * 1024,
            cloneTimeoutMs: 30_000,
          });
          sendJson(response, 200, { data: await attachExports(report, () => publicExports.findings(report, { repoUrl: source.cloneUrl, label: source.cloneUrl.replace(/^https:\/\/github\.com\//, "").replace(/\.git$/, "") })) });
        } finally {
          publicRepositoryScansInFlight -= 1;
        }
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/probes") {
        const payload = await readJsonBody(request);
        const job = await createProbeJob(payload);
        await persistProbeResult(datastore, job);
        sendJson(response, 201, { data: job });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/repository-scans") {
        if (!datastore) {
          sendJson(response, 501, { error: "Datastore is not configured" });
          return;
        }

        const payload = await readJsonBody(request);
        const source = payload.path ?? payload.url ?? payload.repository ?? payload.target;
        const report = await runRepositoryScan(source, {
          maxFiles: payload.maxFiles,
          maxFileBytes: payload.maxFileBytes,
          cloneTimeoutMs: payload.cloneTimeoutMs,
        });
        const result = await persistRepositoryScan(datastore, report, {
          actor: getRequestActor(request, payload),
        });
        await datastore.createProbeJob({
          id: result.persistence.snapshotId,
          mode: "repository",
          status: "completed",
          createdAt: report.scan.startedAt,
          updatedAt: report.scan.completedAt,
          completedAt: report.scan.completedAt,
          target: {
            name: report.scan.targetName,
            repository: report.scan.targetName,
            sourceType: report.scan.sourceType,
            path: report.scan.sourceType === "local" ? report.scan.target : undefined,
            url: report.scan.sourceType === "github" ? report.scan.target : undefined,
          },
          request: {
            mode: "repository",
            target: report.scan.sourceInput ?? report.scan.target,
            repository: report.scan.targetName,
          },
          result: report,
          riskScore: Math.max(0, 100 - Number(report.score?.readinessScore ?? 100)),
          error: null,
        });
        sendJson(response, 201, { data: result });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/scheduler/start") {
        const status = schedulerRuntime.start();
        await createAuditEvent(datastore, {
          action: "scheduler.started",
          entityType: "scheduler",
          entityId: "default",
          summary: "Scheduler started",
          after: status,
        });
        sendJson(response, 200, { data: status });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/scheduler/stop") {
        const before = schedulerRuntime.getStatus();
        const status = schedulerRuntime.stop();
        await createAuditEvent(datastore, {
          action: "scheduler.stopped",
          entityType: "scheduler",
          entityId: "default",
          summary: "Scheduler stopped",
          before,
          after: status,
        });
        sendJson(response, 200, { data: status });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/scheduler/tick") {
        const result = await schedulerRuntime.tick();
        await createAuditEvent(datastore, {
          action: "scheduler.tick",
          entityType: "scheduler",
          entityId: "default",
          summary: `Scheduler tick completed with ${result.runs?.length ?? 0} run(s)`,
          after: result,
        });
        sendJson(response, 200, { data: result });
        return;
      }

      if ((request.method === "PATCH" || request.method === "POST") && url.pathname === "/api/scheduler/config") {
        const payload = await readJsonBody(request);
        const before = schedulerRuntime.getStatus();
        const status = schedulerRuntime.updateConfig(payload);
        await createAuditEvent(datastore, {
          action: "scheduler.config_updated",
          entityType: "scheduler",
          entityId: "default",
          summary: "Scheduler configuration updated",
          before,
          after: status,
          metadata: { patch: payload },
        });
        sendJson(response, 200, { data: status });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/approvals") {
        if (!datastore) {
          sendJson(response, 501, { error: "Datastore is not configured" });
          return;
        }

        const payload = await readJsonBody(request);
        const approval = await datastore.createApprovalRequest({
          ...payload,
          requestedBy: payload.requestedBy ?? getRequestActor(request, payload),
        });
        sendJson(response, 201, { data: approval });
        return;
      }

      if (request.method === "POST" && url.pathname.startsWith("/api/approvals/") && (url.pathname.endsWith("/approve") || url.pathname.endsWith("/reject"))) {
        if (!datastore) {
          sendJson(response, 501, { error: "Datastore is not configured" });
          return;
        }

        if (!hasRole(request, APPROVER_ROLES)) {
          sendJson(response, 403, { error: "Approver role required" });
          return;
        }

        const payload = await readJsonBody(request);
        const id = decodeURIComponent(url.pathname.slice("/api/approvals/".length).replace(/\/(approve|reject)$/, ""));
        const status = url.pathname.endsWith("/approve") ? "approved" : "rejected";
        const approval = await datastore.decideApprovalRequest(id, {
          status,
          actor: getRequestActor(request, payload),
          note: payload.note ?? payload.reason ?? null,
        });
        sendMaybeFound(response, approval, "Approval request not found");
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/monitors") {
        const payload = await readJsonBody(request);
        const policy = await createMonitorPolicy(datastore, payload);
        sendJson(response, 201, { data: policy });
        return;
      }

      if (request.method === "POST" && url.pathname.startsWith("/api/monitors/") && url.pathname.endsWith("/run")) {
        const id = decodeURIComponent(url.pathname.slice("/api/monitors/".length).replace(/\/run$/, ""));
        const result = await runMonitorPolicy(datastore, id, { persistProbeResult });
        sendJson(response, 200, { data: result });
        return;
      }

      if ((request.method === "PATCH" || request.method === "POST") && url.pathname.startsWith("/api/monitors/")) {
        const id = decodeURIComponent(url.pathname.slice("/api/monitors/".length));
        const payload = await readJsonBody(request);
        const policy = await updateMonitorPolicy(datastore, id, payload);
        sendJson(response, 200, { data: policy });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/findings") {
        if (!datastore) {
          sendJson(response, 501, { error: "Datastore is not configured" });
          return;
        }

        const payload = await readJsonBody(request);
        const finding = await datastore.createFinding(payload);
        sendJson(response, 201, { data: finding });
        return;
      }

      if (request.method === "POST" && url.pathname.startsWith("/api/findings/") && url.pathname.endsWith("/notes")) {
        if (!datastore) {
          sendJson(response, 501, { error: "Datastore is not configured" });
          return;
        }

        const id = decodeURIComponent(url.pathname.slice("/api/findings/".length).replace(/\/notes$/, ""));
        const payload = await readJsonBody(request);
        const finding = await datastore.appendFindingNote(id, payload);
        if (!finding) {
          sendJson(response, 404, { error: "Finding not found" });
          return;
        }

        sendJson(response, 201, { data: finding });
        return;
      }

      if ((request.method === "PATCH" || request.method === "POST") && url.pathname.startsWith("/api/findings/")) {
        if (!datastore) {
          sendJson(response, 501, { error: "Datastore is not configured" });
          return;
        }

        const id = decodeURIComponent(url.pathname.slice("/api/findings/".length));
        const payload = await readJsonBody(request);
        const existingFinding = await datastore.getFinding(id);
        if (!existingFinding) {
          sendJson(response, 404, { error: "Finding not found" });
          return;
        }
        if (typeof payload.status === "string") {
          payload.status = payload.status.toLowerCase();
        }
        if (TERMINAL_FINDING_STATUSES.has(payload.status) && !hasRole(request, new Set(["admin"]))) {
          await requireApprovedAction(datastore, payload.approvalId, {
            entityType: "finding",
            entityId: id,
            action: `finding.transition.${payload.status}`,
            alternateActions: ["finding.terminal_status"],
            message: "Finding transition approval required",
          });
        }
        const finding = await datastore.updateFinding(id, payload);

        sendJson(response, 200, { data: finding });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/cbom/snapshots") {
        if (!datastore) {
          sendJson(response, 501, { error: "Datastore is not configured" });
          return;
        }

        const payload = await readJsonBody(request);
        const snapshot = await datastore.createCbomSnapshot(payload);
        sendJson(response, 201, { data: snapshot });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/risk/recompute") {
        const payload = await readJsonBody(request);
        const result = await recomputeRisk(datastore, payload);
        if (!result) {
          sendJson(response, 404, { error: "Asset not found" });
          return;
        }

        sendJson(response, 200, { data: result });
        return;
      }

      if (request.method === "POST" && url.pathname.startsWith("/api/reports/") && url.pathname.endsWith("/exports")) {
        if (!datastore) {
          sendJson(response, 501, { error: "Datastore is not configured" });
          return;
        }

        const type = decodeURIComponent(url.pathname.slice("/api/reports/".length).replace(/\/exports$/, ""));
        const payload = await readJsonBody(request);
        const report = await buildReport(type, { datastore });
        if (!report) {
          sendJson(response, 404, { error: "Report type not found" });
          return;
        }
        if (!hasRole(request, REPORT_EXPORT_ROLES)) {
          await requireApprovedAction(datastore, payload.approvalId, {
            entityType: "report",
            entityId: type,
            action: "report.export",
            message: "Report export approval required",
          });
        }

        const record = await datastore.createReportExport({
          report,
          createdBy: payload.createdBy ?? payload.actor ?? "system",
          approvalId: payload.approvalId ?? null,
          metadata: payload.metadata ?? {},
        });
        sendJson(response, 201, { data: record });
        return;
      }

      if (request.method !== "GET") {
        sendJson(response, 405, { error: "Method not allowed" });
        return;
      }

      if (url.pathname.startsWith("/api/probes/")) {
        const id = decodeURIComponent(url.pathname.slice("/api/probes/".length));
        const job = datastore ? await datastore.getProbeJob(id) : getProbeJob(id);
        if (!job) {
          sendJson(response, 404, { error: "Probe not found" });
          return;
        }

        sendJson(response, 200, { data: job });
        return;
      }

      if (url.pathname.startsWith("/api/monitors/") && url.pathname.endsWith("/runs")) {
        const id = decodeURIComponent(url.pathname.slice("/api/monitors/".length).replace(/\/runs$/, ""));
        const policy = await getMonitorPolicy(datastore, id);
        if (!policy) {
          sendJson(response, 404, { error: "Monitor policy not found" });
          return;
        }

        sendCollection(response, await listMonitorRuns(datastore, { policyId: id }));
        return;
      }

      if (datastore && url.pathname.startsWith("/api/monitors/") && url.pathname.endsWith("/audit")) {
        const id = decodeURIComponent(url.pathname.slice("/api/monitors/".length).replace(/\/audit$/, ""));
        sendCollection(response, await datastore.listAuditEvents({ entityType: "monitor", entityId: id, limit: url.searchParams.get("limit") }));
        return;
      }

      if (url.pathname.startsWith("/api/monitors/")) {
        const id = decodeURIComponent(url.pathname.slice("/api/monitors/".length));
        const policy = await getMonitorPolicy(datastore, id);
        sendMaybeFound(response, policy, "Monitor policy not found");
        return;
      }

      if (url.pathname.startsWith("/api/assets/") && url.pathname.endsWith("/risk")) {
        const id = decodeURIComponent(url.pathname.slice("/api/assets/".length).replace(/\/risk$/, ""));
        const result = await analyzeAssetById(datastore, id);
        sendMaybeFound(response, result, "Asset not found");
        return;
      }

      if (datastore && url.pathname.startsWith("/api/assets/") && url.pathname.endsWith("/audit")) {
        const id = decodeURIComponent(url.pathname.slice("/api/assets/".length).replace(/\/audit$/, ""));
        sendCollection(response, await datastore.listAuditEvents({ entityType: "asset", entityId: id, limit: url.searchParams.get("limit") }));
        return;
      }

      if (datastore && url.pathname.startsWith("/api/assets/")) {
        const [, historySuffix] = url.pathname.split("/history");
        const id = decodeURIComponent(url.pathname.slice("/api/assets/".length).replace(/\/history$/, ""));

        if (historySuffix === "") {
          sendCollection(response, await datastore.listAssetHistory(id));
          return;
        }

        if (url.pathname.endsWith("/history")) {
          sendCollection(response, await datastore.listAssetHistory(id));
          return;
        }

        sendMaybeFound(response, await datastore.getAsset(id), "Asset not found");
        return;
      }

      if (datastore && url.pathname.startsWith("/api/cbom/snapshots/")) {
        const id = decodeURIComponent(url.pathname.slice("/api/cbom/snapshots/".length));
        sendMaybeFound(response, await datastore.getCbomSnapshot(id), "CBOM snapshot not found");
        return;
      }

      if (datastore && url.pathname.startsWith("/api/findings/")) {
        if (url.pathname.endsWith("/audit")) {
          const id = decodeURIComponent(url.pathname.slice("/api/findings/".length).replace(/\/audit$/, ""));
          sendCollection(response, await datastore.listAuditEvents({ entityType: "finding", entityId: id, limit: url.searchParams.get("limit") }));
          return;
        }

        const id = decodeURIComponent(url.pathname.slice("/api/findings/".length));
        sendMaybeFound(response, await datastore.getFinding(id), "Finding not found");
        return;
      }

      if (datastore && url.pathname.startsWith("/api/audit-events/")) {
        const id = decodeURIComponent(url.pathname.slice("/api/audit-events/".length));
        sendMaybeFound(response, await datastore.getAuditEvent(id), "Audit event not found");
        return;
      }

      if (datastore && url.pathname.startsWith("/api/report-exports/") && url.pathname.endsWith("/manifest")) {
        const id = decodeURIComponent(url.pathname.slice("/api/report-exports/".length).replace(/\/manifest$/, ""));
        sendMaybeFound(response, await datastore.getReportExportManifest(id), "Report export not found");
        return;
      }

      if (datastore && url.pathname.startsWith("/api/report-exports/")) {
        const id = decodeURIComponent(url.pathname.slice("/api/report-exports/".length));
        sendMaybeFound(response, await datastore.getReportExport(id), "Report export not found");
        return;
      }

      if (datastore && url.pathname.startsWith("/api/approvals/")) {
        const id = decodeURIComponent(url.pathname.slice("/api/approvals/".length));
        sendMaybeFound(response, await datastore.getApprovalRequest(id), "Approval request not found");
        return;
      }

      if (url.pathname === "/api/reports") {
        sendCollection(response, listReportTypes());
        return;
      }

      if (url.pathname.startsWith("/api/reports/")) {
        const type = decodeURIComponent(url.pathname.slice("/api/reports/".length));
        const report = await buildReport(type, { datastore });
        sendMaybeFound(response, report, "Report type not found");
        return;
      }

      switch (url.pathname) {
        case "/api/health":
          sendJson(response, 200, {
            status: "ok",
            service: "QuantumSentinel API",
            timestamp: new Date().toISOString(),
          });
          break;
        case "/api/scheduler":
          sendJson(response, 200, { data: schedulerRuntime.getStatus() });
          break;
        case "/api/assets":
          sendCollection(response, datastore ? await datastore.listAssets() : []);
          break;
        case "/api/alerts":
          sendCollection(response, await activeAlerts(datastore));
          break;
        case "/api/compliance":
          sendCollection(response, []);
          break;
        case "/api/trends":
          sendCollection(response, []);
          break;
        case "/api/algorithms":
          sendCollection(response, []);
          break;
        case "/api/summary":
          sendJson(response, 200, {
            data: deriveSummary({
              assets: datastore ? await datastore.listAssets() : [],
              alerts: await activeAlerts(datastore),
              compliance: [],
              trends: [],
            }),
          });
          break;
        case "/api/cbom":
          sendJson(response, 200, buildCbom(datastore ? await datastore.listAssets() : []));
          break;
        case "/api/drift":
          sendJson(response, 200, { data: await analyzePortfolioDrift(datastore) });
          break;
        case "/api/findings":
          if (!datastore) {
            sendCollection(response, []);
          } else {
            sendCollection(response, await datastore.listFindings(Object.fromEntries(url.searchParams)));
          }
          break;
        case "/api/remediation/summary":
          if (!datastore) {
            sendJson(response, 501, { error: "Datastore is not configured" });
          } else {
            sendJson(response, 200, { data: await datastore.getRemediationSummary() });
          }
          break;
        case "/api/audit-events":
          if (!datastore) {
            sendCollection(response, []);
          } else {
            sendCollection(response, await datastore.listAuditEvents(Object.fromEntries(url.searchParams)));
          }
          break;
        case "/api/report-exports":
          if (!datastore) {
            sendCollection(response, []);
          } else {
            sendCollection(response, await datastore.listReportExports(Object.fromEntries(url.searchParams)));
          }
          break;
        case "/api/audit-chain/verify":
          if (!datastore) {
            sendJson(response, 501, { error: "Datastore is not configured" });
          } else {
            sendJson(response, 200, { data: await datastore.verifyAuditChain(Object.fromEntries(url.searchParams)) });
          }
          break;
        case "/api/evidence/archive":
          if (!datastore) {
            sendJson(response, 501, { error: "Datastore is not configured" });
          } else {
            sendJson(response, 200, { data: await datastore.getEvidenceArchiveSummary(Object.fromEntries(url.searchParams)) });
          }
          break;
        case "/api/evidence/bundle":
          if (!datastore) {
            sendJson(response, 501, { error: "Datastore is not configured" });
          } else {
            sendJson(response, 200, { data: await datastore.getEvidenceBundle(Object.fromEntries(url.searchParams)) });
          }
          break;
        case "/api/approvals":
          if (!datastore) {
            sendCollection(response, []);
          } else {
            sendCollection(response, await datastore.listApprovalRequests(Object.fromEntries(url.searchParams)));
          }
          break;
        case "/api/cbom/snapshots":
          if (!datastore) {
            sendCollection(response, []);
          } else {
            sendCollection(response, await datastore.listCbomSnapshots());
          }
          break;
        case "/api/events":
          handleEvents(request, response);
          break;
        case "/api/probes":
          sendCollection(response, datastore ? await datastore.listProbeJobs() : listProbeJobs());
          break;
        case "/api/monitors":
          sendCollection(response, await listMonitorPolicies(datastore));
          break;
        case "/api/monitor-runs":
          sendCollection(response, await listMonitorRuns(datastore, Object.fromEntries(url.searchParams)));
          break;
        case "/api/monitor-health":
          sendJson(response, 200, { data: await getMonitorHealth(datastore) });
          break;
        default:
          sendJson(response, 404, { error: "Not found" });
      }
    } catch (error) {
      const statusCode = error.statusCode ?? 500;
      sendJson(response, statusCode, {
        error: statusCode === 500 ? "Internal server error" : error.message,
      });
    }
  });

  server.scheduler = schedulerRuntime;
  return server;
}
