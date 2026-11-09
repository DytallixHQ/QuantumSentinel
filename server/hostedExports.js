// Downloadable exports (CycloneDX 1.7 CBOM + HTML report) for hosted public scans.
// Uses the TypeScript graph engine, which needs Node >= 22.18 (native type stripping).
// On older runtimes, or on any error, exports are omitted and the scan result is returned unchanged.

const ENGINE_TIMEOUT_MS = 3_000;

export function exportsSupported() {
  return Boolean(process.features?.typescript);
}

async function engine() {
  const [scan, network, code, risk, cbom, html] = await Promise.all([
    import("../src/core/graph/graph.ts"),
    import("../src/scanners/network/index.ts"),
    import("../src/scanners/code/index.ts"),
    import("../src/engine/risk/mosca.ts"),
    import("../src/exporters/cyclonedx.ts"),
    import("../src/exporters/htmlReport.ts"),
  ]);
  return { ...scan, ...network, ...code, ...risk, ...cbom, ...html };
}

function finish(e, graph, { title, client, errors = [], now }) {
  const riskConfig = e.resolveRiskConfig({});
  const risk = e.scoreGraph(graph, riskConfig);
  return {
    cbom: e.buildCycloneDxCbom(graph, { risk, toolVersion: "hosted", timestamp: now }),
    reportHtml: e.buildHtmlReport(graph, { risk, riskConfig, title, client, errors, generatedAt: now }),
  };
}

/**
 * Re-observe each public TLS service with the graph engine's raw ClientHello probes
 * (hybrid / pure ML-KEM / classical fallback). Probes target the address the domain
 * scan already validated as public, so DNS is not re-resolved (no rebinding window).
 */
export async function buildDomainExports(report, { probes, now = new Date().toISOString() } = {}) {
  if (!exportsSupported()) return null;
  const host = report?.scan?.assessedAddress;
  const hostname = report?.scan?.target;
  if (!host || !hostname) return null;
  const e = await engine();
  const targets = (report.scan.ports ?? [443]).map((port) => ({
    id: `${hostname}:${port}`, host, domain: hostname, port, protocol: "tls", posture: "external",
  }));
  const { graph, errors } = await e.scanNetwork(targets, { probes, timeoutMs: ENGINE_TIMEOUT_MS, concurrency: 2, now: () => now });
  return finish(e, graph, { title: `Post-Quantum Readiness: ${hostname}`, client: hostname, errors, now });
}

/** Repository and single-file scans: lift line-level findings into the graph. */
export async function buildFindingsExports(report, { repoUrl, label, now = new Date().toISOString() } = {}) {
  if (!exportsSupported() || !Array.isArray(report?.findings)) return null;
  const e = await engine();
  const graph = e.ingestRepoFindings(report.findings, { path: "", repoUrl: repoUrl ?? `upload:${label ?? "file"}`, includeDocumentation: false }, now);
  return finish(e, graph, { title: `Post-Quantum Readiness: ${label ?? repoUrl ?? "scan"}`, client: label ?? repoUrl, now });
}

/** Never let export generation fail or delay a scan beyond `budgetMs`. */
export async function attachExports(report, build, budgetMs = 15_000) {
  try {
    let timer;
    const exports = await Promise.race([
      build(),
      new Promise((resolve) => { timer = setTimeout(() => resolve(null), budgetMs); }),
    ]);
    clearTimeout(timer);
    return exports ? { ...report, exports } : report;
  } catch {
    return report;
  }
}
