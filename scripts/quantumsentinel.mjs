#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import process from "node:process";
import { createDatastore } from "../server/datastore.js";
import { scanDomain } from "../server/domainScanner.js";
import { scanRepository } from "../server/repositoryScanner.js";
import { persistRepositoryScan } from "../server/repositoryScanPersistence.js";
import { persistProbeResult } from "../server/app.js";

function usage() {
  return `QuantumSentinel Q-Day Scanner

Usage:
  quantumsentinel scan [directory] [--json] [--output path] [--html path] [--datastore path]
  quantumsentinel scan-domain <domain> [--ports 443,993] [--json] [--output path] [--html path] [--datastore path]

Options:
  --json          Print the complete JSON report to stdout
  --output, -o    Write the complete JSON report to a file
  --html          Write a self-contained HTML report
  --datastore     Persist scan evidence into a QuantumSentinel datastore
  --ports         Bounded TLS service ports for scan-domain
  --help, -h      Show this help

Graph mode (Node.js >= 22.18):
  quantumsentinel scan --graph --targets <config.json> [--export-cbom <cbom.json>] [--output <graph.json>] [--json]
  Builds an attributed cryptographic graph across network, file, code and KMS targets,
  scores Mosca/HNDL risk, and exports a CycloneDX 1.7 CBOM.
`;
}
function parseArguments(argv) {
  const args = [...argv];
  const command = args.shift();
  if (!command || command === "--help" || command === "-h") return { help: true };
  if (command !== "scan" && command !== "scan-domain") throw new Error(`unknown command: ${command}`);
  let target = ".";
  let output = null;
  let html = null;
  let datastore = null;
  let ports = null;
  let json = false;
  while (args.length) {
    const value = args.shift();
    if (value === "--json") json = true;
    else if (value === "--output" || value === "-o") output = args.shift();
    else if (value === "--html") html = args.shift();
    else if (value === "--datastore") datastore = args.shift();
    else if (value === "--ports") ports = args.shift();
    else if (value.startsWith("-")) throw new Error(`unknown option: ${value}`);
    else target = value;
  }
  if (output === undefined) throw new Error("--output requires a path");
  if (html === undefined) throw new Error("--html requires a path");
  if (datastore === undefined) throw new Error("--datastore requires a path");
  if (command === "scan-domain" && target === ".") throw new Error("scan-domain requires a domain");
  return { command, target, output, html, datastore, ports, json };
}
function escapeHtml(value) {
  return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}
function htmlReport(report) {
  const rows = report.findings.slice(0, 500).map((finding) => `<tr><td><span class="severity ${finding.severity.toLowerCase()}">${escapeHtml(finding.severity)}</span></td><td>${escapeHtml(finding.algorithm)}</td><td>${escapeHtml(finding.classification)}</td><td>${escapeHtml(finding.confidence)}</td><td><code>${escapeHtml(finding.evidence.file)}:${finding.evidence.line}</code><br>${escapeHtml(finding.evidence.excerpt)}</td><td>${escapeHtml(finding.recommendation)}</td></tr>`).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>QuantumSentinel — ${escapeHtml(report.scan.targetName)}</title><style>body{margin:0;background:#071018;color:#dbeafe;font:15px ui-sans-serif,system-ui,-apple-system,sans-serif}main{max-width:1400px;margin:auto;padding:40px}h1{font-size:34px;margin:0 0 8px}.muted{color:#8ca3b7}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:28px 0}.card{background:#0d1b26;border:1px solid #1c3546;border-radius:12px;padding:18px}.score{font-size:38px;font-weight:800;color:#54e6a5}.label{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#8ca3b7}table{width:100%;border-collapse:collapse;background:#0d1b26;border:1px solid #1c3546}th,td{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid #1c3546}th{position:sticky;top:0;background:#102330;color:#9fc4da}code{color:#7dd3fc}.severity{font-weight:700}.critical{color:#fb7185}.high{color:#fbbf24}.info{color:#60a5fa}.notice{border-left:3px solid #fbbf24;padding:12px 16px;background:#241e12;margin:22px 0}</style></head><body><main><h1>QuantumSentinel Q-Day Readiness</h1><p class="muted">${escapeHtml(report.scan.target)} · ${escapeHtml(report.scan.completedAt)}</p><div class="cards"><div class="card"><div class="label">Readiness score</div><div class="score">${report.score.readinessScore}/100 ${escapeHtml(report.score.grade)}</div></div><div class="card"><div class="label">Files scanned</div><strong>${report.scan.filesScanned.toLocaleString()}</strong></div><div class="card"><div class="label">Shor-vulnerable</div><strong>${report.summary.byClassification["shor-vulnerable-public-key"] ?? 0}</strong></div><div class="card"><div class="label">Deprecated</div><strong>${report.summary.byClassification.deprecated ?? 0}</strong></div><div class="card"><div class="label">PQC references</div><strong>${report.summary.byClassification.pqc ?? 0}</strong></div></div><div class="notice">This static assessment is a prioritization aid, not a certification. Review confidence, usage context, exclusions, and runtime boundaries before treating a reference as deployed exposure.</div><h2>Evidence</h2><table><thead><tr><th>Severity</th><th>Algorithm</th><th>Classification</th><th>Confidence</th><th>Evidence</th><th>Recommendation</th></tr></thead><tbody>${rows}</tbody></table><h2>Scoring method</h2><p>${escapeHtml(report.score.method)}</p><h2>Limitations</h2><ul>${report.limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></main></body></html>`;
}
function humanSummary(report) {
  const vulnerable = report.summary.byClassification["shor-vulnerable-public-key"] ?? 0;
  const deprecated = report.summary.byClassification.deprecated ?? 0;
  const pqc = report.summary.byClassification.pqc ?? 0;
  const lines = [
    `QuantumSentinel Q-Day scan: ${report.scan.targetName}`,
    `${report.scan.kind === "domain" ? "Services tested" : "Files scanned"}: ${report.scan.filesScanned.toLocaleString()}`,
    `Readiness score: ${report.score.readinessScore}/100 (${report.score.grade})`,
    `Shor-vulnerable references: ${vulnerable}`,
    `Deprecated references: ${deprecated}`,
    `PQC references: ${pqc}`,
  ];
  const highest = report.findings.filter((finding) => finding.severity === "CRITICAL" || finding.severity === "HIGH").slice(0, 5);
  if (highest.length) {
    lines.push("", "Highest-priority evidence:");
    for (const finding of highest) lines.push(`- ${finding.severity} ${finding.algorithm} at ${finding.evidence.file}:${finding.evidence.line} (${finding.confidence})`);
  }
  return lines.join("\n");
}
const rawArgs = process.argv.slice(2);
if (rawArgs[0] === "scan" && rawArgs.includes("--graph")) {
  if (!process.features.typescript) {
    process.stderr.write("QuantumSentinel: graph mode needs Node.js >= 22.18 (built-in TypeScript type stripping).\n");
    process.exit(1);
  }
  try {
    const { runGraphCli } = await import("../src/core/cliGraph.ts");
    process.exitCode = await runGraphCli(rawArgs.slice(1));
  } catch (error) {
    process.stderr.write(`QuantumSentinel: ${error.message}\n`);
    process.exitCode = 1;
  }
} else try {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) { process.stdout.write(usage()); process.exit(0); }
  const report = options.command === "scan-domain"
    ? await scanDomain(options.target, {
      ports: options.ports == null ? undefined : options.ports.split(",").map((port) => Number(port.trim())),
    })
    : await scanRepository(resolve(options.target));
  let persistence = null;
  if (options.datastore) {
    const datastore = await createDatastore({ filePath: resolve(options.datastore) });
    try {
      if (options.command === "scan-domain") {
        for (const job of report.services) await persistProbeResult(datastore, job);
        persistence = { persistence: { createdAssets: 0, updatedAssets: 0, createdFindings: report.findings.filter((finding) => finding.severity !== "INFO").length, refreshedFindings: 0 } };
        await datastore.createAuditEvent({
          actor: "quantumsentinel-cli", action: "domain_scan.completed", entityType: "domain-scan",
          entityId: report.scan.target, summary: `${report.scan.target} scored ${report.score.readinessScore}/100`,
          metadata: { score: report.score, summary: report.summary, ports: report.scan.ports },
        });
      } else {
        persistence = await persistRepositoryScan(datastore, report, { actor: "quantumsentinel-cli" });
      }
    } finally {
      await datastore.close();
    }
  }
  if (options.output) {
    const output = resolve(options.output);
    await mkdir(dirname(output), { recursive: true });
    await writeFile(output, `${JSON.stringify(report, null, 2)}\n`);
  }
  if (options.html) {
    const html = resolve(options.html);
    await mkdir(dirname(html), { recursive: true });
    await writeFile(html, htmlReport(report));
  }
  process.stdout.write(`${options.json ? JSON.stringify(report, null, 2) : humanSummary(report)}\n`);
  if (options.output && !options.json) process.stdout.write(`Report: ${resolve(options.output)}\n`);
  if (options.html && !options.json) process.stdout.write(`HTML: ${resolve(options.html)}\n`);
  if (persistence && !options.json) {
    const saved = persistence.persistence;
    process.stdout.write(`Persisted: ${saved.createdAssets} new assets, ${saved.updatedAssets} updated assets, ${saved.createdFindings} new findings, ${saved.refreshedFindings} refreshed findings\n`);
  }
} catch (error) {
  process.stderr.write(`QuantumSentinel: ${error.message}\n\n${usage()}`);
  process.exitCode = 1;
}
