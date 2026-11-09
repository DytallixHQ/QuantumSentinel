// `quantumsentinel scan --graph --targets <config.json> [--export-cbom <out.json>] [--output <graph.json>] [--json]`
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { buildCycloneDxCbom } from "../exporters/cyclonedx.ts";
import { buildHtmlReport } from "../exporters/htmlReport.ts";
import type { CryptoPrimitive } from "./graph/types.ts";
import { loadTargets, runGraphScan, type GraphScanDeps } from "./scan.ts";

export const GRAPH_USAGE = `Graph mode:
  quantumsentinel scan --graph --targets <config.json> [--export-cbom <cbom.json>] [--html <report.html>] [--client <name>] [--output <graph.json>] [--json] [--timeout <ms>] [--qday <year>]

  --targets       Targets config (network, filesystem, code, cloud, groups, relations, risk)
  --export-cbom   Write a CycloneDX 1.7 CBOM
  --html          Write a self-contained HTML client report (print to PDF from a browser)
  --client        Client name shown on the HTML report
  --output        Write the attributed graph and risk scores as JSON
  --json          Print the full graph result to stdout
  --timeout       Per-probe network timeout in ms (default 3000)
  --qday          Q-Day year for Mosca scoring (default 2033)
`;

interface GraphArgs {
  targets?: string;
  cbom?: string;
  html?: string;
  client?: string;
  output?: string;
  json: boolean;
  timeoutMs?: number;
  qDay?: number;
}

export function parseGraphArgs(argv: string[]): GraphArgs {
  const a: GraphArgs = { json: false };
  const args = [...argv];
  const need = (flag: string) => {
    const v = args.shift();
    if (v === undefined || v.startsWith("--")) throw new Error(`${flag} requires a value`);
    return v;
  };
  while (args.length) {
    const f = args.shift()!;
    if (f === "--graph") continue;
    else if (f === "--targets") a.targets = need(f);
    else if (f === "--export-cbom") a.cbom = need(f);
    else if (f === "--html") a.html = need(f);
    else if (f === "--client") a.client = need(f);
    else if (f === "--output" || f === "-o") a.output = need(f);
    else if (f === "--json") a.json = true;
    else if (f === "--timeout") a.timeoutMs = Number(need(f));
    else if (f === "--qday") a.qDay = Number(need(f));
    else throw new Error(`unknown graph-mode option: ${f}`);
  }
  if (!a.targets) throw new Error("--targets <config.json> is required with --graph");
  if (a.timeoutMs !== undefined && !(a.timeoutMs > 0)) throw new Error("--timeout must be a positive number");
  if (a.qDay !== undefined && !Number.isInteger(a.qDay)) throw new Error("--qday must be a year");
  return a;
}

async function write(file: string, body: unknown) {
  const out = path.resolve(file);
  await mkdir(path.dirname(out), { recursive: true });
  await writeFile(out, `${JSON.stringify(body, null, 2)}\n`);
  return out;
}

export async function runGraphCli(argv: string[], deps: GraphScanDeps & { stdout?: (s: string) => void; version?: string } = {}): Promise<number> {
  const print = deps.stdout ?? ((s: string) => process.stdout.write(s));
  const a = parseGraphArgs(argv);
  const { cfg, baseDir } = await loadTargets(a.targets!);
  if (a.timeoutMs) cfg.timeoutMs = a.timeoutMs;
  if (a.qDay) cfg.risk = { ...cfg.risk, qDayYear: a.qDay };
  const res = await runGraphScan(cfg, baseDir, deps);
  const graphJson = { ...res.graph.toJSON(), risk: res.risk, errors: res.errors };
  if (a.cbom) {
    const out = await write(a.cbom, buildCycloneDxCbom(res.graph, { risk: res.risk, toolVersion: deps.version }));
    if (!a.json) print(`CBOM (CycloneDX 1.7): ${out}\n`);
  }
  if (a.html) {
    const out = path.resolve(a.html);
    await mkdir(path.dirname(out), { recursive: true });
    await writeFile(out, buildHtmlReport(res.graph, { risk: res.risk, riskConfig: res.riskConfig, client: a.client, errors: res.errors }));
    if (!a.json) print(`HTML report: ${out}\n`);
  }
  if (a.output) {
    const out = await write(a.output, graphJson);
    if (!a.json) print(`Graph: ${out}\n`);
  }
  if (a.json) {
    print(`${JSON.stringify(graphJson, null, 2)}\n`);
    return 0;
  }
  const prims = res.graph.allVertices("CryptoPrimitive") as CryptoPrimitive[];
  const counts = prims.reduce<Record<string, number>>((m, p) => ((m[p.status] = (m[p.status] ?? 0) + 1), m), {});
  const lines = [
    `QuantumSentinel graph scan: ${res.graph.size.vertices} vertices, ${res.graph.size.edges} edges`,
    `Primitives: ${Object.entries(counts).sort().map(([k, v]) => `${k}=${v}`).join(" ") || "none"}`,
    "",
    "Top Mosca/HNDL risk (assets; certificates and keys are in --output/CBOM):",
    ...res.risk.filter((r) => r.score > 0 && res.graph.get(r.id)?.kind !== "CryptoMaterial").slice(0, 10).map((r) => `  ${r.score.toFixed(1).padStart(6)}  ${r.status.padEnd(16)} ${r.id}`),
  ];
  if (!res.risk.some((r) => r.score > 0 && res.graph.get(r.id)?.kind !== "CryptoMaterial")) lines.push("  (no asset exceeds the Mosca threshold)");
  if (res.errors.length) lines.push("", `Probe/ingest errors (${res.errors.length}):`, ...res.errors.slice(0, 20).map((e) => `  ${e.target}: ${e.error}`));
  print(`${lines.join("\n")}\n`);
  return 0;
}
