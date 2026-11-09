// Code ingestor: reuses the existing repository rule set (server/repositoryScanner.js) and
// lifts its line-level findings into CodeAsset vertices linked to classified primitives.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { addAlgorithm } from "../../core/graph/builders.ts";
import { CryptoGraph } from "../../core/graph/graph.ts";
import type { CodeAsset, RiskInputs } from "../../core/graph/types.ts";
import { normalizeCurve } from "../../engine/classifier/classify.ts";

export interface CodeTarget extends RiskInputs {
  path: string;
  repoUrl?: string;
  branch?: string;
  commit?: string;
  includeDocumentation?: boolean; // default false: README/docs mentions are not usage
}

export interface RepoFinding {
  matchedValue: string;
  confidence: string;
  usage: string;
  evidence: { file: string; line: number };
}

type RepoScanner = (path: string) => Promise<{ findings: RepoFinding[] }>;

const USAGE_MAP: Record<string, string> = {
  "signature-or-trust": "signature",
  "key-establishment-or-transport": "key-exchange",
  "data-protection": "encryption",
  "hash-or-integrity": "hash",
};

async function git(cwd: string, args: string[]): Promise<string | undefined> {
  try {
    return (await promisify(execFile)("git", args, { cwd, timeout: 3000 })).stdout.trim() || undefined;
  } catch {
    return undefined;
  }
}

export async function defaultRepoScanner(): Promise<RepoScanner> {
  const mod = (await import(new URL("../../../server/repositoryScanner.js", import.meta.url).href)) as { scanRepository: RepoScanner };
  return mod.scanRepository;
}

/** Map source-code spellings (JWT alg names, curve names) onto registry names. */
export function normalizeToken(token: string): { name: string; curve?: string; keySize?: number } {
  const t = token.replace(/[_ ]/g, "-");
  const jwt = t.match(/^(RS|PS|ES)(256|384|512)$/i);
  if (jwt) {
    const kind = jwt[1].toUpperCase();
    return kind === "ES" ? { name: "ECDSA", curve: { "256": "P-256", "384": "P-384", "512": "P-521" }[jwt[2]] } : { name: kind === "PS" ? "RSASSA-PSS" : "RSA" };
  }
  const rsa = t.match(/^RSA-?(1024|2048|3072|4096)$/i);
  if (rsa) return { name: "RSA", keySize: Number(rsa[1]) };
  const curve = normalizeCurve(t);
  if (curve && curve !== t && /^(P-|secp)/.test(curve)) return { name: "EC", curve };
  if (/^(P-?\d{3}|secp\d+[rk]1|prime256v1)$/i.test(t)) return { name: "EC", curve: normalizeCurve(t) };
  return { name: t };
}

export function ingestRepoFindings(findings: RepoFinding[], t: Required<Pick<CodeTarget, "repoUrl">> & CodeTarget, now: string): CryptoGraph {
  const g = new CryptoGraph();
  const { path: _p, repoUrl, branch, commit, includeDocumentation, ...risk } = t;
  for (const f of findings) {
    if (!includeDocumentation && f.confidence === "documentation-reference") continue;
    const id = `code:${repoUrl}@${commit ?? branch ?? "worktree"}:${f.evidence.file}:${f.evidence.line}`;
    const ev = [{ source: "code" as const, locator: `${f.evidence.file}:${f.evidence.line}`, detail: `${f.matchedValue} (${f.confidence}, ${f.usage})`, observedAt: now }];
    g.addVertex<CodeAsset>({ ...risk, id, kind: "CodeAsset", label: `${f.evidence.file}:${f.evidence.line}`, repoUrl, branch, commit, filePath: f.evidence.file, line: f.evidence.line, evidence: ev });
    const prim = addAlgorithm(g, { ...normalizeToken(f.matchedValue), usage: USAGE_MAP[f.usage] ?? "unknown" }, ev);
    g.addEdge(id, "DEPENDS_ON", prim, { confidence: f.confidence });
  }
  return g;
}

export async function scanCode(targets: CodeTarget[], opts: { scanner?: RepoScanner; now?: () => string } = {}): Promise<CryptoGraph> {
  const scan = opts.scanner ?? (await defaultRepoScanner());
  const now = (opts.now ?? (() => new Date().toISOString()))();
  const g = new CryptoGraph();
  for (const t of targets) {
    const repoUrl = t.repoUrl ?? (await git(t.path, ["remote", "get-url", "origin"])) ?? `file://${t.path}`;
    const commit = t.commit ?? (await git(t.path, ["rev-parse", "HEAD"]));
    const branch = t.branch ?? (await git(t.path, ["rev-parse", "--abbrev-ref", "HEAD"]));
    const { findings } = await scan(t.path);
    g.merge(ingestRepoFindings(findings, { ...t, repoUrl, commit, branch }, now));
  }
  return g;
}
