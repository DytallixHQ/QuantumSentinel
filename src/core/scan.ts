// Graph scan orchestrator: targets config -> ingestors -> merged graph -> risk -> CBOM.
import { readFile } from "node:fs/promises";
import path from "node:path";
import { buildCycloneDxCbom } from "../exporters/cyclonedx.ts";
import { resolveRiskConfig, scoreGraph, type RiskConfig, type RiskResult } from "../engine/risk/mosca.ts";
import { ingestCloudKeys, listAwsKmsKeys, listAzureKeys, listVaultTransitKeys, type AwsKmsLike, type AzureKeyClientLike, type CloudKeyRecord, type FetchLike } from "../scanners/cloud/index.ts";
import { scanCode, type CodeTarget } from "../scanners/code/index.ts";
import { scanFilesystem, type FilesystemTarget } from "../scanners/filesystem/index.ts";
import { scanNetwork, type NetworkProbes, type NetworkTarget, type ProbeError } from "../scanners/network/index.ts";
import { CryptoGraph } from "./graph/graph.ts";
import type { EdgeType, RiskInputs, ServiceGroup } from "./graph/types.ts";

export interface TargetsConfig {
  authorization?: { confirmed: boolean; owner?: string; reference?: string };
  network?: NetworkTarget[];
  filesystem?: FilesystemTarget[];
  code?: CodeTarget[];
  cloud?: {
    awsKms?: { region: string; maxKeys?: number };
    azureKeyVault?: { vaultUrl: string; maxKeys?: number };
    vault?: { address: string; mount?: string; namespace?: string; tokenEnv?: string; maxKeys?: number };
  };
  groups?: Array<RiskInputs & { id: string; label?: string; description?: string; members: string[] }>;
  relations?: Array<{ from: string; type: EdgeType; to: string }>;
  risk?: Partial<Omit<RiskConfig, "defaults">> & { defaults?: Partial<RiskConfig["defaults"]> };
  timeoutMs?: number;
}

export const MAX_NETWORK_TARGETS = 256;
const EDGE_TYPES: EdgeType[] = ["TERMINATES_AT", "ENCRYPTED_WITH", "CONTAINS_KEY", "SIGNS", "MOUNTS", "DEPENDS_ON"];
const PROTOCOLS = ["tls", "ssh", "ikev2", "tcp"];

export function validateTargets(cfg: TargetsConfig): string[] {
  const errs: string[] = [];
  const net = cfg.network ?? [];
  if (net.some((t) => t.protocol !== "tcp") && cfg.authorization?.confirmed !== true) {
    errs.push("network probes require authorization.confirmed = true (you must own or be authorized to test every listed host)");
  }
  if (net.length > MAX_NETWORK_TARGETS) errs.push(`at most ${MAX_NETWORK_TARGETS} network targets per scan`);
  for (const [i, t] of net.entries()) {
    if (!t.host || typeof t.host !== "string") errs.push(`network[${i}].host is required`);
    if (/[/*]/.test(t.host ?? "")) errs.push(`network[${i}].host must be a single host, not a range (no sweeping)`);
    if (!PROTOCOLS.includes(t.protocol)) errs.push(`network[${i}].protocol must be one of ${PROTOCOLS.join(", ")}`);
    if (t.port !== undefined && !(Number.isInteger(t.port) && t.port > 0 && t.port < 65536)) errs.push(`network[${i}].port is invalid`);
  }
  for (const [i, r] of (cfg.relations ?? []).entries()) if (!EDGE_TYPES.includes(r.type)) errs.push(`relations[${i}].type must be one of ${EDGE_TYPES.join(", ")}`);
  for (const [i, t] of [...(cfg.network ?? []), ...(cfg.groups ?? [])].entries()) {
    if (t.criticality !== undefined && !(t.criticality >= 1 && t.criticality <= 10)) errs.push(`target ${i}: criticality must be in [1, 10]`);
    if (t.exposureFactor !== undefined && !(t.exposureFactor >= 0.1 && t.exposureFactor <= 1)) errs.push(`target ${i}: exposureFactor must be in [0.1, 1.0]`);
  }
  return errs;
}

export async function loadTargets(file: string): Promise<{ cfg: TargetsConfig; baseDir: string }> {
  const cfg = JSON.parse(await readFile(file, "utf8")) as TargetsConfig;
  return { cfg, baseDir: path.dirname(path.resolve(file)) };
}

export interface GraphScanDeps {
  probes?: NetworkProbes;
  aws?: (region: string) => Promise<AwsKmsLike>;
  azure?: (vaultUrl: string) => Promise<AzureKeyClientLike>;
  fetch?: FetchLike;
  env?: Record<string, string | undefined>;
  now?: () => string;
  repoScanner?: Parameters<typeof scanCode>[1] extends infer O ? (O extends { scanner?: infer S } ? S : never) : never;
}

export interface GraphScanResult {
  graph: CryptoGraph;
  risk: RiskResult[];
  riskConfig: RiskConfig;
  errors: ProbeError[];
}

async function importOptional(name: string): Promise<Record<string, unknown>> {
  try {
    return (await import(name)) as Record<string, unknown>;
  } catch {
    throw new Error(`optional dependency '${name}' is not installed; run: npm install ${name}`);
  }
}

const liveAws = async (region: string): Promise<AwsKmsLike> => {
  const m = await importOptional("@aws-sdk/client-kms");
  const KMS = m.KMS as new (o: { region: string }) => AwsKmsLike;
  return new KMS({ region });
};

const liveAzure = async (vaultUrl: string): Promise<AzureKeyClientLike> => {
  const keys = await importOptional("@azure/keyvault-keys");
  const id = await importOptional("@azure/identity");
  const Cred = id.DefaultAzureCredential as new () => unknown;
  const KeyClient = keys.KeyClient as new (url: string, cred: unknown) => AzureKeyClientLike;
  return new KeyClient(vaultUrl, new Cred());
};

export async function runGraphScan(cfg: TargetsConfig, baseDir = process.cwd(), deps: GraphScanDeps = {}): Promise<GraphScanResult> {
  const problems = validateTargets(cfg);
  if (problems.length) throw new Error(`invalid targets config:\n- ${problems.join("\n- ")}`);
  const now = deps.now ?? (() => new Date().toISOString());
  const env = deps.env ?? process.env;
  const g = new CryptoGraph();
  const errors: ProbeError[] = [];
  const abs = (p: string) => path.resolve(baseDir, p);

  if (cfg.network?.length) {
    const r = await scanNetwork(cfg.network, { probes: deps.probes, timeoutMs: cfg.timeoutMs, now });
    g.merge(r.graph);
    errors.push(...r.errors);
  }
  if (cfg.filesystem?.length) g.merge(await scanFilesystem(cfg.filesystem.map((t) => ({ ...t, path: abs(t.path) })), { now }));
  if (cfg.code?.length) g.merge(await scanCode(cfg.code.map((t) => ({ ...t, path: abs(t.path) })), { now, scanner: deps.repoScanner }));

  const cloud = cfg.cloud ?? {};
  const keys: CloudKeyRecord[] = [];
  const guard = async (label: string, fn: () => Promise<CloudKeyRecord[]>) => {
    try {
      keys.push(...(await fn()));
    } catch (e) {
      errors.push({ target: label, error: e instanceof Error ? e.message : String(e) });
    }
  };
  if (cloud.awsKms) await guard(`aws-kms:${cloud.awsKms.region}`, async () => listAwsKmsKeys(await (deps.aws ?? liveAws)(cloud.awsKms!.region), cloud.awsKms!.maxKeys));
  if (cloud.azureKeyVault) await guard(`azure:${cloud.azureKeyVault.vaultUrl}`, async () => listAzureKeys(await (deps.azure ?? liveAzure)(cloud.azureKeyVault!.vaultUrl), cloud.azureKeyVault!.maxKeys));
  if (cloud.vault) {
    const v = cloud.vault;
    await guard(`vault:${v.address}`, async () => {
      const token = env[v.tokenEnv ?? "VAULT_TOKEN"];
      if (!token) throw new Error(`Vault token not set in $${v.tokenEnv ?? "VAULT_TOKEN"}`);
      return listVaultTransitKeys({ address: v.address, token, mount: v.mount, namespace: v.namespace, fetch: deps.fetch, maxKeys: v.maxKeys });
    });
  }
  if (keys.length) g.merge(ingestCloudKeys(keys, { now: now() }));

  for (const grp of cfg.groups ?? []) {
    const { members, label, description, id, ...risk } = grp;
    g.addVertex<ServiceGroup>({ ...risk, id, kind: "ServiceGroup", label: label ?? id, description, evidence: [{ source: "config", locator: "targets.groups", observedAt: now() }] });
    for (const m of members) {
      if (g.has(m)) g.addEdge(id, "DEPENDS_ON", m);
      else errors.push({ target: id, error: `group member not found in graph: ${m}` });
    }
  }
  for (const r of cfg.relations ?? []) {
    if (g.has(r.from) && g.has(r.to)) g.addEdge(r.from, r.type, r.to, undefined, [{ source: "config", locator: "targets.relations", observedAt: now() }]);
    else errors.push({ target: `${r.from} -> ${r.to}`, error: "relation endpoint not found in graph" });
  }

  const riskConfig = resolveRiskConfig(cfg.risk);
  const risk = scoreGraph(g, riskConfig);
  return { graph: g, risk, riskConfig, errors };
}

export { buildCycloneDxCbom };
