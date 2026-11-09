import type { CryptoGraph } from "../../core/graph/graph.ts";
import { DEFAULT_RISK_CONFIG, RiskEngine, type RiskConfig, type RiskResult } from "./mosca.ts";

/**
 * Migration priority: how much total risk disappears if one asset's own cryptography (its
 * negotiated or configured primitives and the keys and certificates it holds) is migrated to PQC.
 *
 * Risk scores attach to assets, but migrations happen where the cryptography terminates. A
 * load balancer in front of forty stores carries the risk of all forty. The reduction is computed
 * exactly, by re-scoring the graph with the candidate treated as migrated:
 *
 *   reduction(x) = sum over assets u of [ combinedScore(u) - combinedScore(u | x migrated) ]
 *
 * Assets are endpoints, files, devices and other non-aggregate vertices. Service groups and
 * certificates are left out of the sum, because they repeat the scores of their members and
 * holders. Candidates are vertices whose own cryptography is weak, ranked by their baseline
 * score and capped at `limit` (default 50), since each candidate costs one re-scoring of the graph.
 */
export interface MigrationPriority {
  id: string;
  label: string;
  /** Total combinedScore removed across assets. */
  reduction: number;
  /** Assets whose combinedScore drops. */
  assetsImproved: number;
  /** The candidate's own baseline status (HNDL) and TNFL status. */
  status: RiskResult["status"];
  tnflStatus?: RiskResult["tnfl"]["status"];
}

const WEAK = new Set(["VULNERABLE_SHOR", "PLAINTEXT", "DEGRADED_GROVER"]);

function isSummed(g: CryptoGraph, id: string): boolean {
  const k = g.get(id)?.kind;
  return k !== undefined && k !== "CryptoPrimitive" && k !== "CryptoMaterial" && k !== "ServiceGroup";
}

export function migrationPriorities(
  graph: CryptoGraph,
  cfg: RiskConfig = DEFAULT_RISK_CONFIG,
  opts: { limit?: number; baseline?: RiskResult[] } = {},
): MigrationPriority[] {
  const limit = opts.limit ?? 50;
  const engine = new RiskEngine(graph, cfg);
  const baseline = opts.baseline ?? engine.run();
  const base = new Map(baseline.map((r) => [r.id, r]));
  const candidates = baseline
    .filter((r) => isSummed(graph, r.id) && r.combinedScore > 0)
    .filter((r) => {
      const own = engine.ownStatus(r.id);
      return (own !== undefined && WEAK.has(own)) || (r.tnfl.status !== undefined && WEAK.has(r.tnfl.status));
    })
    .slice(0, limit); // baseline is sorted by combinedScore desc
  const out: MigrationPriority[] = [];
  for (const c of candidates) {
    const after = new RiskEngine(graph, cfg, new Set([c.id])).run();
    let reduction = 0;
    let assetsImproved = 0;
    for (const r of after) {
      if (!isSummed(graph, r.id)) continue;
      const d = base.get(r.id)!.combinedScore - r.combinedScore;
      if (d > 1e-9) {
        reduction += d;
        assetsImproved++;
      }
    }
    if (reduction <= 0) continue;
    out.push({
      id: c.id,
      label: graph.get(c.id)?.label ?? c.id,
      reduction: Math.round(reduction * 1000) / 1000,
      assetsImproved,
      status: c.status,
      tnflStatus: c.tnfl.status,
    });
  }
  return out.sort((a, b) => b.reduction - a.reduction || b.assetsImproved - a.assetsImproved || a.id.localeCompare(b.id));
}
