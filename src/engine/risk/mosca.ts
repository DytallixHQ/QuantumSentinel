import type { CryptoGraph } from "../../core/graph/graph.ts";
import type { CryptoPrimitive, QuantumStatus, Vertex } from "../../core/graph/types.ts";

export type EffectiveStatus = QuantumStatus | "PLAINTEXT";

export interface RiskConfig {
  qDayYear: number; // T_Q-Day as a calendar year
  currentYear: number; // injectable for deterministic tests
  /** Reference date for certificate validity (ISO). Default: today if currentYear is this year, else 1 January of currentYear. */
  asOf?: string;
  defaults: {
    criticality: number;
    retentionYears: number;
    migrationYears: number;
    /** T_trust for signing keys without a validity period (code, firmware, document, KMS signing keys). */
    trustYears: number;
    exposure: { external: number; internal: number; unknown: number };
  };
  /**
   * V(v): how much of the Mosca window counts for a given protection status.
   * Not in the base formula; without it a node protected by ML-KEM would score
   * the same as one protected by RSA.
   */
  statusWeight: Record<EffectiveStatus, number>;
}

export const DEFAULT_RISK_CONFIG: RiskConfig = {
  qDayYear: 2033,
  currentYear: new Date().getUTCFullYear(),
  defaults: { criticality: 5, retentionYears: 5, migrationYears: 3, trustYears: 5, exposure: { external: 1.0, internal: 0.3, unknown: 0.5 } },
  statusWeight: { PLAINTEXT: 1, VULNERABLE_SHOR: 1, UNKNOWN: 0.5, DEGRADED_GROVER: 0.25, HYBRID: 0, SAFE_PQC: 0 },
};

export function resolveRiskConfig(partial: Partial<Omit<RiskConfig, "defaults">> & { defaults?: Partial<RiskConfig["defaults"]> } = {}): RiskConfig {
  return {
    ...DEFAULT_RISK_CONFIG,
    ...partial,
    defaults: { ...DEFAULT_RISK_CONFIG.defaults, ...partial.defaults, exposure: { ...DEFAULT_RISK_CONFIG.defaults.exposure, ...partial.defaults?.exposure } },
    statusWeight: { ...DEFAULT_RISK_CONFIG.statusWeight, ...partial.statusWeight },
  };
}

export interface RiskResult {
  id: string;
  score: number;
  status: EffectiveStatus;
  criticality: number;
  exposure: number;
  retentionYears: number;
  migrationYears: number;
  /** (T_retention + T_migration) - (T_Q-Day - now), before max(0, .) */
  moscaGapYears: number;
  drivers: string[];
  /** Trust now, forge later: signatures that must stay unforgeable past Q-Day. */
  tnfl: TnflResult;
  /** max(HNDL score, TNFL score); used for ranking. */
  combinedScore: number;
  primaryThreat: "HNDL" | "TNFL" | "none";
}

export interface TnflResult {
  score: number;
  /** Worst signature/authentication status observed; undefined when no signature evidence exists. */
  status?: EffectiveStatus;
  /** T_trust: how long signatures made or relied on here must stay unforgeable. */
  trustYears: number;
  /** (T_trust + T_migration) - (T_Q-Day - now), before max(0, .) */
  gapYears: number;
  drivers: string[];
}

// Higher = worse.
const SEVERITY: Record<EffectiveStatus, number> = { SAFE_PQC: 0, HYBRID: 1, DEGRADED_GROVER: 2, UNKNOWN: 3, VULNERABLE_SHOR: 4, PLAINTEXT: 5 };
export function worstStatus(statuses: Iterable<EffectiveStatus>): EffectiveStatus | undefined {
  let worst: EffectiveStatus | undefined;
  for (const s of statuses) if (worst === undefined || SEVERITY[s] > SEVERITY[worst]) worst = s;
  return worst;
}

const clamp = (x: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, x));
// Usages whose quantum break enables forgery (authentication, identity, signing). RSA keys in
// certificates are classified "public-key" and authenticate the holder.
const SIGNATURE_USAGES = new Set(["signature", "public-key"]);
const YEAR_MS = 365.25 * 86_400_000;

interface TnflBase {
  status?: EffectiveStatus;
  trustYears?: number;
  criticality?: number;
  exposure?: number;
  drivers: string[];
}

const CONFIDENTIALITY_USAGES = new Set(["key-exchange", "encryption", "public-key", "kem", "key-agree", "pke", "kdf", "mac", "unknown"]);

/**
 * Mosca / HNDL score:
 *   R(v) = C(v) * E(v) * V(v) * max(0, (T_retention(v) + T_migration(v)) - (T_Q-Day - T_now))
 * T_Q-Day is a calendar year, so it is converted to years-remaining before the subtraction.
 */
export function moscaScore(c: number, e: number, v: number, retentionYears: number, migrationYears: number, cfg: RiskConfig): { score: number; gap: number } {
  const gap = retentionYears + migrationYears - (cfg.qDayYear - cfg.currentYear);
  return { score: clamp(c, 1, 10) * clamp(e, 0.1, 1) * v * Math.max(0, gap), gap };
}

export class RiskEngine {
  private readonly cfg: RiskConfig;
  private readonly g: CryptoGraph;
  private readonly baseMemo = new Map<string, { status?: EffectiveStatus; drivers: string[] }>();
  private readonly effMemo = new Map<string, { status?: EffectiveStatus; exposure: number; drivers: string[] }>();
  private readonly results = new Map<string, RiskResult>();
  private readonly tnflMemo = new Map<string, TnflBase>();

  constructor(graph: CryptoGraph, cfg: RiskConfig = DEFAULT_RISK_CONFIG) {
    this.g = graph;
    this.cfg = cfg;
  }

  private ownExposure(v: Vertex): number {
    if (v.exposureFactor !== undefined) return clamp(v.exposureFactor, 0.1, 1);
    if (v.kind === "NetworkEndpoint") return this.cfg.defaults.exposure[v.posture];
    return this.cfg.defaults.exposure.unknown;
  }

  /** Crypto that directly protects v (own primitives, held material, mounted volumes). */
  private base(id: string, stack = new Set<string>()): { status?: EffectiveStatus; drivers: string[] } {
    const memo = this.baseMemo.get(id);
    if (memo) return memo;
    if (stack.has(id)) return { drivers: [] };
    stack.add(id);
    const v = this.g.get(id)!;
    let out: { status?: EffectiveStatus; drivers: string[] };
    if (v.kind === "CryptoPrimitive") {
      out = { status: v.status, drivers: [`${v.algorithm}: ${v.status}`] };
    } else {
      // Direct primitives (negotiated / configured on v) vs. primitives of held certificates and keys.
      // Held key material only drives HNDL status when v has no direct confidentiality crypto
      // (e.g. a file holding an RSA key), so a TLS endpoint's certificate does not mask its key exchange.
      const direct = new Map<string, CryptoPrimitive>();
      const held = new Map<string, CryptoPrimitive>();
      const visitMaterial = (mid: string) => {
        for (const e of this.g.outgoing(mid, ["ENCRYPTED_WITH"])) this.addPrim(held, e.to);
        for (const e of this.g.incoming(mid, ["SIGNS"])) this.addPrim(held, e.from);
      };
      for (const e of this.g.outgoing(id, ["ENCRYPTED_WITH", "CONTAINS_KEY", "DEPENDS_ON"])) {
        if (e.attrs?.offered === true) continue; // supported but not the effective choice
        const t = this.g.get(e.to)!;
        if (t.kind === "CryptoPrimitive") direct.set(t.id, t);
        else if (t.kind === "CryptoMaterial") visitMaterial(t.id);
      }
      if (v.kind === "CryptoMaterial") visitMaterial(id);
      const conf = [...direct.values()].filter((p) => CONFIDENTIALITY_USAGES.has(p.usage));
      const relevant = conf.length ? conf : [...direct.values(), ...held.values()];
      let status = worstStatus(relevant.map((p) => p.status));
      const drivers = relevant.filter((p) => p.status === status).map((p) => `${p.algorithm} (${p.usage}): ${p.status}`);
      for (const e of this.g.outgoing(id, ["MOUNTS"])) {
        const m = this.base(e.to, stack);
        if (m.status && (status === undefined || SEVERITY[m.status] > SEVERITY[status])) {
          status = m.status;
          drivers.push(`mounted ${e.to}: ${m.status}`);
        }
      }
      if (v.kind === "NetworkEndpoint" && v.classicalFallback) drivers.push("classical fallback accepted alongside PQ key exchange (downgrade exposure for non-PQ clients)");
      if (status === undefined && v.kind === "NetworkEndpoint" && v.protocol === "TCP") {
        status = "PLAINTEXT";
        drivers.push("no transport encryption observed");
      }
      out = { status, drivers: [...new Set(drivers)] };
    }
    stack.delete(id);
    this.baseMemo.set(id, out);
    return out;
  }

  private addPrim(into: Map<string, CryptoPrimitive>, id: string) {
    const p = this.g.get(id);
    if (p?.kind === "CryptoPrimitive") into.set(p.id, p);
  }

  /**
   * Effective protection after TERMINATES_AT: traffic for a backend crosses the network
   * under the terminator's crypto, so the backend inherits the terminator's status and exposure.
   */
  private effective(id: string, stack = new Set<string>()): { status?: EffectiveStatus; exposure: number; drivers: string[] } {
    const memo = this.effMemo.get(id);
    if (memo) return memo;
    const v = this.g.get(id)!;
    const own = this.base(id);
    if (stack.has(id)) return { status: own.status, exposure: this.ownExposure(v), drivers: own.drivers };
    stack.add(id);
    let status = own.status;
    let exposure = this.ownExposure(v);
    const drivers = [...own.drivers];
    for (const e of this.g.outgoing(id, ["TERMINATES_AT"])) {
      const t = this.effective(e.to, stack);
      if (t.exposure > exposure) {
        exposure = t.exposure;
        drivers.push(`exposure ${t.exposure} inherited via TERMINATES_AT ${e.to}`);
      }
      if (t.status && (status === undefined || status === "PLAINTEXT" || SEVERITY[t.status] > SEVERITY[status])) {
        drivers.push(`protected in transit by ${e.to} (${t.status})`);
        status = status === "PLAINTEXT" ? t.status : worstStatus([t.status, ...(status ? [status] : [])]);
      }
    }
    stack.delete(id);
    const out = { status, exposure, drivers };
    this.effMemo.set(id, out);
    return out;
  }

  /** Years from now until a certificate's notAfter (fractional), or undefined. */
  private remainingYears(notAfter: string | undefined): number | undefined {
    if (!notAfter) return undefined;
    const t = Date.parse(notAfter);
    if (Number.isNaN(t)) return undefined;
    const now = this.cfg.asOf ? Date.parse(this.cfg.asOf)
      : this.cfg.currentYear === new Date().getUTCFullYear() ? Date.now() : Date.UTC(this.cfg.currentYear, 0, 1);
    return Math.max(0, (t - now) / YEAR_MS);
  }

  /**
   * Trust-now-forge-later evidence for one vertex: the signature algorithms it relies on and how long
   * they must stay unforgeable. Certificates use their remaining validity (long-lived roots dominate);
   * signing keys without a validity use trustYears; holders and groups take the worst of what they hold.
   */
  private tnflBase(id: string, stack = new Set<string>()): TnflBase {
    const memo = this.tnflMemo.get(id);
    if (memo) return memo;
    if (stack.has(id)) return { drivers: [] };
    stack.add(id);
    const v = this.g.get(id)!;
    const out: TnflBase = { drivers: [] };
    const consider = (status: EffectiveStatus | undefined, trust: number | undefined, driver: string) => {
      if (status === undefined) return;
      if (out.status === undefined || SEVERITY[status] > SEVERITY[out.status]) out.status = status;
      if (trust !== undefined && SEVERITY[status] >= SEVERITY.DEGRADED_GROVER) out.trustYears = Math.max(out.trustYears ?? 0, trust);
      if (SEVERITY[status] >= SEVERITY.DEGRADED_GROVER) out.drivers.push(driver);
    };
    const defaultTrust = v.trustYears ?? this.cfg.defaults.trustYears;
    const sigPrims = (from: string, types: Array<"ENCRYPTED_WITH" | "DEPENDS_ON">) =>
      this.g.outgoing(from, types)
        .filter((e) => e.attrs?.offered !== true)
        .map((e) => this.g.get(e.to))
        .filter((p): p is CryptoPrimitive => p?.kind === "CryptoPrimitive" && SIGNATURE_USAGES.has(p.usage));

    if (v.kind === "CryptoMaterial") {
      if (v.materialType === "certificate") {
        const trust = v.trustYears ?? this.remainingYears(v.notAfter) ?? defaultTrust;
        const anchor = v.subject && v.subject === v.issuer ? "trust anchor " : "";
        for (const p of sigPrims(id, ["ENCRYPTED_WITH"])) consider(p.status, trust, `${anchor}certificate key ${p.algorithm} trusted ${trust.toFixed(1)} more years`);
        for (const e of this.g.incoming(id, ["SIGNS"])) {
          const s = this.g.get(e.from);
          if (s?.kind === "CryptoPrimitive") consider(s.status, trust, `signed with ${s.algorithm}`);
        }
      } else if (v.materialType !== "secret-key-ref") {
        for (const p of sigPrims(id, ["ENCRYPTED_WITH"])) consider(p.status, defaultTrust, `${p.algorithm} signing/identity key trusted ${defaultTrust} years`);
      }
    } else if (v.kind !== "CryptoPrimitive") {
      // Direct authentication primitives (SSH host keys, code-signing references).
      for (const p of sigPrims(id, ["ENCRYPTED_WITH", "DEPENDS_ON"])) consider(p.status, defaultTrust, `${p.algorithm} ${p.usage === "signature" ? "signatures" : "identity key"}`);
      // Held certificates/keys, member assets, and the terminator that authenticates for us.
      const related = [
        ...this.g.outgoing(id, ["CONTAINS_KEY", "MOUNTS", "TERMINATES_AT"]).map((e) => e.to),
        ...this.g.outgoing(id, ["DEPENDS_ON"]).map((e) => e.to).filter((t) => this.g.get(t)?.kind !== "CryptoPrimitive"),
      ];
      const relatedBases = related.map((t) => ({ t, r: this.tnflBase(t, stack) })).sort((a, b) => (b.r.trustYears ?? 0) - (a.r.trustYears ?? 0));
      for (const { t, r } of relatedBases) {
        if (r.status === undefined) continue;
        if (out.status === undefined || SEVERITY[r.status] > SEVERITY[out.status]) out.status = r.status;
        if (r.trustYears !== undefined) out.trustYears = Math.max(out.trustYears ?? 0, r.trustYears);
        if (r.criticality !== undefined) out.criticality = Math.max(out.criticality ?? 0, r.criticality);
        if (r.exposure !== undefined) out.exposure = Math.max(out.exposure ?? 0, r.exposure);
        if (SEVERITY[r.status] >= SEVERITY.DEGRADED_GROVER) out.drivers.push(`via ${this.g.get(t)?.label ?? t}: ${r.drivers[0] ?? r.status}`);
      }
    }
    // Certificates and keys inherit the criticality and exposure of the assets that present them.
    if (v.kind === "CryptoMaterial") {
      for (const e of this.g.incoming(id, ["CONTAINS_KEY"])) {
        const h = this.g.get(e.from)!;
        out.criticality = Math.max(out.criticality ?? 0, h.criticality ?? 0) || undefined;
        out.exposure = Math.max(out.exposure ?? 0, this.ownExposure(h));
      }
    }
    out.drivers = [...new Set(out.drivers)].slice(0, 6);
    stack.delete(id);
    this.tnflMemo.set(id, out);
    return out;
  }

  private tnfl(id: string, criticality: number, exposure: number, migration: number): TnflResult {
    const v = this.g.get(id)!;
    const b = this.tnflBase(id);
    if (b.status === undefined || b.trustYears === undefined) return { score: 0, status: b.status, trustYears: b.trustYears ?? 0, gapYears: 0, drivers: b.drivers };
    const c = Math.max(criticality, v.criticality === undefined ? b.criticality ?? 0 : 0) || criticality;
    const e = Math.max(exposure, b.exposure ?? 0);
    const trust = Math.round(b.trustYears * 10) / 10; // planning precision: 0.1 year
    const { score, gap } = moscaScore(c, e, this.cfg.statusWeight[b.status], trust, migration, this.cfg);
    return { score: round(score), status: b.status, trustYears: trust, gapYears: round(gap), drivers: b.drivers };
  }

  private score(id: string, stack = new Set<string>()): RiskResult {
    const done = this.results.get(id);
    if (done) return done;
    const v = this.g.get(id)!;
    const d = this.cfg.defaults;
    const eff = this.effective(id);
    let status = eff.status;
    let exposure = eff.exposure;
    let criticality = v.criticality ?? d.criticality;
    let retention = v.retentionYears ?? d.retentionYears;
    let migration = v.migrationYears ?? d.migrationYears;
    const drivers = [...eff.drivers];

    // DEPENDS_ON members propagate risk up to their parent (cluster / application).
    if (!stack.has(id)) {
      stack.add(id);
      for (const e of this.g.outgoing(id, ["DEPENDS_ON"])) {
        const child = this.g.get(e.to)!;
        if (child.kind === "CryptoPrimitive") continue; // already in base()
        const r = this.score(e.to, stack);
        if (status === undefined || SEVERITY[r.status] > SEVERITY[status]) status = r.status;
        if (r.exposure > exposure) exposure = r.exposure;
        if (v.kind === "ServiceGroup") {
          retention = Math.max(retention, r.retentionYears);
          migration = Math.max(migration, r.migrationYears);
        }
        if (r.score > 0) drivers.push(`depends on ${e.to} (R=${round(r.score)}, ${r.status}, E=${r.exposure})`);
      }
      stack.delete(id);
    }
    criticality = clamp(criticality, 1, 10);
    const finalStatus: EffectiveStatus = status ?? "UNKNOWN";
    const { score, gap } = moscaScore(criticality, exposure, this.cfg.statusWeight[finalStatus], retention, migration, this.cfg);
    const tnfl = this.tnfl(id, criticality, exposure, migration);
    // Certificates are identity objects: their quantum risk is forgery (TNFL). Static RSA key transport
    // is scored on the endpoint that negotiates it, not on the certificate.
    const isCertificate = v.kind === "CryptoMaterial" && v.materialType === "certificate";
    const hndl = isCertificate ? 0 : round(score);
    const combinedScore = Math.max(hndl, tnfl.score);
    const primaryThreat = combinedScore <= 0 ? "none" : tnfl.score > hndl ? "TNFL" : "HNDL";
    const res: RiskResult = { id, score: hndl, status: finalStatus, criticality, exposure, retentionYears: retention, migrationYears: migration, moscaGapYears: gap, drivers, tnfl, combinedScore, primaryThreat };
    this.results.set(id, res);
    return res;
  }

  /** Score every non-primitive vertex (primitives are inputs, not assets). Sorted by max(HNDL, TNFL) desc, then id. */
  run(): RiskResult[] {
    for (const v of this.g.allVertices()) if (v.kind !== "CryptoPrimitive") this.score(v.id);
    return [...this.results.values()].sort((a, b) => b.combinedScore - a.combinedScore || b.score - a.score || a.id.localeCompare(b.id));
  }
}

function round(x: number): number {
  return Math.round(x * 1000) / 1000;
}

export function scoreGraph(graph: CryptoGraph, cfg: RiskConfig = DEFAULT_RISK_CONFIG): RiskResult[] {
  return new RiskEngine(graph, cfg).run();
}
