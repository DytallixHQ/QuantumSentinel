import { createHash } from "node:crypto";
import type { Edge, EdgeType, Evidence, Vertex, VertexKind } from "./types.ts";

export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

/** Canonical primitive ID: SHA-256(alg || curve/modulus || key_size || usage). */
export function canonicalPrimitiveId(alg: string, curveOrModulus: string | undefined, keySize: number | undefined, usage: string): string {
  return sha256Hex([alg.toUpperCase(), curveOrModulus ?? "", keySize ?? "", usage].join("||"));
}

function edgeKey(from: string, type: EdgeType, to: string): string {
  return `${from}\u0000${type}\u0000${to}`;
}

function mergeEvidence(into: Evidence[], extra: Evidence[] | undefined): void {
  if (!extra) return;
  const seen = new Set(into.map((e) => `${e.source}|${e.locator}|${e.detail ?? ""}`));
  for (const e of extra) {
    const k = `${e.source}|${e.locator}|${e.detail ?? ""}`;
    if (!seen.has(k)) {
      seen.add(k);
      into.push(e);
    }
  }
}

export type Direction = "out" | "in" | "both";

/** In-memory attributed graph with indexed bidirectional adjacency. */
export class CryptoGraph {
  private readonly vertices = new Map<string, Vertex>();
  private readonly edges = new Map<string, Edge>();
  private readonly outIdx = new Map<string, Set<string>>();
  private readonly inIdx = new Map<string, Set<string>>();

  /**
   * Insert a vertex. A vertex with an existing ID is merged: evidence is unioned and
   * risk inputs take the maximum, so the same certificate seen on many hosts is one node.
   */
  addVertex<V extends Vertex>(v: V): V {
    const existing = this.vertices.get(v.id) as V | undefined;
    if (!existing) {
      const copy = { ...v, evidence: [...v.evidence] };
      this.vertices.set(v.id, copy);
      return copy;
    }
    if (existing.kind !== v.kind) throw new Error(`vertex ${v.id} kind conflict: ${existing.kind} vs ${v.kind}`);
    mergeEvidence(existing.evidence, v.evidence);
    for (const k of ["criticality", "exposureFactor", "retentionYears", "migrationYears"] as const) {
      const n = v[k];
      if (n !== undefined) existing[k] = Math.max(existing[k] ?? n, n);
    }
    for (const [k, val] of Object.entries(v)) {
      const rec = existing as unknown as Record<string, unknown>;
      if (rec[k] === undefined && val !== undefined) rec[k] = val;
    }
    return existing;
  }

  addEdge(from: string, type: EdgeType, to: string, attrs?: Edge["attrs"], evidence?: Evidence[]): Edge {
    if (!this.vertices.has(from)) throw new Error(`edge source missing: ${from}`);
    if (!this.vertices.has(to)) throw new Error(`edge target missing: ${to}`);
    const key = edgeKey(from, type, to);
    const existing = this.edges.get(key);
    if (existing) {
      if (evidence) mergeEvidence((existing.evidence ??= []), evidence);
      if (attrs) existing.attrs = { ...existing.attrs, ...attrs };
      return existing;
    }
    const e: Edge = { from, to, type, ...(attrs ? { attrs } : {}), ...(evidence ? { evidence: [...evidence] } : {}) };
    this.edges.set(key, e);
    if (!this.outIdx.has(from)) this.outIdx.set(from, new Set());
    if (!this.inIdx.has(to)) this.inIdx.set(to, new Set());
    this.outIdx.get(from)!.add(key);
    this.inIdx.get(to)!.add(key);
    return e;
  }

  get(id: string): Vertex | undefined {
    return this.vertices.get(id);
  }

  has(id: string): boolean {
    return this.vertices.has(id);
  }

  allVertices(kind?: VertexKind): Vertex[] {
    const all = [...this.vertices.values()];
    return kind ? all.filter((v) => v.kind === kind) : all;
  }

  allEdges(type?: EdgeType): Edge[] {
    const all = [...this.edges.values()];
    return type ? all.filter((e) => e.type === type) : all;
  }

  outgoing(id: string, types?: EdgeType[]): Edge[] {
    return this.select(this.outIdx.get(id), types);
  }

  incoming(id: string, types?: EdgeType[]): Edge[] {
    return this.select(this.inIdx.get(id), types);
  }

  private select(keys: Set<string> | undefined, types?: EdgeType[]): Edge[] {
    if (!keys) return [];
    const out: Edge[] = [];
    for (const k of keys) {
      const e = this.edges.get(k)!;
      if (!types || types.includes(e.type)) out.push(e);
    }
    return out;
  }

  /** Breadth-first traversal; cycle-safe. Returns reachable vertex IDs excluding the start. */
  reachable(start: string, direction: Direction = "out", types?: EdgeType[], maxDepth = Infinity): string[] {
    const seen = new Set([start]);
    const order: string[] = [];
    let frontier = [start];
    for (let depth = 0; frontier.length && depth < maxDepth; depth++) {
      const next: string[] = [];
      for (const id of frontier) {
        const nbrs: string[] = [];
        if (direction !== "in") for (const e of this.outgoing(id, types)) nbrs.push(e.to);
        if (direction !== "out") for (const e of this.incoming(id, types)) nbrs.push(e.from);
        for (const n of nbrs) {
          if (seen.has(n)) continue;
          seen.add(n);
          order.push(n);
          next.push(n);
        }
      }
      frontier = next;
    }
    return order;
  }

  /** Merge another graph (e.g. from a parallel ingestor) into this one. */
  merge(other: CryptoGraph): this {
    for (const v of other.allVertices()) this.addVertex(v);
    for (const e of other.allEdges()) this.addEdge(e.from, e.type, e.to, e.attrs, e.evidence);
    return this;
  }

  get size(): { vertices: number; edges: number } {
    return { vertices: this.vertices.size, edges: this.edges.size };
  }

  /** Deterministic serialization (sorted), suitable for golden tests and diffing. */
  toJSON(): { vertices: Vertex[]; edges: Edge[] } {
    const vertices = [...this.vertices.values()].sort((a, b) => a.id.localeCompare(b.id));
    const edges = [...this.edges.values()].sort((a, b) =>
      edgeKey(a.from, a.type, a.to).localeCompare(edgeKey(b.from, b.type, b.to)),
    );
    return { vertices, edges };
  }
}
