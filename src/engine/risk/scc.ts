/**
 * Memoised solver for values propagated along graph edges that may form cycles.
 *
 * Every propagated quantity in the risk engine is an idempotent maximum (worst status, largest
 * exposure, longest trust), so its value is the same for every vertex of a strongly connected
 * component. A plain recursive memo cuts a cycle wherever it first re-enters a vertex and stores
 * the truncated value, so results depended on vertex order. Here Tarjan's algorithm finds the
 * components, which complete in reverse topological order (successors first); each component is
 * then iterated to a fixed point. In a call to `local`, `get` returns the solved value of a successor
 * in an earlier component, the current estimate for a member of the same component, or undefined
 * before the first estimate exists.
 */
export class SccSolver<T> {
  private readonly solved = new Map<string, T>();
  private readonly index = new Map<string, number>();
  private readonly low = new Map<string, number>();
  private readonly onStack = new Set<string>();
  private readonly stack: string[] = [];
  private counter = 0;
  private readonly succ: (id: string) => string[];
  private readonly local: (id: string, get: (child: string) => T | undefined) => T;

  constructor(succ: (id: string) => string[], local: (id: string, get: (child: string) => T | undefined) => T) {
    this.succ = succ;
    this.local = local;
  }

  get(id: string): T {
    const done = this.solved.get(id);
    if (done !== undefined) return done;
    this.connect(id);
    return this.solved.get(id)!;
  }

  private connect(v: string): void {
    this.index.set(v, this.counter);
    this.low.set(v, this.counter);
    this.counter++;
    this.stack.push(v);
    this.onStack.add(v);
    for (const w of this.succ(v)) {
      if (this.solved.has(w)) continue;
      if (!this.index.has(w)) {
        this.connect(w);
        this.low.set(v, Math.min(this.low.get(v)!, this.low.get(w)!));
      } else if (this.onStack.has(w)) {
        this.low.set(v, Math.min(this.low.get(v)!, this.index.get(w)!));
      }
    }
    if (this.low.get(v) !== this.index.get(v)) return;
    const members: string[] = [];
    let w: string;
    do {
      w = this.stack.pop()!;
      this.onStack.delete(w);
      members.push(w);
    } while (w !== v);
    this.solveComponent(members);
  }

  private solveComponent(members: string[]): void {
    const estimate = new Map<string, T>();
    const get = (c: string) => this.solved.get(c) ?? estimate.get(c);
    const selfLoop = members.length === 1 && this.succ(members[0]).includes(members[0]);
    const passes = members.length === 1 && !selfLoop ? 1 : 2 * members.length + 2;
    for (let i = 0; i < passes; i++) {
      let changed = false;
      for (const m of members) {
        const next = this.local(m, get);
        const prev = estimate.get(m);
        if (prev === undefined || JSON.stringify(prev) !== JSON.stringify(next)) changed = true;
        estimate.set(m, next);
      }
      if (!changed) break;
    }
    for (const m of members) this.solved.set(m, estimate.get(m)!);
  }
}
