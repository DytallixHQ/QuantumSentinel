import assert from "node:assert/strict";
import test from "node:test";
import { SccSolver } from "./scc.ts";

// Max of own weights over everything reachable: the closure the risk engine relies on.
function solver(edges: Record<string, string[]>, w: Record<string, number>) {
  return new SccSolver<number>(
    (id) => edges[id] ?? [],
    (id, get) => Math.max(w[id], ...(edges[id] ?? []).map((c) => get(c) ?? 0)),
  );
}

test("SccSolver: a cycle gets one value whichever member is asked first", () => {
  const edges = { a: ["b"], b: ["c"], c: ["a", "d"], d: [] };
  const w = { a: 1, b: 2, c: 3, d: 9 };
  for (const first of ["a", "b", "c", "d"]) {
    const s = solver(edges, w);
    s.get(first);
    assert.deepEqual(["a", "b", "c", "d"].map((x) => s.get(x)), [9, 9, 9, 9], `first=${first}`);
  }
});

test("SccSolver: max inside a cycle reaches every member, not only the entry point", () => {
  const s = solver({ a: ["b"], b: ["a"] }, { a: 0, b: 5 });
  assert.equal(s.get("a"), 5);
  assert.equal(s.get("b"), 5);
});

test("SccSolver: self loop and DAG", () => {
  assert.equal(solver({ a: ["a"] }, { a: 4 }).get("a"), 4);
  const s = solver({ a: ["b", "c"], b: ["d"], c: ["d"], d: [] }, { a: 1, b: 2, c: 7, d: 3 });
  assert.deepEqual([s.get("a"), s.get("b"), s.get("c"), s.get("d")], [7, 3, 7, 3]);
});
