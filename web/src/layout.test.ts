import { describe, expect, it } from "vitest";

import type { DisplayGraph } from "./display";
import { layeredLayout } from "./layout";

function graph(edges: [string, string][]): DisplayGraph {
  const ids = new Set(edges.flat());
  return {
    nodes: [...ids].map((id) => ({
      id,
      label: id,
      symbol: "process",
      category: "app",
      memberCount: 1,
      listenPorts: [],
    })),
    edges: edges.map(([src, dst]) => ({
      id: `${src}->${dst}:1`,
      src,
      dst,
      dstPort: 1,
      connections: 1,
      activeConns: 0,
      failures: 0,
      resets: 0,
      retransmits: 0,
      rttAvgUs: 0,
      lastSeen: "2026-08-29T12:00:00Z",
    })),
  };
}

describe("layeredLayout", () => {
  it("places dependencies to the right of their callers", () => {
    const g = graph([
      ["loadgen", "gateway"],
      ["gateway", "orders"],
      ["gateway", "users"],
      ["orders", "cache"],
      ["users", "cache"],
    ]);
    const pos = layeredLayout(g);
    expect(pos.get("loadgen")!.x).toBeLessThan(pos.get("gateway")!.x);
    expect(pos.get("gateway")!.x).toBeLessThan(pos.get("orders")!.x);
    expect(pos.get("orders")!.x).toBeLessThan(pos.get("cache")!.x);
    // Same layer shares an x.
    expect(pos.get("orders")!.x).toBe(pos.get("users")!.x);
    // Same layer never overlaps.
    expect(pos.get("orders")!.y).not.toBe(pos.get("users")!.y);
  });

  it("tolerates cycles", () => {
    const g = graph([
      ["a", "b"],
      ["b", "c"],
      ["c", "a"], // back edge
      ["c", "d"],
    ]);
    const pos = layeredLayout(g);
    expect(pos.size).toBe(4);
    // The forward chain still layers left to right.
    expect(pos.get("a")!.x).toBeLessThan(pos.get("b")!.x);
    expect(pos.get("b")!.x).toBeLessThan(pos.get("c")!.x);
  });

  it("is deterministic", () => {
    const g = graph([
      ["x", "y"],
      ["x", "z"],
      ["y", "w"],
      ["z", "w"],
    ]);
    const a = layeredLayout(g);
    const b = layeredLayout(g);
    for (const [id, p] of a) {
      expect(b.get(id)).toEqual(p);
    }
  });

  it("handles an empty graph", () => {
    expect(layeredLayout({ nodes: [], edges: [] }).size).toBe(0);
  });
});
