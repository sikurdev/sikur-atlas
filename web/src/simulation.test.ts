import { describe, expect, it } from "vitest";

import type { GraphSnapshot, NodeData } from "./api";
import { GraphSim } from "./simulation";

function node(id: string): NodeData {
  return {
    id,
    kind: "process",
    label: id,
    firstSeen: "2026-08-29T12:00:00Z",
    lastSeen: "2026-08-29T12:00:00Z",
  };
}

function snap(nodes: string[], edges: [string, string][]): GraphSnapshot {
  return {
    version: 1,
    generatedAt: "2026-08-29T12:00:00Z",
    nodes: nodes.map(node),
    edges: edges.map(([src, dst]) => ({
      id: `${src}->${dst}:80`,
      src,
      dst,
      dstPort: 80,
      protocol: "tcp",
      connections: 1,
      activeConns: 0,
      bytesSent: 0,
      bytesRecv: 0,
      firstSeen: "2026-08-29T12:00:00Z",
      lastSeen: "2026-08-29T12:00:00Z",
    })),
  };
}

describe("GraphSim", () => {
  it("keeps positions stable across snapshot updates", () => {
    const sim = new GraphSim();
    sim.update(snap(["a", "b"], [["a", "b"]]));
    const a1 = sim.nodes().find((n) => n.id === "a")!;
    a1.x = 123;
    a1.y = 456;

    sim.update(snap(["a", "b", "c"], [["a", "b"], ["a", "c"]]));
    const a2 = sim.nodes().find((n) => n.id === "a")!;
    expect(a2).toBe(a1); // same object, layout state preserved
    expect(a2.x).toBe(123);
    sim.stop();
  });

  it("adds new nodes near an existing neighbor", () => {
    const sim = new GraphSim();
    sim.update(snap(["a"], []));
    const a = sim.nodes()[0]!;
    a.x = 1000;
    a.y = 1000;

    sim.update(snap(["a", "b"], [["a", "b"]]));
    const b = sim.nodes().find((n) => n.id === "b")!;
    const dist = Math.hypot((b.x ?? 0) - 1000, (b.y ?? 0) - 1000);
    expect(dist).toBeLessThan(300);
    sim.stop();
  });

  it("drops vanished nodes and their edges", () => {
    const sim = new GraphSim();
    sim.update(snap(["a", "b"], [["a", "b"]]));
    sim.update(snap(["a"], []));
    expect(sim.nodes().map((n) => n.id)).toEqual(["a"]);
    expect(sim.edges()).toHaveLength(0);
    sim.stop();
  });

  it("exposes edges with resolved endpoints", () => {
    const sim = new GraphSim();
    sim.update(snap(["a", "b"], [["a", "b"]]));
    const e = sim.edges()[0]!;
    expect((e.source as { id: string }).id).toBe("a");
    expect((e.target as { id: string }).id).toBe("b");
    sim.stop();
  });
});
