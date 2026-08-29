import { describe, expect, it } from "vitest";

import type { AppGraph, Diff } from "./api";
import {
  applyFilters,
  computeFocus,
  edgeTroubled,
  fromApp,
  fromDiff,
  fromRaw,
} from "./display";

function appGraph(): AppGraph {
  const node = (
    id: string,
    category: "app" | "system" | "external" | "atlas",
    kind: "compose" | "container" | "process" | "external" = "process",
  ) => ({
    id,
    label: id.split(":").pop()!,
    category,
    kind,
    members: [id],
    memberCount: 1,
    firstSeen: "2026-08-29T12:00:00Z",
    lastSeen: "2026-08-29T12:00:00Z",
  });
  const edge = (src: string, dst: string, port: number) => ({
    id: `${src}->${dst}:${port}`,
    src,
    dst,
    dstPort: port,
    protocol: "tcp",
    connections: 5,
    activeConns: 1,
    bytesSent: 100,
    bytesRecv: 200,
    firstSeen: "2026-08-29T12:00:00Z",
    lastSeen: "2026-08-29T12:00:00Z",
    rawEdges: [],
  });
  return {
    generatedAt: "2026-08-29T12:00:00Z",
    nodes: [
      node("svc:compose:demo/gateway", "app", "compose"),
      node("svc:compose:demo/orders", "app", "compose"),
      node("svc:compose:demo/cache", "app", "compose"),
      node("svc:proc:dockerd", "system"),
      node("svc:proc:atlas", "atlas"),
      node("svc:external", "external", "external"),
    ],
    edges: [
      edge("svc:compose:demo/gateway", "svc:compose:demo/orders", 8000),
      edge("svc:compose:demo/orders", "svc:compose:demo/cache", 6379),
      edge("svc:proc:dockerd", "svc:external", 443),
    ],
  };
}

describe("applyFilters", () => {
  it("hides system and atlas nodes with their edges by default", () => {
    const g = applyFilters(fromApp(appGraph()), { showSystem: false, query: "" });
    const ids = g.nodes.map((n) => n.id);
    expect(ids).not.toContain("svc:proc:dockerd");
    expect(ids).not.toContain("svc:proc:atlas");
    expect(g.edges.map((e) => e.id)).not.toContain(
      "svc:proc:dockerd->svc:external:443",
    );
    // App content survives.
    expect(ids).toContain("svc:compose:demo/gateway");
    expect(g.edges).toHaveLength(2);
  });

  it("shows system when asked", () => {
    const g = applyFilters(fromApp(appGraph()), { showSystem: true, query: "" });
    expect(g.nodes.map((n) => n.id)).toContain("svc:proc:dockerd");
    expect(g.edges).toHaveLength(3);
  });
});

describe("computeFocus", () => {
  it("computes transitive upstream and downstream", () => {
    const g = fromApp(appGraph());
    const f = computeFocus(g, "svc:compose:demo/orders");
    expect([...f.downstream].sort()).toEqual([
      "svc:compose:demo/cache",
      "svc:compose:demo/orders",
    ]);
    expect([...f.upstream].sort()).toEqual([
      "svc:compose:demo/gateway",
      "svc:compose:demo/orders",
    ]);
  });

  it("blast radius of the gateway reaches the cache", () => {
    const g = fromApp(appGraph());
    const f = computeFocus(g, "svc:compose:demo/gateway");
    expect(f.downstream.has("svc:compose:demo/cache")).toBe(true);
    expect(f.upstream.has("svc:compose:demo/cache")).toBe(false);
  });
});

describe("fromDiff", () => {
  it("marks added, removed and changed elements", () => {
    const b = appGraph();
    const removedNode = {
      id: "svc:compose:demo/inventory",
      label: "inventory",
      category: "app" as const,
      kind: "compose" as const,
      members: [],
      memberCount: 1,
      firstSeen: "2026-08-29T11:00:00Z",
      lastSeen: "2026-08-29T11:30:00Z",
    };
    const diff: Diff = {
      a: "2026-08-29T11:00:00Z",
      b: "2026-08-29T12:00:00Z",
      addedNodes: [b.nodes[2]!],
      removedNodes: [removedNode],
      addedEdges: [b.edges[1]!],
      removedEdges: [
        {
          ...b.edges[0]!,
          id: "svc:compose:demo/orders->svc:compose:demo/inventory:8000",
          src: "svc:compose:demo/orders",
          dst: "svc:compose:demo/inventory",
        },
      ],
      changedEdges: [
        {
          edge: b.edges[0]!,
          changes: ["failures", "rtt"],
          aConnections: 1,
          aFailures: 0,
          aResets: 0,
          aRetransmits: 0,
          aRttAvgUs: 100,
          aBytesSent: 0,
          aBytesRecv: 0,
        },
      ],
    };
    const g = fromDiff(diff, b);

    const byId = new Map(g.nodes.map((n) => [n.id, n]));
    expect(byId.get("svc:compose:demo/cache")?.diff).toBe("added");
    expect(byId.get("svc:compose:demo/inventory")?.diff).toBe("removed");

    const edges = new Map(g.edges.map((e) => [e.id, e]));
    expect(edges.get(b.edges[1]!.id)?.diff).toBe("added");
    expect(edges.get(b.edges[0]!.id)?.diff).toBe("changed");
    expect(edges.get(b.edges[0]!.id)?.changes).toContain("failures");
    expect(
      edges.get("svc:compose:demo/orders->svc:compose:demo/inventory:8000")?.diff,
    ).toBe("removed");
  });
});

describe("fromRaw", () => {
  it("maps kinds to symbols", () => {
    const g = fromRaw({
      version: 1,
      generatedAt: "2026-08-29T12:00:00Z",
      nodes: [
        {
          id: "container:abc",
          kind: "container",
          label: "cache",
          firstSeen: "2026-08-29T12:00:00Z",
          lastSeen: "2026-08-29T12:00:00Z",
        },
        {
          id: "ext:1.2.3.4",
          kind: "external",
          label: "1.2.3.4",
          firstSeen: "2026-08-29T12:00:00Z",
          lastSeen: "2026-08-29T12:00:00Z",
        },
      ],
      edges: [],
    });
    expect(g.nodes[0]!.symbol).toBe("container");
    expect(g.nodes[1]!.symbol).toBe("external");
    expect(g.nodes[1]!.category).toBe("external");
  });
});

describe("edgeTroubled", () => {
  it("prefers window trouble over lifetime counters", () => {
    const base = fromApp(appGraph()).edges[0]!;
    expect(edgeTroubled(base)).toBe(false);
    expect(edgeTroubled({ ...base, failures: 3 })).toBe(true);
    expect(
      edgeTroubled({
        ...base,
        failures: 3,
        window: {
          seconds: 60, opens: 0, closes: 0, failures: 0, resets: 0,
          retransmits: 0, bytesSent: 0, bytesRecv: 0, rttAvgUs: 0,
          rttMaxUs: 0, activeEnd: 0,
        },
      }),
    ).toBe(false); // old failures, quiet window
  });
});
