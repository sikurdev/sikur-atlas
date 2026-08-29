// DisplayGraph is the single shape GraphCanvas renders, produced from
// the raw view, the application view, or a compare diff. Pure functions,
// unit-tested.
import type {
  AppEdge,
  AppGraph,
  AppNode,
  Diff,
  EdgeData,
  EdgeWindow,
  GraphSnapshot,
  NodeData,
} from "./api";

export type DiffMark = "added" | "removed" | "changed";

export interface DisplayNode {
  id: string;
  label: string;
  symbol: "process" | "container" | "compose" | "external";
  category: "app" | "system" | "external" | "atlas";
  memberCount: number;
  listenPorts: number[];
  diff?: DiffMark;
  raw?: NodeData;
  app?: AppNode;
}

export interface DisplayEdge {
  id: string;
  src: string;
  dst: string;
  dstPort: number;
  connections: number;
  activeConns: number;
  failures: number;
  resets: number;
  retransmits: number;
  rttAvgUs: number;
  lastSeen: string;
  window?: EdgeWindow;
  diff?: DiffMark;
  changes?: string[];
  raw?: EdgeData;
  app?: AppEdge;
}

export interface DisplayGraph {
  nodes: DisplayNode[];
  edges: DisplayEdge[];
}

export function fromRaw(snap: GraphSnapshot): DisplayGraph {
  return {
    nodes: (snap.nodes ?? []).map((n) => ({
      id: n.id,
      label: n.label,
      symbol: n.kind === "container" ? "container" : n.kind === "external" ? "external" : "process",
      category: n.kind === "external" ? "external" : "app",
      memberCount: 1,
      listenPorts: n.listenPorts ?? [],
      raw: n,
    })),
    edges: (snap.edges ?? []).map(displayEdgeFromRaw),
  };
}

function displayEdgeFromRaw(e: EdgeData): DisplayEdge {
  return {
    id: e.id,
    src: e.src,
    dst: e.dst,
    dstPort: e.dstPort,
    connections: e.connections,
    activeConns: e.activeConns,
    failures: e.failures ?? 0,
    resets: e.resets ?? 0,
    retransmits: e.retransmits ?? 0,
    rttAvgUs: e.window?.rttAvgUs ?? e.lastRttUs ?? 0,
    lastSeen: e.lastSeen,
    window: e.window,
    raw: e,
  };
}

export function fromApp(app: AppGraph): DisplayGraph {
  return {
    nodes: (app.nodes ?? []).map(displayNodeFromApp),
    edges: (app.edges ?? []).map(displayEdgeFromApp),
  };
}

function displayNodeFromApp(n: AppNode): DisplayNode {
  return {
    id: n.id,
    label: n.label,
    symbol: n.kind,
    category: n.category,
    memberCount: n.memberCount,
    listenPorts: n.listenPorts ?? [],
    app: n,
  };
}

function displayEdgeFromApp(e: AppEdge): DisplayEdge {
  return {
    id: e.id,
    src: e.src,
    dst: e.dst,
    dstPort: e.dstPort,
    connections: e.connections,
    activeConns: e.activeConns,
    failures: e.failures ?? 0,
    resets: e.resets ?? 0,
    retransmits: e.retransmits ?? 0,
    rttAvgUs: e.window?.rttAvgUs ?? e.lastRttUs ?? 0,
    lastSeen: e.lastSeen,
    window: e.window,
    app: e,
  };
}

/** Builds the compare display: everything at B, plus what A lost
 * (marked removed), with added/changed marks applied. */
export function fromDiff(diff: Diff, bView: AppGraph): DisplayGraph {
  const g = fromApp(bView);
  const added = new Set((diff.addedNodes ?? []).map((n) => n.id));
  const addedE = new Set((diff.addedEdges ?? []).map((e) => e.id));
  const changed = new Map(
    (diff.changedEdges ?? []).map((c) => [c.edge.id, c.changes]),
  );

  for (const n of g.nodes) {
    if (added.has(n.id)) n.diff = "added";
  }
  for (const e of g.edges) {
    if (addedE.has(e.id)) e.diff = "added";
    else if (changed.has(e.id)) {
      e.diff = "changed";
      e.changes = changed.get(e.id);
    }
  }
  const present = new Set(g.nodes.map((n) => n.id));
  for (const n of diff.removedNodes ?? []) {
    // The diff and the B view come from two requests; if a flush landed
    // between them a "removed" node can also exist in B. Never draw a
    // duplicate id.
    if (present.has(n.id)) continue;
    const dn = displayNodeFromApp(n);
    dn.diff = "removed";
    g.nodes.push(dn);
    present.add(dn.id);
  }
  const edgeIDs = new Set(g.edges.map((e) => e.id));
  for (const e of diff.removedEdges ?? []) {
    // Only draw removed edges whose endpoints are drawable, once.
    if (!present.has(e.src) || !present.has(e.dst) || edgeIDs.has(e.id)) continue;
    const de = displayEdgeFromApp(e);
    de.diff = "removed";
    g.edges.push(de);
  }
  return g;
}

export interface Filters {
  showSystem: boolean;
  query: string;
}

/** Which nodes match the search query (empty query matches all). */
export function matchesQuery(n: DisplayNode, q: string): boolean {
  if (q === "") return true;
  const hay = [
    n.label,
    n.raw?.exe,
    n.raw?.containerName,
    n.app?.exe,
    n.app?.image,
    ...(n.raw?.addrs ?? []),
  ];
  return hay.some((h) => h?.toLowerCase().includes(q));
}

/** Applies visibility filters: hidden nodes drop with their edges. */
export function applyFilters(g: DisplayGraph, f: Filters): DisplayGraph {
  const visible = new Set<string>();
  const nodes = g.nodes.filter((n) => {
    if (!f.showSystem && (n.category === "system" || n.category === "atlas")) {
      return false;
    }
    visible.add(n.id);
    return true;
  });
  const edges = g.edges.filter((e) => visible.has(e.src) && visible.has(e.dst));
  return { nodes, edges };
}

export interface FocusSets {
  upstream: Set<string>;
  downstream: Set<string>;
}

/** Focus: the full upstream (callers, transitively) and downstream
 * (dependencies, transitively — the blast radius) of a node. Both sets
 * include the focus node itself. */
export function computeFocus(g: DisplayGraph, nodeId: string): FocusSets {
  const out = new Map<string, string[]>();
  const in_ = new Map<string, string[]>();
  for (const e of g.edges) {
    (out.get(e.src) ?? out.set(e.src, []).get(e.src)!).push(e.dst);
    (in_.get(e.dst) ?? in_.set(e.dst, []).get(e.dst)!).push(e.src);
  }
  const walk = (start: string, adj: Map<string, string[]>): Set<string> => {
    const seen = new Set<string>([start]);
    const queue = [start];
    while (queue.length > 0) {
      const cur = queue.pop()!;
      for (const next of adj.get(cur) ?? []) {
        if (!seen.has(next)) {
          seen.add(next);
          queue.push(next);
        }
      }
    }
    return seen;
  };
  return {
    downstream: walk(nodeId, out),
    upstream: walk(nodeId, in_),
  };
}

/** True when an edge saw trouble (failures, resets) in the shown data. */
export function edgeTroubled(e: DisplayEdge): boolean {
  if (e.window) {
    return e.window.failures > 0 || e.window.resets > 0;
  }
  return e.failures > 0 || e.resets > 0;
}
