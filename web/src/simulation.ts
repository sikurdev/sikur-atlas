// Force-layout wrapper that keeps node positions stable across live
// snapshot updates: nodes are matched by id, new nodes enter near an
// already-placed neighbor, vanished nodes are dropped.
import {
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  forceX,
  forceY,
  type Simulation,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from "d3-force";

import type { EdgeData, GraphSnapshot, NodeData } from "./api";

export interface SimNode extends SimulationNodeDatum {
  id: string;
  data: NodeData;
}

export interface SimEdge extends SimulationLinkDatum<SimNode> {
  id: string;
  data: EdgeData;
}

export class GraphSim {
  private sim: Simulation<SimNode, SimEdge>;
  private nodesById = new Map<string, SimNode>();
  private simEdges: SimEdge[] = [];
  private seq = 0;

  constructor() {
    this.sim = forceSimulation<SimNode>([])
      .force("charge", forceManyBody<SimNode>().strength(-380).distanceMax(600))
      .force("x", forceX<SimNode>(0).strength(0.045))
      .force("y", forceY<SimNode>(0).strength(0.06))
      .force("collide", forceCollide<SimNode>(44))
      .stop();
  }

  /** Merge a fresh snapshot, preserving existing layout state. */
  update(snapshot: GraphSnapshot): void {
    const seen = new Set<string>();
    for (const data of snapshot.nodes) {
      seen.add(data.id);
      const existing = this.nodesById.get(data.id);
      if (existing) {
        existing.data = data;
        continue;
      }
      const node: SimNode = { id: data.id, data };
      const anchor = this.anchorFor(data.id, snapshot.edges);
      // Deterministic pseudo-random spread so simultaneous arrivals fan
      // out instead of stacking.
      const angle = (this.seq++ * 2.399963) % (2 * Math.PI); // golden angle
      const r = 60 + 30 * (this.seq % 3);
      node.x = (anchor?.x ?? 0) + r * Math.cos(angle);
      node.y = (anchor?.y ?? 0) + r * Math.sin(angle);
      this.nodesById.set(data.id, node);
    }
    for (const id of this.nodesById.keys()) {
      if (!seen.has(id)) this.nodesById.delete(id);
    }

    this.simEdges = snapshot.edges
      .filter((e) => this.nodesById.has(e.src) && this.nodesById.has(e.dst))
      .map((e) => ({
        id: e.id,
        source: this.nodesById.get(e.src)!,
        target: this.nodesById.get(e.dst)!,
        data: e,
      }));

    const nodes = [...this.nodesById.values()];
    this.sim.nodes(nodes);
    this.sim.force(
      "link",
      forceLink<SimNode, SimEdge>(this.simEdges)
        .id((n) => n.id)
        .distance(150)
        .strength(0.35),
    );
    this.sim.alpha(Math.max(this.sim.alpha(), 0.5)).restart();
  }

  private anchorFor(id: string, edges: EdgeData[]): SimNode | undefined {
    for (const e of edges) {
      if (e.src === id && this.nodesById.has(e.dst)) {
        return this.nodesById.get(e.dst);
      }
      if (e.dst === id && this.nodesById.has(e.src)) {
        return this.nodesById.get(e.src);
      }
    }
    return undefined;
  }

  nodes(): SimNode[] {
    return this.sim.nodes();
  }

  edges(): SimEdge[] {
    return this.simEdges;
  }

  onTick(cb: () => void): void {
    this.sim.on("tick", cb);
  }

  /** Pin a node to a dragged position. */
  pin(id: string, x: number, y: number): void {
    const n = this.nodesById.get(id);
    if (!n) return;
    n.fx = x;
    n.fy = y;
    this.sim.alpha(Math.max(this.sim.alpha(), 0.25)).restart();
  }

  unpin(id: string): void {
    const n = this.nodesById.get(id);
    if (!n) return;
    n.fx = null;
    n.fy = null;
  }

  stop(): void {
    this.sim.stop();
  }
}
