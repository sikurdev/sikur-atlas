// Layered left-to-right layout for the Overview mode: clients on the
// left, the services they depend on to the right. Deterministic and
// cycle-tolerant.
import type { DisplayGraph } from "./display";

export interface Position {
  x: number;
  y: number;
}

const LAYER_GAP = 260;
const ROW_GAP = 96;

export function layeredLayout(g: DisplayGraph): Map<string, Position> {
  const ids = g.nodes.map((n) => n.id).sort();
  const index = new Map(ids.map((id, i) => [id, i]));

  // Forward adjacency, minus back edges discovered by DFS, so cycles
  // don't break the layering.
  const adj = new Map<string, string[]>(ids.map((id) => [id, []]));
  const edges = [...g.edges].sort((a, b) => a.id.localeCompare(b.id));
  const backEdges = findBackEdges(ids, edges);
  for (const e of edges) {
    if (!index.has(e.src) || !index.has(e.dst)) continue;
    if (backEdges.has(e.id)) continue;
    adj.get(e.src)!.push(e.dst);
  }

  // Longest-path layering: layer(n) = 1 + max(layer of callers).
  const layer = new Map<string, number>(ids.map((id) => [id, 0]));
  // Relax in topological-ish order: iterate until fixpoint (bounded by
  // node count; back edges were removed so this terminates).
  for (let pass = 0; pass < ids.length; pass++) {
    let moved = false;
    for (const id of ids) {
      const base = layer.get(id)!;
      for (const next of adj.get(id) ?? []) {
        if (layer.get(next)! < base + 1) {
          layer.set(next, base + 1);
          moved = true;
        }
      }
    }
    if (!moved) break;
  }

  // Group by layer, initial order alphabetical.
  const layers = new Map<number, string[]>();
  for (const id of ids) {
    const l = layer.get(id)!;
    (layers.get(l) ?? layers.set(l, []).get(l)!).push(id);
  }
  const layerNums = [...layers.keys()].sort((a, b) => a - b);

  // Barycenter ordering: two sweeps aligning nodes with the average row
  // of their neighbors in the previous layer.
  const rowOf = new Map<string, number>();
  for (const l of layerNums) {
    layers.get(l)!.forEach((id, i) => rowOf.set(id, i));
  }
  const neighbors = new Map<string, string[]>(ids.map((id) => [id, []]));
  for (const e of edges) {
    if (!index.has(e.src) || !index.has(e.dst)) continue;
    neighbors.get(e.src)!.push(e.dst);
    neighbors.get(e.dst)!.push(e.src);
  }
  for (let sweep = 0; sweep < 2; sweep++) {
    for (const l of sweep % 2 === 0 ? layerNums : [...layerNums].reverse()) {
      const row = layers.get(l)!;
      const scored = row.map((id) => {
        const ns = neighbors.get(id) ?? [];
        const rows = ns
          .filter((n) => layer.get(n) !== l)
          .map((n) => rowOf.get(n) ?? 0);
        const score =
          rows.length > 0 ? rows.reduce((a, b) => a + b, 0) / rows.length : rowOf.get(id)!;
        return { id, score };
      });
      scored.sort((a, b) => a.score - b.score || a.id.localeCompare(b.id));
      scored.forEach((s, i) => rowOf.set(s.id, i));
      layers.set(
        l,
        scored.map((s) => s.id),
      );
    }
  }

  const positions = new Map<string, Position>();
  const maxRows = Math.max(...layerNums.map((l) => layers.get(l)!.length), 1);
  for (const l of layerNums) {
    const row = layers.get(l)!;
    const offset = ((maxRows - row.length) * ROW_GAP) / 2;
    row.forEach((id, i) => {
      positions.set(id, {
        x: l * LAYER_GAP,
        y: offset + i * ROW_GAP,
      });
    });
  }

  // Center around the origin so the canvas centers nicely.
  let cx = 0;
  let cy = 0;
  for (const p of positions.values()) {
    cx += p.x;
    cy += p.y;
  }
  if (positions.size > 0) {
    cx /= positions.size;
    cy /= positions.size;
    for (const p of positions.values()) {
      p.x -= cx;
      p.y -= cy;
    }
  }
  return positions;
}

/** DFS back-edge detection over deterministic ordering. */
function findBackEdges(
  ids: string[],
  edges: { id: string; src: string; dst: string }[],
): Set<string> {
  const out = new Map<string, { id: string; dst: string }[]>(
    ids.map((id) => [id, []]),
  );
  for (const e of edges) {
    out.get(e.src)?.push({ id: e.id, dst: e.dst });
  }
  const WHITE = 0,
    GREY = 1,
    BLACK = 2;
  const color = new Map<string, number>(ids.map((id) => [id, WHITE]));
  const back = new Set<string>();

  const visit = (start: string) => {
    const stack: { node: string; edgeIdx: number }[] = [
      { node: start, edgeIdx: 0 },
    ];
    color.set(start, GREY);
    while (stack.length > 0) {
      const top = stack[stack.length - 1]!;
      const outEdges = out.get(top.node) ?? [];
      if (top.edgeIdx >= outEdges.length) {
        color.set(top.node, BLACK);
        stack.pop();
        continue;
      }
      const e = outEdges[top.edgeIdx]!;
      top.edgeIdx++;
      const c = color.get(e.dst);
      if (c === GREY) {
        back.add(e.id);
      } else if (c === WHITE) {
        color.set(e.dst, GREY);
        stack.push({ node: e.dst, edgeIdx: 0 });
      }
    }
  };
  for (const id of ids) {
    if (color.get(id) === WHITE) visit(id);
  }
  return back;
}
