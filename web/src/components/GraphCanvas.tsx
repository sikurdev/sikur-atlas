import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import type { DisplayEdge, DisplayGraph, DisplayNode, FocusSets } from "../display";
import { edgeTroubled, matchesQuery } from "../display";
import { layeredLayout, type Position } from "../layout";
import type { Selection } from "../selection";
import { GraphSim, type SimNode } from "../simulation";

interface Props {
  graph: DisplayGraph;
  layout: "overview" | "explore";
  selection: Selection | null;
  onSelect: (sel: Selection | null) => void;
  query: string;
  focus: FocusSets | null;
  /** Reference time for "recent traffic" styling: now when live, the
   * viewed moment in replay. */
  refTimeMs: number;
}

interface Viewport {
  x: number;
  y: number;
  k: number;
}

function isRecent(lastSeen: string, refMs: number): boolean {
  return refMs - new Date(lastSeen).getTime() < 5000;
}

function edgeWidth(connections: number): number {
  return Math.min(1 + Math.log2(connections + 1), 6);
}

export function GraphCanvas({
  graph,
  layout,
  selection,
  onSelect,
  query,
  focus,
  refTimeMs,
}: Props) {
  const svgRef = useRef<SVGSVGElement>(null);
  const simRef = useRef<GraphSim | null>(null);
  const [, setFrame] = useState(0);
  const [viewport, setViewport] = useState<Viewport>({ x: 0, y: 0, k: 1 });
  const [panning, setPanning] = useState(false);
  const dragRef = useRef<{
    mode: "pan" | "node";
    nodeId?: string;
    startX: number;
    startY: number;
    moved: boolean;
    viewport: Viewport;
  } | null>(null);

  if (simRef.current === null) {
    simRef.current = new GraphSim();
  }
  const sim = simRef.current;

  useEffect(() => {
    sim.onTick(() => setFrame((f) => f + 1));
    return () => sim.stop();
  }, [sim]);

  // The sim is kept in sync in every layout mode, so switching back to
  // explore never paints a frame of stale nodes.
  useEffect(() => {
    sim.update(graph);
    setFrame((f) => f + 1);
  }, [graph, sim]);

  const layered = useMemo<Map<string, Position>>(
    () => (layout === "overview" ? layeredLayout(graph) : new Map()),
    [graph, layout],
  );

  // Center the origin in the visible canvas.
  const [size, setSize] = useState({ w: 800, h: 600 });
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const rect = entries[0]?.contentRect;
      if (rect) setSize({ w: rect.width, h: rect.height });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const positionOf = useCallback(
    (id: string): Position | null => {
      if (layout === "overview") {
        return layered.get(id) ?? null;
      }
      const n = sim.byId(id);
      if (!n || n.x == null || n.y == null) return null;
      return { x: n.x, y: n.y };
    },
    [layout, layered, sim],
  );

  const toWorld = useCallback(
    (clientX: number, clientY: number) => {
      const rect = svgRef.current!.getBoundingClientRect();
      const px = clientX - rect.left - size.w / 2 - viewport.x;
      const py = clientY - rect.top - size.h / 2 - viewport.y;
      return { x: px / viewport.k, y: py / viewport.k };
    },
    [size, viewport],
  );

  const onWheel = useCallback(
    (e: React.WheelEvent) => {
      const factor = Math.exp(-e.deltaY * 0.0015);
      setViewport((v) => {
        const k = Math.min(4, Math.max(0.2, v.k * factor));
        const rect = svgRef.current!.getBoundingClientRect();
        const cx = e.clientX - rect.left - size.w / 2;
        const cy = e.clientY - rect.top - size.h / 2;
        const scale = k / v.k;
        return {
          k,
          x: cx - (cx - v.x) * scale,
          y: cy - (cy - v.y) * scale,
        };
      });
    },
    [size],
  );

  const onPointerDown = useCallback(
    (e: React.PointerEvent) => {
      (e.target as Element).setPointerCapture?.(e.pointerId);
      const nodeEl = (e.target as Element).closest?.("[data-node-id]");
      if (nodeEl) {
        dragRef.current = {
          mode: "node",
          nodeId: nodeEl.getAttribute("data-node-id")!,
          startX: e.clientX,
          startY: e.clientY,
          moved: false,
          viewport,
        };
      } else {
        dragRef.current = {
          mode: "pan",
          startX: e.clientX,
          startY: e.clientY,
          moved: false,
          viewport,
        };
        setPanning(true);
      }
    },
    [viewport],
  );

  const onPointerMove = useCallback(
    (e: React.PointerEvent) => {
      const drag = dragRef.current;
      if (!drag) return;
      const dx = e.clientX - drag.startX;
      const dy = e.clientY - drag.startY;
      if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
      if (drag.mode === "pan") {
        setViewport({
          ...drag.viewport,
          x: drag.viewport.x + dx,
          y: drag.viewport.y + dy,
        });
      } else if (drag.nodeId && drag.moved && layout === "explore") {
        const p = toWorld(e.clientX, e.clientY);
        sim.pin(drag.nodeId, p.x, p.y);
      }
    },
    [sim, toWorld, layout],
  );

  const onPointerUp = useCallback(
    (e: React.PointerEvent) => {
      const drag = dragRef.current;
      dragRef.current = null;
      setPanning(false);
      if (!drag) return;
      if (drag.mode === "node" && drag.nodeId) {
        if (layout === "explore") sim.unpin(drag.nodeId);
        if (!drag.moved) {
          onSelect({ type: "node", id: drag.nodeId });
        }
      } else if (drag.mode === "pan" && !drag.moved) {
        onSelect(null);
      }
      e.preventDefault();
    },
    [sim, onSelect, layout],
  );

  const q = query.trim().toLowerCase();

  const touchingEdges = useMemo(() => {
    if (selection?.type !== "node") return new Set<string>();
    const set = new Set<string>();
    for (const e of graph.edges) {
      if (e.src === selection.id || e.dst === selection.id) set.add(e.id);
    }
    return set;
  }, [selection, graph.edges]);

  const inFocus = useCallback(
    (id: string) =>
      focus == null || focus.upstream.has(id) || focus.downstream.has(id),
    [focus],
  );

  const emptyGraph = graph.nodes.length === 0;
  // In explore mode positions come from the sim's node objects, so
  // render order follows the sim; in overview follow the graph.
  const renderNodes: { id: string; data: DisplayNode }[] =
    layout === "explore"
      ? sim.nodes().map((n: SimNode) => ({ id: n.id, data: n.data }))
      : graph.nodes.map((n) => ({ id: n.id, data: n }));

  return (
    <div className="canvas-wrap">
      <svg
        ref={svgRef}
        className={panning ? "panning" : undefined}
        onWheel={onWheel}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        data-testid="graph-canvas"
      >
        <defs>
          <pattern
            id="graticule"
            width="30"
            height="30"
            patternUnits="userSpaceOnUse"
          >
            <circle cx="1" cy="1" r="1" fill="var(--line-faint)" />
          </pattern>
          {/* userSpaceOnUse keeps arrowheads a constant size instead of
              scaling with edge width. */}
          {["arrow", "arrow-accent", "arrow-hazard"].map((id) => (
            <marker
              key={id}
              id={id}
              viewBox="0 0 8 8"
              refX="7"
              refY="4"
              markerWidth="9"
              markerHeight="9"
              markerUnits="userSpaceOnUse"
              orient="auto-start-reverse"
            >
              <path
                d="M0,0.6 L7.2,4 L0,7.4 z"
                fill={
                  id === "arrow-accent"
                    ? "var(--accent)"
                    : id === "arrow-hazard"
                      ? "var(--hazard)"
                      : "var(--water)"
                }
              />
            </marker>
          ))}
        </defs>
        <g
          transform={`translate(${size.w / 2 + viewport.x}, ${size.h / 2 + viewport.y}) scale(${viewport.k})`}
        >
          <rect
            x={-8000}
            y={-8000}
            width={16000}
            height={16000}
            fill="url(#graticule)"
          />
          <g>
            {graph.edges.map((e) => {
              const sp = positionOf(e.src);
              const tp = positionOf(e.dst);
              if (!sp || !tp) return null;
              return (
                <EdgePath
                  key={e.id}
                  edge={e}
                  sp={sp}
                  tp={tp}
                  selected={selection?.type === "edge" && selection.id === e.id}
                  touching={touchingEdges.has(e.id)}
                  dimmed={!inFocus(e.src) || !inFocus(e.dst)}
                  recent={isRecent(e.lastSeen, refTimeMs)}
                  onSelect={onSelect}
                />
              );
            })}
          </g>
          <g>
            {renderNodes.map(({ id, data }) => {
              const p = positionOf(id);
              if (!p) return null;
              const isMatch = q === "" || matchesQuery(data, q);
              return (
                <NodeMark
                  key={id}
                  node={data}
                  pos={p}
                  selected={selection?.type === "node" && selection.id === id}
                  dimmed={(q !== "" && !isMatch) || !inFocus(id)}
                />
              );
            })}
          </g>
        </g>
      </svg>
      {emptyGraph && (
        <div className="empty-hint">
          <p>
            Nothing to show here. Atlas draws TCP connections from the moment
            they are opened — make one:
          </p>
          <p>
            <code>curl example.com</code>
          </p>
        </div>
      )}
    </div>
  );
}

function EdgePath({
  edge,
  sp,
  tp,
  selected,
  touching,
  dimmed,
  recent,
  onSelect,
}: {
  edge: DisplayEdge;
  sp: Position;
  tp: Position;
  selected: boolean;
  touching: boolean;
  dimmed: boolean;
  recent: boolean;
  onSelect: (sel: Selection) => void;
}) {
  const dx = tp.x - sp.x;
  const dy = tp.y - sp.y;
  const len = Math.hypot(dx, dy) || 1;
  const off = Math.min(24, len * 0.12);
  const mx = (sp.x + tp.x) / 2;
  const my = (sp.y + tp.y) / 2;
  const cx = mx - (dy / len) * off;
  const cy = my + (dx / len) * off;
  const trim = 22 / len;
  const x1 = sp.x + dx * trim * 0.9;
  const y1 = sp.y + dy * trim * 0.9;
  const x2 = tp.x - dx * trim;
  const y2 = tp.y - dy * trim;
  const d = `M${x1},${y1} Q${cx},${cy} ${x2},${y2}`;

  const troubled = edgeTroubled(edge) || edge.diff === "removed";
  const highlight = selected || touching;
  const isUnix = edge.protocol === "unix";
  const cls = [
    "edge",
    selected && "selected",
    touching && "touching",
    dimmed && "dimmed",
    troubled && "troubled",
    isUnix && "unix",
    edge.diff && `diff-${edge.diff}`,
    edge.activeConns > 0 && "active",
  ]
    .filter(Boolean)
    .join(" ");

  const marker = highlight
    ? "url(#arrow-accent)"
    : troubled
      ? "url(#arrow-hazard)"
      : "url(#arrow)";
  return (
    <g data-testid="edge">
      <path
        className={cls}
        d={d}
        strokeWidth={edgeWidth(edge.connections)}
        markerEnd={marker}
        strokeDasharray={
          edge.diff === "removed"
            ? "3 5"
            : isUnix
              ? "2 4"
              : recent && !highlight
                ? "7 3"
                : undefined
        }
      />
      <path
        className="edge-hit"
        d={d}
        onPointerUp={(e) => {
          e.stopPropagation();
          onSelect({ type: "edge", id: edge.id });
        }}
      />
      {(highlight || edge.diff === "changed") && (
        <text className="edge-label" x={cx} y={cy - 6}>
          {isUnix ? (edge.path ?? "unix") : `:${edge.dstPort}`}
          {highlight ? ` · ${edge.connections} conn` : ""}
          {edge.diff === "changed" ? " · changed" : ""}
        </text>
      )}
    </g>
  );
}

function NodeMark({
  node,
  pos,
  selected,
  dimmed,
}: {
  node: DisplayNode;
  pos: Position;
  selected: boolean;
  dimmed: boolean;
}) {
  const ports = node.listenPorts;
  const cls = [
    "node",
    `kind-${node.symbol}`,
    `cat-${node.category}`,
    selected && "selected",
    dimmed && "dimmed",
    node.diff && `diff-${node.diff}`,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <g
      className={cls}
      transform={`translate(${pos.x}, ${pos.y})`}
      data-node-id={node.id}
      data-testid="node"
      data-diff={node.diff ?? undefined}
    >
      {node.symbol === "process" && <circle className="symbol" r="15" />}
      {node.symbol === "container" && (
        <rect className="symbol" x="-14" y="-14" width="28" height="28" rx="2" />
      )}
      {node.symbol === "compose" && (
        <>
          <rect
            className="symbol-echo"
            x="-11"
            y="-17"
            width="28"
            height="28"
            rx="2"
          />
          <rect className="symbol" x="-17" y="-11" width="28" height="28" rx="2" />
        </>
      )}
      {node.symbol === "external" && (
        <rect
          className="symbol"
          x="-11.5"
          y="-11.5"
          width="23"
          height="23"
          transform="rotate(45)"
        />
      )}
      {node.memberCount > 1 && (
        <g transform="translate(16, -16)">
          <circle className="badge" r="9" />
          <text className="badge-text" y="3">
            {node.memberCount}
          </text>
        </g>
      )}
      {node.diff === "added" && (
        <text className="diff-mark" x="-24" y="-14">
          +
        </text>
      )}
      {node.diff === "removed" && (
        <text className="diff-mark removed" x="-24" y="-14">
          −
        </text>
      )}
      <text className="node-label" y="34">
        {node.label}
      </text>
      {ports.length > 0 && (
        <text className="ports" y="48" textAnchor="middle">
          :{ports.slice(0, 4).join(" :")}
          {ports.length > 4 ? " …" : ""}
        </text>
      )}
    </g>
  );
}
