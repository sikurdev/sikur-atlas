import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import type { GraphSnapshot } from "../api";
import { GraphSim, type SimEdge, type SimNode } from "../simulation";
import type { Selection } from "../selection";

interface Props {
  snapshot: GraphSnapshot | null;
  selection: Selection | null;
  onSelect: (sel: Selection | null) => void;
  query: string;
}

interface Viewport {
  x: number;
  y: number;
  k: number;
}

/** True while an edge saw traffic in the last few seconds. */
function isRecent(lastSeen: string, now: number): boolean {
  return now - new Date(lastSeen).getTime() < 5000;
}

function edgeWidth(connections: number): number {
  return Math.min(1 + Math.log2(connections + 1), 6);
}

function matches(node: SimNode, q: string): boolean {
  const hay = [
    node.data.label,
    node.data.exe,
    node.data.containerName,
    ...(node.data.addrs ?? []),
  ];
  return hay.some((h) => h?.toLowerCase().includes(q));
}

export function GraphCanvas({ snapshot, selection, onSelect, query }: Props) {
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

  useEffect(() => {
    if (snapshot) {
      sim.update(snapshot);
      setFrame((f) => f + 1);
    }
  }, [snapshot, sim]);

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
        // Keep the point under the cursor fixed while zooming.
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
        const nodeId = nodeEl.getAttribute("data-node-id")!;
        dragRef.current = {
          mode: "node",
          nodeId,
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
      } else if (drag.nodeId && drag.moved) {
        const p = toWorld(e.clientX, e.clientY);
        sim.pin(drag.nodeId, p.x, p.y);
      }
    },
    [sim, toWorld],
  );

  const onPointerUp = useCallback(
    (e: React.PointerEvent) => {
      const drag = dragRef.current;
      dragRef.current = null;
      setPanning(false);
      if (!drag) return;
      if (drag.mode === "node" && drag.nodeId) {
        sim.unpin(drag.nodeId);
        if (!drag.moved) {
          onSelect({ type: "node", id: drag.nodeId });
        }
      } else if (drag.mode === "pan" && !drag.moved) {
        onSelect(null);
      }
      e.preventDefault();
    },
    [sim, onSelect],
  );

  const nodes = sim.nodes();
  const edges = sim.edges();
  const now = Date.now();
  const q = query.trim().toLowerCase();

  const touchingEdges = useMemo(() => {
    if (selection?.type !== "node") return new Set<string>();
    const set = new Set<string>();
    for (const e of edges) {
      if (e.data.src === selection.id || e.data.dst === selection.id) {
        set.add(e.id);
      }
    }
    return set;
  }, [selection, edges]);

  const emptyGraph = !snapshot || snapshot.nodes.length === 0;

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
          <marker
            id="arrow"
            viewBox="0 0 8 8"
            refX="7"
            refY="4"
            markerWidth="7"
            markerHeight="7"
            orient="auto-start-reverse"
          >
            <path d="M0,0.6 L7.2,4 L0,7.4 z" fill="var(--water)" />
          </marker>
          <marker
            id="arrow-accent"
            viewBox="0 0 8 8"
            refX="7"
            refY="4"
            markerWidth="7"
            markerHeight="7"
            orient="auto-start-reverse"
          >
            <path d="M0,0.6 L7.2,4 L0,7.4 z" fill="var(--accent)" />
          </marker>
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
            {edges.map((e) => (
              <EdgePath
                key={e.id}
                edge={e}
                selected={selection?.type === "edge" && selection.id === e.id}
                touching={touchingEdges.has(e.id)}
                dimmed={
                  (q !== "" || selection?.type === "node") &&
                  !touchingEdges.has(e.id) &&
                  !(selection?.type === "edge" && selection.id === e.id) &&
                  selection?.type !== undefined
                }
                recent={isRecent(e.data.lastSeen, now)}
                onSelect={onSelect}
              />
            ))}
          </g>
          <g>
            {nodes.map((n) => {
              const isMatch = q === "" || matches(n, q);
              const isSelected =
                selection?.type === "node" && selection.id === n.id;
              return (
                <NodeMark
                  key={n.id}
                  node={n}
                  selected={isSelected}
                  dimmed={q !== "" && !isMatch}
                />
              );
            })}
          </g>
        </g>
      </svg>
      {emptyGraph && (
        <div className="empty-hint">
          <p>
            No connections observed yet. Atlas shows TCP connections from the
            moment they are opened — make one:
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
  selected,
  touching,
  dimmed,
  recent,
  onSelect,
}: {
  edge: SimEdge;
  selected: boolean;
  touching: boolean;
  dimmed: boolean;
  recent: boolean;
  onSelect: (sel: Selection) => void;
}) {
  const s = edge.source as SimNode;
  const t = edge.target as SimNode;
  if (s.x == null || t.x == null || s.y == null || t.y == null) return null;

  // Slight arc so opposite-direction edges don't overlap.
  const mx = (s.x + t.x) / 2;
  const my = (s.y + t.y) / 2;
  const dx = t.x - s.x;
  const dy = t.y - s.y;
  const len = Math.hypot(dx, dy) || 1;
  const off = Math.min(24, len * 0.12);
  const cx = mx - (dy / len) * off;
  const cy = my + (dx / len) * off;
  // Trim the path so the arrow lands on the symbol edge, not its center.
  const trim = 22 / len;
  const x1 = s.x + dx * trim * 0.9;
  const y1 = s.y + dy * trim * 0.9;
  const x2 = t.x - dx * trim;
  const y2 = t.y - dy * trim;
  const d = `M${x1},${y1} Q${cx},${cy} ${x2},${y2}`;

  const cls = [
    "edge",
    selected && "selected",
    touching && "touching",
    dimmed && "dimmed",
    edge.data.activeConns > 0 && "active",
  ]
    .filter(Boolean)
    .join(" ");

  const highlight = selected || touching;
  return (
    <g data-testid="edge">
      <path
        className={cls}
        d={d}
        strokeWidth={edgeWidth(edge.data.connections)}
        markerEnd={highlight ? "url(#arrow-accent)" : "url(#arrow)"}
        strokeDasharray={recent && !highlight ? "7 3" : undefined}
      />
      <path
        className="edge-hit"
        d={d}
        onPointerUp={(e) => {
          e.stopPropagation();
          onSelect({ type: "edge", id: edge.id });
        }}
      />
      {highlight && (
        <text className="edge-label" x={cx} y={cy - 6}>
          :{edge.data.dstPort} · {edge.data.connections} conn
        </text>
      )}
    </g>
  );
}

function NodeMark({
  node,
  selected,
  dimmed,
}: {
  node: SimNode;
  selected: boolean;
  dimmed: boolean;
}) {
  const { x = 0, y = 0 } = node;
  const kind = node.data.kind;
  const ports = node.data.listenPorts ?? [];
  const cls = ["node", `kind-${kind}`, selected && "selected", dimmed && "dimmed"]
    .filter(Boolean)
    .join(" ");

  return (
    <g
      className={cls}
      transform={`translate(${x}, ${y})`}
      data-node-id={node.id}
      data-testid="node"
    >
      {kind === "process" && <circle className="symbol" r="15" />}
      {kind === "container" && (
        <rect className="symbol" x="-14" y="-14" width="28" height="28" rx="2" />
      )}
      {kind === "external" && (
        <rect
          className="symbol"
          x="-11.5"
          y="-11.5"
          width="23"
          height="23"
          transform="rotate(45)"
        />
      )}
      <text y="32">{node.data.label}</text>
      {ports.length > 0 && (
        <text className="ports" y="46" textAnchor="middle">
          :{ports.slice(0, 4).join(" :")}
          {ports.length > 4 ? " …" : ""}
        </text>
      )}
    </g>
  );
}
