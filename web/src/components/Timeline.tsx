import { useCallback, useEffect, useRef, useState } from "react";

import { fetchTimeline, type TimelinePayload } from "../api";

export type TimeMode =
  | { kind: "live" }
  | { kind: "at"; at: number }
  | { kind: "compare"; a: number; b: number };

interface Props {
  mode: TimeMode;
  pinnedA: number | null;
  historyEnabled: boolean;
  onScrub: (at: number) => void;
  onLive: () => void;
  onPinA: () => void;
  onClearCompare: () => void;
}

const RANGE_SECONDS = 15 * 60;
const VB_W = 720;
const VB_H = 46;

function fmtClock(unix: number): string {
  const d = new Date(unix * 1000);
  return d.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/** The Replay timeline: activity history, scrubbing, and compare
 * pinning. Clicking picks a moment; LIVE returns to now. */
export function Timeline({
  mode,
  pinnedA,
  historyEnabled,
  onScrub,
  onLive,
  onPinA,
  onClearCompare,
}: Props) {
  const [data, setData] = useState<TimelinePayload | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    if (!historyEnabled) return;
    let stopped = false;
    const load = async () => {
      const now = Math.floor(Date.now() / 1000);
      try {
        const payload = await fetchTimeline(now - RANGE_SECONDS, now, 10);
        if (!stopped) setData(payload);
      } catch {
        // Timeline is decorative when the backend hiccups; retry next tick.
      }
    };
    void load();
    const t = setInterval(load, 10_000);
    return () => {
      stopped = true;
      clearInterval(t);
    };
  }, [historyEnabled]);

  const pickTime = useCallback(
    (e: React.PointerEvent<SVGSVGElement>) => {
      if (!data) return;
      const rect = svgRef.current!.getBoundingClientRect();
      const frac = Math.min(1, Math.max(0, (e.clientX - rect.left) / rect.width));
      const t = Math.round(data.from + frac * (data.to - data.from));
      onScrub(t);
    },
    [data, onScrub],
  );

  if (!historyEnabled) return null;

  const maxOpens = Math.max(1, ...(data?.buckets ?? []).map((b) => b.opens));
  const toX = (unix: number) =>
    data ? ((unix - data.from) / Math.max(1, data.to - data.from)) * VB_W : 0;

  const cursorAt =
    mode.kind === "at" ? mode.at : mode.kind === "compare" ? mode.b : null;

  return (
    <div className="timeline" data-testid="timeline">
      <div className="timeline-controls">
        <button
          className={`pill ${mode.kind === "live" ? "on" : ""}`}
          onClick={onLive}
          data-testid="btn-live"
        >
          ● LIVE
        </button>
        <span className="timeline-mode" data-testid="time-mode">
          {mode.kind === "live" && "streaming"}
          {mode.kind === "at" && `viewing ${fmtClock(mode.at)}`}
          {mode.kind === "compare" &&
            `comparing ${fmtClock(mode.a)} → ${fmtClock(mode.b)}`}
        </span>
        <span className="spacer" />
        {mode.kind === "at" && (
          <button className="pill" onClick={onPinA} data-testid="btn-pin-a">
            {pinnedA == null ? "Pin A for compare" : "Repin A"}
          </button>
        )}
        {pinnedA != null && mode.kind !== "compare" && (
          <span className="timeline-hint">
            A = {fmtClock(pinnedA)} — pick B on the timeline
          </span>
        )}
        {mode.kind === "compare" && (
          <button
            className="pill"
            onClick={onClearCompare}
            data-testid="btn-exit-compare"
          >
            ✕ exit compare
          </button>
        )}
      </div>
      <svg
        ref={svgRef}
        className="timeline-strip"
        viewBox={`0 0 ${VB_W} ${VB_H}`}
        preserveAspectRatio="none"
        onPointerUp={pickTime}
        data-testid="timeline-strip"
      >
        {data?.buckets.map((b) => {
          const x = toX(b.start);
          const w = (data.step / Math.max(1, data.to - data.from)) * VB_W;
          const h = (b.opens / maxOpens) * (VB_H - 14);
          return (
            <g key={b.start}>
              {b.opens > 0 && (
                <rect
                  className="tl-activity"
                  x={x}
                  y={VB_H - 10 - h}
                  width={Math.max(1, w - 1)}
                  height={h}
                />
              )}
              {b.failures > 0 && (
                <rect
                  className="tl-failures"
                  x={x}
                  y={VB_H - 8}
                  width={Math.max(1, w - 1)}
                  height={5}
                />
              )}
            </g>
          );
        })}
        {pinnedA != null && data && (
          <line
            className="tl-pin"
            x1={toX(pinnedA)}
            x2={toX(pinnedA)}
            y1={0}
            y2={VB_H}
          />
        )}
        {cursorAt != null && data && (
          <line
            className="tl-cursor"
            x1={toX(cursorAt)}
            x2={toX(cursorAt)}
            y1={0}
            y2={VB_H}
          />
        )}
        {data && (
          <line className="tl-axis" x1={0} x2={VB_W} y1={VB_H - 9.5} y2={VB_H - 9.5} />
        )}
      </svg>
    </div>
  );
}
