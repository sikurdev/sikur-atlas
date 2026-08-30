import type { LensFinding, LensReport } from "../api";
import type { Selection } from "../selection";

// Human titles for the finding kinds (lens/v1 rule set).
const KIND_TITLES: Record<string, string> = {
  oom: "OOM kill",
  "oom-cgroup": "OOM kill (cgroup)",
  crash: "crash",
  exit: "exit",
  "exit-clean": "exited (clean)",
  exec: "started",
  "service-gone": "disappeared",
  "service-back": "back",
  "listen-lost": "stopped listening",
  "rss-pressure": "memory pressure",
  throttle: "CPU throttled",
  "failures-start": "failures began",
  "failures-end": "failures ceased",
  "resets-spike": "resets",
  "retrans-spike": "retransmits",
  "traffic-stop": "traffic stopped",
  "traffic-resume": "traffic resumed",
  "chronic-failure": "failing since before window",
};

// Tone per kind: hazard for degradation, ok for recovery.
const RECOVERY_KINDS = new Set([
  "failures-end",
  "traffic-resume",
  "service-back",
  "exec",
]);

function clock(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

interface Props {
  report: LensReport | null; // null while loading
  error: string | null;
  onClose: () => void;
  // Jump the timeline into Replay at a moment (unix seconds).
  onJump: (t: number) => void;
  onSelect: (sel: Selection | null) => void;
  onFocus: (id: string | null) => void;
  onCompareAround: (a: number, b: number) => void;
}

export function LensPanel({
  report,
  error,
  onClose,
  onJump,
  onSelect,
  onFocus,
  onCompareAround,
}: Props) {
  return (
    <aside className="lens-panel" data-testid="lens-panel">
      <div className="lens-head">
        <h2>Incident Lens</h2>
        <button
          className="pill"
          onClick={onClose}
          data-testid="btn-lens-close"
        >
          Close
        </button>
      </div>
      {report == null && error == null && (
        <p className="legend-note">investigating…</p>
      )}
      {error != null && <p className="legend-note warn">{error}</p>}
      {report != null && <LensBody report={report} {...bodyProps()} />}
    </aside>
  );

  function bodyProps() {
    return { onJump, onSelect, onFocus, onCompareAround };
  }
}

function LensBody({
  report,
  onJump,
  onSelect,
  onFocus,
  onCompareAround,
}: {
  report: LensReport;
  onJump: (t: number) => void;
  onSelect: (sel: Selection | null) => void;
  onFocus: (id: string | null) => void;
  onCompareAround: (a: number, b: number) => void;
}) {
  const findings = report.findings ?? [];
  const chronic = report.chronic ?? [];
  const recovery = report.recovery ?? [];
  const blastServices = report.blastRadius.services ?? [];
  const blastEdges = report.blastRadius.edges ?? [];
  const fromU = Math.floor(new Date(report.from).getTime() / 1000);
  const toU = Math.floor(new Date(report.to).getTime() / 1000);

  const label = (id: string) => report.labels[id] ?? id;

  return (
    <>
      <p className="kind-tag">
        {clock(report.from)} → {clock(report.to)}
        {report.service ? ` · focused on ${label(report.service)}` : ""}
      </p>

      {report.origin != null && (
        <section className="lens-origin" data-testid="lens-origin">
          <h3>
            likely origin <span className="lens-badge inference">inference</span>
          </h3>
          <p className="lens-origin-name">
            <button
              className="linkish"
              onClick={() => onSelect({ type: "node", id: report.origin!.service })}
            >
              {report.origin.label}
            </button>{" "}
            <span className="mono">{clock(report.origin.time)}</span>
          </p>
          <p className="lens-explain">{report.origin.explanation}</p>
          <div className="actions">
            <button
              className="pill"
              onClick={() => onFocus(report.origin!.service)}
              data-testid="btn-lens-focus-origin"
            >
              Focus origin
            </button>
            <button
              className="pill"
              onClick={() =>
                onJump(Math.floor(new Date(report.origin!.time).getTime() / 1000))
              }
              data-testid="btn-lens-origin-moment"
            >
              View moment
            </button>
            <button
              className="pill"
              onClick={() => {
                const t = Math.floor(
                  new Date(report.origin!.time).getTime() / 1000,
                );
                onCompareAround(Math.max(fromU, t - 60), Math.min(toU, t + 120));
              }}
              data-testid="btn-lens-compare-around"
            >
              Compare around
            </button>
          </div>
        </section>
      )}
      {report.origin == null && report.unresolved && (
        <section className="lens-origin" data-testid="lens-unresolved">
          <h3>origin unresolved</h3>
          <p className="lens-explain">{report.unresolved}</p>
        </section>
      )}
      {report.origin == null && !report.unresolved && (
        <p className="legend-note" data-testid="lens-quiet">
          Nothing notable recorded in this window.
        </p>
      )}

      {findings.length > 0 && (
        <section>
          <h3>evidence chain</h3>
          <ol className="lens-chain" data-testid="lens-chain">
            {findings.map((f, i) => (
              <FindingRow
                key={i}
                f={f}
                originIdx={report.origin?.findingIndex ?? -1}
                idx={i}
                onJump={onJump}
                onSelect={onSelect}
              />
            ))}
          </ol>
        </section>
      )}

      {(blastServices.length > 0 || blastEdges.length > 0) && (
        <section data-testid="lens-blast">
          <h3>blast radius</h3>
          <ul className="change-list">
            {blastServices.map((s) => (
              <li key={s} className="warn">
                <button
                  className="linkish"
                  onClick={() => onSelect({ type: "node", id: s })}
                >
                  {label(s)}
                </button>
              </li>
            ))}
            {blastEdges.map((e) => (
              <li key={e} className="warn">
                <button
                  className="linkish"
                  onClick={() => onSelect({ type: "edge", id: e })}
                >
                  {edgeLabel(e, report)}
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}

      {recovery.length > 0 && (
        <section data-testid="lens-recovery">
          <h3>recovery</h3>
          <ul className="change-list">
            {recovery.map((r, i) => (
              <li key={i} className={r.recoveredAt ? "add" : ""}>
                {r.subject.includes("->")
                  ? edgeLabel(r.subject, report)
                  : label(r.subject)}
                {": "}
                {r.recoveredAt
                  ? `${r.detail} at ${clock(r.recoveredAt)}`
                  : r.detail}
              </li>
            ))}
          </ul>
        </section>
      )}

      {chronic.length > 0 && (
        <details className="lens-chronic" data-testid="lens-chronic">
          <summary>
            chronic context ({chronic.length}) — failing since before this
            window
          </summary>
          <ul className="change-list">
            {chronic.map((f, i) => (
              <li key={i}>
                {f.edge ? edgeLabel(f.edge, report) : f.label}: {f.detail}
              </li>
            ))}
          </ul>
        </details>
      )}

      <p className="legend-note">
        Findings are recorded facts with timestamps; only the origin and
        propagation lines are inference, from the documented {report.ruleSet}{" "}
        rules. No model, no scores.
      </p>
    </>
  );
}

function edgeLabel(edgeID: string, report: LensReport): string {
  // Service edge ids look like "svc:a->svc:b:8000" or "...:unix:/path".
  const arrow = edgeID.indexOf("->");
  if (arrow < 0) return edgeID;
  const src = edgeID.slice(0, arrow);
  const rest = edgeID.slice(arrow + 2);
  // The destination id ends at the port/path suffix; find the shortest
  // known label match.
  for (const id of Object.keys(report.labels)) {
    if (rest.startsWith(id + ":")) {
      const suffix = rest.slice(id.length + 1);
      const l = report.labels;
      return `${l[src] ?? src} → ${l[id] ?? id}${suffix.startsWith("unix:") ? " (ipc)" : ":" + suffix}`;
    }
  }
  return edgeID;
}

function FindingRow({
  f,
  idx,
  originIdx,
  onJump,
  onSelect,
}: {
  f: LensFinding;
  idx: number;
  originIdx: number;
  onJump: (t: number) => void;
  onSelect: (sel: Selection | null) => void;
}) {
  const t = Math.floor(new Date(f.time).getTime() / 1000);
  const tone = RECOVERY_KINDS.has(f.kind) ? "add" : "warn";
  return (
    <li
      className={`lens-finding ${tone}${idx === originIdx ? " origin" : ""}`}
      data-testid="lens-finding"
      data-kind={f.kind}
    >
      <button
        className="linkish mono lens-time"
        onClick={() => onJump(t)}
        title="View this moment in Replay"
      >
        {clock(f.time)}
      </button>{" "}
      <button
        className="linkish"
        onClick={() =>
          onSelect(
            f.edge
              ? { type: "edge", id: f.edge }
              : { type: "node", id: f.service },
          )
        }
      >
        {f.label}
      </button>{" "}
      <span className={`lens-kind ${tone}`}>{KIND_TITLES[f.kind] ?? f.kind}</span>
      {idx === originIdx && <span className="lens-badge inference">origin</span>}
      <div className="lens-detail">{f.detail}</div>
      <details className="lens-evidence">
        <summary>evidence ({f.evidence.length})</summary>
        <ul>
          {f.evidence.map((e, i) => (
            <li key={i} className="mono">
              {e.source} @{new Date(e.time * 1000).toLocaleTimeString("en-GB", { hour12: false })}
              {e.spanSecs ? ` (${e.spanSecs}s)` : ""}: {e.detail}
            </li>
          ))}
        </ul>
      </details>
    </li>
  );
}
