/** The map key, shown when nothing is selected — Atlas draws a chart of
 * the machine, and a chart carries its legend. */
export function Legend() {
  return (
    <div className="legend" data-testid="legend">
      <h3>map key</h3>
      <div className="legend-row">
        <svg width="30" height="30">
          <circle cx="15" cy="15" r="10" fill="var(--paper)" stroke="var(--ink)" strokeWidth="1.5" />
        </svg>
        host process
      </div>
      <div className="legend-row">
        <svg width="30" height="30">
          <rect x="5" y="5" width="20" height="20" rx="2" fill="var(--paper-inset)" stroke="var(--ink)" strokeWidth="1.5" />
        </svg>
        container
      </div>
      <div className="legend-row">
        <svg width="34" height="30">
          <rect x="9" y="3" width="20" height="20" rx="2" fill="var(--paper)" stroke="var(--line)" strokeWidth="1.5" />
          <rect x="5" y="7" width="20" height="20" rx="2" fill="var(--paper-inset)" stroke="var(--ink)" strokeWidth="1.5" />
        </svg>
        compose service (grouped)
      </div>
      <div className="legend-row">
        <svg width="30" height="30">
          <rect
            x="15"
            y="3.7"
            width="16"
            height="16"
            transform="rotate(45 15 15)"
            fill="var(--paper)"
            stroke="var(--ink-soft)"
            strokeWidth="1.5"
            strokeDasharray="3 3"
          />
        </svg>
        external endpoints
      </div>
      <div className="legend-row">
        <svg width="30" height="14">
          <line x1="2" y1="7" x2="28" y2="7" stroke="var(--water)" strokeWidth="3" />
        </svg>
        connections (width = volume)
      </div>
      <div className="legend-row">
        <svg width="30" height="14">
          <line x1="2" y1="7" x2="28" y2="7" stroke="var(--water-deep)" strokeWidth="2" strokeDasharray="7 3" />
        </svg>
        traffic in the last 5s
      </div>
      <div className="legend-row">
        <svg width="30" height="14">
          <line x1="2" y1="7" x2="28" y2="7" stroke="var(--hazard)" strokeWidth="3" />
        </svg>
        failures / resets in window
      </div>
      <p className="legend-note">
        Click a node or edge to inspect it. Focus dims everything outside
        a service&rsquo;s dependency closure. The timeline below scrubs
        into recorded history; pin a moment to compare two states. The
        graph updates live from the agent&rsquo;s eBPF event stream.
      </p>
    </div>
  );
}
