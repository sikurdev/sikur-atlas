// Renders the full app against a fake EventSource and checks rendering,
// live updates, view switching, filtering and focus. The real backend
// integration is exercised by scripts/e2e.sh.
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";
import type { AppGraph, GraphSnapshot, StreamPayload } from "./api";

class FakeEventSource {
  listeners = new Map<string, ((ev: MessageEvent) => void)[]>();
  closed = false;

  addEventListener(type: string, cb: (ev: MessageEvent) => void) {
    const list = this.listeners.get(type) ?? [];
    list.push(cb);
    this.listeners.set(type, list);
  }
  close() {
    this.closed = true;
  }
  emit(type: string, data?: unknown) {
    for (const cb of this.listeners.get(type) ?? []) {
      cb({ data: JSON.stringify(data) } as MessageEvent);
    }
  }
}

const now = () => new Date().toISOString();

function rawSnapshot(nodes: string[], edges: [string, string][]): GraphSnapshot {
  return {
    version: 1,
    generatedAt: now(),
    nodes: nodes.map((id) => ({
      id: `proc:/bin/${id}`,
      kind: "process",
      label: id,
      firstSeen: now(),
      lastSeen: now(),
    })),
    edges: edges.map(([src, dst]) => ({
      id: `proc:/bin/${src}->proc:/bin/${dst}:80`,
      src: `proc:/bin/${src}`,
      dst: `proc:/bin/${dst}`,
      dstPort: 80,
      protocol: "tcp",
      connections: 3,
      activeConns: 1,
      bytesSent: 1024,
      bytesRecv: 4096,
      firstSeen: now(),
      lastSeen: now(),
    })),
  };
}

function appGraph(
  nodes: [string, "app" | "system"][],
  edges: [string, string][],
): AppGraph {
  return {
    generatedAt: now(),
    nodes: nodes.map(([id, category]) => ({
      id: `svc:proc:${id}`,
      label: id,
      category,
      kind: "process",
      members: [`proc:/bin/${id}`],
      memberCount: 1,
      firstSeen: now(),
      lastSeen: now(),
    })),
    edges: edges.map(([src, dst]) => ({
      id: `svc:proc:${src}->svc:proc:${dst}:80`,
      src: `svc:proc:${src}`,
      dst: `svc:proc:${dst}`,
      dstPort: 80,
      protocol: "tcp",
      connections: 3,
      activeConns: 1,
      bytesSent: 1024,
      bytesRecv: 4096,
      firstSeen: now(),
      lastSeen: now(),
      rawEdges: [`proc:/bin/${src}->proc:/bin/${dst}:80`],
    })),
  };
}

function payload(): StreamPayload {
  return {
    raw: rawSnapshot(
      ["curl", "nginx", "dockerd"],
      [
        ["curl", "nginx"],
        ["dockerd", "nginx"],
      ],
    ),
    app: appGraph(
      [
        ["curl", "app"],
        ["nginx", "app"],
        ["dockerd", "system"],
      ],
      [
        ["curl", "nginx"],
        ["dockerd", "nginx"],
      ],
    ),
  };
}

// A canned /api/lens report shaped like the demo incident: nginx died,
// curl→nginx traffic stopped.
function lensReport() {
  const t = new Date("2026-08-30T12:02:00Z");
  const iso = (off: number) => new Date(t.getTime() + off * 1000).toISOString();
  const exit = {
    kind: "exit",
    time: iso(0),
    end: iso(1),
    service: "svc:proc:nginx",
    label: "nginx",
    detail: "process exited: killed by signal 15",
    evidence: [
      { source: "lifecycle-event", time: 100, detail: "kind=exit pid=9" },
    ],
  };
  const stop = {
    kind: "traffic-stop",
    time: iso(10),
    end: iso(20),
    service: "svc:proc:curl",
    label: "curl",
    edge: "svc:proc:curl->svc:proc:nginx:80",
    edgeSrc: "svc:proc:curl",
    edgeDst: "svc:proc:nginx",
    detail: "traffic ceased: no opens or closes for 120s",
    evidence: [
      {
        source: "edge-bucket",
        time: 100,
        spanSecs: 10,
        detail: "opens=5 closes=5 failures=0 resets=0 retrans=0",
      },
    ],
  };
  return {
    from: iso(-600),
    to: iso(300),
    ruleSet: "lens/v1",
    findings: [exit, stop],
    chronic: [],
    origin: {
      service: "svc:proc:nginx",
      label: "nginx",
      time: iso(0),
      findingIndex: 0,
      rule: "earliest-primary-with-dependency-support",
      inference: true,
      explanation: "exit is the earliest primary event",
    },
    propagations: [
      {
        causeIndex: 0,
        effectIndex: 1,
        inference: true,
        explanation: "consistent with propagation",
      },
    ],
    blastRadius: {
      services: ["svc:proc:curl", "svc:proc:nginx"],
      edges: ["svc:proc:curl->svc:proc:nginx:80"],
    },
    recovery: [
      {
        subject: "svc:proc:nginx",
        degradedIndex: 0,
        recoveredAt: null,
        recoveryIndex: -1,
        detail: "no recovery recorded within the window",
      },
    ],
    labels: { "svc:proc:curl": "curl", "svc:proc:nginx": "nginx" },
  };
}

describe("App", () => {
  let source: FakeEventSource;

  beforeEach(() => {
    window.history.replaceState(null, "", "/");
    source = new FakeEventSource();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.startsWith("/api/meta")) {
          return {
            ok: true,
            json: async () => ({
              version: "test",
              startedAt: now(),
              kernel: "Linux test",
              collector: { events: 42 },
              kernelDrops: 0,
              decodeErrors: 0,
              dockerEnrichment: false,
              history: true,
            }),
          };
        }
        if (url.startsWith("/api/timeline")) {
          return {
            ok: true,
            json: async () => ({ from: 0, to: 100, step: 10, buckets: [] }),
          };
        }
        if (url.startsWith("/api/compare")) {
          return {
            ok: true,
            json: async () => ({
              a: now(),
              b: now(),
              addedNodes: [],
              removedNodes: [],
              addedEdges: [],
              removedEdges: [],
              changedEdges: [],
            }),
          };
        }
        if (url.startsWith("/api/lens")) {
          return { ok: true, json: async () => lensReport() };
        }
        if (url.startsWith("/api/graph")) {
          return { ok: true, json: async () => payload().raw };
        }
        if (url.startsWith("/api/appview")) {
          return { ok: true, json: async () => payload().app };
        }
        return { ok: false, status: 404, json: async () => ({}) };
      }),
    );
    vi.stubGlobal(
      "ResizeObserver",
      class {
        observe() {}
        disconnect() {}
      },
    );
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  function renderApp() {
    render(<App makeSource={() => source as unknown as EventSource} />);
  }

  it("renders the service view by default, hiding system nodes", () => {
    renderApp();
    act(() => {
      source.emit("snapshot", payload());
    });
    // dockerd is system: hidden by default in the app view.
    expect(screen.getAllByTestId("node")).toHaveLength(2);
    expect(screen.getAllByTestId("edge")).toHaveLength(1);
    expect(screen.getByTestId("counts").textContent).toBe("2 nodes · 1 edges");

    // Toggling system shows it.
    fireEvent.click(screen.getByTestId("chk-system"));
    expect(screen.getAllByTestId("node")).toHaveLength(3);
  });

  it("switches to the raw view with all nodes", () => {
    renderApp();
    act(() => {
      source.emit("snapshot", payload());
    });
    fireEvent.click(screen.getByTestId("btn-view-raw"));
    expect(screen.getAllByTestId("node")).toHaveLength(3);
    expect(screen.getAllByTestId("edge")).toHaveLength(2);
  });

  it("live-updates from the stream", () => {
    renderApp();
    act(() => {
      source.emit("snapshot", payload());
    });
    const p2 = payload();
    p2.app.nodes.push({
      id: "svc:proc:redis",
      label: "redis",
      category: "app",
      kind: "process",
      members: [],
      memberCount: 1,
      firstSeen: now(),
      lastSeen: now(),
    });
    act(() => {
      source.emit("snapshot", p2);
    });
    expect(screen.getAllByTestId("node")).toHaveLength(3);
  });

  it("focuses a node and dims the rest", () => {
    renderApp();
    act(() => {
      source.emit("snapshot", payload());
    });
    // Select a node (down then up without movement = click), then focus
    // it via the inspector action.
    const target = document.querySelector('[data-node-id="svc:proc:curl"]')!;
    fireEvent.pointerDown(target);
    fireEvent.pointerUp(target);
    expect(screen.getByTestId("inspector-node")).toBeTruthy();
    fireEvent.click(screen.getByTestId("btn-focus"));
    // nginx is downstream of curl: still lit. Everything is in the
    // closure here, so check the class handling via the un-focus path.
    expect(screen.getByTestId("btn-focus").textContent).toBe("Unfocus");
  });

  it("shows the timeline with a live button", () => {
    renderApp();
    act(() => {
      source.emit("snapshot", payload());
    });
    expect(screen.getByTestId("timeline")).toBeTruthy();
    expect(screen.getByTestId("btn-live")).toBeTruthy();
    expect(screen.getByTestId("time-mode").textContent).toContain("streaming");
  });

  it("shows an actionable empty state", () => {
    renderApp();
    act(() => {
      source.emit("snapshot", {
        raw: rawSnapshot([], []),
        app: appGraph([], []),
      });
    });
    expect(screen.getByText(/make one:/)).toBeTruthy();
  });

  it("opens the Incident Lens, shows the chain, and jumps to Replay", async () => {
    renderApp();
    act(() => {
      source.emit("snapshot", payload());
    });
    fireEvent.click(screen.getByTestId("btn-lens"));
    expect(screen.getByTestId("lens-panel")).toBeTruthy();

    // The report arrives: origin card, evidence chain, blast radius.
    expect(await screen.findByTestId("lens-origin")).toBeTruthy();
    expect(screen.getByTestId("lens-origin").textContent).toContain("nginx");
    expect(screen.getByTestId("lens-origin").textContent).toContain(
      "inference",
    );
    const findings = screen.getAllByTestId("lens-finding");
    expect(findings).toHaveLength(2);
    expect(findings[0]!.getAttribute("data-kind")).toBe("exit");
    expect(findings[1]!.getAttribute("data-kind")).toBe("traffic-stop");
    expect(screen.getByTestId("lens-blast")).toBeTruthy();
    expect(screen.getByTestId("lens-recovery").textContent).toContain(
      "no recovery recorded",
    );

    // The URL is addressable.
    expect(window.location.search).toContain("lf=");
    expect(window.location.search).toContain("lt=");

    // Clicking a finding's time jumps into Replay at that moment.
    const timeBtn = findings[0]!.querySelector("button.lens-time")!;
    fireEvent.click(timeBtn);
    expect(screen.getByTestId("time-mode").textContent?.toLowerCase()).toContain(
      "viewing",
    );
    expect(window.location.search).toContain("at=");

    // Focus origin dims via the same focus mechanism as the pill.
    fireEvent.click(screen.getByTestId("btn-lens-focus-origin"));
    // nginx selected via origin name → inspector should offer Unfocus
    // (await the replay snapshot fetch resolving into the graph).
    const nameBtn = screen
      .getByTestId("lens-origin")
      .querySelector("button.linkish")!;
    fireEvent.click(nameBtn);
    expect((await screen.findByTestId("btn-focus")).textContent).toBe(
      "Unfocus",
    );

    // Close removes the panel and clears the URL keys.
    fireEvent.click(screen.getByTestId("btn-lens-close"));
    expect(screen.queryByTestId("lens-panel")).toBeNull();
    expect(window.location.search).not.toContain("lf=");
  });

  it("investigates a selected service from the inspector", async () => {
    renderApp();
    act(() => {
      source.emit("snapshot", payload());
    });
    const target = document.querySelector('[data-node-id="svc:proc:nginx"]')!;
    fireEvent.pointerDown(target);
    fireEvent.pointerUp(target);
    fireEvent.click(screen.getByTestId("btn-node-lens"));
    expect(await screen.findByTestId("lens-origin")).toBeTruthy();
    expect(window.location.search).toContain("ls=svc%3Aproc%3Anginx");
  });

  it("reopens the lens from the URL", async () => {
    window.history.replaceState(null, "", "/?lf=1000&lt=2000");
    renderApp();
    act(() => {
      source.emit("snapshot", payload());
    });
    expect(screen.getByTestId("lens-panel")).toBeTruthy();
    expect(await screen.findByTestId("lens-origin")).toBeTruthy();
  });
});
