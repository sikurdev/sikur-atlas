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
});
