// Renders the full app against a fake EventSource and checks the graph
// appears and live-updates. This tests the UI's rendering pipeline; the
// real backend integration is exercised by scripts/e2e.sh.
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";
import type { GraphSnapshot } from "./api";

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

function snapshot(nodes: string[], edges: [string, string][]): GraphSnapshot {
  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    nodes: nodes.map((id) => ({
      id: `proc:/bin/${id}`,
      kind: "process",
      label: id,
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
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
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
    })),
  };
}

describe("App", () => {
  let source: FakeEventSource;

  beforeEach(() => {
    source = new FakeEventSource();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        json: async () => ({
          version: "test",
          startedAt: new Date().toISOString(),
          kernel: "Linux test",
          collector: { events: 42 },
          kernelDrops: 0,
          decodeErrors: 0,
          dockerEnrichment: false,
        }),
      })),
    );
    vi.stubGlobal("ResizeObserver", class {
      observe() {}
      disconnect() {}
    });
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("renders nodes and edges from the stream and live-updates", async () => {
    render(<App makeSource={() => source as unknown as EventSource} />);

    expect(screen.getByTestId("status").textContent).toContain("connecting");

    act(() => {
      source.emit("snapshot", snapshot(["curl", "nginx"], [["curl", "nginx"]]));
    });

    expect(screen.getByTestId("status").textContent).toContain("live");
    expect(screen.getAllByTestId("node")).toHaveLength(2);
    expect(screen.getAllByTestId("edge")).toHaveLength(1);
    expect(screen.getByTestId("counts").textContent).toBe(
      "2 nodes · 1 edges",
    );

    // A second snapshot must merge in without a reload.
    act(() => {
      source.emit(
        "snapshot",
        snapshot(["curl", "nginx", "redis"], [
          ["curl", "nginx"],
          ["nginx", "redis"],
        ]),
      );
    });
    expect(screen.getAllByTestId("node")).toHaveLength(3);
    expect(screen.getAllByTestId("edge")).toHaveLength(2);
  });

  it("shows the map key when nothing is selected", () => {
    render(<App makeSource={() => source as unknown as EventSource} />);
    act(() => {
      source.emit("snapshot", snapshot(["a"], []));
    });
    expect(screen.getByTestId("legend")).toBeTruthy();
  });

  it("shows an actionable empty state", () => {
    render(<App makeSource={() => source as unknown as EventSource} />);
    act(() => {
      source.emit("snapshot", snapshot([], []));
    });
    expect(screen.getByText(/No connections observed yet/)).toBeTruthy();
  });
});
