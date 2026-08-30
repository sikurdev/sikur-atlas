#!/usr/bin/env node
// Drives a real browser against a running agent and verifies the whole
// investigation surface: live view, filtering, inspector, focus, raw
// drill-down, Replay (?at=), Compare (?a=&b=) — with screenshots as
// evidence.
//
// Usage: node web/scripts/ui-smoke.mjs [baseURL] [t1] [t2]
import { chromium } from "playwright";

const base = process.argv[2] ?? "http://127.0.0.1:7171";
const t1 = Number(process.argv[3]) || null;
const t2 = Number(process.argv[4]) || null;
const MIN_NODES = Number(process.env.UI_SMOKE_MIN_NODES ?? "5");

const checks = [];
const ok = (what) => {
  checks.push(what);
  console.log("  ✓ " + what);
};

const browser = await chromium.launch();
const consoleTail = [];
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  page.on("console", (msg) => {
    consoleTail.push(`[${msg.type()}] ${msg.text()}`);
    if (consoleTail.length > 30) consoleTail.shift();
  });
  page.on("pageerror", (err) => consoleTail.push(`[pageerror] ${err.message}`));

  // ---- live view (Services / Overview by default) ----
  await page.goto(base, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(
    (min) => document.querySelectorAll('[data-testid="node"]').length >= min,
    MIN_NODES,
    { timeout: 45000 },
  );
  const status = await page.getByTestId("status").innerText();
  if (!status.includes("live")) {
    throw new Error(`stream status is ${JSON.stringify(status)}, want live`);
  }
  const liveNodes = await page.locator('[data-testid="node"]').count();
  ok(`live service view renders ${liveNodes} nodes, status live`);
  await page.waitForTimeout(2500); // let the layout settle
  await page.screenshot({ path: "atlas-ui-live.png" });

  // ---- filtering dims non-matching nodes ----
  await page.getByLabel("Filter nodes").fill("cache");
  await page.waitForFunction(
    () => document.querySelectorAll(".node.dimmed").length >= 1,
    undefined,
    { timeout: 5000 },
  );
  ok("search filter dims non-matching nodes");
  await page.getByLabel("Filter nodes").fill("");

  // ---- inspector + focus + blast radius ----
  const cacheNode = page
    .locator('[data-testid="node"]', { hasText: "cache" })
    .first();
  await cacheNode.locator(".symbol").first().click({ force: true });
  await page.waitForSelector('[data-testid="inspector-node"]', { timeout: 5000 });
  await page.waitForSelector('[data-testid="deps-in"]', { timeout: 5000 });
  ok("inspector shows node identity and dependants");

  // Resource evidence renders for the selected service.
  await page.waitForSelector('[data-testid="node-resources"]', { timeout: 10000 });
  const resources = await page.getByTestId("node-resources").innerText();
  if (!resources.includes("%") || !resources.includes("procs")) {
    throw new Error(`resources section incomplete: ${resources}`);
  }
  ok("inspector shows sampled resources (cpu/memory/procs)");

  // AF_UNIX IPC: reports is only reachable over its socket; the edge
  // must render and identify itself with the socket path.
  await page
    .locator('[data-testid="node"]', { hasText: "reports" })
    .first()
    .locator(".symbol")
    .first()
    .click({ force: true });
  await page.waitForSelector('[data-testid="deps-in"]', { timeout: 5000 });
  await page.locator('[data-testid="deps-in"] button').first().click();
  await page.waitForSelector('[data-testid="inspector-edge"]', { timeout: 5000 });
  const edgeKind = await page.getByTestId("edge-kind").innerText();
  if (!edgeKind.includes("unix socket") || !edgeKind.includes("/sockets/reports.sock")) {
    throw new Error(`unix edge not identified: ${edgeKind}`);
  }
  ok("unix IPC edge renders with its socket path");

  // Back to a node selection for the focus check.
  await cacheNode.locator(".symbol").first().click({ force: true });
  await page.waitForSelector('[data-testid="inspector-node"]', { timeout: 5000 });
  await page.getByTestId("btn-focus").click();
  await page.waitForFunction(
    () => document.querySelectorAll(".node.dimmed").length >= 1,
    undefined,
    { timeout: 5000 },
  );
  ok("focus dims nodes outside the dependency closure");
  await page.screenshot({ path: "atlas-ui-focus.png" });
  await page.getByTestId("btn-focus").click(); // unfocus

  // ---- raw drill-down ----
  await page.getByTestId("btn-raw").click();
  await page.waitForFunction(
    (min) => document.querySelectorAll('[data-testid="node"]').length >= min,
    liveNodes,
    { timeout: 10000 },
  );
  const rawNodes = await page.locator('[data-testid="node"]').count();
  ok(`raw drill-down shows ${rawNodes} raw nodes (>= ${liveNodes} services)`);
  await page.getByTestId("btn-view-app").click();

  // ---- timeline is present and carries real activity bars ----
  await page.waitForSelector('[data-testid="timeline-strip"]', { timeout: 5000 });
  await page.waitForFunction(
    () => document.querySelectorAll(".tl-activity").length >= 1,
    undefined,
    { timeout: 15000 },
  );
  ok("timeline strip renders recorded activity");
  await page.waitForFunction(
    () =>
      document.querySelectorAll('[data-testid="tl-lifecycle"]').length +
        document.querySelectorAll('[data-testid="tl-oom"]').length >=
      1,
    undefined,
    { timeout: 10000 },
  );
  ok("timeline shows lifecycle markers (restart/OOM episodes)");

  if (t1 != null) {
    // ---- Replay at T1: the stopped service is back on screen ----
    await page.goto(`${base}/?at=${t1}`, { waitUntil: "domcontentloaded" });
    await page
      .locator('[data-testid="node"]', { hasText: "inventory" })
      .first()
      .waitFor({ timeout: 15000 });
    const mode = await page.getByTestId("time-mode").innerText();
    if (!mode.includes("viewing")) {
      throw new Error(`replay mode label wrong: ${mode}`);
    }
    ok("replay at T1 reconstructs the stopped inventory service");
    await page.waitForTimeout(1500);
    await page.screenshot({ path: "atlas-ui-replay.png" });
  }

  if (t1 != null && t2 != null) {
    // ---- Compare T1 vs T2: the change is identified ----
    await page.goto(`${base}/?a=${t1}&b=${t2}`, { waitUntil: "domcontentloaded" });
    await page.waitForSelector('[data-testid="inspector-diff"]', {
      timeout: 15000,
    });
    const removed = await page.getByTestId("diff-removed").innerText();
    if (!removed.includes("inventory")) {
      throw new Error(`compare panel misses inventory: ${removed}`);
    }
    const diffLife = await page.getByTestId("diff-lifecycle").innerText();
    if (!diffLife.includes("oom")) {
      throw new Error(`compare lifecycle misses the OOM: ${diffLife}`);
    }
    ok("compare lists recorded lifecycle evidence (OOM, restarts)");
    await page
      .locator('[data-testid="node"][data-diff="removed"]')
      .first()
      .waitFor({ timeout: 10000 });
    ok("compare identifies the removed service in panel and on canvas");
    await page.waitForTimeout(1500);
    await page.screenshot({ path: "atlas-ui-compare.png" });

    // Exit compare back to live.
    await page.getByTestId("btn-exit-compare").click();
    await page.getByTestId("btn-live").click();
    await page.waitForFunction(
      () => {
        const el = document.querySelector('[data-testid="status"]');
        return el && el.textContent && el.textContent.includes("live");
      },
      undefined,
      { timeout: 10000 },
    );
    ok("exit compare returns to live");
  }

  console.log(`UI E2E OK: ${checks.length} interactions verified`);
} catch (err) {
  console.error("UI E2E FAILED:", err.message ?? err);
  if (consoleTail.length > 0) {
    console.error("browser console tail:");
    for (const line of consoleTail) console.error("  " + line);
  }
  try {
    // What the agent was actually serving at failure time.
    const app = await (await fetch(`${base}/api/appview`)).json();
    console.error(
      "appview at failure:",
      JSON.stringify({
        nodes: app.nodes.map((n) => n.label),
        edges: app.edges.map((e) => `${e.src}->${e.dst}${e.protocol === "unix" ? " [unix]" : ""}`),
      }),
    );
  } catch {
    // best effort
  }
  try {
    const page = (await browser.contexts())[0]?.pages()[0];
    if (page) await page.screenshot({ path: "atlas-ui-failure.png" });
  } catch {
    // best effort
  }
  process.exitCode = 1;
} finally {
  await browser.close();
}
