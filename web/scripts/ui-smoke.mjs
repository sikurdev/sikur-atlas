#!/usr/bin/env node
// Drives a real browser against a running agent and verifies the UI
// renders the live graph: nodes appear, the stream reports live, and a
// screenshot is captured as evidence.
//
// Usage: node web/scripts/ui-smoke.mjs [baseURL] [screenshotPath]
import { chromium } from "playwright";

const base = process.argv[2] ?? "http://127.0.0.1:7171";
const shot = process.argv[3] ?? "atlas-ui.png";
const MIN_NODES = Number(process.env.UI_SMOKE_MIN_NODES ?? "5");

const browser = await chromium.launch();
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  await page.goto(base, { waitUntil: "domcontentloaded" });

  await page.waitForFunction(
    (min) => document.querySelectorAll('[data-testid="node"]').length >= min,
    MIN_NODES,
    { timeout: 45000 },
  );
  const nodeCount = await page
    .locator('[data-testid="node"]')
    .count();
  const edgeCount = await page.locator('[data-testid="edge"]').count();
  const status = await page.getByTestId("status").innerText();

  if (!status.includes("live")) {
    throw new Error(`stream status is ${JSON.stringify(status)}, want live`);
  }

  // Select the busiest-looking node and check the inspector opens.
  await page.locator('[data-testid="node"]').first().click();
  await page.waitForSelector('[data-testid="inspector-node"]', {
    timeout: 5000,
  });

  // Let the force layout settle before the evidence screenshot.
  await page.waitForTimeout(3000);
  await page.screenshot({ path: shot });

  console.log(
    `UI SMOKE OK: ${nodeCount} nodes, ${edgeCount} edges rendered, ` +
      `status live, inspector opens; screenshot: ${shot}`,
  );
} catch (err) {
  console.error("UI SMOKE FAILED:", err.message ?? err);
  process.exitCode = 1;
} finally {
  await browser.close();
}
