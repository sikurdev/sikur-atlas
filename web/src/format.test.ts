import { describe, expect, it } from "vitest";

import { formatAgo, formatBytes, formatCount, shortExe } from "./format";

describe("formatBytes", () => {
  it("formats across magnitudes", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(2048)).toBe("2.00 KiB");
    expect(formatBytes(10 * 1024)).toBe("10.0 KiB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.00 MiB");
    expect(formatBytes(200 * 1024 * 1024)).toBe("200 MiB");
  });
  it("handles invalid input", () => {
    expect(formatBytes(-1)).toBe("–");
    expect(formatBytes(NaN)).toBe("–");
  });
});

describe("formatAgo", () => {
  const now = new Date("2026-08-29T12:00:00Z");
  it("buckets sensibly", () => {
    expect(formatAgo("2026-08-29T11:59:59.5Z", now)).toBe("now");
    expect(formatAgo("2026-08-29T11:59:30Z", now)).toBe("30s ago");
    expect(formatAgo("2026-08-29T11:15:00Z", now)).toBe("45m ago");
    expect(formatAgo("2026-08-29T02:00:00Z", now)).toBe("10h ago");
    expect(formatAgo("2026-08-24T12:00:00Z", now)).toBe("5d ago");
  });
  it("handles garbage", () => {
    expect(formatAgo("not a date", now)).toBe("–");
  });
});

describe("formatCount", () => {
  it("compacts large numbers", () => {
    expect(formatCount(7)).toBe("7");
    expect(formatCount(1500)).toBe("1.5k");
    expect(formatCount(25000)).toBe("25k");
    expect(formatCount(3_400_000)).toBe("3.4M");
  });
});

describe("shortExe", () => {
  it("keeps short paths and trims long ones", () => {
    expect(shortExe("/usr/bin")).toBe("/usr/bin");
    expect(shortExe("/usr/local/bin/python3.12")).toBe(".../bin/python3.12");
  });
});
