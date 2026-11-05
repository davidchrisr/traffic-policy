import { describe, expect, it } from "vitest";
import type { DashboardStatus } from "@traffic-policy/contracts/dashboard";
import { latestStatus } from "./live-status.ts";

const status = (
  desiredRevision: string,
  pending: boolean,
): DashboardStatus => ({
  desiredRevision,
  appliedRevision: "9",
  pending,
  lastError: null,
  lastSeen: null,
  receipt: null,
  conditions: [],
  needsReview: 0,
  gateway: null,
});

describe("latest status", () => {
  it("keeps a page's newer revision until the shared poll reaches it", () => {
    const applied = status("9", false);
    const saved = status("10", true);

    expect(latestStatus(null, saved)).toBe(saved);
    expect(latestStatus(applied, saved)).toBe(saved);
    expect(latestStatus(status("10", false), saved)).toEqual(
      status("10", false),
    );
    expect(latestStatus(saved, applied)).toBe(saved);
  });
});
