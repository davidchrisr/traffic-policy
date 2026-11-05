import { describe, expect, it } from "vitest";
import {
  servicesSnapshotSchema,
  type ServiceState,
  type ServicesSnapshot,
} from "@traffic-policy/contracts/services";
import { statusItems, worstTone } from "./service-status-view.ts";

const checkedAt = "2026-10-25T00:00:00.000Z";

const running: Omit<ServiceState, "id"> = {
  loadState: "loaded",
  activeState: "active",
  subState: "running",
  result: "success",
  exitStatus: null,
  restarts: "0",
};

function snapshot(
  maintenance: Partial<Omit<ServiceState, "id">> = {},
  link: Partial<Omit<ServiceState, "id">> = {},
): ServicesSnapshot {
  return servicesSnapshotSchema.parse({
    checkedAt,
    controller: {
      available: true,
      snapshot: {
        scope: "controller",
        checkedAt,
        services: [
          { id: "controller", ...running },
          { id: "machine", ...running, ...link },
        ],
      },
    },
    gateway: {
      available: true,
      snapshot: {
        scope: "gateway",
        checkedAt,
        services: [
          { id: "gateway", ...running },
          { id: "enforcement", ...running },
          { id: "suricata", ...running },
          { id: "suricata-rotate", ...running, ...maintenance },
        ],
      },
    },
  });
}

const applied = { pending: false, lastError: null, stale: false };

describe("header status", () => {
  it("groups rules, the gateway link, the gateway with its enforcement service, and Suricata with its log rotation", () => {
    const items = statusItems(applied, snapshot(), false, false);

    expect(items.map((item) => [item.id, item.tone, item.problems])).toEqual([
      ["rules", "allow", []],
      ["link", "allow", []],
      ["gateway", "allow", []],
      ["suricata", "allow", []],
    ]);
    expect(worstTone(items.map((item) => item.tone))).toBe("allow");
  });
  it.each([
    [
      { activeState: "failed", exitStatus: 1 },
      "Log rotation: Failed · exit 1",
      "destructive",
    ],
    [
      { loadState: "not-found", activeState: "inactive" },
      "Log rotation: Not available",
      "destructive",
    ],
    [{ activeState: "inactive" }, "Log rotation: Stopped", "pending"],
    [{ activeState: "activating" }, "Log rotation: Starting", "pending"],
  ])("lists the failing part of Suricata for %o", (state, problem, tone) => {
    const suricata = statusItems(applied, snapshot(state), false, false)[3]!;

    expect(suricata).toMatchObject({ problems: [problem], tone });
  });
  it("reports an unreadable gateway once per row, stale services, and no problems while checking", () => {
    const unread = servicesSnapshotSchema.parse({
      ...snapshot(),
      gateway: {
        available: false,
        message: "Gateway service status is unavailable.",
      },
    });

    expect(
      statusItems(applied, unread, false, false).map((item) => item.problems),
    ).toEqual([
      [],
      [],
      ["Gateway service status is unavailable."],
      ["Gateway service status is unavailable."],
    ]);
    expect(statusItems(applied, snapshot(), true, false)[2]!.problems).toEqual([
      "Gateway service: Out of date",
      "Enforcement service: Out of date",
    ]);
    expect(
      statusItems(
        { pending: false, lastError: "failed", stale: false },
        null,
        false,
        false,
      ).map((item) => [item.tone, item.problems]),
    ).toEqual([
      ["destructive", ["Rule changes: Not confirmed"]],
      ["muted", []],
      ["muted", []],
      ["muted", []],
    ]);
  });
  it("counts a running link process only while the gateway is in contact", () => {
    const link = (
      sync: typeof applied,
      state: Partial<Omit<ServiceState, "id">> = {},
    ) => statusItems(sync, snapshot({}, state), false, false)[1]!;

    expect(link({ ...applied, stale: true })).toMatchObject({
      tone: "pending",
      problems: ["Gateway contact: No contact in 15 seconds"],
    });
    expect(
      link(
        { ...applied, stale: true },
        { activeState: "failed", exitStatus: 1 },
      ),
    ).toMatchObject({
      tone: "destructive",
      problems: [
        "Link process: Failed · exit 1",
        "Gateway contact: No contact in 15 seconds",
      ],
    });
  });
});
