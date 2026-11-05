import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { policySchema, type Policy } from "@traffic-policy/contracts";
import { connectionMarkScopes } from "@traffic-policy/core/nftables";
import {
  ConnectionMarks,
  fileMarkStore,
  type MarkStore,
} from "./connection-marks.ts";

const at = "2026-10-27T00:00:00.000Z";

const client = "11111111-1111-4111-8111-111111111111";

const directories: string[] = [];

afterEach(async () => {
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
});

const rule = (id: number, hostname: string | null) => ({
  id: `00000000-0000-4000-8000-${String(id).padStart(12, "0")}`,
  subject: hostname
    ? { kind: "instance", instanceId: client }
    : { kind: "global" },
  direction: hostname ? "outgoing" : "both",
  peer: hostname ? { kind: "hostname", value: hostname } : { kind: "any" },
  protocol: null,
  portStart: null,
  portEnd: null,
  icmpType: null,
  icmpCode: null,
  action: hostname ? "allow" : "block",
  priority: "normal",
  enabled: true,
  notBefore: null,
  expiresAt: null,
  dnsDestinations: hostname ? ["192.0.2.0/24"] : null,
  createdAt: at,
  modifiedAt: at,
  reason: "",
});

// A policy with one DNS Allow rule for each hostname, by rule number.
function policy(hostnames: Record<number, string>): Policy {
  return policySchema.parse({
    protocolVersion: 1,
    revision: "1",
    generatedAt: at,
    instances: [{ id: client, name: "Client", addresses: ["10.0.0.1"] }],
    rules: [
      ...Object.entries(hostnames).map(([id, hostname]) =>
        rule(Number(id), hostname),
      ),
      rule(999, null),
    ],
    settings: {
      dnsGraceSeconds: 300,
      permissionLimit: 4096,
      trafficHistoryBytes: "268435456",
      dnsHistoryBytes: "134217728",
      blockedHistoryBytes: "106954752",
      otherHistoryBytes: "27262976",
      auditBytes: "134217728",
      collectorBytes: "134217728",
      gatewayDiskBytes: "4294967296",
      controllerDiskBytes: "8589934592",
      historyMaxAgeDays: null,
      auditMaxAgeDays: null,
      localNetworks: [],
      reverseDnsResolver: null,
    },
  });
}

function memory() {
  const writes: Parameters<MarkStore["write"]>[0][] = [];

  const store: MarkStore = {
    read: async () => writes.at(-1) ?? null,
    write: async (state) => {
      writes.push(structuredClone(state));
    },
  };

  return { store, writes };
}

const values = (marks: ReadonlyMap<string, number>) => [...marks.values()];

describe("connection marks", () => {
  it("saves new marks, keeps the installed policy's marks, and never gives a number out twice", async () => {
    const { store, writes } = memory();
    const marks = new ConnectionMarks(store);
    const first = policy({ 1: "a.example", 2: "b.example" });

    expect(values(await marks.assign(first, null))).toEqual([1, 2]);
    expect(writes).toHaveLength(1);

    // Preparing a candidate without rule 2 keeps rule 2's mark for the installed policy.
    const second = policy({ 1: "a.example", 3: "c.example" });

    expect(values(await marks.assign(second, first))).toEqual([1, 3]);
    expect(Object.values(writes.at(-1)!.marks)).toEqual([1, 2, 3]);

    // Once neither policy has rule 2, its mark is dropped and not reused.
    expect(values(await marks.assign(second, second))).toEqual([1, 3]);
    expect(writes.at(-1)).toEqual({
      version: 1,
      next: 4,
      marks: Object.fromEntries(
        connectionMarkScopes(second).map((scope, index) => [
          scope,
          [1, 3][index],
        ]),
      ),
    });
    expect(values(await marks.assign(first, second))).toEqual([1, 4]);

    const writesBefore = writes.length;

    await marks.assign(first, first);
    await marks.assign(first, first);
    expect(writes).toHaveLength(writesBefore + 1);
  });

  it("continues from saved marks after a restart", async () => {
    const { store } = memory();

    await new ConnectionMarks(store).assign(policy({ 1: "a.example" }), null);

    expect(
      values(
        await new ConnectionMarks(store).assign(
          policy({ 1: "a.example", 2: "b.example" }),
          null,
        ),
      ),
    ).toEqual([1, 2]);
  });

  it("refuses to number past the 24-bit range", async () => {
    const marks = new ConnectionMarks({
      read: async () => ({ version: 1, next: 0xffffff, marks: {} }),
      write: async () => {},
    });

    await expect(
      marks.assign(policy({ 1: "a.example", 2: "b.example" }), null),
    ).rejects.toMatchObject({ code: "connection_marks_exhausted" });
  });

  it("reads missing state as empty and names the file when it is unreadable", async () => {
    const directory = await mkdtemp(join(process.cwd(), ".tmp/tests/marks-"));

    directories.push(directory);
    const store = fileMarkStore(directory);

    expect(await store.read()).toBeNull();
    await store.write({ version: 1, next: 2, marks: { scope: 1 } });
    expect(await store.read()).toEqual({
      version: 1,
      next: 2,
      marks: { scope: 1 },
    });
    await writeFile(join(directory, "connection-marks.json"), "broken JSON");
    await expect(store.read()).rejects.toThrow(
      `Connection mark state ${join(directory, "connection-marks.json")} could not be read`,
    );
  });
});
