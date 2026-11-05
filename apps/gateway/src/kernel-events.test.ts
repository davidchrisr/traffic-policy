import { expect, it, vi } from "vitest";
import type { EventEmitter } from "node:events";

interface ObserverProcess extends EventEmitter {
  stdout: EventEmitter;
  stderr: EventEmitter;
  kill: () => void;
}

const transport = vi.hoisted(() => ({
  children: [] as ObserverProcess[],
}));

vi.mock("node:child_process", async () => {
  const { EventEmitter } = await import("node:events");

  return {
    spawn: () => {
      const child = Object.assign(new EventEmitter(), {
        stdout: new EventEmitter(),
        stderr: new EventEmitter(),
        kill: () => {},
      });

      transport.children.push(child);

      return child;
    },
  };
});

import { KernelEvents } from "./kernel-events.ts";
import { parseConnections } from "./connections.ts";
import { TrafficAccounting } from "./telemetry.ts";

it("pins queued lifecycle ownership before an address is reassigned", () => {
  const id = "11111111-1111-4111-8111-111111111111";

  const instances = [
    {
      id,
      name: "Original",
      addresses: ["10.22.241.10"],
      ownershipId: "33333333-3333-4333-8333-333333333333",
    },
  ];

  const events = new KernelEvents((addresses) =>
    instances.filter((instance) =>
      addresses.some((address) => instance.addresses.includes(address)),
    ),
  );

  events.start();

  const xml = (kind: string) =>
    `<flow type="${kind}"><meta direction="original"><layer3><src>10.22.241.10</src><dst>10.22.242.20</dst></layer3><layer4 protonum="6"><sport>50000</sport><dport>443</dport></layer4><counters><packets>1</packets><bytes>100</bytes></counters></meta><meta direction="reply"><layer3><src>10.22.242.20</src><dst>10.22.241.10</dst></layer3><layer4 protonum="6"><sport>443</sport><dport>50000</dport></layer4><counters><packets>1</packets><bytes>50</bytes></counters></meta><meta direction="independent"><id>1</id></meta></flow>\n`;

  transport.children[0]!.stdout.emit("data", Buffer.from(xml("new")));
  transport.children[0]!.stdout.emit("data", Buffer.from(xml("destroy")));
  instances[0]!.id = "22222222-2222-4222-8222-222222222222";
  const records = events.read(null, "0").events;
  expect(records).toHaveLength(2);
  const accounting = new TrafficAccounting();

  const first = records[0]!,
    last = records[1]!;

  accounting.newConnection(
    parseConnections(`<conntrack>${first.record}</conntrack>`)[0]!,
    { instances: first.instances, gatewayAddresses: [] },
    first.observedAt,
  );

  const observed = accounting.observe(
    parseConnections(`<conntrack>${last.record}</conntrack>`)[0]!,
    { instances: last.instances, gatewayAddresses: [] },
    last.observedAt,
    true,
    last.id,
  );

  expect(observed[0]!.instanceId).toBe(id);
  expect(observed[0]!.sentBytes).toBe("100");
  events.close();
});

it("retains a dropped-record warning until the gateway advances its cursor", () => {
  const events = new KernelEvents(() => []);
  const first = transport.children.length;
  events.start();
  const conntrack = transport.children[first]!;
  vi.spyOn(console, "error").mockImplementation(() => {});

  conntrack.stderr.emit(
    "data",
    Buffer.from("WARNING: We have hit ENOBUFS! We are losing events."),
  );
  const reply = events.read(null, "0");
  expect(reply).toMatchObject({ gap: true, condition: null, sequence: "1" });
  expect(events.read(events.epoch, "0")).toEqual({ ...reply, reset: false });
  expect(events.read(events.epoch, reply.sequence)).toMatchObject({
    gap: false,
    condition: null,
  });
  events.close();
  vi.restoreAllMocks();
});

it("restarts a stopped stream and clears its condition once it runs", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  const events = new KernelEvents(() => []);
  const first = transport.children.length;
  events.start();
  const conntrack = transport.children[first]!;

  conntrack.emit("close");
  const reply = events.read(null, "0");
  expect(reply).toMatchObject({
    gap: true,
    condition: "Kernel observation stream stopped",
  });
  expect(transport.children).toHaveLength(first + 2);

  await vi.advanceTimersByTimeAsync(1000);
  expect(transport.children).toHaveLength(first + 3);
  transport.children[first + 2]!.emit("spawn");
  expect(events.read(events.epoch, "0").gap).toBe(true);
  expect(events.read(events.epoch, reply.sequence)).toMatchObject({
    gap: false,
    condition: null,
  });
  events.close();
  vi.useRealTimers();
});

it("paginates loss markers and retains eviction gaps for retries", () => {
  const events = new KernelEvents(() => []);
  const first = transport.children.length;
  events.start();
  vi.spyOn(console, "error").mockImplementation(() => {});

  try {
    const child = transport.children[first]!;

    for (let index = 0; index < 130; index++)
      child.stderr.emit("data", Buffer.from("ENOBUFS"));
    const page = events.read(null, "0");
    expect(page.events).toHaveLength(128);
    expect(page.sequence).toBe("128");
    expect(events.read(events.epoch, "0").events).toEqual(page.events);
    const next = events.read(events.epoch, page.sequence);
    expect(next).toMatchObject({ sequence: "130", gap: true });
    expect(next.events).toHaveLength(2);
    expect(events.read(events.epoch, next.sequence)).toMatchObject({
      gap: false,
      events: [],
    });

    for (let index = 0; index < 4096; index++)
      child.stderr.emit("data", Buffer.from("ENOBUFS"));
    expect(events.read(events.epoch, "0")).toMatchObject({ gap: true });
    expect(events.read(events.epoch, "0").events).toEqual(
      events.read(events.epoch, "0").events,
    );
  } finally {
    events.close();
    vi.restoreAllMocks();
  }
});

it("records unregistered drops traced in their own chain, but not Block traces without an ingress trace", () => {
  const events = new KernelEvents(() => []);
  const first = transport.children.length;

  events.start();

  const trace = (id: string, chain: string, packet: string) =>
    [
      `trace id ${id} inet traffic_policy ${chain} packet: ${packet}`,
      `trace id ${id} inet traffic_policy ${chain} rule counter drop (verdict drop)`,
    ].join("\n") + "\n";

  transport.children[first + 1]!.stdout.emit(
    "data",
    Buffer.from(
      trace(
        "1a",
        "u_c",
        'iif "lan0" ip saddr 10.22.241.99 ip daddr 93.184.216.34 ip protocol tcp tcp dport 443',
      ) +
        trace(
          "2b",
          "b4_o_11111111111141118111111111111111_22222222222242228222222222222222_3_c",
          "ip saddr 10.22.241.10 ip daddr 93.184.216.34 ip protocol tcp tcp dport 443",
        ),
    ),
  );

  expect(events.read(null, "0").events.map((event) => event.record)).toEqual([
    'trace id 1a inet traffic_policy u_c packet: iif "lan0" ip saddr 10.22.241.99 ip daddr 93.184.216.34 ip protocol tcp tcp dport 443\ntranslated:packet: iif "lan0" ip saddr 10.22.241.99 ip daddr 93.184.216.34 ip protocol tcp tcp dport 443',
  ]);
  events.close();
});
