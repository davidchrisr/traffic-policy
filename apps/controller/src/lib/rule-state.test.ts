import { describe, expect, it } from "vitest";
import { ruleSchema, type Rule } from "@traffic-policy/contracts";
import {
  combineStates,
  decideService,
  inspectorBuiltIns,
  inspectorRules,
  reviewKey,
  stateDescription,
} from "./rule-state.ts";

const instanceId = "11111111-1111-4111-8111-111111111111";

const instances = [
  { id: instanceId, name: "Client", addresses: ["10.22.241.10"] },
];

const now = Date.parse("2026-10-10T00:00:00.000Z");

let sequence = 0;

// `instanceId` is shorthand for an instance subject.
function rule(
  partial: Partial<Rule> & { instanceId?: string | null } = {},
): Rule {
  const { instanceId, ...rest } = partial;

  return ruleSchema.parse({
    id: `00000000-0000-4000-8000-${String(++sequence).padStart(12, "0")}`,
    subject: instanceId ? { kind: "instance", instanceId } : { kind: "global" },
    direction: "both",
    peer: { kind: "any" },
    protocol: null,
    ports: null,
    icmpType: null,
    icmpCode: null,
    action: "block",
    priority: "normal",
    enabled: true,
    notBefore: null,
    expiresAt: null,
    dnsDestinations: null,
    createdAt: "2026-10-01T00:00:00.000Z",
    modifiedAt: "2026-10-01T00:00:00.000Z",
    reason: "",
    ...rest,
  });
}

const service = {
  instanceId,
  direction: "outgoing" as const,
  peerIp: "10.22.242.20",
  protocol: 6,
  port: 18080,
};

describe("Monitor rule state", () => {
  it("waits for review only while the catch-all decides a reviewed service", () => {
    const catchAll = rule();

    expect(
      decideService(
        [catchAll],
        instances,
        [],
        new Set(),
        service,
        undefined,
        now,
      )?.state,
    ).toBe("block");
    expect(
      decideService(
        [catchAll],
        instances,
        [],
        new Set([reviewKey(service)]),
        service,
        undefined,
        now,
      )?.state,
    ).toBe("waiting");

    const allow = rule({
      action: "allow",
      peer: { kind: "ip", value: "10.22.242.20" },
    });

    expect(
      decideService(
        [catchAll, allow],
        instances,
        [],
        new Set([reviewKey(service)]),
        service,
        undefined,
        now,
      )?.state,
    ).toBe("allow");
  });
  it("varies on IP rows that depend on DNS and decides name rows by name", () => {
    const named = rule({
      action: "allow",
      direction: "outgoing",
      peer: { kind: "hostname", value: "proof.example" },
    });

    const publicService = { ...service, peerIp: "8.8.8.8" };

    const byAddress = decideService(
      [rule(), named],
      instances,
      [],
      new Set(),
      publicService,
      undefined,
      now,
    );

    expect(byAddress?.state).toBe("varies");
    expect(stateDescription("varies", byAddress)).toBe(
      "Depends on DNS. Allowed while proof.example resolves to this address. Otherwise blocked by the catch-all.",
    );
    expect(
      decideService(
        [rule(), named],
        instances,
        [],
        new Set(),
        publicService,
        "proof.example",
        now,
      )?.state,
    ).toBe("allow");
  });
  it("varies when an address rule inside a subnet decides the service differently", () => {
    const subnet = [
      { id: instanceId, name: "Clients", addresses: ["10.22.241.0/24"] },
    ];

    const allow = rule({ instanceId, action: "allow" });

    const block = rule({
      subject: { kind: "address", value: "10.22.241.10" },
      peer: { kind: "ip", value: "10.22.242.20" },
    });

    const decision = decideService(
      [rule(), allow, block],
      subnet,
      [],
      new Set(),
      service,
      undefined,
      now,
    );

    expect(decision?.state).toBe("varies");
    expect(stateDescription("varies", decision)).toMatch(
      /^Allowed by .+, except blocked by .+ for 10\.22\.241\.10\.$/,
    );
    // The inspector lists the rule that decides the exception too.
    expect(
      inspectorRules([decision]).map(({ rule: value, note }) => [
        value.id,
        note,
      ]),
    ).toEqual(
      expect.arrayContaining([
        [allow.id, null],
        [block.id, "Decides for 10.22.241.10."],
      ]),
    );
    expect(
      decideService(
        [rule(), allow],
        subnet,
        [],
        new Set(),
        service,
        undefined,
        now,
      )?.state,
    ).toBe("allow");
  });
  it("decides an instance's service on each of its paths in the peer's family", () => {
    const parent = "22222222-2222-4222-8222-222222222222";

    // The instance has one address inside the parent and one outside it, in each family.
    const nested = [
      { id: parent, name: "Parent", addresses: ["10.0.0.0/24", "fd00::/64"] },
      {
        id: instanceId,
        name: "Client",
        addresses: ["10.0.0.2", "10.1.0.2", "fd00::2"],
      },
    ];

    const allow = rule({
      subject: { kind: "instance", instanceId: parent },
      action: "allow",
    });

    const decide = (peerIp: string, addresses = nested) =>
      decideService(
        [rule(), allow],
        addresses,
        [],
        new Set(),
        { ...service, peerIp },
        undefined,
        now,
      );

    const split = decide("10.22.242.20");

    expect(split?.state).toBe("varies");
    expect(split?.exceptions.map(({ address }) => address)).toEqual([
      "10.1.0.2",
    ]);

    // An IPv6 service is decided by the IPv6 address, inside the parent, not the IPv4 one outside.
    const outside = [
      nested[0]!,
      { ...nested[1]!, addresses: ["10.1.0.2", "fd00::2"] },
    ];

    expect(decide("10.22.242.20", outside)?.state).toBe("block");
    expect(decide("2001:db8::20", outside)?.state).toBe("allow");
  });
  it("ignores an instance path that its address rules cover entirely", () => {
    const halves = ["10.22.241.0/25", "10.22.241.128/25"].map((value) =>
      rule({ subject: { kind: "address", value }, action: "allow" }),
    );

    expect(
      decideService(
        [rule(), ...halves],
        [{ id: instanceId, name: "Clients", addresses: ["10.22.241.0/24"] }],
        [],
        new Set(),
        service,
        undefined,
        now,
      )?.state,
    ).toBe("allow");
  });
  it("varies when a name rule decides on another path of the instance", () => {
    const subnet = [
      { id: instanceId, name: "Clients", addresses: ["10.22.241.0/24"] },
    ];

    const named = rule({
      subject: { kind: "address", value: "10.22.241.2" },
      action: "allow",
      direction: "outgoing",
      peer: { kind: "hostname", value: "proof.example" },
    });

    const decision = decideService(
      [rule(), named],
      subnet,
      [],
      new Set(),
      { ...service, peerIp: "8.8.8.8" },
      undefined,
      now,
    );

    expect(decision?.state).toBe("varies");
    expect(stateDescription("varies", decision)).toBe(
      "Blocked by the catch-all, except allowed while proof.example resolves to this address, otherwise blocked by the catch-all for 10.22.241.2.",
    );
  });
  it("decides services with the gateway by Gateway peer rules and the gateway's own accepts", () => {
    const endpoint = {
      addresses: ["10.22.241.1"],
      dnsPort: 5353,
      machinePort: 9443,
      controllerPort: 9445,
      controllerAddresses: ["10.22.240.20"],
      upstreamDns: { address: "10.22.240.53", port: 53 },
    };

    const toGateway = {
      ...service,
      peerIp: "10.22.241.1",
      protocol: 6,
      port: 22,
    };

    const ssh = rule({
      instanceId,
      action: "allow",
      direction: "outgoing",
      peer: { kind: "gateway" },
      protocol: 6,
      ports: [{ start: 22, end: 22 }],
    });

    const decide = (
      rules: Rule[],
      traffic: Parameters<typeof decideService>[4],
      gateway: typeof endpoint | null = endpoint,
    ) =>
      decideService(
        rules,
        instances,
        [],
        new Set(),
        traffic,
        undefined,
        now,
        gateway,
      );

    expect(decide([rule(), ssh], toGateway)?.state).toBe("allow");
    // Without the gateway's addresses, the address is an ordinary peer.
    expect(decide([rule(), ssh], toGateway, null)?.state).toBe("block");

    const lookup = decide([rule()], { ...toGateway, protocol: 17, port: 5353 });

    expect(lookup?.state).toBe("allow");
    expect(stateDescription("allow", lookup)).toBe(
      "Allowed by the built-in DNS rule",
    );

    // DHCP is accepted only from the protocol's port, which Monitor does not record.
    const dhcp = decide([rule()], { ...toGateway, protocol: 17, port: 67 });

    expect(dhcp?.state).toBe("varies");
    expect(stateDescription("varies", dhcp)).toBe(
      "Allowed from port 68 by the built-in DHCP rule, otherwise blocked by the catch-all.",
    );

    // No rule decides the lookup, so the inspector names the accept instead, once for each accept.
    expect(inspectorRules([lookup])).toEqual([]);
    expect(inspectorBuiltIns([lookup, lookup, dhcp])).toEqual([
      { direction: "outgoing", label: "DNS · Gateway · UDP:5353" },
      {
        direction: "outgoing",
        label: "DHCP · Gateway · UDP:67 · from port 68",
      },
    ]);
    expect(
      decide([rule(), rule({ action: "allow", protocol: 17 })], {
        ...toGateway,
        protocol: 17,
        port: 67,
      })?.builtIn,
    ).toBeNull();

    // The controller link is accepted for the controller's addresses only.
    const management = (addresses: string[]) =>
      decideService(
        [rule()],
        [{ id: instanceId, name: "Management", addresses }],
        [],
        new Set(),
        { ...toGateway, port: 9443 },
        undefined,
        now,
        endpoint,
      );

    expect(stateDescription("varies", management(["10.22.240.0/24"]))).toBe(
      "Allowed for 10.22.240.20 by the built-in controller link rule, otherwise blocked by the catch-all.",
    );
    expect(management(["10.22.240.20"])?.state).toBe("allow");
    expect(management(["10.22.241.10"])?.state).toBe("block");

    // The gateway may be a DHCP client of an instance, in either IP version.
    for (const [port, from] of [
      [67, 68],
      [547, 546],
    ])
      expect(
        decide([rule()], {
          ...toGateway,
          direction: "incoming",
          protocol: 17,
          port,
        })?.builtIn,
      ).toMatchObject({ name: "DHCP", condition: `from port ${from}` });

    // With the controller's port shared with the upstream resolver's, the resolver's lookups are
    // still accepted.
    expect(
      decideService(
        [rule()],
        [{ id: instanceId, name: "Resolver", addresses: ["10.22.240.53"] }],
        [],
        new Set(),
        { ...toGateway, direction: "incoming", port: 53 },
        undefined,
        now,
        { ...endpoint, controllerPort: 53 },
      )?.state,
    ).toBe("allow");
  });
  it("colours group rows only when every service has the same outcome", () => {
    expect(combineStates([])).toBeNull();
    expect(combineStates(["allow", "allow"])).toBe("allow");
    expect(combineStates(["allow", "block"])).toBe("varies");
    expect(combineStates(["block", "waiting"])).toBe("varies");
  });
  it("lists deciding rules first and equally specific rules with the reason they have no effect", () => {
    const catchAll = rule();
    const block = rule({ peer: { kind: "ip", value: "10.22.242.20" } });

    const temporaryAllow = rule({
      action: "allow",
      peer: { kind: "ip", value: "10.22.242.20" },
      expiresAt: "2026-10-11T00:00:00.000Z",
    });

    const named = rule({
      action: "allow",
      direction: "outgoing",
      peer: { kind: "hostname", value: "proof.example" },
      protocol: 17,
    });

    const rules = [catchAll, block, temporaryAllow, named];

    const decide = (protocol: number) =>
      decideService(
        rules,
        instances,
        [],
        new Set(),
        { ...service, protocol },
        undefined,
        now,
      );

    expect(
      inspectorRules([decide(6)]).map(({ rule: value, note }) => [
        value.id,
        note,
      ]),
    ).toEqual([
      [block.id, null],
      [
        temporaryAllow.id,
        "No effect. Block wins between otherwise equal rules.",
      ],
    ]);
    expect(
      inspectorRules([
        decideService(
          [catchAll, named],
          instances,
          [],
          new Set(),
          { ...service, peerIp: "8.8.8.8", protocol: 17 },
          undefined,
          now,
        ),
      ]).map(({ rule: value, dns }) => [value.id, dns !== null]),
    ).toEqual([
      [named.id, true],
      [catchAll.id, false],
    ]);
  });
  it("explains a name rule that refuses a private answer", () => {
    const catchAll = rule();

    const named = rule({
      action: "allow",
      direction: "outgoing",
      peer: { kind: "hostname", value: "nas.home" },
    });

    const decision = decideService(
      [catchAll, named],
      instances,
      [],
      new Set(),
      { ...service, peerIp: "192.168.1.5" },
      "nas.home",
      now,
    );

    expect(decision?.state).toBe("block");
    expect(stateDescription("block", decision)).toBe(
      "Blocked by the catch-all. nas.home resolves to 192.168.1.5, which is not a public address, so nas.home · any does not apply. Add the address to the rule's permitted destination networks for it to apply.",
    );
    expect(
      inspectorRules([decision]).map(({ rule: value, note }) => [
        value.id,
        note,
      ]),
    ).toEqual([
      [
        named.id,
        "No effect for 192.168.1.5: not a public address. Add the address to its permitted destination networks for it to apply.",
      ],
      [catchAll.id, null],
    ]);
  });
});
