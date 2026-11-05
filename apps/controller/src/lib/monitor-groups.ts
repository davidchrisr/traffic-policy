import type { MonitorSnapshot } from "@traffic-policy/contracts/dashboard";

type TrafficService = {
  key: string;
  instanceId: string;
  peerIp: string;
  receivedBytes: string;
  sentBytes: string;
};

export function groupDestinations<T extends TrafficService>(services: T[]) {
  const groups = new Map<
    string,
    {
      key: string;
      instanceId: string;
      peerIp: string;
      services: T[];
      received: bigint;
      sent: bigint;
    }
  >();

  for (const service of services) {
    const key = JSON.stringify([service.instanceId, service.peerIp]);
    let group = groups.get(key);

    if (!group) {
      group = {
        key,
        instanceId: service.instanceId,
        peerIp: service.peerIp,
        services: [],
        received: 0n,
        sent: 0n,
      };
      groups.set(key, group);
    }

    group.services.push(service);
    group.received += BigInt(service.receivedBytes);
    group.sent += BigInt(service.sentBytes);
  }

  return [...groups.values()].map(({ received, sent, ...group }) => ({
    ...group,
    receivedBytes: received.toString(),
    sentBytes: sent.toString(),
  }));
}

export function groupNames<
  T extends {
    key: string;
    instanceId: string;
    peerIp: string;
    receivedBytes: string;
    sentBytes: string;
  },
>(
  peers: T[],
  names: {
    instanceId: string;
    peerIp: string;
    hostname: string;
    domain: string | null;
  }[],
) {
  const domains = new Map<string, Map<string, T[]>>(),
    ungrouped: (T & { names: string[] })[] = [];

  const sum = (items: T[]) => ({
    receivedBytes: items
      .reduce((total, item) => total + BigInt(item.receivedBytes), 0n)
      .toString(),
    sentBytes: items
      .reduce((total, item) => total + BigInt(item.sentBytes), 0n)
      .toString(),
  });

  for (const peer of peers) {
    const aliases = names.filter(
      (name) =>
        name.instanceId === peer.instanceId && name.peerIp === peer.peerIp,
    );

    // An IP joins a name only when exactly one name was observed for it; otherwise it is listed
    // under IP addresses with every observed name as secondary text.
    if (aliases.length !== 1) {
      ungrouped.push({
        ...peer,
        names: aliases.map((alias) => alias.hostname).sort(),
      });
      continue;
    }

    const label = aliases[0]!,
      domain = label.domain ?? label.hostname;

    let hosts = domains.get(domain);

    if (!hosts) {
      hosts = new Map();
      domains.set(domain, hosts);
    }

    hosts.set(label.hostname, [...(hosts.get(label.hostname) ?? []), peer]);
  }

  return {
    domains: [...domains.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([name, hosts]) => {
        const entries = [...hosts.entries()]
          .sort(([left], [right]) => left.localeCompare(right))
          .map(([hostname, members]) => ({
            name: hostname,
            peers: members,
            ...sum(members),
          }));

        return {
          name,
          hosts: entries,
          ...sum(entries.flatMap((host) => host.peers)),
        };
      }),
    ungrouped,
  };
}

type EventSummary = NonNullable<MonitorSnapshot["eventSummary"]>;

// Blocked sample rows under the rule and direction that blocked them, with the rule's counted
// packets for the instance. Rules that counted packets without sample rows are listed only for the
// instance itself: under a destination, service, or name they need not concern it. When the summary
// did not read every event in the period, a narrower view reports instance blocks instead.
export function groupBlocked(summary: EventSummary, instanceView: boolean) {
  const partial =
    summary.scannedFrom !== null ||
    summary.eventsLimited ||
    summary.eventsTruncated;

  const totals = new Map(
    summary.blockedTotals.map((total) => [
      `${total.ruleId}|${total.direction}`,
      total,
    ]),
  );

  const rules = new Map<
    string,
    {
      key: string;
      ruleId: string | null;
      direction: EventSummary["events"][number]["direction"];
      rows: EventSummary["events"];
      packets: bigint | null;
      incomplete: boolean;
    }
  >();

  for (const group of summary.events) {
    if (group.type !== "blocked") continue;
    const key = `${group.ruleId}|${group.direction}`;
    let rule = rules.get(key);

    if (!rule) {
      const total = totals.get(key);

      rule = {
        key,
        ruleId: group.ruleId,
        direction: group.direction,
        rows: [],
        packets: total ? BigInt(total.packets) : null,
        incomplete:
          total !== undefined && BigInt(total.packets) > BigInt(total.samples),
      };
      rules.set(key, rule);
    }

    rule.rows.push(group);
  }

  const unsampled = [...totals]
    .flatMap(([key, total]) =>
      rules.has(key) || BigInt(total.packets) === 0n
        ? []
        : [
            {
              key,
              ruleId: total.ruleId,
              direction: total.direction,
              rows: [],
              packets: BigInt(total.packets),
              incomplete: true,
            },
          ],
    )
    .sort((left, right) =>
      left.packets === right.packets
        ? left.key.localeCompare(right.key)
        : left.packets > right.packets
          ? -1
          : 1,
    );

  return {
    rules: [...rules.values(), ...(instanceView ? unsampled : [])],
    partial,
    // The instance counted blocked packets whose samples this narrower summary may have missed.
    instanceBlocked:
      !instanceView &&
      partial &&
      summary.blockedTotals.some((total) => BigInt(total.packets) > 0n),
  };
}
