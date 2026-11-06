import type {
  ServiceId,
  ServiceState,
  ServicesSnapshot,
} from "@traffic-policy/contracts/services";

export type StatusTone = "allow" | "pending" | "destructive" | "muted";

export type StatusItemId = "rules" | "gateway" | "suricata";

export interface StatusItem {
  id: StatusItemId;
  label: string;
  tone: StatusTone;
  // One line per part that needs attention, listed under the item; empty when it runs normally.
  problems: string[];
  // What the item covers, for its tooltip.
  description: string;
}

export interface GatewaySync {
  pending: boolean;
  lastError: string | null;
  contactAgeMs: number | null;
}

interface Part {
  // Null for a notice that covers every part of the item.
  label: string | null;
  state: string;
  tone: StatusTone;
}

// The browser server is not listed: the page that shows it is served by it.
type ListedServiceId = Exclude<ServiceId, "controller">;

const labels: Record<ListedServiceId, string> = {
  machine: "Link process",
  gateway: "Gateway service",
  enforcement: "Enforcement service",
  suricata: "Suricata",
  "suricata-rotate": "Log rotation",
};

function transitionLabel(state: string): string {
  switch (state) {
    case "activating":
      return "Starting";
    case "deactivating":
      return "Stopping";
    case "reloading":
      return "Reloading";
    default:
      return state;
  }
}

function servicePart(
  service: ServiceState,
  stale: boolean,
): Omit<Part, "label"> {
  if (stale) return { state: "Out of date", tone: "pending" };

  if (service.loadState !== "loaded")
    return { state: "Not available", tone: "destructive" };

  if (service.activeState === "failed")
    return {
      state:
        service.exitStatus === null
          ? "Failed"
          : `Failed · exit ${service.exitStatus}`,
      tone: "destructive",
    };

  if (service.activeState === "active")
    return { state: "Running", tone: "allow" };

  if (service.activeState === "inactive")
    return { state: "Stopped", tone: "pending" };

  return { state: transitionLabel(service.activeState), tone: "pending" };
}

const rank: Record<StatusTone, number> = {
  allow: 0,
  muted: 1,
  pending: 2,
  destructive: 3,
};

export function worstTone(tones: StatusTone[]): StatusTone {
  return tones.reduce<StatusTone>(
    (worst, tone) => (rank[tone] > rank[worst] ? tone : worst),
    "allow",
  );
}

function contactAge(ageMs: number): string {
  const totalSeconds = Math.floor(ageMs / 1000);
  const seconds = totalSeconds % 60;
  const minutes = Math.floor(totalSeconds / 60) % 60;
  const hours = Math.floor(totalSeconds / 3600);

  if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`;

  if (totalSeconds >= 60) return `${minutes}m ${seconds}s`;

  return `${seconds}s`;
}

function item(
  id: StatusItemId,
  label: string,
  description: string,
  parts: Part[],
): StatusItem {
  return {
    id,
    label,
    tone: worstTone(parts.map((part) => part.tone)),
    // A notice for a whole host can come from both hosts an item covers; it is listed once.
    problems: [
      ...new Set(
        parts.flatMap((part) =>
          part.tone === "pending" || part.tone === "destructive"
            ? [part.label ? `${part.label}: ${part.state}` : part.state]
            : [],
        ),
      ),
    ],
    description,
  };
}

// Rule application, the gateway with the controller's link to it and its enforcement service, and
// Suricata with its output maintenance. A missing or stale services read marks every service it
// covers instead of hiding it.
export function statusItems(
  sync: GatewaySync,
  services: ServicesSnapshot | null,
  servicesStale: boolean,
  servicesFailed: boolean,
): StatusItem[] {
  const stale = sync.contactAgeMs === null || sync.contactAgeMs > 15000;

  const parts = (
    scope: "controller" | "gateway",
    ids: ListedServiceId[],
  ): Part[] => {
    const source = services?.[scope];

    // An unreadable host is one problem for every service it reports, not one per service.
    const unreadable = servicesFailed
      ? "Service status could not be refreshed."
      : source?.available === false
        ? source.message
        : null;

    if (unreadable)
      return [{ label: null, state: unreadable, tone: "pending" }];

    return ids.map((id) => {
      const service =
        source?.available &&
        source.snapshot.services.find((value) => value.id === id);

      return service
        ? { label: labels[id], ...servicePart(service, servicesStale) }
        : { label: labels[id], state: "Checking", tone: "muted" };
    });
  };

  return [
    item(
      "rules",
      "Rules",
      "Whether the gateway has confirmed the saved policy.",
      [
        {
          label: "Rule changes",
          ...(sync.lastError
            ? { state: "Not confirmed", tone: "destructive" as const }
            : sync.pending
              ? { state: "Applying", tone: "pending" as const }
              : stale
                ? { state: "Out of date", tone: "pending" as const }
                : { state: "Applied", tone: "allow" as const }),
        },
      ],
    ),
    // A running link process counts only while the gateway answered it within 15 seconds.
    item(
      "gateway",
      "Gateway",
      "Receives the policy from the controller's link process, answers DNS for managed clients, and collects traffic. The enforcement service applies rules in nftables.",
      [
        {
          label: "Gateway contact",
          ...(stale
            ? {
                state:
                  sync.contactAgeMs === null
                    ? "No contact yet"
                    : `No contact for ${contactAge(sync.contactAgeMs)}`,
                tone: "destructive" as const,
              }
            : { state: "Connected", tone: "allow" as const }),
        },
        ...parts("controller", ["machine"]),
        ...parts("gateway", ["gateway", "enforcement"]),
      ],
    ),
    item(
      "suricata",
      "Suricata",
      "Records HTTP and TLS names from traffic. Log rotation keeps its log files within their size limit.",
      parts("gateway", ["suricata", "suricata-rotate"]),
    ),
  ];
}
