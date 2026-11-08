import type { Rule } from "@traffic-policy/contracts";
import type { RequestSuggestions } from "@traffic-policy/contracts/dashboard";

export type RequestPeer = Extract<Rule["peer"], { kind: "hostname" | "ip" }>;

// One observed hostname is chosen; several, or a list that left some out, require a choice, and the
// empty hostname cannot be saved. Where a hostname rule would not admit the address, the IP is.
export function requestPeer(
  peerIp: string,
  suggestions: RequestSuggestions,
  admitsAddress: boolean,
) {
  const choices: RequestPeer[] = [
    ...suggestions.hostnames.map((value) => ({
      kind: "hostname" as const,
      value,
    })),
    { kind: "ip", value: peerIp },
  ];

  const peer = (
    !admitsAddress || !suggestions.hostnames.length
      ? { kind: "ip", value: peerIp }
      : suggestions.hostnames.length > 1 || !suggestions.complete
        ? { kind: "hostname", value: "" }
        : choices[0]!
  ) satisfies RequestPeer;

  return { peer, choices };
}
