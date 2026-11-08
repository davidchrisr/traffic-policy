import { expect, it } from "vitest";
import { nameSchema } from "@traffic-policy/contracts";
import { requestPeer } from "./request-peer.ts";

const complete = (hostnames: string[]) => ({ hostnames, complete: true });

it("prefers one observed hostname and requires a choice when an address has several", () => {
  expect(requestPeer("203.0.113.10", complete(["api.example"]), true)).toEqual({
    peer: { kind: "hostname", value: "api.example" },
    choices: [
      { kind: "hostname", value: "api.example" },
      { kind: "ip", value: "203.0.113.10" },
    ],
  });

  const ambiguous = requestPeer(
    "203.0.113.10",
    complete(["api.example", "cdn.example"]),
    true,
  );

  expect(nameSchema.safeParse(ambiguous.peer.value).success).toBe(false);
  expect(ambiguous.choices).toEqual([
    { kind: "hostname", value: "api.example" },
    { kind: "hostname", value: "cdn.example" },
    { kind: "ip", value: "203.0.113.10" },
  ]);
  expect(requestPeer("203.0.113.10", complete([]), true).peer).toEqual({
    kind: "ip",
    value: "203.0.113.10",
  });
});

it("requires a choice when the observed names may be incomplete", () => {
  const partial = requestPeer(
    "203.0.113.10",
    { hostnames: ["api.example"], complete: false },
    true,
  );

  expect(partial.peer).toEqual({ kind: "hostname", value: "" });
  expect(partial.choices).toHaveLength(2);
});

it("chooses the IP address where a hostname rule would not admit it, keeping the names as choices", () => {
  const local = requestPeer("192.168.1.10", complete(["nas.example"]), false);

  expect(local.peer).toEqual({ kind: "ip", value: "192.168.1.10" });
  expect(local.choices).toEqual([
    { kind: "hostname", value: "nas.example" },
    { kind: "ip", value: "192.168.1.10" },
  ]);
});
