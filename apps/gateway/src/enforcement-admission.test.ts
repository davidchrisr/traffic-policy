import { expect, it } from "vitest";
import {
  EnforcementAdmission,
  ENFORCEMENT_DNS_LIMIT,
  ENFORCEMENT_CONTROL_LIMIT,
  ENFORCEMENT_FRAME_BUDGET,
} from "./enforcement-admission.ts";

it("admits 4096 DNS jobs while preserving thirty-two independent control slots", () => {
  const owner = new EnforcementAdmission();

  const dns = Array.from({ length: ENFORCEMENT_DNS_LIMIT }, () => {
    const lease = owner.open();
    lease.admit("dns");

    return lease;
  });

  expect(() => owner.open().admit("dns")).toThrow("queue is full");

  const controls = Array.from({ length: ENFORCEMENT_CONTROL_LIMIT }, () => {
    const lease = owner.open();
    lease.admit("control");

    return lease;
  });

  expect(() => owner.open().admit("control")).toThrow("queue is full");
  dns[0]!.close();
  expect(() => owner.open().admit("dns")).toThrow("queue is full");
  dns[0]!.complete();
  expect(() => owner.open().admit("dns")).not.toThrow();
  controls[0]!.complete();
  expect(() => owner.open().admit("control")).not.toThrow();
});

it("bounds aggregate frames and restores capacity after unfinished connections close", () => {
  const owner = new EnforcementAdmission();

  const frames = Array.from({ length: 8 }, () => {
    const frame = owner.open();
    frame.receive(ENFORCEMENT_FRAME_BUDGET / 8);

    return frame;
  });

  const next = owner.open();
  expect(() => next.receive(1)).toThrow("memory allocation is exhausted");
  frames[0]!.close();
  frames[0]!.close();
  expect(() => next.receive(ENFORCEMENT_FRAME_BUDGET / 8)).not.toThrow();
  expect(() => next.receive(1)).toThrow("memory allocation is exhausted");
});

it.each(["disconnect-first", "complete-first"])(
  "retains parsed-command bytes until both work and socket end, %s",
  (order) => {
    const owner = new EnforcementAdmission();
    const command = owner.open();
    command.receive(ENFORCEMENT_FRAME_BUDGET);
    command.admit("dns");

    if (order === "disconnect-first") command.close();
    else command.complete();
    expect(() => owner.open().receive(1)).toThrow(
      "memory allocation is exhausted",
    );

    if (order === "disconnect-first") command.complete();
    else command.close();
    command.close();
    command.complete();
    const next = owner.open();
    expect(() => next.receive(ENFORCEMENT_FRAME_BUDGET)).not.toThrow();
    expect(() => owner.open().receive(1)).toThrow(
      "memory allocation is exhausted",
    );
  },
);

it("does not change a saturated byte reservation after a rejected chunk", () => {
  const owner = new EnforcementAdmission();
  const first = owner.open();
  first.receive(ENFORCEMENT_FRAME_BUDGET - 1);
  expect(() => first.receive(2)).toThrow("memory allocation is exhausted");
  expect(() => owner.open().receive(1)).not.toThrow();
  expect(() => owner.open().receive(1)).toThrow(
    "memory allocation is exhausted",
  );
});

it("rejects repeated admission and data after admission or closure", () => {
  const owner = new EnforcementAdmission();
  const command = owner.open();
  command.admit("control");
  expect(() => command.admit("dns")).toThrow("admitted twice");
  expect(() => command.receive(1)).toThrow("frame is closed");
  command.complete();
  expect(() => command.admit("control")).toThrow("admitted twice");
  const closed = owner.open();
  closed.close();
  expect(() => closed.admit("dns")).toThrow("admitted twice");
  expect(() => closed.receive(1)).toThrow("frame is closed");
});
