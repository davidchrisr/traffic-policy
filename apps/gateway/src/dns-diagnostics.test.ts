import { afterEach, expect, it, vi } from "vitest";
import {
  DnsFailureDiagnostics,
  type DnsDiagnostic,
  type DnsFailure,
} from "./dns-diagnostics.ts";

const failure: DnsFailure = {
  code: "dns_authorization_expired",
  stage: "enforcement",
  upstreamMs: 1,
  enforcementMs: 2100,
  totalMs: 2101,
  responseAgeMs: 2100,
};

afterEach(() => vi.useRealTimers());

it("limits a 500-error burst, reports exhaustion once, and flushes counts without another request", () => {
  vi.useFakeTimers();
  let now = 0;
  const entries: DnsDiagnostic[] = [];

  const diagnostics = new DnsFailureDiagnostics(
    (entry) => entries.push(entry),
    () => now,
  );

  try {
    for (let count = 0; count < 500; count++) diagnostics.report(failure);
    expect(
      entries.filter((entry) => entry.event === "dns_failure"),
    ).toHaveLength(20);
    expect(
      entries.filter((entry) => entry.event === "dns_diagnostics_rate_limited"),
    ).toHaveLength(1);
    now = 60000;
    vi.advanceTimersByTime(60000);
    expect(entries.at(-1)).toMatchObject({
      event: "dns_failure_summary",
      failures: 500,
      detailed: 20,
      suppressed: 480,
      byCode: [{ code: failure.code, failures: 500 }],
      otherCodeFailures: 0,
    });
    vi.advanceTimersByTime(60000);
    expect(entries).toHaveLength(22);
  } finally {
    diagnostics.close();
  }
});

it("refills one token every three seconds without repeated exhaustion notices", () => {
  let now = 0;
  const entries: DnsDiagnostic[] = [];

  const diagnostics = new DnsFailureDiagnostics(
    (entry) => entries.push(entry),
    () => now,
  );

  try {
    for (let count = 0; count < 21; count++) diagnostics.report(failure);
    now = 2999;
    diagnostics.report(failure);
    expect(
      entries.filter((entry) => entry.event === "dns_failure"),
    ).toHaveLength(20);
    now = 3000;
    diagnostics.report(failure);
    diagnostics.report(failure);
    expect(
      entries.filter((entry) => entry.event === "dns_failure"),
    ).toHaveLength(21);
    expect(
      entries.filter((entry) => entry.event === "dns_diagnostics_rate_limited"),
    ).toHaveLength(1);
    diagnostics.close();
    expect(entries.at(-1)).toMatchObject({
      failures: 24,
      detailed: 21,
      suppressed: 3,
    });
  } finally {
    diagnostics.close();
  }
});

it("keeps the bucket across reporting boundaries and bounds error-code cardinality", () => {
  let now = 0;
  const entries: DnsDiagnostic[] = [];

  const diagnostics = new DnsFailureDiagnostics(
    (entry) => entries.push(entry),
    () => now,
  );

  try {
    for (let count = 0; count < 500; count++)
      diagnostics.report({
        ...failure,
        code: `code_${count}`,
      });
    now = 59000;

    for (let count = 0; count < 20; count++) diagnostics.report(failure);
    expect(
      entries.filter((entry) => entry.event === "dns_failure"),
    ).toHaveLength(39);
    now = 60000;
    diagnostics.report(failure);
    diagnostics.report(failure);
    expect(
      entries.filter((entry) => entry.event === "dns_failure"),
    ).toHaveLength(40);

    const summary = entries.find(
      (entry) => entry.event === "dns_failure_summary",
    );

    expect(summary).toMatchObject({
      failures: 520,
      detailed: 39,
      suppressed: 481,
      otherCodeFailures: 504,
    });

    if (!summary || summary.event !== "dns_failure_summary")
      throw new Error("Missing summary");
    expect(summary.byCode).toHaveLength(16);
    expect(
      entries.filter((entry) => entry.event === "dns_diagnostics_rate_limited"),
    ).toHaveLength(2);

    for (const entry of entries) {
      if (entry.event === "dns_failure" && entry.code.startsWith("code_"))
        expect(entry.message).toBe("DNS authorization failed");
    }
  } finally {
    diagnostics.close();
  }
});

it("stays silent without failures and closes timers after a single final summary", () => {
  vi.useFakeTimers();
  const entries: DnsDiagnostic[] = [];
  const diagnostics = new DnsFailureDiagnostics((entry) => entries.push(entry));
  vi.advanceTimersByTime(120000);
  expect(entries).toHaveLength(0);
  diagnostics.report(failure);
  diagnostics.close();
  diagnostics.close();
  diagnostics.report(failure);
  vi.advanceTimersByTime(120000);
  expect(entries.map((entry) => entry.event)).toEqual([
    "dns_failure",
    "dns_failure_summary",
  ]);
  expect(vi.getTimerCount()).toBe(0);
});

it("starts refill from use of a full bucket rather than banking an idle partial tick", () => {
  let now = 0;
  const entries: DnsDiagnostic[] = [];

  const diagnostics = new DnsFailureDiagnostics(
    (entry) => entries.push(entry),
    () => now,
  );

  try {
    now = 2999;

    for (let count = 0; count < 20; count++) diagnostics.report(failure);
    now = 3000;
    diagnostics.report(failure);
    expect(
      entries.filter((entry) => entry.event === "dns_failure"),
    ).toHaveLength(20);
    now = 5999;
    diagnostics.report(failure);
    expect(
      entries.filter((entry) => entry.event === "dns_failure"),
    ).toHaveLength(21);
  } finally {
    diagnostics.close();
  }
});

it("gives processing and persistence failures independent reporting budgets", () => {
  const entries: DnsDiagnostic[] = [];

  const processing = new DnsFailureDiagnostics(
    (entry) => entries.push(entry),
    () => 0,
  );

  const observations = new DnsFailureDiagnostics(
    (entry) => entries.push(entry),
    () => 0,
    "resolver-observation",
  );

  for (let count = 0; count < 500; count++) {
    processing.report(failure);
    observations.report({
      ...failure,
      stage: "observation",
      code: "observation_persistence_failed",
    });
  }

  processing.close();
  observations.close();

  for (const service of ["resolver-gate", "resolver-observation"]) {
    expect(
      entries.filter(
        (entry) => entry.service === service && entry.event === "dns_failure",
      ),
    ).toHaveLength(20);
    expect(
      entries.filter(
        (entry) =>
          entry.service === service &&
          entry.event === "dns_diagnostics_rate_limited",
      ),
    ).toHaveLength(1);
    expect(
      entries.filter(
        (entry) =>
          entry.service === service && entry.event === "dns_failure_summary",
      )[0],
    ).toMatchObject({ failures: 500, detailed: 20, suppressed: 480 });
  }
});
