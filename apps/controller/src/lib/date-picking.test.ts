import { describe, expect, it } from "vitest";
import { CalendarDate, fromDate } from "@internationalized/date";
import {
  instantAt,
  minutesOf,
  nextDay,
  nextOccurrence,
  nextQuarterHour,
  passOf,
} from "./date-picking.ts";

// New York moves its clocks forward on 2026-03-08 and 2027-03-14 at 02:00, and back on
// 2026-11-01 and 2027-11-07 at 02:00.
const zone = "America/New_York";

const at = (hour: number, minute = 0) => hour * 60 + minute;

const local = (instant: string) => fromDate(new Date(instant), zone);

describe("date picking", () => {
  it("rounds up to the next quarter hour", () => {
    expect(nextQuarterHour(Date.parse("2026-11-12T16:42:10Z"))).toBe(
      "2026-11-12T16:45:00.000Z",
    );
    expect(nextQuarterHour(Date.parse("2026-11-12T16:45:00Z"))).toBe(
      "2026-11-12T17:00:00.000Z",
    );
  });

  it("keeps the local time on the next day across a clock change", () => {
    expect(nextDay("2026-10-31T13:00:00.000Z", zone)).toBe(
      "2026-11-01T14:00:00.000Z",
    );
  });

  it("places a local day and time", () => {
    const day = new CalendarDate(2026, 11, 12);

    expect(instantAt(day, at(9, 30), zone)).toBe("2026-11-12T14:30:00.000Z");
    expect(minutesOf(local("2026-11-12T14:30:00.000Z"))).toBe(at(9, 30));
  });

  it("keeps a value on the pass through a repeated hour it is already on", () => {
    const day = new CalendarDate(2027, 11, 7);
    const second = local("2027-11-07T06:30:00.000Z");
    const first = local("2027-11-07T05:30:00.000Z");

    expect(passOf(null, zone)).toBe("compatible");
    expect(passOf(first, zone)).toBe("compatible");
    expect(passOf(local("2026-11-12T14:30:00.000Z"), zone)).toBe("compatible");
    expect(passOf(second, zone)).toBe("later");
    expect(instantAt(day, at(1, 30), zone, passOf(second, zone))).toBe(
      "2027-11-07T06:30:00.000Z",
    );
    expect(instantAt(day, at(1, 15), zone, passOf(second, zone))).toBe(
      "2027-11-07T06:15:00.000Z",
    );
    expect(instantAt(day, at(1, 30), zone, passOf(first, zone))).toBe(
      "2027-11-07T05:30:00.000Z",
    );
  });

  it("takes the next time a picked time comes around", () => {
    const now = Date.parse("2026-11-12T16:42:00Z");

    expect(nextOccurrence(at(13), zone, now)).toBe("2026-11-12T18:00:00.000Z");
    expect(nextOccurrence(at(8), zone, now)).toBe("2026-11-13T13:00:00.000Z");
  });

  it("takes the second pass through a repeated hour before tomorrow", () => {
    expect(
      nextOccurrence(at(1, 45), zone, Date.parse("2026-11-01T05:50:00Z")),
    ).toBe("2026-11-01T06:45:00.000Z");
  });

  it("waits for a day that has a time a clock change skips", () => {
    expect(
      nextOccurrence(at(2, 30), zone, Date.parse("2026-03-08T07:15:00Z")),
    ).toBe("2026-03-09T06:30:00.000Z");
    expect(
      nextOccurrence(at(2, 30), zone, Date.parse("2027-03-13T17:00:00Z")),
    ).toBe("2027-03-15T06:30:00.000Z");
  });
});
