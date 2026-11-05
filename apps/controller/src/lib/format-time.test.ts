import { describe, expect, it } from "vitest";
import { formatInstant, formatInstantInSentence } from "./format-time.ts";

describe("list time formatting", () => {
  const now = new Date(2026, 9, 25, 15, 0);
  const at = (date: Date) => formatInstant(date.toISOString(), now, "en-US");

  it("reads relative within an hour in either direction", () => {
    expect(at(new Date(2026, 9, 25, 14, 59, 30))).toBe("just now");
    expect(at(new Date(2026, 9, 25, 14, 53))).toBe("7 min ago");
    expect(at(new Date(2026, 9, 25, 15, 0, 20))).toBe("in 1 min");
    expect(at(new Date(2026, 9, 25, 15, 40))).toBe("in 40 min");
  });

  it("reads whole hours within a day, even across midnight", () => {
    expect(at(new Date(2026, 9, 25, 11, 50))).toBe("3 hr ago");
    expect(at(new Date(2026, 9, 24, 15, 30))).toBe("23 hr ago");
    expect(at(new Date(2026, 9, 26, 2, 0))).toBe("in 11 hr");
    expect(at(new Date(2026, 9, 25, 15, 59, 40))).toBe("in 1 hr");
    expect(at(new Date(2026, 9, 25, 14, 0, 20))).toBe("1 hr ago");
  });

  it("reads calendar days through six days", () => {
    expect(at(new Date(2026, 9, 24, 9, 0))).toBe("Yesterday");
    expect(at(new Date(2026, 9, 27, 9, 0))).toBe("in 2 days");
    expect(at(new Date(2026, 9, 26, 18, 0))).toBe("Tomorrow");
    expect(at(new Date(2026, 9, 21, 9, 0))).toBe("4 days ago");
    expect(at(new Date(2026, 9, 19, 9, 0))).toBe("6 days ago");
  });

  it("shows the date from seven days, with the year only for other years", () => {
    // ICU may separate the time and day period with a narrow no-break space.
    const plain = (date: Date) => at(date).replace(/\s/gu, " ");

    expect(plain(new Date(2026, 9, 18, 18, 18))).toBe("Oct 18, 6:18 PM");
    expect(plain(new Date(2026, 10, 2, 9, 0))).toBe("Nov 2, 9:00 AM");
    expect(plain(new Date(2025, 9, 13, 18, 18))).toBe("Oct 13, 2025");
  });

  it("lowercases yesterday and tomorrow inside a sentence", () => {
    const tomorrow = new Date(2026, 9, 26, 18, 0).toISOString();

    expect(formatInstantInSentence(tomorrow, now, "en-US")).toBe("tomorrow");
  });
});
