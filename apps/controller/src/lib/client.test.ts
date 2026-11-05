import { describe, expect, it } from "vitest";
import { displayBytes, displayTrafficBytes } from "./client.ts";

describe("byte formatting", () => {
  it("uses decimal units for traffic at each boundary", () => {
    expect(displayTrafficBytes("0")).toBe("0 B");
    expect(displayTrafficBytes("999")).toBe("999 B");
    expect(displayTrafficBytes("1000")).toBe("1.00 KB");
    expect(displayTrafficBytes("7050")).toBe("7.05 KB");
    expect(displayTrafficBytes("999999")).toBe("999.99 KB");
    expect(displayTrafficBytes("1000000")).toBe("1.00 MB");
    expect(displayTrafficBytes("1000000000")).toBe("1.00 GB");
  });
  it("formats large counters with exact integer arithmetic", () => {
    expect(displayTrafficBytes("9007199254740993")).toBe("9.00 PB");
    expect(displayTrafficBytes("18446744073709551615")).toBe("18.44 EB");
  });
  it("keeps storage formatting in binary units", () => {
    expect(displayBytes("1000")).toBe("1000 B");
    expect(displayBytes("1024")).toBe("1.00 KiB");
    expect(displayBytes("1048576")).toBe("1.00 MiB");
  });
});
