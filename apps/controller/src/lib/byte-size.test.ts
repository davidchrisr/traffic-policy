import { describe, expect, it } from "vitest";
import { formatByteSize, parseByteSize } from "./byte-size.ts";

describe("byte size input", () => {
  it("reads decimal units, binary units, and bare byte counts", () => {
    expect(parseByteSize("4 GiB")).toEqual({ bytes: "4294967296" });
    expect(parseByteSize("4GB")).toEqual({ bytes: "4000000000" });
    expect(parseByteSize(" 128 mib ")).toEqual({ bytes: "134217728" });
    expect(parseByteSize("500 KB")).toEqual({ bytes: "500000" });
    expect(parseByteSize("1048576")).toEqual({ bytes: "1048576" });
    expect(parseByteSize("0 B")).toEqual({ bytes: "0" });
  });

  it("accepts decimals only when they land on whole bytes", () => {
    expect(parseByteSize("1.5 GiB")).toEqual({ bytes: "1610612736" });
    expect(parseByteSize("0.25 KB")).toEqual({ bytes: "250" });
    expect(parseByteSize("1.1 KiB")).toEqual({
      error: "The size must be a whole number of bytes.",
    });
  });

  it("rejects bare prefixes, unknown units, malformed text, and values over uint64", () => {
    expect(parseByteSize("4G")).toEqual({ error: "Use GB or GiB." });
    expect(parseByteSize("4 gigs")).toEqual({
      error: "Use B, KB, MB, GB, TB, KiB, MiB, GiB, or TiB.",
    });
    expect(parseByteSize("")).toEqual({
      error: "Enter a size such as 4 GiB, 500 MB, or 1048576.",
    });
    expect(parseByteSize("-1 GiB")).toEqual({
      error: "Enter a size such as 4 GiB, 500 MB, or 1048576.",
    });
    expect(parseByteSize("18446744073709551615")).toEqual({
      bytes: "18446744073709551615",
    });
    expect(parseByteSize("16 EiB")).toEqual({
      error: "The size is too large.",
    });
  });

  it("shows the shortest exact form", () => {
    expect(formatByteSize("4294967296")).toBe("4 GiB");
    expect(formatByteSize("4000000000")).toBe("4 GB");
    expect(formatByteSize("134217728")).toBe("128 MiB");
    expect(formatByteSize("1048577")).toBe("1048577 B");
    expect(formatByteSize("0")).toBe("0 B");
  });
});
