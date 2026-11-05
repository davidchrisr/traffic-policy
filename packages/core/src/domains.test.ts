import { expect, it } from "vitest";
import { registrableDomain } from "./domains.ts";

it("uses public and private suffixes, wildcards, exceptions, and IDNA", () => {
  expect(registrableDomain("api.example.co.uk")).toBe("example.co.uk");
  expect(registrableDomain("a.project.blogspot.com")).toBe(
    "project.blogspot.com",
  );
  expect(registrableDomain("a.city.kawasaki.jp")).toBe("city.kawasaki.jp");
  expect(registrableDomain("a.b.ck")).toBe("a.b.ck");
  expect(registrableDomain("a.www.ck")).toBe("www.ck");
  expect(registrableDomain("食狮.中国")).toBe("xn--85x722f.xn--fiqs8s");
  expect(registrableDomain("co.uk")).toBeNull();
  expect(registrableDomain("192.0.2.1")).toBeNull();
});
