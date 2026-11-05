import { expect, it } from "vitest";
import { ManagedConnections } from "./managed-connections.ts";
import { parseConnections } from "./connections.ts";

const selection = (...addresses: string[]) =>
  new ManagedConnections(
    addresses.length ? [{ id: "instance", addresses }] : [],
  );

it("accepts a complete empty managed snapshot while rejecting incomplete XML", () => {
  const selected = selection();
  const bytes = selected.write(Buffer.from("<conntrack>\n</conntrack>\n"));
  expect(
    parseConnections(Buffer.concat([bytes, selected.end()]).toString()),
  ).toEqual([]);
  expect(() => parseConnections("<conntrack>")).toThrow("complete document");
  expect(() => parseConnections("<other/>")).toThrow(
    "not a conntrack document",
  );
});

function flow(
  id: number,
  source: string,
  destination: string,
  replySource = destination,
) {
  return `<flow><meta direction="original"><layer3 protonum="2" protoname="ipv4"><src>${source}</src><dst>${destination}</dst></layer3><layer4 protonum="17"><sport>40000</sport><dport>53</dport></layer4></meta><meta direction="reply"><layer3 protonum="2" protoname="ipv4"><src>${replySource}</src><dst>${source}</dst></layer3><layer4 protonum="17"><sport>53</sport><dport>40000</dport></layer4></meta><meta direction="independent"><id>${id}</id></meta></flow>\n`;
}

it("retains original and translated endpoints inside managed networks across fragmented native output", () => {
  const selected = selection("10.22.241.0/24", "10.22.242.20");

  const input = Buffer.from(
    '<?xml version="1.0"?>\n<conntrack>\n' +
      flow(1, "10.22.240.10", "10.22.240.40") +
      flow(2, "10.22.241.10", "8.8.8.8") +
      flow(3, "203.0.113.5", "198.51.100.10", "10.22.242.20") +
      "</conntrack>",
  );

  const output: Buffer[] = [];

  for (let i = 0; i < input.length; i += 7)
    output.push(selected.write(input.subarray(i, i + 7)));
  output.push(selected.end());
  const rows = parseConnections(Buffer.concat(output).toString());
  expect(rows).toHaveLength(2);
  expect(rows.map((row) => row.flow.initiatorIp)).toEqual([
    "10.22.241.10",
    "203.0.113.5",
  ]);
  expect(rows[1]!.flow.responderIp).toBe("10.22.242.20");
});

it("ignores master metadata when selecting managed original and reply endpoints", () => {
  const selected = selection("10.22.241.10");

  const unrelated = flow(1, "10.22.240.10", "10.22.240.40").replace(
    "</flow>",
    '<meta direction="master"><layer3><src>10.22.241.10</src><dst>8.8.8.8</dst></layer3></meta></flow>',
  );

  const bytes = selected.write(
    Buffer.from("<conntrack>\n" + unrelated + "</conntrack>\n"),
  );

  expect(
    parseConnections(Buffer.concat([bytes, selected.end()]).toString()),
  ).toEqual([]);
});

it("rejects incomplete documents and malformed tuple identities instead of publishing a partial snapshot", () => {
  const selected = selection("10.22.241.10");
  selected.write(Buffer.from("<conntrack>\n"));
  expect(() => selected.end()).toThrow("complete document");
  const malformed = selection();
  expect(() =>
    malformed.write(Buffer.from("<conntrack>\n<flow></flow>\n")),
  ).toThrow("identity");
});

it("bounds managed response bytes while allowing unrelated flows to be discarded", () => {
  const selected = selection("10.22.241.10");
  selected.write(Buffer.from("<conntrack>\n"));
  const unrelated = flow(1, "10.22.240.10", "10.22.240.40");

  for (let i = 0; i < 4000; i++)
    expect(selected.write(Buffer.from(unrelated))).toHaveLength(0);
  const managed = Buffer.from(flow(2, "10.22.241.10", "8.8.8.8"));
  expect(() => {
    for (let i = 0; i < 5000; i++) selected.write(managed);
  }).toThrow("transport allocation");
});

it("counts the complete escaped XML content against the caller's remaining budget", () => {
  const xml =
    "<conntrack>\n" + flow(1, "10.22.241.10", "8.8.8.8") + "</conntrack>\n";

  const budget = Buffer.byteLength(JSON.stringify(xml)) - 2;

  const exact = new ManagedConnections(
    [{ id: "instance", addresses: ["10.22.241.10"] }],
    budget,
  );

  const output = Buffer.concat([
    exact.write(Buffer.from(xml)),
    exact.end(),
  ]).toString();

  expect(output).toBe(xml);

  const excess = new ManagedConnections(
    [{ id: "instance", addresses: ["10.22.241.10"] }],
    budget - 1,
  );

  expect(() => excess.write(Buffer.from(xml))).toThrow("transport allocation");
});
