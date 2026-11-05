import { expect, it } from "vitest";
import { CommandFrame } from "./command-frame.ts";

it("decodes coalesced frames independently and rejects a truncated final frame", () => {
  const frame = new CommandFrame();
  const values: unknown[] = [];
  frame.write(Buffer.from('{"id":1}\n{"id":2}\n{"id":'), (value) =>
    values.push(value),
  );
  expect(values).toEqual([{ id: 1 }, { id: 2 }]);
  expect(() => frame.end()).toThrow("before its complete frame");
});

it("applies the byte limit to individual frames rather than a connection lifetime", () => {
  const frame = new CommandFrame();
  let count = 0;
  const value = JSON.stringify({ text: "x".repeat(1100000) }) + "\n";
  frame.write(Buffer.from(value + value), () => {
    count++;
  });
  frame.end();
  expect(count).toBe(2);
});

it("preserves split multibyte characters in inbound commands", () => {
  const frame = new CommandFrame();
  const values: unknown[] = [];

  for (const byte of Buffer.from(JSON.stringify({ name: "é 東京 🚀" }) + "\n"))
    frame.write(Buffer.from([byte]), (value) => values.push(value));
  frame.end();
  expect(values).toEqual([{ name: "é 東京 🚀" }]);
});

it("bounds received raw bytes before decoding", () => {
  const frame = new CommandFrame();
  expect(() =>
    frame.write(Buffer.alloc(2 * 1024 * 1024 + 1), () => {}),
  ).toThrow("exceeds its limit");
});
