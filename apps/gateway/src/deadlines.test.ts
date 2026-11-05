import { expect, it } from "vitest";
import { Deadlines } from "./deadlines.ts";

it("replaces deadlines and removes arbitrary keys without duplicate expiry", () => {
  const queue = new Deadlines<string>();
  queue.set("a", 30);
  queue.set("b", 10);
  queue.set("c", 20);
  queue.set("a", 5);
  queue.delete("c");
  const seen: string[] = [];
  queue.drain(9, (key) => seen.push(key));
  expect(seen).toEqual(["a"]);
  queue.set("b", 50);
  queue.drain(49, (key) => seen.push(key));
  expect(seen).toEqual(["a"]);
  queue.drain(50, (key) => seen.push(key));
  expect(seen).toEqual(["a", "b"]);
});

it("lets a cursor advance without consuming confirmed expiry", () => {
  const queue = new Deadlines<number>();

  for (let n = 30; n > 0; n--) queue.set(n, n);

  const cursor = queue.cursor(),
    seen: number[] = [];

  cursor.drain(10, (key) => seen.push(key));
  cursor.drain(10, (key) => seen.push(key));
  cursor.drain(15, (key) => seen.push(key));
  expect(seen).toEqual(Array.from({ length: 15 }, (_, n) => n + 1));
  const original: number[] = [];
  queue.drain(30, (key) => original.push(key));
  expect(original).toEqual(Array.from({ length: 30 }, (_, n) => n + 1));
});

it("agrees with a reference map through replacements, deletion and expiry", () => {
  const queue = new Deadlines<number>(),
    reference = new Map<number, number>();

  let state = 12345;

  for (let step = 0; step < 1000; step++) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;

    const key = state % 47,
      deadline = step + (state % 31);

    if (state % 5 === 0) {
      queue.delete(key);
      reference.delete(key);
    } else {
      queue.set(key, deadline);
      reference.set(key, deadline);
    }

    const expected: number[] = [];

    for (const [id, at] of reference)
      if (at <= step) {
        expected.push(id);
        reference.delete(id);
      }

    const actual: number[] = [];
    queue.drain(step, (id) => actual.push(id));
    expect(actual.sort((a, b) => a - b)).toEqual(
      expected.sort((a, b) => a - b),
    );
  }
});
