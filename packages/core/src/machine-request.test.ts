import { expect, it, vi, afterEach } from "vitest";
import { EventEmitter } from "node:events";

const transport = vi.hoisted(() => ({
  callback: null as null | ((response: EventEmitter) => void),
  destroy: vi.fn(),
}));

vi.mock("node:http", () => ({
  request: (
    _options: import("node:http").RequestOptions,
    callback: (response: EventEmitter) => void,
  ) => {
    transport.callback = callback;
    const request = new EventEmitter();

    return Object.assign(request, {
      destroy: transport.destroy,
      end: () => {},
    });
  },
}));

vi.mock("node:fs/promises", async (original) => ({
  ...(await original<typeof import("node:fs/promises")>()),
  readFile: async () => Buffer.from("fixture"),
}));

import { requestJson } from "./io.server.ts";

afterEach(() => {
  vi.useRealTimers();
  transport.destroy.mockClear();
});

it("ends a trickling machine response at the elapsed deadline", async () => {
  vi.useFakeTimers();

  const result = requestJson(
    new URL("https://fixture.invalid"),
    { ca: "ca", certificate: "cert", key: "key" },
    "GET",
    undefined,
    100,
  );

  const rejected = expect(result).rejects.toThrow("timed out");
  await vi.advanceTimersByTimeAsync(1);
  const response = Object.assign(new EventEmitter(), { statusCode: 200 });
  transport.callback!(response);

  for (let index = 0; index < 5; index++) {
    response.emit("data", Buffer.from(" "));
    await vi.advanceTimersByTimeAsync(20);
  }

  await rejected;
  expect(transport.destroy).toHaveBeenCalledTimes(1);
});

it("clears the deadline after a complete response", async () => {
  vi.useFakeTimers();

  const result = requestJson(
    new URL("https://fixture.invalid"),
    { ca: "ca", certificate: "cert", key: "key" },
    "GET",
    undefined,
    100,
  );

  await vi.advanceTimersByTimeAsync(1);
  const response = Object.assign(new EventEmitter(), { statusCode: 200 });
  transport.callback!(response);
  response.emit("data", Buffer.from('{"ok":true}'));
  response.emit("end");
  await expect(result).resolves.toEqual({ ok: true });
  await vi.advanceTimersByTimeAsync(200);
  expect(transport.destroy).not.toHaveBeenCalled();
});
