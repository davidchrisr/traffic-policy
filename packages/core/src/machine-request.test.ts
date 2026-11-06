import { expect, it, vi, afterEach } from "vitest";
import { EventEmitter } from "node:events";

const transport = vi.hoisted(() => ({
  callback: null as null | ((response: EventEmitter) => void),
  request: null as EventEmitter | null,
  destroy: vi.fn(),
}));

vi.mock("node:http", () => ({
  request: (
    _options: import("node:http").RequestOptions,
    callback: (response: EventEmitter) => void,
  ) => {
    transport.callback = callback;
    const request = new EventEmitter();

    transport.request = request;

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

it.each(["trickling", "timeout", "tls"])(
  "keeps the request deadline during %s and records only actual replies",
  async (mode) => {
    vi.useFakeTimers();
    const onResponse = vi.fn();

    const result = requestJson(
      new URL("https://fixture.invalid"),
      { ca: "ca", certificate: "cert", key: "key" },
      "GET",
      undefined,
      100,
      onResponse,
    );

    const rejected = expect(result).rejects.toThrow(
      mode === "tls" ? "TLS handshake failed" : "timed out",
    );

    await vi.advanceTimersByTimeAsync(1);
    const response = Object.assign(new EventEmitter(), { statusCode: 200 });

    if (mode === "trickling") transport.callback!(response);

    if (mode === "tls")
      transport.request!.emit("error", new Error("TLS handshake failed"));

    for (let index = 0; index < 5; index++) {
      if (mode === "trickling") response.emit("data", Buffer.from(" "));
      await vi.advanceTimersByTimeAsync(20);
    }

    await rejected;
    expect(transport.destroy).toHaveBeenCalledTimes(1);
    expect(onResponse).toHaveBeenCalledTimes(mode === "trickling" ? 1 : 0);
  },
);

it.each([200, 503])(
  "records contact and clears the deadline after HTTP %i",
  async (statusCode) => {
    vi.useFakeTimers();
    const onResponse = vi.fn();

    const result = requestJson(
      new URL("https://fixture.invalid"),
      { ca: "ca", certificate: "cert", key: "key" },
      "GET",
      undefined,
      100,
      onResponse,
    );

    const settled =
      statusCode === 200
        ? expect(result).resolves.toEqual({ ok: true })
        : expect(result).rejects.toMatchObject({
            status: 503,
            code: "kernel_operation_failed",
          });

    await vi.advanceTimersByTimeAsync(1);
    expect(onResponse).not.toHaveBeenCalled();
    const response = Object.assign(new EventEmitter(), { statusCode });
    transport.callback!(response);
    expect(onResponse).toHaveBeenCalledTimes(1);
    response.emit(
      "data",
      Buffer.from(
        statusCode === 200
          ? '{"ok":true}'
          : '{"code":"kernel_operation_failed","message":"nft rejected rules"}',
      ),
    );
    response.emit("end");
    await settled;
    await vi.advanceTimersByTimeAsync(200);
    expect(transport.destroy).toHaveBeenCalledTimes(statusCode === 200 ? 0 : 1);
  },
);

it("rejects when recording contact fails", async () => {
  vi.useFakeTimers();

  const result = requestJson(
    new URL("https://fixture.invalid"),
    { ca: "ca", certificate: "cert", key: "key" },
    "GET",
    undefined,
    100,
    () => {
      throw new Error("Contact storage failed");
    },
  );

  const rejected = expect(result).rejects.toThrow("Contact storage failed");

  await vi.advanceTimersByTimeAsync(1);
  transport.callback!(Object.assign(new EventEmitter(), { statusCode: 200 }));
  await rejected;
  await vi.advanceTimersByTimeAsync(200);
  expect(transport.destroy).toHaveBeenCalledTimes(1);
});
