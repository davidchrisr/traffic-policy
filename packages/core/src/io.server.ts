import { createHash, randomUUID } from "node:crypto";
import { open, rename, mkdir, readFile, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import { request as httpRequest } from "node:http";
import { createMachineConnection } from "./machine-server.server.ts";
import type { IncomingMessage } from "node:http";
import type { z } from "zod";
import { MAX_MACHINE_FRAME_BYTES } from "@traffic-policy/contracts";

export function hasErrorCode(
  cause: unknown,
  code: string,
): cause is Error & { code: string } {
  return cause instanceof Error && "code" in cause && cause.code === code;
}

export class ServiceError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

// oxlint-disable-next-line anti-slop/no-unknown-parameters -- This generic JSON serializer accepts documents with different schemas without erasing caller types.
export function stableJson(value: unknown): string {
  // oxlint-disable-next-line anti-slop/no-unknown-parameters, anti-slop/no-unknown-returns -- This generic JSON serializer accepts documents with different schemas without erasing caller types. Canonicalization preserves arbitrary JSON values; it does not establish a domain contract.
  const normalize = (item: unknown): unknown => {
    if (Array.isArray(item)) return item.map(normalize);

    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- The generic JSON canonicalizer sorts object members and preserves scalar representations.
    if (item !== null && typeof item === "object")
      return Object.fromEntries(
        Object.entries(item)
          .sort(([left], [right]) => left.localeCompare(right))
          .map(([key, child]) => [key, normalize(child)]),
      );

    return item;
  };

  return JSON.stringify(normalize(value));
}

// oxlint-disable-next-line anti-slop/no-unknown-parameters -- This generic JSON serializer accepts documents with different schemas without erasing caller types.
export const hashDocument = (value: unknown) =>
  createHash("sha256").update(stableJson(value)).digest("hex");

export async function atomicJson(
  path: string,
  // oxlint-disable-next-line anti-slop/no-unknown-parameters -- This generic JSON serializer accepts documents with different schemas without erasing caller types.
  value: unknown,
  mode = 0o600,
): Promise<void> {
  await atomicFile(path, `${JSON.stringify(value)}\n`, mode);
}

export async function atomicFile(
  path: string,
  value: string | Uint8Array,
  mode = 0o600,
): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${randomUUID()}.pending`;

  try {
    const file = await open(temporary, "wx", mode);

    try {
      await file.writeFile(value);
      await file.sync();
    } finally {
      await file.close();
    }

    await rename(temporary, path);
    const directory = await open(dirname(path), "r");

    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  } catch (error) {
    // Remove only this operation's temporary file. A renamed destination can
    // already be visible even when the final directory sync fails.
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

export async function readJson<T>(
  path: string,
  schema: z.ZodType<T>,
): Promise<T> {
  return schema.parse(JSON.parse(await readFile(path, "utf8")));
}

export async function readBody(
  request: IncomingMessage,
  limit = MAX_MACHINE_FRAME_BYTES,
  // oxlint-disable-next-line anti-slop/no-unknown-returns -- The bounded JSON transport returns raw data for validation by its endpoint caller.
): Promise<unknown> {
  const chunks: Buffer[] = [];
  let length = 0;

  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += bytes.length;

    if (length > limit)
      throw new ServiceError(
        413,
        "body_too_large",
        "Request body exceeds its limit",
      );
    chunks.push(bytes);
  }

  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new ServiceError(
      400,
      "invalid_json",
      "Request body is not valid JSON",
    );
  }
}

export interface TlsFiles {
  ca: string;
  certificate: string;
  key: string;
}

export async function requestJson(
  url: URL,
  tls: TlsFiles,
  method = "GET",
  // oxlint-disable-next-line anti-slop/no-unknown-parameters -- The JSON transport serializes endpoint payloads and hands raw responses to their validators.
  body?: unknown,
  timeoutMs = 10000,
  onResponse?: () => void,
  // oxlint-disable-next-line anti-slop/no-unknown-returns -- The bounded JSON transport returns raw data for validation by its endpoint caller.
): Promise<unknown> {
  if (url.protocol !== "https:")
    throw new ServiceError(
      500,
      "insecure_transport",
      "Machine transport requires HTTPS",
    );

  const [ca, cert, key] = await Promise.all([
    readFile(tls.ca),
    readFile(tls.certificate),
    readFile(tls.key),
  ]);

  const payload =
    body === undefined ? undefined : Buffer.from(JSON.stringify(body));

  if (payload && payload.length > MAX_MACHINE_FRAME_BYTES)
    throw new ServiceError(
      413,
      "request_capacity",
      "Machine request exceeds its transport allocation",
    );

  return new Promise((resolve, reject) => {
    let settled = false;

    // oxlint-disable-next-line anti-slop/no-unknown-parameters -- The JSON transport serializes endpoint payloads and hands raw responses to their validators.
    const finish = (cause: unknown, value?: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);

      if (cause) {
        request.destroy();
        reject(cause);
      } else resolve(value);
    };

    const fail = (cause: unknown) => finish(cause);
    const headers: Record<string, string | number> = {};
    headers.Accept = "application/json";

    if (payload) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = payload.length;
    }

    // HTTP framing always travels over this verified TLS connection; no plain
    // TCP listener or client connection is selected.
    const request = httpRequest(
      {
        hostname: url.hostname,
        port: url.port ? Number(url.port) : 443,
        path: `${url.pathname}${url.search}`,
        method,
        createConnection: () => createMachineConnection(url, { ca, cert, key }),
        headers,
      },
      (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (chunk: Buffer) => {
          size += chunk.length;

          if (size > MAX_MACHINE_FRAME_BYTES) {
            response.destroy(new Error("Machine response exceeds its limit"));

            return;
          }

          chunks.push(chunk);
        });
        response.on("error", fail);
        response.on("aborted", () =>
          fail(new Error("Machine response ended prematurely")),
        );
        response.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");

          if (
            (response.statusCode ?? 500) < 200 ||
            (response.statusCode ?? 500) >= 300
          ) {
            // oxlint-disable-next-line anti-slop/no-known-value-widening -- Remote HTTP error fields remain untrusted until their individual string checks below.
            let failure: { code?: unknown; message?: unknown } = {};

            try {
              const decoded = JSON.parse(text);

              if (
                decoded &&
                // oxlint-disable-next-line anti-slop/no-runtime-typeof -- This is the remote HTTP error boundary; string checks constrain displayed error fields.
                typeof decoded === "object" &&
                !Array.isArray(decoded)
              )
                failure = decoded;
            } catch {
              /* Preserve the HTTP failure for invalid error bodies. */
            }

            fail(
              new ServiceError(
                response.statusCode ?? 503,
                // oxlint-disable-next-line anti-slop/no-runtime-typeof -- This is the remote HTTP error boundary; string checks constrain displayed error fields.
                typeof failure.code === "string" &&
                  /^[a-z_]{1,64}$/.test(failure.code)
                  ? failure.code
                  : "remote_failure",
                // oxlint-disable-next-line anti-slop/no-runtime-typeof -- This is the remote HTTP error boundary; string checks constrain displayed error fields.
                typeof failure.message === "string"
                  ? failure.message.slice(0, 4096)
                  : `Machine endpoint returned HTTP ${response.statusCode}`,
              ),
            );

            return;
          }

          try {
            finish(null, JSON.parse(text));
          } catch {
            fail(new Error("Machine endpoint returned invalid JSON"));
          }
        });

        // A verified peer has replied even when its status or body reports a failure.
        try {
          onResponse?.();
        } catch (error) {
          fail(error);
        }
      },
    );

    const timer = setTimeout(
      () => fail(new Error("Machine request timed out")),
      timeoutMs,
    );

    request.on("error", fail);
    request.end(payload);
  });
}
