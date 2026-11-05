import { z } from "zod";

const apiFailureSchema = z.object({
  code: z.string(),
  message: z.string(),
  fields: z
    .array(z.object({ path: z.string(), message: z.string() }))
    .optional(),
  requestId: z.string().optional(),
});

export type ApiFailure = z.infer<typeof apiFailureSchema>;

export class ApiError extends Error {
  constructor(
    public status: number,
    public failure: ApiFailure,
  ) {
    super(failure.message);
  }
}

// What went wrong, for places without a form to highlight fields in: the field messages when
// the server lists them, otherwise its message.
// oxlint-disable-next-line anti-slop/no-unknown-parameters -- JavaScript can throw any value; this reads the failures api() raises.
export function failureMessage(failure: unknown, fallback: string): string {
  if (failure instanceof ApiError) {
    const fields = failure.failure.fields?.map((field) => field.message) ?? [];

    return fields.length ? fields.join("; ") : failure.failure.message;
  }

  return failure instanceof Error ? failure.message : fallback;
}

export async function api(
  path: string,
  method = "GET",
  // oxlint-disable-next-line anti-slop/no-unknown-parameters -- This HTTP transport serializes endpoint-specific payloads; server services validate them.
  body?: unknown,
  signal?: AbortSignal,
  // oxlint-disable-next-line anti-slop/no-unknown-returns -- Successful HTTP data stays untrusted until the caller validates its endpoint schema.
): Promise<unknown> {
  const options: RequestInit = {
    method,
    credentials: "same-origin",
    signal,
    headers: { Accept: "application/json" },
  };

  if (body !== undefined) {
    options.headers = {
      Accept: "application/json",
      "Content-Type": "application/json",
    };
    options.body = JSON.stringify(body);
  }

  const response = await fetch(`/api/${path}`, options);
  const result = await response.json();

  if (!response.ok)
    throw new ApiError(response.status, apiFailureSchema.parse(result));

  return result;
}

export function displayBytes(raw: string): string {
  return scaledBytes(raw, 1024n, [
    "B",
    "KiB",
    "MiB",
    "GiB",
    "TiB",
    "PiB",
    "EiB",
  ]);
}

export function displayTrafficBytes(raw: string): string {
  return scaledBytes(raw, 1000n, ["B", "KB", "MB", "GB", "TB", "PB", "EB"]);
}

function scaledBytes(raw: string, base: bigint, units: string[]): string {
  const bytes = BigInt(raw);

  let divisor = 1n,
    index = 0;

  while (bytes >= divisor * base && index < units.length - 1) {
    divisor *= base;
    index++;
  }

  if (!index) return `${bytes} B`;
  const digits = (bytes * 100n) / divisor;

  return `${digits / 100n}.${String(digits % 100n).padStart(2, "0")} ${units[index]}`;
}

export const addressName = (value: string) => value;
