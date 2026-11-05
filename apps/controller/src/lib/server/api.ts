import { z } from "zod";
import { ServiceError } from "@traffic-policy/core/io";

// oxlint-disable-next-line anti-slop/no-unknown-parameters -- JavaScript can throw any value; this function is the HTTP error boundary.
export function apiError(error: unknown, requestId: string): Response {
  if (error instanceof z.ZodError)
    return Response.json(
      {
        code: "validation_failed",
        message: "Review the highlighted values",
        fields: error.issues.map((issue) => ({
          path: issue.path.join("."),
          message: issue.message,
        })),
        requestId,
      },
      { status: 400 },
    );

  if (error instanceof ServiceError)
    return Response.json(
      { code: error.code, message: error.message, requestId },
      { status: error.status },
    );
  console.error(
    JSON.stringify({
      requestId,
      error: error instanceof Error ? error.message : "Unexpected error",
    }),
  );

  return Response.json(
    {
      code: "unavailable",
      message:
        "The request could not be completed. The saved rules remain in place.",
      requestId,
    },
    { status: 503 },
  );
}

// oxlint-disable-next-line anti-slop/no-unknown-returns -- The bounded body decoder returns raw JSON; authorized services validate mutation schemas.
export async function requestBody(request: Request): Promise<unknown> {
  const size = Number(request.headers.get("Content-Length") ?? 0);

  if (size > 2 * 1024 * 1024)
    throw new ServiceError(
      413,
      "body_too_large",
      "Request body exceeds its limit",
    );
  const reader = request.body?.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;

  if (reader) {
    try {
      for (;;) {
        const { done, value } = await reader.read();

        if (done) break;
        bytes += value.byteLength;

        if (bytes > 2 * 1024 * 1024) {
          await reader.cancel();
          throw new ServiceError(
            413,
            "body_too_large",
            "Request body exceeds its limit",
          );
        }

        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
  }

  const text = Buffer.concat(chunks).toString("utf8");

  try {
    return JSON.parse(text);
  } catch {
    throw new ServiceError(
      400,
      "invalid_json",
      "Request body is not valid JSON",
    );
  }
}
