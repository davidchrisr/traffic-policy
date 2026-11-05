import type { Handle, HandleServerError } from "@sveltejs/kit/hooks";
import { randomUUID } from "node:crypto";
import { controllerConfig } from "#lib/server/config.ts";
import { store } from "#lib/server/services.ts";
import { setSessionCookie } from "#lib/server/session-cookie.ts";

export const handle: Handle = async ({ event, resolve }) => {
  event.locals.requestId = randomUUID();
  const token = event.cookies.get("tp_session");
  const session = store().authenticated(token);
  event.locals.actor = session ? "Admin" : null;
  event.locals.client = {
    address: event.getClientAddress(),
    agent: (event.request.headers.get("User-Agent") ?? "").slice(0, 256),
  };

  if (token && session?.renewedUntil)
    setSessionCookie(event.cookies, token, new Date(session.renewedUntil));
  const path = event.url.pathname;

  if (
    !["GET", "HEAD", "OPTIONS"].includes(event.request.method) &&
    event.request.headers.get("Origin") !== controllerConfig().publicOrigin
  ) {
    return Response.json(
      {
        code: "invalid_origin",
        message: "Request origin is not authorized",
        requestId: event.locals.requestId,
      },
      { status: 403 },
    );
  }

  const publicPath =
    path === "/login" ||
    path === "/api/auth/login" ||
    path === "/api/auth/session" ||
    path === "/healthz";

  if (
    !publicPath &&
    !path.startsWith("/_app/") &&
    !path.startsWith("/favicon") &&
    !event.locals.actor
  ) {
    if (path.startsWith("/api/"))
      return Response.json(
        {
          code: "authentication_required",
          message: "Sign in to continue",
          requestId: event.locals.requestId,
        },
        { status: 401 },
      );

    return new Response(null, { status: 303, headers: { Location: "/login" } });
  }

  const response = await resolve(event);
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("Referrer-Policy", "same-origin");
  response.headers.set("X-Request-ID", event.locals.requestId);

  if (path.startsWith("/api/"))
    response.headers.set("Cache-Control", "no-store");

  return response;
};

export const handleError: HandleServerError = ({ event, error }) => {
  console.error(
    JSON.stringify({
      requestId: event.locals.requestId,
      error: error instanceof Error ? error.message : "Unexpected error",
    }),
  );

  return {
    status: 500,
    message: "The request could not be completed",
    requestId: event.locals.requestId,
  };
};
