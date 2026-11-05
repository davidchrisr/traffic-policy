import type { Cookies } from "@sveltejs/kit";
import { controllerConfig } from "./config.ts";

type CookieOptions = Parameters<Cookies["set"]>[2];

// A browser session cookie ends with the browser; a remembered one carries the session's expiry.
export function setSessionCookie(
  cookies: Cookies,
  token: string,
  expiresAt: Date | null,
): void {
  const options: CookieOptions = {
    path: "/",
    httpOnly: true,
    secure: controllerConfig().browserTransport === "https",
    sameSite: "strict",
  };

  if (expiresAt) options.expires = expiresAt;

  cookies.set("tp_session", token, options);
}
