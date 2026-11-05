import { fail, redirect } from "@sveltejs/kit";
import type { Actions } from "./$types";
import { store } from "#lib/server/services.ts";
import { setSessionCookie } from "#lib/server/session-cookie.ts";
import { REMEMBERED_MS } from "#lib/server/store.ts";
import { ServiceError } from "@traffic-policy/core/io";

export const actions: Actions = {
  default: async ({ request, cookies, getClientAddress }) => {
    const data = await request.formData();
    const password = data.get("password");

    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- FormDataEntryValue is a string or File; the password must be the string member.
    if (typeof password !== "string")
      return fail(400, { message: "Enter the password" });

    try {
      const remembered = data.get("remember") === "on";

      const token = await store().login(
        password,
        getClientAddress(),
        remembered,
      );

      setSessionCookie(
        cookies,
        token,
        remembered ? new Date(Date.now() + REMEMBERED_MS) : null,
      );
    } catch (error) {
      return fail(error instanceof ServiceError ? error.status : 503, {
        message:
          error instanceof ServiceError
            ? error.message
            : "Sign-in is unavailable",
      });
    }

    redirect(303, "/monitor");
  },
};
