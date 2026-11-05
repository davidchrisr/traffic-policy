import type { RequestHandler } from "@sveltejs/kit";
import { store } from "#lib/server/services.ts";

export const GET: RequestHandler = () => {
  try {
    store().desired();

    return Response.json({ ready: true });
  } catch {
    return Response.json({ ready: false }, { status: 503 });
  }
};
