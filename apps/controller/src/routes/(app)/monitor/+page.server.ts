import type { PageServerLoad } from "./$types";
import { store } from "#lib/server/services.ts";

export const load: PageServerLoad = () =>
  store().monitor(
    new Date(Date.now() - 300000).toISOString(),
    new Date().toISOString(),
  );
