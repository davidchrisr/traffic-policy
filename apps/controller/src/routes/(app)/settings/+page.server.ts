import type { PageServerLoad } from "./$types";
import { store } from "#lib/server/services.ts";

export const load: PageServerLoad = () => ({
  ...store().resources(),
  instances: store().desired().instances,
  rules: store().desired().rules,
});
