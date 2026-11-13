import type { PageServerLoad } from "./$types";
import { store } from "#lib/server/services.ts";

export const load: PageServerLoad = () => {
  const { instances, rules, ruleSets } = store().desired();

  return { ...store().resources(), instances, rules, ruleSets };
};
