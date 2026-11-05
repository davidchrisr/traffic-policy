import type { PageServerLoad } from "./$types";
import { store } from "#lib/server/services.ts";

export const load: PageServerLoad = () => store().requests();
