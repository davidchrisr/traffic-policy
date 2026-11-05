import type { LayoutServerLoad } from "./$types";
import { store } from "#lib/server/services.ts";

export const load: LayoutServerLoad = () => ({ status: store().status() });
