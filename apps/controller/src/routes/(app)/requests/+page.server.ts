import { error } from "@sveltejs/kit";
import { ipSchema } from "@traffic-policy/contracts";
import type { PageServerLoad } from "./$types";
import { store } from "#lib/server/services.ts";

// Monitor links here with ?host= to open an unregistered host's Request, which the load includes
// even when it is older than the newest Requests.
export const load: PageServerLoad = ({ url }) => {
  const host = ipSchema.nullable().safeParse(url.searchParams.get("host"));

  if (!host.success) error(400, "The host is not an IP address");

  return store().requests(host.data);
};
