import type { PageServerLoad } from "./$types";
import { store } from "#lib/server/services.ts";
import {
  DEFAULT_TRAFFIC_PERIOD,
  TRAFFIC_PERIOD_COOKIE,
  readPeriodCookie,
  trafficWindow,
} from "#lib/traffic-period.ts";

// Loads the period this browser last chose, so the first render already shows it.
export const load: PageServerLoad = async ({ cookies }) => {
  const now = Date.now();

  const period = readPeriodCookie(cookies.get(TRAFFIC_PERIOD_COOKIE), now) ?? {
    period: DEFAULT_TRAFFIC_PERIOD,
    since: now,
  };

  const window = trafficWindow(period.period, now, period.since);

  return {
    snapshot: await store().monitor(window.from, window.to),
    period,
  };
};
