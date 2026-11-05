import { getContext, setContext } from "svelte";
import type { DashboardStatus } from "@traffic-policy/contracts/dashboard";

// The status the app layout polls every five seconds, shared so a page need not poll it again.
// Null until the first poll answers.
export interface LiveStatus {
  readonly current: DashboardStatus | null;
}

const key = Symbol("live-status");

export const shareStatus = (status: LiveStatus) => setContext(key, status);

export const liveStatus = () => getContext<LiveStatus>(key);

// The shared status, unless the page loaded a newer revision, as it does right after its own change.
export const latestStatus = (
  shared: DashboardStatus | null,
  loaded: DashboardStatus,
) =>
  shared && BigInt(shared.desiredRevision) >= BigInt(loaded.desiredRevision)
    ? shared
    : loaded;
