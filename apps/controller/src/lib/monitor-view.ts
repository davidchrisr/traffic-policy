import {
  monitorSelectionSchema,
  type MonitorSelection,
  type MonitorService,
  type MonitorSnapshot,
} from "@traffic-policy/contracts/dashboard";
import { ApiError } from "./client.ts";
import { RefreshRunner } from "./refresh-runner.ts";
import { trafficPeriods, trafficWindow } from "./traffic-period.ts";

export type MonitorScope =
  | { kind: "all" }
  | { kind: "instance"; instanceId: string }
  | {
      kind: "domain" | "hostname";
      instanceId: string;
      name: string;
      key: string;
    }
  | { kind: "destination"; instanceId: string; peerIp: string; key: string }
  | ({ kind: "service" } & Pick<
      MonitorService,
      "key" | "instanceId" | "direction" | "peerIp" | "protocol" | "port"
    >);

export interface MonitorViewState {
  scope: MonitorScope;
  period: string;
  since: number;
  model: MonitorSnapshot;
  roster: MonitorService[];
  names: MonitorSnapshot["names"];
  reviews: MonitorSnapshot["reviews"];
  servicesTruncated: boolean;
  busy: boolean;
  // A whole-period event scan is running, and when the kept whole-period summary of this view was
  // scanned.
  scanning: boolean;
  scannedAt: number | null;
  // Why the last whole-period scan of this view failed; polls keep it, unlike error.
  scanError: string;
  error: string;
  hasMeasurements: boolean;
  hasRoster: boolean;
}

// Polls refresh the event summary at most this often; user changes refresh it at once.
const EVENT_SUMMARY_REFRESH_MS = 15000;

const FULL_SCAN_TIMEOUT_MS = 60000;

type Loader = (
  query: URLSearchParams,
  signal: AbortSignal,
) => Promise<MonitorSnapshot>;

function selection(scope: MonitorScope): MonitorSelection {
  switch (scope.kind) {
    case "all":
      return {};
    case "instance":
      return { instanceId: scope.instanceId };
    case "destination":
      return { instanceId: scope.instanceId, peerIp: scope.peerIp };
    case "domain":
      return { instanceId: scope.instanceId, domain: scope.name };
    case "hostname":
      return { instanceId: scope.instanceId, hostname: scope.name };
    case "service":
      return {
        instanceId: scope.instanceId,
        peerIp: scope.peerIp,
        direction: scope.direction,
        protocol: scope.protocol,
        port: scope.port,
      };
  }
}

export class MonitorView {
  private state: MonitorViewState;
  private loadedView: string;
  private loadedPeriod: string;
  private listeners = new Set<(state: MonitorViewState) => void>();
  private timer: ReturnType<typeof setInterval> | undefined;
  private started = false;
  private disposed = false;
  private scheduled = false;
  // The last event summary, kept for the view it was loaded for between its refreshes. A
  // whole-period summary is kept until the view changes or the period is scanned again.
  private summary: {
    view: string;
    at: number;
    full: boolean;
    value: MonitorSnapshot["eventSummary"];
  } | null = null;
  private fullScan: { view: string; controller: AbortController } | null = null;
  private runner: RefreshRunner<{
    model: MonitorSnapshot;
    roster: MonitorSnapshot;
    view: string;
    period: string;
  }>;

  constructor(
    initial: MonitorSnapshot,
    private readonly load: Loader,
    private readonly now = Date.now,
  ) {
    this.state = {
      scope: { kind: "all" },
      period: "300",
      since: now(),
      model: initial,
      roster: initial.services,
      names: initial.names,
      reviews: initial.reviews,
      servicesTruncated: initial.servicesTruncated,
      busy: false,
      scanning: false,
      scannedAt: null,
      scanError: "",
      error: "",
      hasMeasurements: true,
      hasRoster: true,
    };
    this.loadedPeriod = this.periodKey();
    this.loadedView = this.viewKey();
    this.runner = new RefreshRunner({
      onValue: (next) => {
        if (next.view !== this.viewKey()) return;
        this.loadedView = next.view;
        this.loadedPeriod = next.period;
        let model = next.model;
        const kept = this.summary?.view === next.view ? this.summary : null;

        if (model.eventSummary && !kept?.full)
          this.summary = {
            view: next.view,
            at: this.now(),
            full: false,
            value: model.eventSummary,
          };
        else if (kept) model = { ...model, eventSummary: kept.value };

        this.publish({
          model,
          roster: next.roster.services,
          names: next.roster.names,
          reviews: next.roster.reviews,
          servicesTruncated: next.roster.servicesTruncated,
          error: "",
        });
      },
      onError: (failure) =>
        this.publish({
          error:
            failure instanceof Error && failure.name === "TimeoutError"
              ? "Traffic refresh timed out. Try again."
              : "Traffic could not be refreshed. Try again.",
        }),
      onBusy: (busy) => this.publish({ busy }),
    });
  }
  get snapshot(): MonitorViewState {
    return this.state;
  }
  subscribe(listener: (state: MonitorViewState) => void) {
    this.listeners.add(listener);
    listener(this.state);

    return () => {
      this.listeners.delete(listener);
    };
  }
  private periodKey() {
    return JSON.stringify([
      this.state.period,
      this.state.period === "from-now" ? this.state.since : null,
    ]);
  }
  private viewKey(scope = this.state.scope) {
    return JSON.stringify([this.periodKey(), scope.kind, selection(scope)]);
  }
  private publish(patch: Partial<MonitorViewState>) {
    this.state = { ...this.state, ...patch };

    // A view change abandons a whole-period scan of the previous view.
    if (this.fullScan && this.fullScan.view !== this.viewKey())
      this.fullScan.controller.abort(
        new DOMException("Scan superseded", "AbortError"),
      );
    this.state = {
      ...this.state,
      hasMeasurements: this.loadedView === this.viewKey(),
      hasRoster: this.loadedPeriod === this.periodKey(),
      scannedAt:
        this.summary?.full && this.summary.view === this.viewKey()
          ? this.summary.at
          : null,
    };

    for (const listener of this.listeners) listener(this.state);
  }
  private schedule() {
    if (!this.started || this.scheduled || this.disposed) return;
    this.scheduled = true;
    queueMicrotask(() => {
      this.scheduled = false;

      if (!this.disposed) void this.refresh();
    });
  }
  select(scope: MonitorScope) {
    const normalized = monitorSelectionSchema.parse(selection(scope));
    let next: MonitorScope;

    switch (scope.kind) {
      case "all":
        next = { kind: "all" };
        break;
      case "instance":
        next = { kind: "instance", instanceId: normalized.instanceId! };
        break;
      case "domain":
      case "hostname":
        next = {
          kind: scope.kind,
          instanceId: normalized.instanceId!,
          name:
            scope.kind === "domain" ? normalized.domain! : normalized.hostname!,
          key: scope.key,
        };
        break;
      case "destination":
        next = {
          kind: "destination",
          instanceId: normalized.instanceId!,
          peerIp: normalized.peerIp!,
          key: scope.key,
        };
        break;
      case "service":
        next = {
          kind: "service",
          instanceId: normalized.instanceId!,
          peerIp: normalized.peerIp!,
          direction: normalized.direction!,
          protocol: normalized.protocol!,
          port: normalized.port!,
          key: scope.key,
        };
        break;
    }

    if (this.viewKey(next) === this.viewKey()) return;
    this.publish({ scope: next, error: "", scanError: "" });
    this.schedule();
  }
  setPeriod(period: string) {
    if (
      period !== "from-now" &&
      !trafficPeriods.some((item) => item.value === period)
    )
      throw new Error("Unknown traffic period");

    if (period === this.state.period) return;
    this.publish({ period, error: "", scanError: "" });
    this.schedule();
  }
  setSince(since: number) {
    if (since === this.state.since) return;
    this.publish(
      this.state.period === "from-now" ? { since, scanError: "" } : { since },
    );

    if (this.state.period === "from-now") this.schedule();
  }
  start() {
    if (this.started || this.disposed) return;
    this.started = true;
    void this.refresh();
    this.timer = setInterval(() => {
      void this.refresh(false);
    }, 5000);
  }
  refresh(supersede = true): Promise<void> {
    if (this.disposed) return Promise.resolve();

    if (supersede) this.publish({ error: "" });

    const view = this.viewKey(),
      period = this.periodKey(),
      scope = this.state.scope;

    const { window, query } = this.query();
    const kept = this.summary?.view === view ? this.summary : null;

    if (
      scope.kind !== "all" &&
      !kept?.full &&
      (supersede || !kept || this.now() - kept.at >= EVENT_SUMMARY_REFRESH_MS)
    )
      query.set("events", "recent");

    return this.runner.run(async (signal) => {
      const [model, roster] = await Promise.all([
        this.load(query, signal),
        scope.kind === "all"
          ? Promise.resolve(null)
          : this.load(new URLSearchParams(window), signal),
      ]);

      return { model, roster: roster ?? model, view, period };
    }, supersede);
  }
  // Summarizes the selected scope's events over the whole period, beyond the newest 100,000 events
  // a recent summary reads, outside the refresh batches so polls continue meanwhile.
  async scanWholePeriod(): Promise<void> {
    if (this.disposed || this.state.scope.kind === "all") return;
    this.fullScan?.controller.abort(
      new DOMException("Scan superseded", "AbortError"),
    );
    const view = this.viewKey();
    const controller = new AbortController();
    const scan = { view, controller };
    this.fullScan = scan;
    this.publish({ scanning: true, scanError: "" });
    const { query } = this.query();
    query.set("events", "full");

    try {
      const model = await this.load(
        query,
        AbortSignal.any([
          controller.signal,
          AbortSignal.timeout(FULL_SCAN_TIMEOUT_MS),
        ]),
      );

      if (view === this.viewKey() && model.eventSummary) {
        this.summary = {
          view,
          at: this.now(),
          full: true,
          value: model.eventSummary,
        };

        if (this.loadedView === view)
          this.publish({
            model: { ...this.state.model, eventSummary: model.eventSummary },
          });
      }
    } catch (failure) {
      if (!controller.signal.aborted && !this.disposed)
        this.publish({
          scanError:
            failure instanceof Error && failure.name === "TimeoutError"
              ? "The whole-period scan timed out. Select a shorter period."
              : failure instanceof ApiError
                ? failure.message
                : "The whole-period scan failed. Try again.",
        });
    } finally {
      if (this.fullScan === scan) {
        this.fullScan = null;

        if (!this.disposed) this.publish({ scanning: false });
      }
    }
  }
  private query() {
    const window = trafficWindow(
      this.state.period,
      this.now(),
      this.state.since,
    );

    const query = new URLSearchParams(window);

    for (const [key, value] of Object.entries(selection(this.state.scope)))
      query.set(key, value === null ? "null" : String(value));

    return { window, query };
  }
  dispose() {
    this.fullScan?.controller.abort(
      new DOMException("View closed", "AbortError"),
    );
    this.disposed = true;
    clearInterval(this.timer);
    this.runner.dispose();
    this.listeners.clear();
  }
}
