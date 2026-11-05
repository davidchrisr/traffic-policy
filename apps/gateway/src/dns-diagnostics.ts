export type DnsFailureStage =
  "admission" | "upstream" | "validation" | "enforcement" | "observation";

type DiagnosticService = "resolver-gate" | "resolver-observation";

const messages: Record<DnsFailureStage, string> = {
  admission: "DNS query admission failed",
  upstream: "Upstream DNS request failed",
  validation: "DNS response validation failed",
  enforcement: "DNS authorization failed",
  observation: "DNS observation could not be saved",
};

export interface DnsFailure {
  code: string;
  stage: DnsFailureStage;
  upstreamMs: number | null;
  enforcementMs: number | null;
  totalMs: number;
  responseAgeMs: number | null;
}

export type DnsDiagnostic =
  | (DnsFailure & {
      service: DiagnosticService;
      event: "dns_failure";
      message: string;
      at: string;
    })
  | {
      service: DiagnosticService;
      event: "dns_diagnostics_rate_limited";
      at: string;
      detailBurst: number;
      refillMs: number;
      windowMs: number;
    }
  | {
      service: DiagnosticService;
      event: "dns_failure_summary";
      at: string;
      durationMs: number;
      failures: number;
      detailed: number;
      suppressed: number;
      byCode: { code: string; failures: number }[];
      otherCodeFailures: number;
    };

const BURST = 20;

const REFILL_MS = 3000;

const WINDOW_MS = 60000;

const CODE_LIMIT = 16;

export class DnsFailureDiagnostics {
  private tokens = BURST;
  private lastRefill: number;
  private windowStarted: number | null = null;
  private timer: NodeJS.Timeout | null = null;
  private failures = 0;
  private detailed = 0;
  private codes = new Map<string, number>();
  private otherCodeFailures = 0;
  private closed = false;
  constructor(
    private readonly emit: (entry: DnsDiagnostic) => void = (entry) =>
      console.error(JSON.stringify(entry)),
    private readonly now: () => number = () => performance.now(),
    private readonly service: DiagnosticService = "resolver-gate",
  ) {
    this.lastRefill = now();
  }
  report(failure: DnsFailure) {
    if (this.closed) return;
    const now = this.now();

    if (this.windowStarted !== null && now - this.windowStarted >= WINDOW_MS)
      this.flush();

    if (this.windowStarted === null) {
      this.windowStarted = now;
      this.timer = setTimeout(() => this.flush(), WINDOW_MS);
      this.timer.unref();
    }

    const refilled = Math.floor((now - this.lastRefill) / REFILL_MS);

    if (this.tokens === BURST) this.lastRefill = now;
    else if (refilled > 0) {
      this.tokens = Math.min(BURST, this.tokens + refilled);
      this.lastRefill =
        this.tokens === BURST ? now : this.lastRefill + refilled * REFILL_MS;
    }

    const code = failure.code;
    this.failures++;
    const count = this.codes.get(code);

    if (count !== undefined) this.codes.set(code, count + 1);
    else if (this.codes.size < CODE_LIMIT) this.codes.set(code, 1);
    else this.otherCodeFailures++;

    if (this.tokens >= 1) {
      this.tokens--;
      this.detailed++;
      this.emit({
        code,
        message: messages[failure.stage],
        stage: failure.stage,
        upstreamMs: failure.upstreamMs,
        enforcementMs: failure.enforcementMs,
        totalMs: failure.totalMs,
        responseAgeMs: failure.responseAgeMs,
        service: this.service,
        event: "dns_failure",
        at: new Date().toISOString(),
      });

      return;
    }

    if (this.failures - this.detailed === 1) {
      this.emit({
        service: this.service,
        event: "dns_diagnostics_rate_limited",
        at: new Date().toISOString(),
        detailBurst: BURST,
        refillMs: REFILL_MS,
        windowMs: WINDOW_MS,
      });
    }
  }
  private flush() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;

    if (this.windowStarted === null) return;
    this.emit({
      service: this.service,
      event: "dns_failure_summary",
      at: new Date().toISOString(),
      durationMs: Math.round(this.now() - this.windowStarted),
      failures: this.failures,
      detailed: this.detailed,
      suppressed: this.failures - this.detailed,
      byCode: [...this.codes].map(([code, failures]) => ({ code, failures })),
      otherCodeFailures: this.otherCodeFailures,
    });
    this.windowStarted = null;
    this.failures = 0;
    this.detailed = 0;
    this.codes.clear();
    this.otherCodeFailures = 0;
  }
  close() {
    if (this.closed) return;
    this.flush();
    this.closed = true;
  }
}
