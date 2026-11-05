import { ServiceError } from "@traffic-policy/core/io";

export const ENFORCEMENT_DNS_LIMIT = 4096;

export const ENFORCEMENT_CONTROL_LIMIT = 32;

export const ENFORCEMENT_CONNECTION_LIMIT = 4160;

export const ENFORCEMENT_FRAME_BUDGET = 64 * 1024 * 1024;

export type EnforcementLane = "dns" | "control";

export interface EnforcementReservation {
  receive(bytes: number): void;
  admit(lane: EnforcementLane): void;
  complete(): void;
  close(): void;
}

export class EnforcementAdmission {
  private bytes = 0;
  private dns = 0;
  private control = 0;

  open(): EnforcementReservation {
    let retained = 0;
    let lane: EnforcementLane | null = null;
    let closed = false;
    let completed = false;

    const release = () => {
      this.bytes -= retained;
      retained = 0;
    };

    return {
      receive: (bytes) => {
        if (closed || lane !== null || completed)
          throw new Error("Enforcement command frame is closed");

        if (!Number.isSafeInteger(bytes) || bytes < 0)
          throw new Error("Enforcement frame byte count is invalid");

        if (this.bytes + bytes > ENFORCEMENT_FRAME_BUDGET)
          throw new ServiceError(
            429,
            "enforcement_frame_capacity",
            "Enforcement request memory allocation is exhausted",
          );
        this.bytes += bytes;
        retained += bytes;
      },
      admit: (requested) => {
        if (closed || lane !== null || completed)
          throw new Error("Enforcement command cannot be admitted twice");
        const used = requested === "dns" ? this.dns : this.control;

        const limit =
          requested === "dns"
            ? ENFORCEMENT_DNS_LIMIT
            : ENFORCEMENT_CONTROL_LIMIT;

        if (used >= limit)
          throw new ServiceError(429, "busy", "Enforcement queue is full");
        lane = requested;

        if (lane === "dns") this.dns++;
        else this.control++;
      },
      complete: () => {
        if (lane === null || completed) return;
        completed = true;

        if (lane === "dns") this.dns--;
        else this.control--;

        if (closed) release();
      },
      close: () => {
        if (closed) return;
        closed = true;

        // A disconnected caller still owns its admitted command until it settles.
        if (lane === null || completed) release();
      },
    };
  }
}
