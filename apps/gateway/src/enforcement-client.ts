import { createConnection, type Socket } from "node:net";
import { randomUUID } from "node:crypto";
import { ServiceError, hashDocument } from "@traffic-policy/core/io";
import { MAX_MACHINE_FRAME_BYTES } from "@traffic-policy/contracts";
import {
  enforcementResponseSchema,
  parseEnforcementResult,
  type EnforcementRequest,
  type EnforcementResult,
} from "@traffic-policy/contracts/enforcement";
import { CommandFrame } from "./command-frame.ts";
import {
  EnforcementAdmission,
  ENFORCEMENT_FRAME_BUDGET,
  type EnforcementLane,
} from "./enforcement-admission.ts";

type Response = ReturnType<typeof enforcementResponseSchema.parse>;

interface PendingRequest {
  accept: (response: Response) => void;
  reject: (cause: unknown) => void;
  release: () => void;
  timer: ReturnType<typeof setTimeout>;
  expired: boolean;
}

const clients = new Map<string, EnforcementClient>();

class EnforcementClient {
  readonly channels = new Set<EnforcementChannel>();
  private readonly current = new Map<EnforcementLane, EnforcementChannel>();
  private readonly admission = new EnforcementAdmission();
  private retainedBytes = 0;

  constructor(readonly path: string) {}

  retain(bytes: number) {
    if (this.retainedBytes + bytes > ENFORCEMENT_FRAME_BUDGET)
      throw new ServiceError(
        429,
        "enforcement_frame_capacity",
        "Enforcement transport memory allocation is exhausted",
      );
    this.retainedBytes += bytes;
  }
  release(bytes: number) {
    this.retainedBytes -= bytes;
  }
  detach(channel: EnforcementChannel) {
    if (this.current.get(channel.lane) === channel)
      this.current.delete(channel.lane);
  }
  remove(channel: EnforcementChannel) {
    this.detach(channel);
    this.channels.delete(channel);

    if (!this.channels.size && clients.get(this.path) === this)
      clients.delete(this.path);
  }
  request(
    payload: string,
    id: string,
    lane: EnforcementLane,
    timeoutMs: number,
  ): Promise<Response> {
    return new Promise((accept, reject) => {
      const bytes = Buffer.byteLength(payload);
      const reservation = this.admission.open();
      this.retain(bytes);

      try {
        reservation.admit(lane);
      } catch (error) {
        this.release(bytes);
        reservation.close();
        throw error;
      }

      reservation.close();
      let released = false;

      const release = () => {
        if (released) return;
        released = true;
        reservation.complete();
        this.release(bytes);
      };

      let channel = this.current.get(lane);

      try {
        if (!channel) {
          channel = new EnforcementChannel(this, lane);
          this.channels.add(channel);
          this.current.set(lane, channel);
        }

        channel.request(payload, id, timeoutMs, accept, reject, release);
      } catch (error) {
        release();

        if (!this.channels.size && clients.get(this.path) === this)
          clients.delete(this.path);
        reject(error);
      }
    });
  }
  close() {
    for (const channel of [...this.channels])
      channel.fail(new Error("Enforcement service transport closed"));
  }
}

class EnforcementChannel {
  private readonly socket: Socket;
  private readonly pending = new Map<string, PendingRequest>();
  private responseBytes = 0;
  private active = 0;
  private retiring = false;
  private closed = false;

  constructor(
    private readonly owner: EnforcementClient,
    readonly lane: EnforcementLane,
  ) {
    this.socket = createConnection(owner.path);

    const frames = new CommandFrame((bytes) => {
      owner.retain(bytes);
      this.responseBytes += bytes;
    });

    this.socket.on("data", (chunk) => {
      if (this.closed) return;

      try {
        frames.write(chunk, (raw, bytes) => {
          owner.release(bytes);
          this.responseBytes -= bytes;
          const parsed = enforcementResponseSchema.safeParse(raw);

          if (!parsed.success)
            throw new ServiceError(
              502,
              "invalid_enforcement_response",
              "Enforcement service returned an invalid response",
            );
          const response = parsed.data;
          const request = this.pending.get(response.id);

          if (!request)
            throw new Error("Enforcement response identity mismatch");
          this.pending.delete(response.id);
          clearTimeout(request.timer);
          request.release();

          if (!request.expired) {
            this.active--;
            request.accept(response);
          }

          this.idle();
        });
      } catch (error) {
        this.fail(error);
      }
    });
    this.socket.on("error", (error) => this.fail(error));
    this.socket.on("end", () => {
      try {
        frames.end();
      } catch (error) {
        this.fail(error);

        return;
      }

      this.fail(
        new Error("Enforcement connection ended before its complete response"),
      );
    });
    this.socket.on("close", () =>
      this.fail(
        new Error("Enforcement connection closed before its complete response"),
      ),
    );
  }

  request(
    payload: string,
    id: string,
    timeoutMs: number,
    accept: (response: Response) => void,
    reject: (cause: unknown) => void,
    release: () => void,
  ) {
    if (this.closed || this.retiring)
      throw new Error("Enforcement connection is draining");

    const request: PendingRequest = {
      accept,
      reject,
      release,
      expired: false,
      timer: setTimeout(() => {
        request.expired = true;
        this.active--;
        reject(new Error("Enforcement service timed out"));
        // Retain expired identities only while other admitted requests drain.
        // This bounds late-response state by existing request/memory admission.
        this.retiring = true;
        this.owner.detach(this);
        this.idle();
      }, timeoutMs),
    };

    this.pending.set(id, request);
    this.active++;
    this.socket.ref();

    try {
      this.socket.write(payload);
    } catch (error) {
      this.fail(error);
    }
  }
  private idle() {
    if (this.active) return;

    if (this.retiring)
      queueMicrotask(() =>
        this.fail(new Error("Enforcement connection drained")),
      );
    else this.socket.unref();
  }
  fail(cause: unknown) {
    if (this.closed) return;
    this.closed = true;
    this.socket.destroy();
    this.owner.release(this.responseBytes);
    this.responseBytes = 0;

    for (const request of this.pending.values()) {
      clearTimeout(request.timer);
      request.release();

      if (!request.expired) request.reject(cause);
    }

    this.pending.clear();
    this.active = 0;
    this.owner.remove(this);
  }
}

export function closeEnforcementConnections(socketPath: string) {
  clients.get(socketPath)?.close();
}

export async function enforcementRequest<C extends EnforcementRequest>(
  socketPath: string,
  command: C,
  timeoutMs = 10000,
): Promise<EnforcementResult<C["operation"]>> {
  const id = randomUUID();
  const operation = command.operation;
  const payload = `${JSON.stringify({ ...command, id })}\n`;

  if (Buffer.byteLength(payload) > MAX_MACHINE_FRAME_BYTES)
    throw new ServiceError(
      413,
      "command_capacity",
      "Enforcement command exceeds its transport allocation",
    );
  let client = clients.get(socketPath);

  if (!client) {
    client = new EnforcementClient(socketPath);
    clients.set(socketPath, client);
  }

  const response = await client.request(
    payload,
    id,
    operation === "resolve" ? "dns" : "control",
    timeoutMs,
  );

  if (!response.ok)
    throw new ServiceError(response.status, response.code, response.message);
  let value: EnforcementResult<C["operation"]>;

  try {
    value = parseEnforcementResult<C["operation"]>(operation, response.value);
  } catch {
    throw new ServiceError(
      502,
      "invalid_enforcement_response",
      "Enforcement service returned an invalid response",
    );
  }

  if (
    "policy" in value &&
    (value.receipt.revision !== value.policy.revision ||
      value.receipt.policyHash !== hashDocument(value.policy))
  )
    throw new ServiceError(
      502,
      "invalid_enforcement_response",
      "Enforcement service returned an invalid response",
    );

  return value;
}
