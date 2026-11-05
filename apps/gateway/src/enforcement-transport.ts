import { createServer, type Socket } from "node:net";
import { ServiceError } from "@traffic-policy/core/io";
import { MAX_MACHINE_FRAME_BYTES } from "@traffic-policy/contracts";
import {
  enforcementCommandSchema,
  parseEnforcementResult,
  type EnforcementCommand,
  type EnforcementResult,
} from "@traffic-policy/contracts/enforcement";
import { CommandFrame } from "./command-frame.ts";
import {
  EnforcementAdmission,
  ENFORCEMENT_CONNECTION_LIMIT,
  ENFORCEMENT_FRAME_BUDGET,
  type EnforcementReservation,
} from "./enforcement-admission.ts";
import { PendingWork } from "./shutdown.ts";

export type EnforcementDispatch = (
  command: EnforcementCommand,
) => Promise<EnforcementResult>;

export function createEnforcementTransport(dispatch: EnforcementDispatch) {
  const admission = new EnforcementAdmission();
  const work = new PendingWork();
  const sockets = new Set<Socket>();
  let stopping = false;
  let outboundBytes = 0;
  let closing: Promise<void> | null = null;

  const server = createServer({ allowHalfOpen: true }, (socket) => {
    sockets.add(socket);
    let active = 0;
    let ended = false;
    let reservation: EnforcementReservation | null = null;
    const ids = new Set<string>();

    const frame = new CommandFrame((bytes) => {
      reservation ??= admission.open();
      reservation.receive(bytes);
    });

    const finish = () => {
      if (!active && (ended || stopping)) socket.end();
    };

    const write = async (payload: string) => {
      if (socket.destroyed || socket.writableEnded) return;
      const bytes = Buffer.byteLength(payload);

      if (
        bytes > MAX_MACHINE_FRAME_BYTES ||
        outboundBytes + bytes > ENFORCEMENT_FRAME_BUDGET
      ) {
        socket.destroy();

        return;
      }

      outboundBytes += bytes;
      await new Promise<void>((resolve) =>
        socket.write(payload, () => {
          outboundBytes -= bytes;
          resolve();
        }),
      );
    };

    socket.setTimeout(15000, () => socket.destroy());
    socket.on("data", (chunk) => {
      if (stopping || socket.destroyed) return;

      try {
        frame.write(chunk, (raw) => {
          const held = reservation!;
          reservation = null;
          let input: EnforcementCommand;

          try {
            input = enforcementCommandSchema.parse(raw);

            if (ids.has(input.id))
              throw new Error(
                "Duplicate in-flight enforcement request identity",
              );
          } catch (error) {
            held.close();
            throw error;
          }

          try {
            held.admit(input.operation === "resolve" ? "dns" : "control");
          } catch {
            held.close();
            work.track(
              write(
                `${JSON.stringify({ id: input.id, ok: false, status: 429, code: "busy", message: "Enforcement queue is full" })}\n`,
              ),
            );

            return;
          }

          held.close();
          ids.add(input.id);
          active++;

          const task = (async () => {
            try {
              let payload: string;

              try {
                const value = parseEnforcementResult(
                  input.operation,
                  await dispatch(input),
                );

                payload = `${JSON.stringify({ id: input.id, ok: true, value })}\n`;

                if (Buffer.byteLength(payload) > MAX_MACHINE_FRAME_BYTES)
                  throw new ServiceError(
                    503,
                    input.operation === "connections"
                      ? "connection_snapshot_capacity"
                      : "enforcement_response_capacity",
                    "Enforcement response exceeds its transport allocation",
                  );
              } catch (error) {
                payload = `${JSON.stringify({ id: input.id, ok: false, status: error instanceof ServiceError ? error.status : 503, code: error instanceof ServiceError ? error.code : "enforcement_failed", message: error instanceof Error ? error.message : "Enforcement failed" })}\n`;
              } finally {
                // The command has settled. A client can receive its response
                // before this socket's write callback runs and send more work.
                // Response bytes and shutdown remain tracked independently.
                held.complete();
              }

              await write(payload);
            } finally {
              ids.delete(input.id);
              active--;
              finish();
            }
          })();

          work.track(task);
        });
      } catch {
        socket.destroy();
      }
    });
    socket.on("end", () => {
      try {
        frame.end();
      } catch {
        socket.destroy();
      }

      ended = true;
      finish();
    });
    socket.on("close", () => {
      reservation?.close();
      sockets.delete(socket);
    });
    socket.on("error", () => {});

    if (stopping) socket.destroy();
  });

  server.maxConnections = ENFORCEMENT_CONNECTION_LIMIT;

  return {
    server,
    close: () => {
      if (closing) return closing;
      stopping = true;

      for (const socket of sockets) socket.pause();

      const listener = new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );

      closing = (async () => {
        // Stop accepting commands before draining admitted work, even for peers
        // whose sockets have already disappeared.
        await work.drain();

        for (const socket of sockets) socket.end();
        await listener;
      })();

      return closing;
    },
  };
}
