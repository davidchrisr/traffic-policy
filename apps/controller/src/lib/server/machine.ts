import { readFile } from "node:fs/promises";
import { setTimeout as sleep } from "node:timers/promises";
import { createMachineServer } from "@traffic-policy/core/machine-server";
import { TLSSocket } from "node:tls";
import { z } from "zod";
import {
  eventBatchSchema,
  gatewayReceiptSchema,
  type Policy,
} from "@traffic-policy/contracts";
import {
  hashDocument,
  readBody,
  requestJson,
  ServiceError,
} from "@traffic-policy/core/io";
import { controllerConfig, type ControllerConfig } from "./config.ts";
import { PRUNE_SLICE_MS, type ControllerStore } from "./store.ts";
import { store } from "./services.ts";
import { gatewayHealthSchema } from "@traffic-policy/contracts/dashboard";

let started = false;

// The gateway lost its policy or could not restore it; send the desired one.
const RESEND_CODES = new Set(["not_initialized", "enforcement_restore_failed"]);

// Delivers the desired policy and records a failure against the revision it tried; a failure to
// record that reaches the caller instead.
export async function deliverPolicy(
  owner: ControllerStore,
  config: Pick<ControllerConfig, "gatewayUrl" | "tls">,
  request: typeof requestJson = requestJson,
): Promise<void> {
  const policy = owner.desired();

  try {
    await sendPolicy(owner, policy, config, request);
  } catch (error) {
    owner.deliveryFailed(
      error instanceof Error ? error.message : "Gateway is unavailable",
      policy.revision,
    );
    throw error;
  }
}

async function sendPolicy(
  owner: ControllerStore,
  policy: Policy,
  config: Pick<ControllerConfig, "gatewayUrl" | "tls">,
  request: typeof requestJson,
) {
  const onResponse = () => owner.seen();

  const send = async () =>
    owner.confirm(
      policy,
      gatewayReceiptSchema.parse(
        await request(
          new URL("/v1/policy", config.gatewayUrl),
          config.tls,
          "PUT",
          policy,
          undefined,
          onResponse,
        ),
      ),
    );

  if (owner.status().pending) await send();
  else {
    let status;

    try {
      status = gatewayHealthSchema.parse(
        await request(
          new URL("/v1/status", config.gatewayUrl),
          config.tls,
          "GET",
          undefined,
          undefined,
          onResponse,
        ),
      );
    } catch (error) {
      if (!(error instanceof ServiceError && RESEND_CODES.has(error.code)))
        throw error;
    }

    if (status) owner.gatewayHealth(status);

    // A gateway that restored another revision receives the desired one again.
    if (
      status?.receipt.revision === policy.revision &&
      status.receipt.policyHash === hashDocument(policy)
    )
      owner.confirm(policy, status.receipt);
    else await send();
  }
}

// Runs `work` unless a run is in flight. The run is registered before `work` starts, so work that
// finishes without awaiting still releases it for the next call. `work` handles its own errors.
export function exclusive(work: () => Promise<void> | void) {
  let running: Promise<void> | null = null;

  return {
    run() {
      running ??= Promise.resolve()
        .then(work)
        .finally(() => {
          running = null;
        });

      return running;
    },
    get running() {
      return running;
    },
  };
}

// The gateway link: receives the gateway's observations over mTLS, and every 2 seconds delivers the
// desired policy and trims history beyond its retention. It runs as its own process beside the browser server and shares only the
// database with it. Resolves once storage is open and the machine port listens.
export async function startMachine(): Promise<void> {
  if (started) return;
  started = true;
  const config = controllerConfig();
  // Opening storage first keeps an uninitialized or incompatible database from listening.
  const owner = store();

  // Each new failure message and the recovery after it reach the journal once, not every attempt.
  let failure: string | null = null;

  const deliver = async () => {
    try {
      await deliverPolicy(owner, config);

      if (failure !== null)
        console.log(
          JSON.stringify({ service: "machine", deliveryRecovered: true }),
        );
      failure = null;
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Gateway is unavailable";

      if (message !== failure)
        console.error(
          JSON.stringify({ service: "machine", deliveryFailed: message }),
        );
      failure = message;
    }
  };

  let trimFailure: string | null = null,
    closing = false;

  // Finishes retention a slice at a time, pausing as long as each slice so the browser process
  // gets the database between them. A save that shrinks an allocation trims only its first slice.
  const trim = async () => {
    try {
      while (!owner.prune() && !closing) await sleep(PRUNE_SLICE_MS);
      trimFailure = null;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);

      if (message !== trimFailure)
        console.error(
          JSON.stringify({ service: "machine", trimFailed: message }),
        );
      trimFailure = message;
    }
  };

  const delivery = exclusive(deliver),
    trimming = exclusive(trim);

  const schedule = () => {
    void delivery.run();
    void trimming.run();
  };

  const [ca, cert, key] = await Promise.all([
    readFile(config.tls.ca),
    readFile(config.tls.certificate),
    readFile(config.tls.key),
  ]);

  const machine = createMachineServer(
    {
      ca,
      cert,
      key,
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: "TLSv1.3",
    },
    (request, response) => {
      void (async () => {
        if (
          !(request.socket instanceof TLSSocket) ||
          request.socket.getPeerCertificate().subject?.CN !==
            config.gatewayIdentity
        ) {
          throw new ServiceError(
            403,
            "unauthorized_identity",
            "Machine identity is not authorized",
          );
        }

        if (request.method !== "POST" || request.url !== "/v1/observations")
          throw new ServiceError(
            404,
            "not_found",
            "Machine endpoint does not exist",
          );

        const acknowledgement = owner.ingest(
          eventBatchSchema.parse(await readBody(request)),
        );

        response.writeHead(200, {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
        });
        response.end(JSON.stringify(acknowledgement));
      })().catch((error) => {
        if (response.destroyed) return;
        response.writeHead(
          error instanceof ServiceError
            ? error.status
            : error instanceof z.ZodError
              ? 400
              : 503,
          { "Content-Type": "application/json" },
        );
        response.end(
          JSON.stringify({
            code:
              error instanceof ServiceError ? error.code : "ingestion_failed",
            message: error.message,
          }),
        );
      });
    },
  );

  const server = machine.server;
  server.maxConnections = 32;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.machinePort, config.listenAddress, resolve);
  });

  const timer = setInterval(schedule, 2000);

  schedule();

  // Stops delivering and trimming, drains accepted observations, the delivery in flight, and the
  // trim slice in flight, then closes storage.
  const close = () => {
    closing = true;
    clearInterval(timer);
    void Promise.all([machine.close(), delivery.running, trimming.running])
      .catch((error) => {
        console.error(error);
        process.exitCode = 1;
      })
      .finally(() => owner.close());
  };

  process.once("SIGTERM", close);
  process.once("SIGINT", close);
}
