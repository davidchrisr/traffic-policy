import {
  serviceSnapshotSchema,
  servicesSnapshotSchema,
  type ServiceSnapshot,
  type ServicesSnapshot,
} from "@traffic-policy/contracts/services";
import { readServiceStatus } from "@traffic-policy/core/systemd";
import { requestJson } from "@traffic-policy/core/io";
import { controllerConfig } from "./config.ts";
import { requireAdmin } from "./services.ts";

interface ServiceStatusReaders {
  controller: () => Promise<ServiceSnapshot>;
  gateway: () => Promise<ServiceSnapshot>;
}

async function gatewayStatus(): Promise<ServiceSnapshot> {
  const config = controllerConfig();

  return serviceSnapshotSchema.parse(
    await requestJson(
      new URL("/v1/services", config.gatewayUrl),
      config.tls,
      "GET",
      undefined,
      5000,
    ),
  );
}

export async function servicesStatus(
  actor: string | null,
  readers: ServiceStatusReaders = {
    controller: () => readServiceStatus("controller"),
    gateway: gatewayStatus,
  },
): Promise<ServicesSnapshot> {
  requireAdmin(actor);

  const read = async (scope: "controller" | "gateway") => {
    const snapshot = await readers[scope]();

    if (snapshot.scope !== scope)
      throw new Error("Service status belongs to another host");

    return snapshot;
  };

  const [controller, gateway] = await Promise.allSettled([
    read("controller"),
    read("gateway"),
  ]);

  return servicesSnapshotSchema.parse({
    checkedAt: new Date().toISOString(),
    controller:
      controller.status === "fulfilled"
        ? { available: true, snapshot: controller.value }
        : {
            available: false,
            message: "Controller service status could not be read.",
          },
    gateway:
      gateway.status === "fulfilled"
        ? { available: true, snapshot: gateway.value }
        : {
            available: false,
            message:
              "Gateway service status is unavailable. Check the gateway host and its connection.",
          },
  });
}
