import { beforeEach, expect, it, vi } from "vitest";
import {
  serviceIds,
  serviceSnapshotSchema,
  type ServiceSnapshot,
} from "@traffic-policy/contracts/services";
import { servicesStatus } from "./service-status.ts";

const readers = {
  controller: vi.fn<() => Promise<ServiceSnapshot>>(),
  gateway: vi.fn<() => Promise<ServiceSnapshot>>(),
};

function snapshot(scope: "controller" | "gateway"): ServiceSnapshot {
  return serviceSnapshotSchema.parse({
    scope,
    checkedAt: new Date().toISOString(),
    services: serviceIds[scope].map((id) => ({
      id,
      loadState: "loaded",
      activeState: "active",
      subState: "running",
      result: "success",
      exitStatus: 0,
      restarts: "0",
    })),
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  readers.controller.mockResolvedValue(snapshot("controller"));
  readers.gateway.mockResolvedValue(snapshot("gateway"));
});

it("marks a failed local read unavailable while retaining the gateway observation", async () => {
  readers.controller.mockRejectedValue(new Error("systemctl unavailable"));
  const result = await servicesStatus("Admin", readers);
  expect(result.controller).toMatchObject({ available: false });
  expect(result.controller).not.toHaveProperty("snapshot");
  expect(result.gateway.available).toBe(true);
});

it("requires Admin before reading local or remote service state", async () => {
  await expect(servicesStatus(null, readers)).rejects.toMatchObject({
    status: 401,
  });
  expect(readers.controller).not.toHaveBeenCalled();
  expect(readers.gateway).not.toHaveBeenCalled();
});

it("marks unreachable gateway status unavailable while preserving independently observed controller state", async () => {
  readers.gateway.mockRejectedValue(new Error("gateway offline"));
  const result = await servicesStatus("Admin", readers);
  expect(result.controller.available).toBe(true);
  expect(result.gateway).toMatchObject({ available: false });
  expect(result.gateway).not.toHaveProperty("snapshot");
});

it("rejects a valid report from the wrong host instead of relabeling it", async () => {
  readers.gateway.mockResolvedValue(snapshot("controller"));
  expect((await servicesStatus("Admin", readers)).gateway.available).toBe(
    false,
  );
});

it("returns current validated observations from both hosts", async () => {
  const result = await servicesStatus("Admin", readers);
  expect(result.controller.available).toBe(true);
  expect(result.gateway.available).toBe(true);
});
