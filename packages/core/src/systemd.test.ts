import { expect, it, vi } from "vitest";
import { readServiceStatus } from "./systemd.server.ts";

function report(
  unit: string,
  state = "active",
  result = "success",
  exit = "0",
) {
  return `Id=${unit}\nLoadState=loaded\nActiveState=${state}\nSubState=${state === "active" ? "running" : "dead"}\nResult=${result}\nExecMainStatus=${exit}\nNRestarts=0`;
}

it("binds every observed state to the fixed unit catalog and permits a stopped Suricata", async () => {
  const reader = vi.fn(async (names: string[]) =>
    names
      .map((name) =>
        report(name, name === "tp-suricata.service" ? "inactive" : "active"),
      )
      .join("\n\n"),
  );

  const result = await readServiceStatus("gateway", reader);
  expect(reader).toHaveBeenCalledWith([
    "tp-gateway.service",
    "tp-enforcement.service",
    "tp-suricata.service",
    "tp-suricata-rotate.service",
  ]);
  expect(
    result.services.find((service) => service.id === "suricata")?.activeState,
  ).toBe("inactive");
  expect(
    result.services.find((service) => service.id === "enforcement")
      ?.activeState,
  ).toBe("active");
});

it("reports a failed log rotation service with its exit result", async () => {
  const snapshot = await readServiceStatus("gateway", async (names) =>
    names
      .map((name) =>
        name === "tp-suricata-rotate.service"
          ? report(name, "failed", "exit-code", "1")
          : report(name),
      )
      .join("\n\n"),
  );

  expect(
    snapshot.services.find((service) => service.id === "suricata-rotate"),
  ).toMatchObject({
    activeState: "failed",
    result: "exit-code",
    exitStatus: 1,
  });
});

it("rejects a missing log rotation report", async () => {
  await expect(
    readServiceStatus("gateway", async (names) =>
      names
        .filter((name) => name !== "tp-suricata-rotate.service")
        .map((name) => report(name))
        .join("\n\n"),
    ),
  ).rejects.toMatchObject({ code: "invalid_service_status" });
});

const link = report("tp-controller-machine.service");

it("reports a failed gateway link beside the browser server with its observed exit result", async () => {
  const reader = vi.fn(async (names: string[]) =>
    names
      .map((name) =>
        name === "tp-controller-machine.service"
          ? report(name, "failed", "exit-code", "1")
          : report(name),
      )
      .join("\n\n"),
  );

  const result = await readServiceStatus("controller", reader);
  expect(reader).toHaveBeenCalledWith([
    "tp-controller.service",
    "tp-controller-machine.service",
  ]);
  expect(result.services).toMatchObject([
    { id: "controller", activeState: "active" },
    {
      id: "machine",
      activeState: "failed",
      result: "exit-code",
      exitStatus: 1,
    },
  ]);
});

it.each([
  report("another.service") + "\n\n" + link,
  report("tp-controller.service"),
  report("tp-controller.service") + "\n\n" + report("tp-controller.service"),
  report("tp-controller.service").replace(
    "ExecMainStatus=0",
    "ExecMainStatus=1e2",
  ) +
    "\n\n" +
    link,
  report("tp-controller.service").replace("NRestarts=0", "NRestarts=-1") +
    "\n\n" +
    link,
])(
  "rejects missing, duplicate, misbound or malformed service observations",
  async (output) => {
    await expect(
      readServiceStatus("controller", async () => output),
    ).rejects.toMatchObject({ code: "invalid_service_status" });
  },
);

it("preserves unavailable counters as missing, not zero", async () => {
  const result = await readServiceStatus("gateway", async (names) =>
    names
      .map((name) =>
        name === "tp-suricata-rotate.service"
          ? `Id=${name}\nLoadState=loaded\nActiveState=active\nSubState=running\nResult=success`
          : report(name),
      )
      .join("\n\n"),
  );

  expect(
    result.services.find((service) => service.id === "suricata-rotate"),
  ).toMatchObject({ exitStatus: null, restarts: null });
});

it("shares in-flight reads and releases a failed query for later fresh reads", async () => {
  let reject!: (error: Error) => void;

  const reader = vi.fn(
    () =>
      new Promise<string>((_resolve, failure) => {
        reject = failure;
      }),
  );

  const first = readServiceStatus("controller", reader);
  const second = readServiceStatus("controller", reader);
  expect(second).toBe(first);
  reject(new Error("bus unavailable"));
  await expect(first).rejects.toThrow("bus unavailable");
  await expect(second).rejects.toThrow("bus unavailable");
  await expect(
    readServiceStatus(
      "controller",
      async () => report("tp-controller.service") + "\n\n" + link,
    ),
  ).resolves.toMatchObject({ scope: "controller" });
  expect(reader).toHaveBeenCalledTimes(1);
});
