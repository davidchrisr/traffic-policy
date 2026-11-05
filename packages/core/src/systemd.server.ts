import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  serviceIds,
  serviceSnapshotSchema,
  type ServiceId,
  type ServiceScope,
  type ServiceSnapshot,
} from "@traffic-policy/contracts/services";
import { ServiceError } from "./io.server.ts";

const execute = promisify(execFile);

const units: Record<ServiceId, string> = {
  controller: "tp-controller.service",
  machine: "tp-controller-machine.service",
  gateway: "tp-gateway.service",
  enforcement: "tp-enforcement.service",
  suricata: "tp-suricata.service",
  "suricata-rotate": "tp-suricata-rotate.service",
};

async function show(names: string[]): Promise<string> {
  const result = await execute(
    "/usr/bin/systemctl",
    [
      "show",
      ...names,
      "--property=Id,LoadState,ActiveState,SubState,Result,ExecMainStatus,NRestarts",
    ],
    { encoding: "utf8", timeout: 2000, maxBuffer: 16384 },
  );

  return result.stdout;
}

const pending = new Map<ServiceScope, Promise<ServiceSnapshot>>();

export function readServiceStatus(
  scope: ServiceScope,
  reader = show,
): Promise<ServiceSnapshot> {
  const active = pending.get(scope);

  if (active) return active;
  const task = query(scope, reader);
  pending.set(scope, task);
  void task
    .finally(() => {
      if (pending.get(scope) === task) pending.delete(scope);
    })
    .catch(() => {});

  return task;
}

async function query(
  scope: ServiceScope,
  reader: typeof show,
): Promise<ServiceSnapshot> {
  const ids = serviceIds[scope];
  const names = ids.map((id) => units[id]);
  const output = await reader(names);

  const reports = output
    .trim()
    .split(/\n\s*\n/)
    .map((block) => {
      const fields: Record<string, string> = {};

      for (const line of block.split("\n")) {
        const separator = line.indexOf("=");

        if (separator < 1) throw new Error("Invalid service property framing");
        const key = line.slice(0, separator);

        if (Object.hasOwn(fields, key))
          throw new Error("Duplicate service property");
        fields[key] = line.slice(separator + 1);
      }

      return fields;
    });

  try {
    if (reports.length !== names.length)
      throw new Error("Missing service report");

    const state = (name: string) => {
      const matches = reports.filter((report) => report.Id === name);

      if (matches.length !== 1) throw new Error("Service identity mismatch");
      const report = matches[0]!;
      const exit = report.ExecMainStatus;

      if (exit !== undefined && !/^(0|[1-9][0-9]*)$/.test(exit))
        throw new Error("Invalid service exit status");

      return {
        loadState: report.LoadState,
        activeState: report.ActiveState,
        subState: report.SubState,
        result:
          report.Result === undefined || report.Result === ""
            ? null
            : report.Result,
        exitStatus: exit === undefined ? null : Number(exit),
        restarts: report.NRestarts ?? null,
      };
    };

    const services = ids.map((id) => ({ id, ...state(units[id]) }));

    return serviceSnapshotSchema.parse({
      scope,
      checkedAt: new Date().toISOString(),
      services,
    });
  } catch {
    throw new ServiceError(
      503,
      "invalid_service_status",
      "Service status could not be validated",
    );
  }
}
