import { readFile, writeFile } from "node:fs/promises";
import { managedTablePresent, runNativeCommand } from "./native-access.ts";
import { withInstallationLock } from "./enforcement-owner.ts";

interface ForwardingOperations {
  disable: () => Promise<void>;
  protected: () => Promise<boolean>;
  install: () => Promise<void>;
  enable: () => Promise<void>;
}

async function forwarding(value: "0" | "1") {
  await writeFile("/proc/sys/net/ipv4/ip_forward", `${value}\n`);
  await writeFile("/proc/sys/net/ipv6/conf/all/forwarding", `${value}\n`);
}

export async function startProtectedForwarding(
  operations: ForwardingOperations = {
    disable: () => forwarding("0"),
    protected: managedTablePresent,
    install: async () => {
      const program = await readFile(
        "/etc/traffic-policy/forward-guard.nft",
        "utf8",
      );

      await runNativeCommand("/usr/sbin/nft", ["--file", "-"], program);
    },
    enable: () => forwarding("1"),
  },
  lock: typeof withInstallationLock = withInstallationLock,
): Promise<void> {
  await lock(async () => {
    await operations.disable();

    if (!(await operations.protected())) await operations.install();
    await operations.enable();
  });
}
