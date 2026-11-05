import { startProtectedForwarding } from "../apps/gateway/src/forward-guard.ts";

if (process.platform !== "linux" || process.getuid?.() !== 0)
  throw new Error(
    "Forwarding protection requires its Linux privileged context",
  );

await startProtectedForwarding();
