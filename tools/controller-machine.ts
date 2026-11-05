import { startMachine } from "../apps/controller/src/lib/server/machine.ts";

await startMachine();

console.log(JSON.stringify({ service: "machine", ready: true }));
