import { parentPort } from "node:worker_threads";
import { z } from "zod";
import { atomicFile } from "@traffic-policy/core/io";
import type { CollectorCommand, CollectorReply } from "./collector-writer.ts";

const port = parentPort;

if (!port) throw new Error("Collector worker requires a parent port");

let writing = false;

const errorCodeSchema = z.string();

port.on("message", (command: CollectorCommand) => {
  if (writing)
    throw new Error("Collector worker received overlapping commands");

  if (command.kind === "close") {
    port.close();

    return;
  }

  writing = true;
  void (async () => {
    let reply: CollectorReply;

    try {
      await atomicFile(command.path, command.bytes, command.mode);
      reply = { kind: "written", id: command.id };
    } catch (error) {
      const code = errorCodeSchema.safeParse(
        error instanceof Error && "code" in error ? error.code : null,
      );

      reply = {
        kind: "failed",
        id: command.id,
        message: error instanceof Error ? error.message : String(error),
        code: code.success ? code.data : null,
      };
    }

    writing = false;
    port.postMessage(reply);
  })();
});
