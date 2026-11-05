import { createServer as createHttpsServer } from "node:https";
import { createServer as createHttpServer } from "node:http";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { controllerConfig } from "../apps/controller/src/lib/server/config.ts";

const config = controllerConfig();

process.env.BODY_SIZE_LIMIT = "2M";

const path = process.argv[2];

if (!path) throw new Error("Controller handler path is required");

const { handler } = await import(pathToFileURL(resolve(path)).href);

const server =
  config.browserTransport !== "https"
    ? createHttpServer(handler)
    : createHttpsServer(
        {
          cert: await readFile(config.tls.certificate),
          key: await readFile(config.tls.key),
          minVersion: "TLSv1.3",
        },
        handler,
      );

server.requestTimeout = 15000;

server.headersTimeout = 5000;

server.maxConnections = 64;

await new Promise<void>((ready, reject) => {
  server.once("error", reject);
  server.listen(
    config.browserPort,
    config.browserListenAddress ?? config.listenAddress,
    ready,
  );
});

process.once("SIGTERM", () => server.close());

process.once("SIGINT", () => server.close());

console.log(JSON.stringify({ service: "controller", ready: true }));
