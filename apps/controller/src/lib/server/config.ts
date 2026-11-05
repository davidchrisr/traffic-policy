import { readFileSync } from "node:fs";
import { z } from "zod";
import ipaddr from "ipaddr.js";
import { ipSchema } from "@traffic-policy/contracts";

export const controllerConfigSchema = z
  .object({
    database: z.string().startsWith("/"),
    listenAddress: ipSchema,
    browserListenAddress: ipSchema.optional(),
    browserPort: z.number().int().min(1024).max(65535),
    machinePort: z.number().int().min(1024).max(65535),
    browserTransport: z
      .enum(["https", "http-local-test", "http-lan-test"])
      .default("https"),
    publicOrigin: z.string().url(),
    gatewayUrl: z.string().url().startsWith("https://"),
    gatewayIdentity: z.string().min(1).max(128),
    tls: z
      .object({
        ca: z.string().startsWith("/"),
        certificate: z.string().startsWith("/"),
        key: z.string().startsWith("/"),
      })
      .strict(),
  })
  .strict()
  .superRefine((config, context) => {
    const origin = new URL(config.publicOrigin);

    if (origin.origin !== config.publicOrigin)
      context.addIssue({
        code: "custom",
        path: ["publicOrigin"],
        message: "Use an origin without a path, credentials, or query",
      });

    if (config.browserTransport === "https" && origin.protocol !== "https:") {
      context.addIssue({
        code: "custom",
        path: ["publicOrigin"],
        message: "HTTPS transport requires an HTTPS origin",
      });
    }

    if (
      config.browserTransport === "http-local-test" &&
      (origin.protocol !== "http:" ||
        !["127.0.0.1", "[::1]", "localhost"].includes(origin.hostname))
    ) {
      context.addIssue({
        code: "custom",
        path: ["publicOrigin"],
        message: "Local HTTP tests require a loopback HTTP origin",
      });
    }

    if (config.browserTransport === "http-lan-test") {
      const address = ipaddr.isValid(origin.hostname)
        ? ipaddr.parse(origin.hostname)
        : null;

      if (
        origin.protocol !== "http:" ||
        address?.kind() !== "ipv4" ||
        address.range() !== "private"
      ) {
        context.addIssue({
          code: "custom",
          path: ["publicOrigin"],
          message: "LAN HTTP tests require a private IPv4 HTTP origin",
        });
      }
    }
  });

export type ControllerConfig = z.infer<typeof controllerConfigSchema>;

let cached: ControllerConfig | null = null;

export function controllerConfig(): ControllerConfig {
  if (cached) return cached;
  const path = process.env.TP_CONTROLLER_CONFIG;

  if (!path) throw new Error("TP_CONTROLLER_CONFIG is required");
  cached = controllerConfigSchema.parse(JSON.parse(readFileSync(path, "utf8")));

  return cached;
}
