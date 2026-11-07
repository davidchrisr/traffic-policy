import { z } from "zod";
import { ipSchema, uint64Schema } from "@traffic-policy/contracts";

const pathSchema = z.string().startsWith("/");

export const gatewayConfigSchema = z
  .object({
    gatewayId: z.string().uuid(),
    listenAddress: ipSchema,
    machinePort: z.number().int().min(1024).max(65535),
    controllerUrl: z.string().url().startsWith("https://"),
    controllerIdentity: z.string().min(1).max(128),
    dnsListenAddresses: z.array(ipSchema).min(1).max(32),
    dnsPort: z.number().int().min(1024).max(65535),
    // Requested per UDP DNS listener; a kernel cap below it is reported, not fatal.
    dnsReceiveBufferBytes: z
      .number()
      .int()
      .min(65536)
      .max(67108864)
      .default(8388608),
    upstreamDns: z
      .object({ address: ipSchema, port: z.number().int().min(1).max(65535) })
      .strict(),
    enforcementSocket: pathSchema,
    stateDirectory: pathSchema,
    collectorBytes: uint64Schema,
    tls: z
      .object({ ca: pathSchema, certificate: pathSchema, key: pathSchema })
      .strict(),
    suricataFile: pathSchema,
  })
  .strict();

export type GatewayConfig = z.infer<typeof gatewayConfigSchema>;
