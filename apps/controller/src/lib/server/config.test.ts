import { describe, expect, it } from "vitest";
import { controllerConfigSchema } from "./config.ts";

const config = {
  database: "/state/controller.sqlite3",
  listenAddress: "127.0.0.1",
  browserPort: 9444,
  machinePort: 9445,
  publicOrigin: "https://localhost:9444",
  gatewayUrl: "https://gateway.example:9443",
  gatewayIdentity: "gateway",
  tls: {
    ca: "/cert/ca.crt",
    certificate: "/cert/controller.crt",
    key: "/cert/controller.key",
  },
};

describe("browser transport boundaries", () => {
  it("requires explicit local test mode before accepting HTTP", () => {
    expect(
      controllerConfigSchema.safeParse({
        ...config,
        publicOrigin: "http://127.0.0.1:9444",
      }).success,
    ).toBe(false);
    expect(
      controllerConfigSchema.parse({
        ...config,
        browserTransport: "http-local-test",
        publicOrigin: "http://127.0.0.1:9444",
      }).browserTransport,
    ).toBe("http-local-test");
  });
  it("rejects remote plaintext origins and keeps machine endpoints encrypted", () => {
    expect(
      controllerConfigSchema.safeParse({
        ...config,
        browserTransport: "http-local-test",
        publicOrigin: "http://10.22.240.20:9444",
      }).success,
    ).toBe(false);
    expect(
      controllerConfigSchema.safeParse({
        ...config,
        gatewayUrl: "http://gateway.example:9443",
      }).success,
    ).toBe(false);
    expect(
      controllerConfigSchema.safeParse({
        ...config,
        publicOrigin: "https://localhost:9444/path",
      }).success,
    ).toBe(false);
  });
  it.each(["10.22.240.20", "172.16.0.10", "192.168.1.100"])(
    "accepts %s only with explicit LAN HTTP test mode",
    (address) => {
      const publicOrigin = `http://${address}:9444`;
      expect(
        controllerConfigSchema.safeParse({ ...config, publicOrigin }).success,
      ).toBe(false);

      const parsed = controllerConfigSchema.parse({
        ...config,
        browserListenAddress: address,
        browserTransport: "http-lan-test",
        publicOrigin,
      });

      expect(parsed.browserListenAddress).toBe(address);
      expect(parsed.listenAddress).toBe(config.listenAddress);
      expect(parsed.gatewayUrl).toBe(config.gatewayUrl);
    },
  );
  it.each([
    "http://8.8.8.8:9444",
    "http://172.32.0.10:9444",
    "http://127.0.0.1:9444",
    "http://controller.example:9444",
    "http://[fd42::1]:9444",
    "https://192.168.1.100:9444",
  ])("rejects %s in LAN HTTP test mode", (publicOrigin) => {
    expect(
      controllerConfigSchema.safeParse({
        ...config,
        browserTransport: "http-lan-test",
        publicOrigin,
      }).success,
    ).toBe(false);
  });
});
