import type { RequestHandler } from "@sveltejs/kit";
import { z } from "zod";
import {
  instantSchema,
  ipSchema,
  ruleInputSchema,
} from "@traffic-policy/contracts";
import { monitorSelectionSchema } from "@traffic-policy/contracts/dashboard";
import { removeInstance } from "#lib/server/services.ts";
import { apiError, requestBody } from "#lib/server/api.ts";
import {
  deleteRule,
  dismissHostRequest,
  expectedRevisionSchema,
  saveInstance,
  saveRule,
  saveSettings,
  store,
} from "#lib/server/services.ts";
import { ServiceError } from "@traffic-policy/core/io";
import { setSessionCookie } from "#lib/server/session-cookie.ts";
import { REMEMBERED_MS } from "#lib/server/store.ts";
import { reverseLookup } from "#lib/server/reverse-dns.ts";
import { servicesStatus } from "#lib/server/service-status.ts";

const handle: RequestHandler = async (event) => {
  try {
    const path = event.params.endpoint;
    const method = event.request.method;

    if (path === "auth/session" && method === "GET")
      return Response.json({
        authenticated: !!event.locals.actor,
        identity: event.locals.actor,
      });

    if (path === "auth/login" && method === "POST") {
      const input = z
        .object({
          password: z.string().max(2048),
          remember: z.boolean().optional(),
        })
        .strict()
        .parse(await requestBody(event.request));

      const remembered = input.remember ?? false;

      const token = await store().login(
        input.password,
        event.getClientAddress(),
        remembered,
      );

      setSessionCookie(
        event.cookies,
        token,
        remembered ? new Date(Date.now() + REMEMBERED_MS) : null,
      );

      return Response.json({ authenticated: true, identity: "Admin" });
    }

    if (path === "auth/logout" && method === "POST") {
      store().logout(event.cookies.get("tp_session"));
      event.cookies.delete("tp_session", { path: "/" });

      return Response.json({ authenticated: false, identity: null });
    }

    if (path === "services" && method === "GET")
      return Response.json(await servicesStatus(event.locals.actor));

    if (path === "status" && method === "GET")
      return Response.json(store().status());

    if (path === "rules" && method === "GET")
      return Response.json(store().rules());

    if (path === "rules" && method === "POST") {
      const policy = saveRule(event.locals, await requestBody(event.request));

      return Response.json(
        { revision: policy.revision, pending: true },
        { status: 202 },
      );
    }

    const ruleId = path?.match(/^rules\/([^/]+)$/)?.[1];

    if (ruleId && method === "PUT") {
      const policy = saveRule(
        event.locals,
        await requestBody(event.request),
        ruleId,
      );

      return Response.json(
        { revision: policy.revision, pending: true },
        { status: 202 },
      );
    }

    if (ruleId && method === "DELETE") {
      const policy = deleteRule(
        event.locals,
        ruleId,
        await requestBody(event.request),
      );

      return Response.json(
        { revision: policy.revision, pending: true },
        { status: 202 },
      );
    }

    const renewal = path?.match(/^rules\/([^/]+)\/renew$/)?.[1];

    if (renewal && method === "POST") {
      const input = z
        .object({
          expectedRevision: z.string(),
          durationSeconds: z.number().int().min(1).max(31536000),
        })
        .strict()
        .parse(await requestBody(event.request));

      const current = store()
        .desired()
        .rules.find((rule) => rule.id === renewal);

      if (!current)
        throw new ServiceError(404, "rule_not_found", "Rule no longer exists");

      const {
        id: _id,
        createdAt: _createdAt,
        modifiedAt: _modifiedAt,
        ...editable
      } = current;

      const fields = ruleInputSchema.parse(editable);
      fields.expiresAt = new Date(
        Math.floor(Date.now() / 1000) * 1000 + input.durationSeconds * 1000,
      ).toISOString();

      const policy = saveRule(
        event.locals,
        { expectedRevision: input.expectedRevision, rule: fields },
        renewal,
      );

      return Response.json(
        { revision: policy.revision, pending: true },
        { status: 202 },
      );
    }

    if (path?.startsWith("instances/") && method === "DELETE") {
      removeInstance(
        event.locals,
        path.slice("instances/".length),
        await requestBody(event.request),
      );

      return Response.json({ accepted: true }, { status: 202 });
    }

    if (path === "instances" && method === "GET")
      return Response.json({
        instances: store().desired().instances,
        rules: store().desired().rules,
        revision: store().desired().revision,
      });

    if (path === "instances" && method === "PUT") {
      const policy = saveInstance(
        event.locals,
        await requestBody(event.request),
      );

      return Response.json(
        { revision: policy.revision, pending: true },
        { status: 202 },
      );
    }

    if (path === "names/lookup" && method === "POST") {
      const input = z
        .object({ instanceId: z.string().uuid(), address: ipSchema })
        .strict()
        .parse(await requestBody(event.request));

      return Response.json(
        await reverseLookup(
          event.locals.actor,
          input.instanceId,
          input.address,
        ),
      );
    }

    if (path === "settings" && method === "GET")
      return Response.json(store().resources());

    if (path === "settings" && method === "PUT") {
      const policy = saveSettings(
        event.locals,
        await requestBody(event.request),
      );

      return Response.json(
        { revision: policy.revision, pending: true },
        { status: 202 },
      );
    }

    if (path === "history" && method === "GET") {
      const limit = z.coerce
        .number()
        .int()
        .min(1)
        .max(500)
        .parse(event.url.searchParams.get("limit") ?? 100);

      return Response.json(store().history(limit));
    }

    if (path === "requests" && method === "GET")
      return Response.json(
        store().requests(
          ipSchema.nullable().parse(event.url.searchParams.get("host")),
        ),
      );

    const dismiss = path?.match(/^requests\/hosts\/([^/]+)\/dismiss$/)?.[1];

    if (dismiss && method === "POST") {
      dismissHostRequest(event.locals, dismiss);

      return Response.json({ dismissed: true });
    }

    const namesFor = path?.match(/^requests\/([^/]+)\/names$/)?.[1];

    if (namesFor && method === "GET")
      return Response.json(store().requestNames(namesFor));

    if (path === "monitor" && method === "GET") {
      const query = event.url.searchParams;

      const from = instantSchema.parse(
        query.get("from") ?? new Date(Date.now() - 300000).toISOString(),
      );

      const to = instantSchema.parse(
        query.get("to") ?? new Date().toISOString(),
      );

      const selection = monitorSelectionSchema.parse({
        instanceId: query.has("instanceId")
          ? query.get("instanceId")
          : undefined,
        peerIp: query.has("peerIp") ? query.get("peerIp") : undefined,
        domain: query.has("domain") ? query.get("domain") : undefined,
        hostname: query.has("hostname") ? query.get("hostname") : undefined,
        protocol: query.has("protocol")
          ? Number(query.get("protocol"))
          : undefined,
        port: query.has("port")
          ? query.get("port") === "null"
            ? null
            : Number(query.get("port"))
          : undefined,
        direction: query.has("direction") ? query.get("direction") : undefined,
      });

      const events = z
        .enum(["recent", "full"])
        .optional()
        .parse(query.get("events") ?? undefined);

      return Response.json(
        await store().monitor(
          from,
          to,
          selection,
          events,
          event.request.signal,
        ),
      );
    }

    if (path === "policy" && method === "GET")
      return Response.json(store().desired());

    if (path === "policy/reapply" && method === "POST") {
      const input = expectedRevisionSchema.parse(
        await requestBody(event.request),
      );

      const policy = store().mutation(
        input.expectedRevision,
        "policy-reapplied",
        "Gateway",
        (value) => value,
        event.locals.client,
      );

      return Response.json(
        { revision: policy.revision, pending: true },
        { status: 202 },
      );
    }

    throw new ServiceError(404, "not_found", "API endpoint does not exist");
  } catch (error) {
    return apiError(error, event.locals.requestId);
  }
};

export const GET = handle;

export const POST = handle;

export const PUT = handle;

export const DELETE = handle;
