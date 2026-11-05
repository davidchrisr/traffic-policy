import type {
  AddressLease,
  DnsDecision,
  GatewayReceipt,
  Resolution,
  ResolutionReceipt,
} from "@traffic-policy/contracts";
import type { EnforcementResult } from "@traffic-policy/contracts/enforcement";
import { addressLeases, DnsRuleIndex } from "@traffic-policy/core";
import { ServiceError } from "@traffic-policy/core/io";
import type { Policy } from "@traffic-policy/contracts";
import type { DnsLedger } from "./dns-ledger.ts";

export interface ResolutionAuthorization {
  // The client's most specific instance, which receipts and denials report.
  instanceId: string;
  // Each permission the answer grants, by the scope path that holds it.
  expected: {
    path: string;
    ruleId: string;
    address: string;
    deadline: number;
  }[];
}

export interface PreparedResolution extends ResolutionAuthorization {
  learned: AddressLease[];
}

// A lookup the policy denies, with the decision that denied it.
export interface DeniedResolution {
  instanceId: string;
  denied: DnsDecision;
}

export function prepareResolution(
  policy: Policy,
  resolution: Resolution,
  now: number,
  index = new DnsRuleIndex(policy),
): PreparedResolution | DeniedResolution {
  const context = index.context(resolution.clientIp);

  if (!context)
    throw new ServiceError(
      400,
      "unknown_dns_client",
      "DNS client is not in an instance",
    );
  const { instanceId } = context;
  const decision = index.decide(context, resolution.question, now);

  if (!decision.allowed) return { instanceId, denied: decision };

  if (Math.abs(now - Date.parse(resolution.responseAt)) > 5000)
    throw new ServiceError(
      400,
      "stale_dns_response",
      "DNS authorization requires a current local response",
    );

  const learned = addressLeases(policy, resolution, index);
  const responseTime = Date.parse(resolution.responseAt);

  const expected = learned.flatMap((lease) =>
    index.match(lease).flatMap(({ path, rules }) =>
      rules
        .filter(
          (rule) =>
            (!rule.notBefore || Date.parse(rule.notBefore) <= responseTime) &&
            (!rule.expiresAt || Date.parse(rule.expiresAt) > responseTime),
        )
        .map((rule) => ({
          path,
          ruleId: rule.id,
          address: lease.address,
          deadline:
            Math.floor(
              Math.min(
                Date.parse(lease.expiresAt),
                rule.expiresAt ? Date.parse(rule.expiresAt) : Infinity,
              ) / 1000,
            ) * 1000,
        })),
    ),
  );

  return {
    instanceId,
    learned,
    expected,
  };
}

// The resolve result for a denied lookup, identified by the policy that denied it.
export function resolutionDenial(
  receipt: GatewayReceipt,
  instanceId: string,
  decision: DnsDecision,
): EnforcementResult<"resolve"> {
  return {
    ...decision,
    allowed: false,
    instanceId,
    revision: receipt.revision,
    policyHash: receipt.policyHash,
  };
}

export function resolutionReceipt(
  receipt: GatewayReceipt,
  prepared: ResolutionAuthorization,
  ledger: DnsLedger,
  now: number,
): ResolutionReceipt {
  for (const permission of prepared.expected) {
    if (
      permission.deadline <= now ||
      ledger.permissionDeadline(
        permission.path,
        permission.ruleId,
        permission.address,
      ) <= now
    )
      throw new ServiceError(
        503,
        "dns_authorization_expired",
        "DNS authorization expired before local confirmation; retry the query",
      );
  }

  return {
    ...receipt,
    permissions: ledger.permissionCount(now),
    instanceId: prepared.instanceId,
  };
}
