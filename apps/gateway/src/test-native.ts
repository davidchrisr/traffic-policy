import {
  compileNftables,
  compileDnsUpdate,
  connectionMarkScopes,
  dnsChains,
  type DnsChain,
  type Infrastructure,
  type MarkAssignments,
} from "@traffic-policy/core/nftables";
import type { Policy } from "@traffic-policy/contracts";
import { ServiceError } from "@traffic-policy/core/io";
import { ConnectionMarks } from "./connection-marks.ts";
import type { NativeAccess, FullNativeInput } from "./native-access.ts";

// Connection marks numbered from 1, with no saved state.
export const testConnectionMarks = () =>
  new ConnectionMarks({ read: async () => null, write: async () => {} });

export const sequentialMarks = (policy: Policy): MarkAssignments =>
  new Map(
    connectionMarkScopes(policy).map((scope, index) => [scope, index + 1]),
  );

// This model applies native operations only. It has no filesystem/journal access.
export class TestNative implements NativeAccess {
  readonly programs: string[] = [];
  readonly installed = new Map<string, DnsChain>();
  private prepared = new Map<string, DnsChain[]>();
  full = 0;
  delta = 0;
  private comment: string | null = null;
  constructor(
    private readonly dnsPort = 5353,
    private readonly infrastructure: Infrastructure = {
      upstreamInterfaces: ["wan0"],
      controllerAddresses: ["192.0.2.9"],
      machinePort: 9443,
      controllerPort: 9445,
      upstreamDns: { address: "192.0.2.53", port: 53 },
    },
  ) {}
  async compileFull(input: FullNativeInput): Promise<string> {
    const program = compileNftables(input.policy, input.permissions, {
      tableExists: this.comment !== null,
      dnsPort: this.dnsPort,
      now: input.now,
      policyHash: input.policyHash,
      existingPermissionCount: input.existingAllocation,
      marks: input.marks,
      infrastructure: this.infrastructure,
    });

    this.prepared.set(
      program,
      structuredClone(dnsChains(input.policy, input.permissions, input.marks)),
    );

    return program;
  }
  async check(_program: string) {}
  async applyFull(program: string) {
    this.full++;
    this.programs.push(program);
    const match = program.match(/comment "(revision:[^"]+)"/);

    if (!match) throw new Error("Native transaction has no policy identity");
    this.comment = match[1]!;
    this.installed.clear();
    const groups = this.prepared.get(program);

    if (!groups)
      throw new Error("Native program was not compiled by this adapter");

    for (const group of groups)
      this.installed.set(group.name, structuredClone(group));
  }
  async applyDns(changes: DnsChain[], now: number) {
    const program = compileDnsUpdate(changes, now);

    if (!program) return;

    if (this.comment === null)
      throw new ServiceError(503, "kernel_operation_failed", "No such table");
    this.delta++;
    this.programs.push(program);

    for (const group of changes)
      this.installed.set(group.name, structuredClone(group));
  }
  async tablePresent() {
    return this.comment !== null;
  }
  // Models an external `nft flush ruleset`.
  flush() {
    this.comment = null;
    this.installed.clear();
  }
  async connections() {
    return "<conntrack></conntrack>";
  }
  localAddresses() {
    return ["127.0.0.1", "10.22.240.1"];
  }
}
