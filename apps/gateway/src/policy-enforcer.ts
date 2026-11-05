import type {
  Policy,
  Resolution,
  GatewayReceipt,
  AddressLease,
} from "@traffic-policy/contracts";
import { MAX_MACHINE_FRAME_BYTES } from "@traffic-policy/contracts";
import {
  DnsRuleIndex,
  InstanceOwners,
  leaseKey,
  reconcileLeases,
} from "@traffic-policy/core";
import { setTimeout as delay } from "node:timers/promises";
import { DnsLedger, type DnsBatch } from "./dns-ledger.ts";
import { hashDocument, ServiceError } from "@traffic-policy/core/io";
import type { NativeAccess } from "./native-access.ts";
import type { PolicyJournal } from "./policy-journal.ts";
import type { ConnectionMarks } from "./connection-marks.ts";
import type { EnforcementResult } from "@traffic-policy/contracts/enforcement";
import {
  permissionsForLeases,
  permissionCount,
  stateBytes,
  assertPermissionAllocation,
  instanceView,
  type Snapshot,
  type ManagedInstanceView,
} from "./policy-enforcer-state.ts";
import {
  prepareResolution,
  resolutionDenial,
  resolutionReceipt,
  type DeniedResolution,
  type PreparedResolution,
  type ResolutionAuthorization,
} from "./resolution-authorization.ts";

export interface ConfirmedView {
  receipt: GatewayReceipt;
  policy: Policy;
  permissions: number;
  resolutions: number;
}

export interface PolicyEnforcerDependencies {
  bootId: string;
  journal: PolicyJournal;
  native: NativeAccess;
  marks: ConnectionMarks;
  capacity: (bytes: bigint, gatewayDiskBytes: string) => void;
  clock?: () => number;
}

type Confirmed = { policy: Policy; receipt: GatewayReceipt; dns: DnsLedger };

type ResolutionRequest = {
  resolution: Resolution;
  accept: (result: EnforcementResult<"resolve">) => void;
  // oxlint-disable-next-line anti-slop/no-unknown-parameters -- Promise rejection preserves the original thrown cause; it is not a domain input.
  reject: (error: unknown) => void;
};

type ResolutionBatch = { requests: ResolutionRequest[]; openedAt: number };

const DNS_BATCH_LIMIT = 16;

const DNS_BATCH_WAIT_MS = 2;

const TABLE_CHECK_MS = 5000;

// nft commits each transaction atomically, so a reported failure left the
// previously installed program in place.
// oxlint-disable-next-line anti-slop/no-unknown-parameters -- Classifies a caught native failure without reshaping its cause.
function rejectedAtomically(error: unknown): boolean {
  return (
    error instanceof ServiceError && error.code === "kernel_operation_failed"
  );
}

export class PolicyEnforcer {
  #snapshot: Confirmed | null = null;
  private fullIntent: Snapshot | null = null;
  private applicationError: ServiceError | null = null;
  private latestPolicy: Policy | null = null;
  private restoreCandidates: Policy[] = [];
  private recoveryTimer: ReturnType<typeof setTimeout> | null = null;
  private recoveryDelay = 1000;
  private tableTimer: ReturnType<typeof setTimeout> | null = null;
  private closing = false;
  private installation = 0;
  private tail: Promise<unknown> = Promise.resolve();
  private dnsBatch: ResolutionBatch | null = null;
  private instances: readonly ManagedInstanceView[] = Object.freeze([]);
  // The instance covering each managed address, and each instance's policy position, rebuilt
  // with `instances`.
  private owners = new InstanceOwners<ManagedInstanceView>([]);
  private positions = new Map<ManagedInstanceView, number>();
  private readonly dnsIndexes = new WeakMap<Policy, DnsRuleIndex>();
  private readonly bootId: string;
  private readonly journal: PolicyJournal;
  private readonly native: NativeAccess;
  private readonly marks: ConnectionMarks;
  private readonly capacity: PolicyEnforcerDependencies["capacity"];
  private readonly now: () => number;
  private constructor(deps: PolicyEnforcerDependencies) {
    this.bootId = deps.bootId;
    this.journal = deps.journal;
    this.native = deps.native;
    this.marks = deps.marks;
    this.capacity = deps.capacity;
    this.now = deps.clock ?? (() => Date.now());
  }
  static async open(deps: PolicyEnforcerDependencies): Promise<PolicyEnforcer> {
    const owner = new PolicyEnforcer(deps);

    try {
      await owner.restore();
      owner.watchTable();

      return owner;
    } catch (error) {
      await owner.close();
      throw error;
    }
  }
  // The managed instances that own any of the addresses, in policy order.
  managedOwners(addresses: readonly string[]): readonly ManagedInstanceView[] {
    if (this.fullIntent)
      throw new ServiceError(
        503,
        "policy_application_pending",
        "Instance ownership is unavailable during policy installation",
      );

    if (this.applicationError) throw this.applicationError;
    const found = new Map<ManagedInstanceView, number>();

    for (const address of addresses) {
      const owner = this.owners.find(address);

      if (owner) found.set(owner, this.positions.get(owner)!);
    }

    return [...found]
      .sort((left, right) => left[1] - right[1])
      .map(([view]) => view);
  }
  collection(): ConfirmedView {
    return this.confirmedState();
  }
  // prepare, apply, and resolve take ownership of their argument: the enforcement service passes one it parsed
  // for the request and does not use it again.
  prepare(policy: Policy): Promise<{ revision: string; policyHash: string }> {
    return this.mutate(async () => {
      const result = await this.applyPolicy(policy, true);

      return { revision: result.revision, policyHash: result.policyHash };
    });
  }
  apply(policy: Policy): Promise<GatewayReceipt> {
    return this.mutate(() => this.applyPolicy(policy, false));
  }
  resolve(resolution: Resolution): Promise<EnforcementResult<"resolve">> {
    return new Promise((accept, reject) => {
      let batch = this.dnsBatch;

      if (!batch || batch.requests.length === DNS_BATCH_LIMIT) {
        batch = { requests: [], openedAt: performance.now() };
        const queued = batch;
        void this.mutate(async () => {
          const remaining =
            DNS_BATCH_WAIT_MS - (performance.now() - queued.openedAt);

          if (remaining > 0) await delay(remaining);

          if (this.dnsBatch === queued) this.dnsBatch = null;
          await this.resolveBatch(queued.requests);
          // oxlint-disable-next-line anti-slop/no-unknown-parameters -- Fan out the shared transaction's original rejection without reclassifying its cause.
        }).catch((error: unknown) => {
          for (const request of queued.requests) request.reject(error);
        });
        this.dnsBatch = batch;
      }

      batch.requests.push({ resolution, accept, reject });
    });
  }
  async status(): Promise<ConfirmedView> {
    return this.confirmedState();
  }
  async connections(): Promise<EnforcementResult<"connections">> {
    const state = this.confirmedState();
    const installation = this.installation;

    const instances = this.instances.map((instance) => ({
      ...instance,
      addresses: [...instance.addresses],
    }));

    const observedAt = new Date(this.now()).toISOString();

    const metadata = {
      bootId: this.bootId,
      revision: state.policy.revision,
      policyHash: state.receipt.policyHash,
      instances,
      gatewayAddresses: this.native.localAddresses(),
      observedAt,
    };

    // Command identities are UUIDs, so every response has this envelope size.
    const overhead = Buffer.byteLength(
      JSON.stringify({
        id: "00000000-0000-4000-8000-000000000000",
        ok: true,
        value: { ...metadata, xml: "" },
      }) + "\n",
    );

    const xml = await this.native.connections(
      instances,
      MAX_MACHINE_FRAME_BYTES - overhead,
    );

    this.assertAvailable();

    if (installation !== this.installation)
      throw new ServiceError(
        503,
        "connection_snapshot_changed",
        "Policy changed during connection collection; the sample was discarded",
      );

    return {
      ...metadata,
      xml,
    };
  }
  async close(): Promise<void> {
    this.closing = true;
    this.cancelRecovery();

    if (this.tableTimer) clearTimeout(this.tableTimer);
    await this.tail;
  }
  private mutate<T>(action: () => Promise<T>): Promise<T> {
    if (this.closing)
      return Promise.reject(
        new ServiceError(
          503,
          "enforcement_stopping",
          "Enforcement service is stopping",
        ),
      );
    // A policy/status operation closes the admission group at its FIFO position.
    this.dnsBatch = null;

    const result = this.tail.then(action);

    this.tail = result.catch(() => {});

    return result;
  }
  private publish(snapshot: Confirmed) {
    this.#snapshot = snapshot;
  }
  private dnsIndex(policy: Policy): DnsRuleIndex {
    let index = this.dnsIndexes.get(policy);

    if (!index) {
      // apply/prepare own cloned policies; DNS mutations never edit them.
      index = new DnsRuleIndex(policy);
      this.dnsIndexes.set(policy, index);
    }

    return index;
  }
  private setInstances(instances: readonly ManagedInstanceView[]) {
    this.instances = instances;
    this.owners = new InstanceOwners(instances);
    this.positions = new Map(
      instances.map((view, position) => [view, position] as const),
    );
  }
  private async readyDns() {
    this.assertAvailable();

    if (!this.#snapshot)
      throw new ServiceError(
        503,
        "not_initialized",
        "No policy has been applied",
      );

    return this.#snapshot;
  }
  private assertAvailable() {
    if (this.applicationError) throw this.applicationError;

    if (this.fullIntent)
      throw new ServiceError(
        503,
        "policy_application_pending",
        "A configured policy application has not completed",
      );
  }
  // The kernel or saved state is incomplete; reinstall without waiting for
  // the controller.
  private interrupted() {
    this.applicationError = new ServiceError(
      503,
      "enforcement_unavailable",
      "The last firewall update did not complete. Enforcement is unavailable until a full policy application succeeds.",
    );
    this.scheduleRecovery();
  }
  private cancelRecovery() {
    if (this.recoveryTimer) clearTimeout(this.recoveryTimer);
    this.recoveryTimer = null;
  }
  private scheduleRecovery() {
    if (this.closing || this.recoveryTimer) return;
    this.recoveryTimer = setTimeout(() => {
      this.recoveryTimer = null;
      void this.mutate(async () => {
        if (this.applicationError) await this.recover();
      }).catch(() => this.scheduleRecovery());
    }, this.recoveryDelay);
    this.recoveryDelay = Math.min(this.recoveryDelay * 2, 30000);
    this.recoveryTimer.unref();
  }
  private async recover() {
    const current = this.#snapshot;

    if (!current && !this.fullIntent && this.restoreCandidates.length) {
      if (!(await this.restoreSaved())) throw this.applicationError;

      return;
    }

    const candidate =
      this.fullIntent ??
      (current
        ? {
            policy: current.policy,
            leases: current.dns.leaseValues(),
            permissions: [],
            receipt: null,
          }
        : null);

    if (candidate) await this.install(candidate);
  }

  // An external ruleset flush removes the table without notice, while confirmed
  // state would keep reporting the policy as enforced.
  private watchTable() {
    if (this.closing) return;
    this.tableTimer = setTimeout(() => {
      this.tableTimer = null;
      void this.checkTable().finally(() => this.watchTable());
    }, TABLE_CHECK_MS);
    this.tableTimer.unref();
  }
  private async checkTable() {
    // Installations replace the table atomically, so it is never absent
    // between them; checking outside the lock keeps DNS admission unblocked.
    const settled = () =>
      this.#snapshot && !this.applicationError && !this.fullIntent;

    try {
      if (!settled() || (await this.native.tablePresent())) return;
      await this.mutate(async () => {
        if (!settled() || (await this.native.tablePresent())) return;
        console.error(
          JSON.stringify({
            service: "enforcement",
            step: "table-check",
            error: "Managed nftables table is missing",
          }),
        );
        this.applicationError = new ServiceError(
          503,
          "enforcement_unavailable",
          "The firewall table was removed outside Traffic Policy. Enforcement is unavailable until the policy is reinstalled.",
        );
        await this.recover();
      });
    } catch {
      this.scheduleRecovery();
    }
  }

  private async restore() {
    const candidates: Policy[] = [];
    let failed = false;

    for (const kind of ["full-pending", "full-applied"] as const) {
      try {
        const saved = await this.journal.read(kind);

        if (saved) candidates.push(saved.policy);
      } catch (error) {
        failed = true;
        console.error(
          JSON.stringify({
            service: "enforcement",
            step: "restore-read",
            checkpoint: kind,
            error:
              error instanceof Error ? error.message : "Checkpoint read failed",
          }),
        );
      }
    }

    candidates.sort((left, right) =>
      BigInt(left.revision) > BigInt(right.revision)
        ? -1
        : BigInt(left.revision) < BigInt(right.revision)
          ? 1
          : 0,
    );
    this.latestPolicy = candidates[0] ?? null;
    this.restoreCandidates = candidates;

    if (candidates.length && (await this.restoreSaved())) return;

    if (!failed && !candidates.length) return;
    this.applicationError = new ServiceError(
      503,
      "enforcement_restore_failed",
      "Saved firewall policy could not be restored. Apply a corrected policy.",
    );

    // A transient failure must not leave forwarding guarded until manual repair.
    if (candidates.length) this.scheduleRecovery();
  }
  private async restoreSaved(): Promise<boolean> {
    for (const policy of this.restoreCandidates) {
      try {
        await this.install(
          { policy, leases: [], permissions: [], receipt: null },
          true,
        );

        return true;
      } catch (error) {
        console.error(
          JSON.stringify({
            service: "enforcement",
            step: "restore-apply",
            revision: policy.revision,
            error:
              error instanceof Error ? error.message : "Policy restore failed",
          }),
        );
      }
    }

    // Retries choose among saved policies, newest first, not the last attempt.
    this.fullIntent = null;

    return false;
  }
  private async prepareCandidate(candidate: Snapshot) {
    const now = this.now();

    const grants = permissionsForLeases(
      candidate.policy,
      candidate.leases,
      now,
      this.dnsIndex(candidate.policy),
    );

    const existingAllocation = this.#snapshot?.dns.permissionCount(now) ?? 0;

    assertPermissionAllocation(
      grants,
      candidate.policy.settings.permissionLimit,
      existingAllocation,
    );
    const policyHash = hashDocument(candidate.policy);

    const marks = await this.marks.assign(
      candidate.policy,
      this.#snapshot?.policy ?? null,
    );

    const program = await this.native.compileFull({
      policy: candidate.policy,
      permissions: grants,
      now,
      policyHash,
      existingAllocation,
      marks,
    });

    if (Buffer.byteLength(program) > 4 * 1024 * 1024)
      throw new ServiceError(
        507,
        "native_policy_capacity",
        "Native policy exceeds its command allocation. Reduce policy complexity.",
      );

    const snapshotBytes = stateBytes({
      ...candidate,
      permissions: grants,
    });

    this.capacity(
      snapshotBytes * 2n,
      candidate.policy.settings.gatewayDiskBytes,
    );
    await this.native.check(program);

    return { grants, policyHash, program, marks };
  }
  // Restore candidates are already saved. Restoring never rewrites or removes
  // a newer saved policy, so a failed restore keeps it for the next attempt.
  private async install(
    candidate: Snapshot,
    restoring = false,
  ): Promise<GatewayReceipt> {
    const { grants, policyHash, program, marks } =
      await this.prepareCandidate(candidate);

    const prior = this.fullIntent;
    this.installation++;
    this.fullIntent = candidate;

    if (
      !this.latestPolicy ||
      BigInt(candidate.policy.revision) >= BigInt(this.latestPolicy.revision)
    )
      this.latestPolicy = candidate.policy;

    if (!restoring)
      try {
        await this.journal.replace("full-pending", {
          version: 1,
          policy: candidate.policy,
          receipt: null,
        });
      } catch (error) {
        // The kernel is unchanged.
        this.fullIntent = prior;
        throw error;
      }

    try {
      await this.native.applyFull(program);
    } catch (error) {
      if (!rejectedAtomically(error)) {
        // The kernel may have changed owners even though no receipt is durable.
        this.setInstances(instanceView(candidate.policy));
        this.interrupted();
      } else if (restoring) this.fullIntent = prior;
      else await this.withdrawIntent(prior);

      throw error;
    }

    // Ownership follows kernel transitions, including unpublished applications.
    this.setInstances(instanceView(candidate.policy, this.instances));

    const receipt: GatewayReceipt = {
      protocolVersion: 1,
      revision: candidate.policy.revision,
      policyHash,
      bootId: this.bootId,
      appliedAt: new Date(this.now()).toISOString(),
      permissions: permissionCount(grants),
    };

    const next = {
      policy: candidate.policy,
      receipt,
      dns: new DnsLedger(
        candidate.policy,
        receipt,
        this.dnsIndex(candidate.policy),
        candidate.leases,
        grants,
        marks,
      ),
    };

    try {
      await this.journal.replace("full-applied", {
        version: 1,
        policy: candidate.policy,
        receipt,
      });

      if (!restoring || candidate.policy === this.restoreCandidates[0])
        await this.journal.removeDurably("full-pending");
    } catch (error) {
      this.interrupted();
      throw error;
    }

    this.publish(next);
    this.fullIntent = null;
    this.applicationError = null;
    this.restoreCandidates = [];
    this.cancelRecovery();
    this.recoveryDelay = 1000;

    return { ...receipt };
  }

  // The previous program still enforces; restore the obligation that preceded
  // this candidate so availability matches the kernel.
  private async withdrawIntent(prior: Snapshot | null) {
    this.fullIntent = prior;

    if (prior)
      await this.journal.replace("full-pending", {
        version: 1,
        policy: prior.policy,
        receipt: null,
      });
    else await this.journal.removeDurably("full-pending");
  }

  private async installDns(batch: DnsBatch) {
    const now = this.now();
    const changed = batch.chains(now);

    try {
      await this.native.applyDns(changed, now);
    } catch (error) {
      if (!rejectedAtomically(error)) this.interrupted();
      // A missing table also rejects updates atomically.
      else void this.checkTable();

      throw error;
    }

    batch.commit();
  }

  private async applyPolicy(
    policy: Policy,
    prepareOnly: true,
  ): Promise<{ revision: string; policyHash: string }>;
  private async applyPolicy(
    policy: Policy,
    prepareOnly: false,
  ): Promise<GatewayReceipt>;
  private async applyPolicy(
    policy: Policy,
    prepareOnly: boolean,
  ): Promise<GatewayReceipt | { revision: string; policyHash: string }> {
    const previous = this.#snapshot;
    const latest = this.latestPolicy;

    if (latest && BigInt(policy.revision) < BigInt(latest.revision)) {
      throw new ServiceError(
        409,
        "stale_revision",
        "Policy revision is older than the applied revision",
      );
    }

    if (
      latest &&
      policy.revision === latest.revision &&
      hashDocument(policy) !== hashDocument(latest)
    ) {
      throw new ServiceError(
        409,
        "revision_conflict",
        "A revision cannot identify different policies",
      );
    }

    if (
      !prepareOnly &&
      previous &&
      policy.revision === previous.policy.revision &&
      !this.applicationError &&
      !this.fullIntent
    ) {
      return this.confirmedState().receipt;
    }

    const leases = reconcileLeases(
      policy,
      previous?.dns.leaseValues() ?? [],
      this.now(),
      previous !== null &&
        previous.policy.settings.dnsGraceSeconds !==
          policy.settings.dnsGraceSeconds,
    );

    const candidate: Snapshot = {
      policy: policy,
      leases,
      receipt: null,
      permissions: [],
    };

    if (prepareOnly) {
      await this.prepareCandidate(candidate);

      return {
        revision: policy.revision,
        policyHash: hashDocument(policy),
      };
    }

    return this.install(candidate);
  }
  private async resolveBatch(requests: ResolutionRequest[]): Promise<void> {
    const current = await this.readyDns();
    let batch = current.dns.begin(this.now());

    let pending: {
      request: ResolutionRequest;
      prepared: ResolutionAuthorization;
    }[] = [];

    const pendingLeases = new Map<string, AddressLease>();

    const commit = async () => {
      if (!pending.length) return;
      await this.installDns(batch);

      for (const { request, prepared } of pending) {
        try {
          // A scheduled Block can take effect while the install runs; the answer then stays
          // withheld.
          const index = this.dnsIndex(current.policy);
          const context = index.context(request.resolution.clientIp);

          const decision = context
            ? index.decide(context, request.resolution.question, this.now())
            : null;

          if (!decision)
            throw new ServiceError(
              400,
              "unknown_dns_client",
              "DNS client is not in an instance",
            );
          request.accept(
            decision.allowed
              ? resolutionReceipt(
                  current.receipt,
                  prepared,
                  current.dns,
                  this.now(),
                )
              : resolutionDenial(
                  current.receipt,
                  prepared.instanceId,
                  decision,
                ),
          );
        } catch (error) {
          request.reject(error);
        }
      }

      pending = [];
      pendingLeases.clear();
      batch = current.dns.begin(this.now());
    };

    for (const request of requests) {
      let prepared: PreparedResolution | DeniedResolution;

      try {
        prepared = prepareResolution(
          current.policy,
          request.resolution,
          this.now(),
          this.dnsIndex(current.policy),
        );
      } catch (error) {
        request.reject(error);
        continue;
      }

      if ("denied" in prepared) {
        request.accept(
          resolutionDenial(
            current.receipt,
            prepared.instanceId,
            prepared.denied,
          ),
        );
        continue;
      }

      const now = this.now();
      batch.expire(now);

      const shortens = prepared.learned.some((value) => {
        const previous = pendingLeases.get(leaseKey(value));

        return (
          previous !== undefined &&
          Date.parse(batch.selected(value).expiresAt) <
            Date.parse(previous.expiresAt)
        );
      });

      let undo: () => void;

      try {
        undo = batch.stage(prepared.learned, now);
      } catch (error) {
        request.reject(error);
        continue;
      }

      if (shortens) {
        undo();
        // Confirm earlier answers before committing a shorter conflicting lease.
        await commit();

        try {
          prepared = prepareResolution(
            current.policy,
            request.resolution,
            this.now(),
            this.dnsIndex(current.policy),
          );

          if ("denied" in prepared) {
            request.accept(
              resolutionDenial(
                current.receipt,
                prepared.instanceId,
                prepared.denied,
              ),
            );
            continue;
          }

          batch.stage(prepared.learned, this.now());
        } catch (error) {
          request.reject(error);
          continue;
        }
      }

      pending.push({
        request,
        prepared: {
          instanceId: prepared.instanceId,
          expected: prepared.expected,
        },
      });

      for (const value of prepared.learned) {
        const key = leaseKey(value),
          selected = batch.lease(key);

        if (selected) pendingLeases.set(key, selected.value);
      }
    }

    await commit();
  }
  private confirmedState(): ConfirmedView {
    this.assertAvailable();

    if (!this.#snapshot)
      throw new ServiceError(
        503,
        "not_initialized",
        "No policy has been applied",
      );

    const now = this.now(),
      count = this.#snapshot.dns.permissionCount(now);

    return {
      receipt: {
        ...this.#snapshot.receipt!,
        permissions: count,
      },
      policy: this.#snapshot.policy,
      permissions: count,
      resolutions: this.#snapshot.dns.resolutionCount(now),
    };
  }
}
