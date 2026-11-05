import { dirname, join } from "node:path";
import { open, unlink } from "node:fs/promises";
import { z } from "zod";
import {
  policySchema,
  gatewayReceiptSchema,
  uint64Schema,
  type Policy,
  type GatewayReceipt,
} from "@traffic-policy/contracts";
import { DnsRuleIndex } from "@traffic-policy/core";
import {
  atomicJson,
  readJson,
  hashDocument,
  hasErrorCode,
  ServiceError,
} from "@traffic-policy/core/io";
import { StorageBudget, GATEWAY_RESERVE } from "@traffic-policy/core/storage";
import { EventBuffer } from "./buffer.ts";
import type { PolicyView } from "./eve.ts";
import { CollectorWriter } from "./collector-writer.ts";
import { enforcementRequest } from "./enforcement-client.ts";
import type { GatewayConfig } from "./config.ts";
import type {
  DnsAdmission,
  EnforcementHealth as Health,
  EnforcementCollection as Collection,
} from "@traffic-policy/contracts/enforcement";

const intentSchema = z
  .object({
    version: z.literal(1),
    policy: policySchema,
    phase: z.enum(["prepared", "native-started", "native-committed"]),
    receipt: gatewayReceiptSchema.nullable(),
  })
  .strict();

type Intent = z.infer<typeof intentSchema>;

// Limits are configured in the controller settings. The gateway remembers the
// last enforcement-confirmed values so a enforcement outage cannot shrink retained
// observations or widen the disk quota to setup defaults.
const limitsSchema = z
  .object({
    version: z.literal(1),
    collectorBytes: uint64Schema,
    gatewayDiskBytes: uint64Schema,
  })
  .strict();

type Limits = z.infer<typeof limitsSchema>;

const DEFAULT_GATEWAY_DISK_BYTES = "4294967296";

const limitsPath = (config: GatewayConfig) =>
  join(config.stateDirectory, "confirmed-limits.json");

async function rememberedLimits(config: GatewayConfig): Promise<Limits | null> {
  try {
    return await readJson(limitsPath(config), limitsSchema);
  } catch (error) {
    if (hasErrorCode(error, "ENOENT")) return null;
    throw error;
  }
}

// The DNS index is built once per confirmed policy, so admission does not scan the policy.
function confirmedPolicy(policy: Policy, hash: string) {
  return { policy, hash, index: new DnsRuleIndex(policy) };
}

interface Dependencies {
  request: typeof enforcementRequest;
  persist: typeof atomicJson;
  removeIntent: (path: string) => Promise<void>;
  createBuffer: (config: GatewayConfig, budget: StorageBudget) => EventBuffer;
}

async function removeIntent(path: string): Promise<void> {
  try {
    await unlink(path);
  } catch (error) {
    if (!hasErrorCode(error, "ENOENT")) throw error;
  }

  const directory = await open(dirname(path), "r");

  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

export class GatewayPolicy {
  private tail: Promise<unknown> = Promise.resolve();
  private intent: Intent | null = null;
  private loaded = false;
  private confirmed: ReturnType<typeof confirmedPolicy> | null;
  private remembered: string | null = null;
  private allocation: string;
  private constructor(
    private config: GatewayConfig,
    private buffer: EventBuffer,
    private budget: StorageBudget,
    private dependencies: Dependencies,
    initial: Collection | null,
  ) {
    this.confirmed = initial
      ? confirmedPolicy(initial.policy, initial.receipt.policyHash)
      : null;
    this.allocation = config.collectorBytes;
  }
  static async open(
    config: GatewayConfig,
    overrides: Partial<Dependencies> = {},
  ) {
    const dependencies: Dependencies = {
      request: enforcementRequest,
      persist: atomicJson,
      removeIntent,
      createBuffer: (bufferConfig, budget) => {
        const writer = new CollectorWriter(budget);

        return new EventBuffer(
          bufferConfig,
          undefined,
          writer.writeJson,
          undefined,
          budget,
          writer,
        );
      },
      ...overrides,
    };

    let initial: Collection | null;

    try {
      initial = await dependencies.request(config.enforcementSocket, {
        operation: "collection",
      });
    } catch (error) {
      // Explicit policy failures permit management startup without claiming
      // confirmed ownership. Transport failures and malformed replies still stop it.
      if (
        !(error instanceof ServiceError) ||
        ![
          "not_initialized",
          "enforcement_restore_failed",
          "enforcement_unavailable",
          "policy_application_pending",
        ].includes(error.code)
      )
        throw error;
      initial = null;
    }

    const remembered = initial ? null : await rememberedLimits(config);

    const preparedConfig = {
      ...config,
      collectorBytes:
        initial?.policy.settings.collectorBytes ??
        remembered?.collectorBytes ??
        config.collectorBytes,
    };

    const budget = new StorageBudget(
      [
        config.stateDirectory,
        join(dirname(config.stateDirectory), "enforcement"),
        dirname(config.suricataFile),
      ],
      BigInt(
        initial?.policy.settings.gatewayDiskBytes ??
          remembered?.gatewayDiskBytes ??
          DEFAULT_GATEWAY_DISK_BYTES,
      ),
      GATEWAY_RESERVE,
    );

    const buffer = dependencies.createBuffer(preparedConfig, budget);

    try {
      await buffer.start();
    } catch (error) {
      await buffer.close();
      throw error;
    }

    const owner = new GatewayPolicy(
      preparedConfig,
      buffer,
      budget,
      dependencies,
      initial,
    );

    return { owner, buffer, budget };
  }
  // The confirmed policy and its index without a copy, for readers that only read them.
  confirmedView(): PolicyView | null {
    return this.confirmed;
  }
  // Decides DNS admission against the last enforcement-confirmed policy, so a lookup needs no enforcement
  // round trip. The enforcement service checks the policy again before it installs or releases an answer.
  // Returns null for a client that no instance covers.
  admitDns(clientIp: string, question: string): DnsAdmission | null {
    if (!this.confirmed)
      throw new ServiceError(
        503,
        "not_initialized",
        "No policy has been applied",
      );
    const { policy, hash, index } = this.confirmed;
    const context = index.context(clientIp);

    if (!context) return null;

    return {
      ...index.decide(context, question, Date.now()),
      instanceId: context.instanceId,
      revision: policy.revision,
      policyHash: hash,
    };
  }
  health(): Promise<Health> {
    return this.refresh("status");
  }
  collection(): Promise<Collection> {
    return this.refresh("collection");
  }
  private get path() {
    return join(this.config.stateDirectory, "policy-apply.json");
  }
  private serialize<T>(action: () => Promise<T>): Promise<T> {
    const result = this.tail.then(action);
    this.tail = result.catch(() => {});

    return result;
  }
  private async load() {
    if (this.loaded) return;

    try {
      this.intent = await readJson(this.path, intentSchema);
    } catch (error) {
      if (!hasErrorCode(error, "ENOENT")) throw error;
    }

    this.loaded = true;
  }
  private confirm(policy: Policy, hash: string): boolean {
    if (this.confirmed) {
      const previous = BigInt(this.confirmed.policy.revision),
        next = BigInt(policy.revision);

      if (next < previous) return false;

      if (next === previous && hash !== this.confirmed.hash)
        throw new ServiceError(
          502,
          "invalid_enforcement_response",
          "Enforcement service changed a confirmed policy identity",
        );

      // Routine refreshes report the policy already held; its copy and index stay.
      if (next === previous) return true;
    }

    this.confirmed = confirmedPolicy(policy, hash);
    // Native confirmation establishes the live quota even if local cleanup fails.
    this.budget.limit = BigInt(policy.settings.gatewayDiskBytes);

    return true;
  }
  private async rememberLimits(policy: Policy) {
    const limits: Limits = {
      version: 1,
      collectorBytes: policy.settings.collectorBytes,
      gatewayDiskBytes: policy.settings.gatewayDiskBytes,
    };

    const text = JSON.stringify(limits);

    if (text === this.remembered) return;
    await this.dependencies.persist(limitsPath(this.config), limits);
    this.remembered = text;
  }
  private async synchronize(state: Health | Collection) {
    await this.load();

    if (this.intent) {
      // A lost apply reply must not hide a later confirmed policy or its quota
      // while collector recovery or a repeated enforcement request still fails.
      if (
        state.policy.revision === this.intent.policy.revision &&
        state.receipt.policyHash === hashDocument(this.intent.policy)
      )
        this.confirm(state.policy, state.receipt.policyHash);

      await this.resume();
    }

    if (!this.confirm(state.policy, state.receipt.policyHash)) return;
    await this.rememberLimits(state.policy);

    if (this.allocation !== state.policy.settings.collectorBytes) {
      await this.buffer.allocation(state.policy.settings.collectorBytes);
      this.allocation = state.policy.settings.collectorBytes;
    }
  }
  private refresh(operation: "status"): Promise<Health>;
  private refresh(operation: "collection"): Promise<Collection>;
  private async refresh(
    operation: "status" | "collection",
  ): Promise<Health | Collection> {
    // Initial setup may have a saved application that must establish enforcement state.
    if (!this.confirmed) await this.recover();

    // Network waits do not hold the coordinator or collector mutation queues.
    const state =
      operation === "status"
        ? await this.dependencies.request(this.config.enforcementSocket, {
            operation: "status",
          })
        : await this.dependencies.request(this.config.enforcementSocket, {
            operation: "collection",
          });

    await this.serialize(() => this.synchronize(state));

    return state;
  }
  recover(): Promise<void> {
    return this.serialize(async () => {
      await this.load();

      if (this.intent) await this.resume();
    });
  }
  apply(policy: Policy): Promise<GatewayReceipt> {
    return this.serialize(async () => {
      await this.load();

      if (
        this.confirmed &&
        BigInt(policy.revision) < BigInt(this.confirmed.policy.revision)
      )
        throw new ServiceError(
          409,
          "stale_revision",
          "Policy revision is older than the applied revision",
        );

      if (
        this.confirmed &&
        policy.revision === this.confirmed.policy.revision &&
        hashDocument(policy) !== this.confirmed.hash
      )
        throw new ServiceError(
          409,
          "revision_conflict",
          "A revision cannot identify different policies",
        );

      if (this.intent) {
        const pendingRevision = BigInt(this.intent.policy.revision);

        if (BigInt(policy.revision) < pendingRevision)
          throw new ServiceError(
            409,
            "stale_revision",
            "Policy revision is older than the pending revision",
          );

        if (BigInt(policy.revision) === pendingRevision) {
          if (hashDocument(this.intent.policy) !== hashDocument(policy))
            throw new ServiceError(
              409,
              "revision_conflict",
              "A revision cannot identify different policies",
            );

          return this.resume();
        }
      }

      const budget = this.budgetFor(policy);
      // Include journal replacements, enforcement snapshots and collector checkpoints.
      budget.assertRoom(
        BigInt(Buffer.byteLength(JSON.stringify(policy))) * 8n + 2097152n,
        true,
      );
      const previousIntent = this.intent;
      this.intent = {
        version: 1,
        policy: policy,
        phase: "prepared",
        receipt: null,
      };

      try {
        return await this.resume();
      } catch (error) {
        // Failed preparation has not superseded the durable earlier obligation.
        if (!this.intent) this.intent = previousIntent;
        throw error;
      }
    });
  }
  private budgetFor(policy: Policy) {
    return new StorageBudget(
      this.budget.paths,
      BigInt(policy.settings.gatewayDiskBytes),
      this.budget.reserve,
    );
  }
  private async resume(): Promise<GatewayReceipt> {
    const intent = this.intent!;

    try {
      const receipt = await this.buffer.coordinateAllocation(
        intent.policy.settings.collectorBytes,
        async () => {
          if (intent.phase === "prepared") {
            const prepared = await this.dependencies.request(
              this.config.enforcementSocket,
              {
                operation: "prepare",
                policy: intent.policy,
              },
            );

            if (
              prepared.revision !== intent.policy.revision ||
              prepared.policyHash !== hashDocument(intent.policy)
            )
              throw new ServiceError(
                503,
                "policy_drift",
                "Gateway preparation receipt does not match the pending policy",
              );
            this.intent = { ...intent, phase: "native-started" };
          }

          await this.dependencies.persist(this.path, this.intent!);

          const receipt = await this.dependencies.request(
            this.config.enforcementSocket,
            {
              operation: "apply",
              policy: intent.policy,
            },
          );

          if (
            receipt.revision !== intent.policy.revision ||
            receipt.policyHash !== hashDocument(intent.policy)
          )
            throw new ServiceError(
              503,
              "policy_drift",
              "Gateway application receipt does not match the pending policy",
            );

          if (!this.confirm(intent.policy, receipt.policyHash))
            throw new ServiceError(
              503,
              "policy_drift",
              "Pending application precedes the enforcement service-confirmed policy",
            );
          this.intent = { ...intent, phase: "native-committed", receipt };
          await this.dependencies.persist(this.path, this.intent);
          await this.rememberLimits(intent.policy);

          return receipt;
        },
        this.budgetFor(intent.policy),
      );

      this.allocation = intent.policy.settings.collectorBytes;
      await this.dependencies.removeIntent(this.path);
      this.intent = null;

      return receipt;
    } catch (error) {
      if (this.intent?.phase === "prepared") this.intent = null;
      throw error;
    }
  }
}
