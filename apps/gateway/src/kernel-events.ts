import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { StringDecoder } from "node:string_decoder";
import { parseConnections } from "./connections.ts";
import type { ObservedInstance } from "@traffic-policy/contracts/enforcement";
import type { ManagedInstanceView } from "./policy-enforcer-state.ts";

export interface KernelEvent {
  id: string;
  sequence: string;
  observedAt: string;
  kind: "new" | "destroy" | "trace" | "gap";
  record: string;
  instances: ObservedInstance[];
}

export class KernelEvents {
  readonly epoch = randomUUID();
  private sequence = 0n;
  private retained: KernelEvent[] = [];
  private children: ChildProcess[] = [];
  private bytes = 0;
  private stopped = false;
  private restarts = new Set<ReturnType<typeof setTimeout>>();
  private tracePackets = new Map<
    string,
    { packet: string; latest: string; at: number; original: boolean }
  >();
  // Streams that are currently stopped, by binary.
  private outages = new Map<string, string>();
  constructor(
    private owners: (
      addresses: readonly string[],
    ) => readonly ManagedInstanceView[],
  ) {}
  private record(
    kind: KernelEvent["kind"],
    record: string,
    instances: readonly ManagedInstanceView[] = [],
  ) {
    const event = {
      id: randomUUID(),
      sequence: (++this.sequence).toString(),
      observedAt: new Date().toISOString(),
      kind,
      record,
      instances: instances.map((instance) => ({
        ...instance,
        addresses: [...instance.addresses],
      })),
    };

    const bytes = Buffer.byteLength(JSON.stringify(event));
    this.retained.push(event);
    this.bytes += bytes;

    while (this.retained.length > 4096 || this.bytes > 4 * 1024 * 1024) {
      const oldest = this.retained.shift()!;
      this.bytes -= Buffer.byteLength(JSON.stringify(oldest));
    }
  }
  private watch(
    binary: string,
    args: string[],
    line: (record: string) => void,
    delay = 1000,
  ) {
    const child = spawn(binary, args, { stdio: ["ignore", "pipe", "pipe"] });
    const decoder = new StringDecoder("utf8");
    this.children.push(child);
    let pending = "";
    let restarting = false;

    // A stream that stops loses records until its replacement starts.
    const restart = (reason: string) => {
      if (this.stopped || restarting) return;
      restarting = true;
      this.record("gap", reason);
      this.outages.set(binary, reason);
      this.children = this.children.filter((value) => value !== child);

      const timer = setTimeout(() => {
        this.restarts.delete(timer);
        this.watch(binary, args, line, Math.min(delay * 2, 30000));
      }, delay);

      timer.unref();
      this.restarts.add(timer);
    };

    child.on("spawn", () => this.outages.delete(binary));
    child.stdout?.on("data", (bytes: Buffer) => {
      this.outages.delete(binary);
      pending += decoder.write(bytes);

      if (Buffer.byteLength(pending) > 256 * 1024) {
        pending = "";
        this.record("gap", "Kernel observation exceeded its framing limit");

        return;
      }

      for (;;) {
        const newline = pending.indexOf("\n");

        if (newline < 0) break;
        const record = pending.slice(0, newline);
        pending = pending.slice(newline + 1);

        try {
          line(record);
        } catch {
          this.record("gap", "Kernel observation could not be decoded");
        }
      }
    });
    // Warnings such as conntrack's ENOBUFS report dropped records; the stream
    // continues, so they are a gap rather than a lasting condition.
    child.stderr?.on("data", (bytes: Buffer) => {
      const diagnostic = bytes.toString().slice(0, 1024).trim();

      if (diagnostic.startsWith("NOTICE:")) return;
      this.record("gap", diagnostic);
      console.error(
        JSON.stringify({
          service: "enforcement",
          step: "kernel-events",
          source: binary,
          error: diagnostic,
        }),
      );
    });
    child.on("error", (error) => restart(error.message));
    child.on("close", () => restart("Kernel observation stream stopped"));
  }
  start() {
    this.watch(
      "/usr/sbin/conntrack",
      ["-E", "-e", "NEW,DESTROY", "-o", "xml", "-b", "1048576"],
      (record) => {
        const kind = record.match(/^<flow type="(new|destroy)"/);

        if (!kind) return;

        const connection = parseConnections(
          `<conntrack>${record}</conntrack>`,
        )[0];

        if (!connection) return;

        const instances = this.owners([
          connection.flow.initiatorIp,
          connection.flow.responderIp,
        ]);

        if (instances.length)
          this.record(kind[1] === "new" ? "new" : "destroy", record, instances);
      },
    );
    this.watch("/usr/sbin/nft", ["-n", "monitor", "trace"], (record) => {
      const match = record.match(
        /^trace id ([a-f0-9]+) inet traffic_policy (\S+) (.*)$/,
      );

      if (!match) return;
      const [, id, chain, body] = match;
      const now = Date.now();

      for (const [key, value] of this.tracePackets)
        if (now - value.at > 2000) this.tracePackets.delete(key);

      if (body!.startsWith("packet:") && !this.tracePackets.has(id!)) {
        this.tracePackets.set(id!, {
          packet: body!,
          latest: body!,
          at: now,
          // Unregistered drops start their own traces: no ingress trace marks their packets.
          original: chain === "trace_ingress" || /^u_[cu]$/.test(chain!),
        });

        if (this.tracePackets.size > 2048)
          this.tracePackets.delete(this.tracePackets.keys().next().value!);
      }

      if (body!.startsWith("packet:") && this.tracePackets.has(id!))
        this.tracePackets.get(id!)!.latest = body!;

      if (
        /^(?:b[46]_[oi]_[a-f0-9]{32}_[a-f0-9]{32}_[0-9]+_[ct]|u_[cu])$/.test(
          chain!,
        ) &&
        body!.includes("(verdict drop)")
      ) {
        const packet = this.tracePackets.get(id!);
        this.tracePackets.delete(id!);

        if (packet?.original)
          this.record(
            "trace",
            `trace id ${id} inet traffic_policy ${chain} ${packet.packet}\ntranslated:${packet.latest}`,
          );
      }
    });
  }
  read(epoch: string | null, after: string) {
    const reset = epoch !== this.epoch;
    const cursor = reset ? 0n : BigInt(after);
    const first = this.retained[0];
    let bytes = 0;

    const events = this.retained
      .filter((event) => BigInt(event.sequence) > cursor)
      .slice(0, 128)
      .filter((event) => {
        bytes += Buffer.byteLength(JSON.stringify(event));

        return bytes <= 1024 * 1024;
      });

    const result = {
      epoch: this.epoch,
      sequence: events.at(-1)?.sequence ?? (reset ? "0" : after),
      events,
      reset,
      gap:
        events.some((event) => event.kind === "gap") ||
        (!!first && cursor < BigInt(first.sequence) - 1n),
      condition: this.outages.values().next().value ?? null,
    };

    return result;
  }
  close() {
    this.stopped = true;

    for (const timer of this.restarts) clearTimeout(timer);
    this.restarts.clear();

    for (const child of this.children) child.kill("SIGTERM");
  }
}
