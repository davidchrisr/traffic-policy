import { StringDecoder } from "node:string_decoder";
import {
  canonicalIp,
  MAX_MACHINE_FRAME_BYTES,
  ScopeTree,
} from "@traffic-policy/contracts";
import { ServiceError } from "@traffic-policy/core/io";

/** Streams the conntrack CLI document, retaining managed endpoint identities. */
export class ManagedConnections {
  private readonly decoder = new StringDecoder("utf8");
  private pending = "";
  private started = false;
  private ended = false;
  private bytes = 0;
  private readonly instances: ScopeTree;

  constructor(
    instances: readonly { id: string; addresses: readonly string[] }[],
    private readonly maxBytes = MAX_MACHINE_FRAME_BYTES,
  ) {
    this.instances = new ScopeTree(instances);
  }

  private select(value: string): string {
    const line = value.trim();

    if (!line) return "";

    if (!this.started && /^<\?xml\b.*\?>$/.test(line)) return "";

    if (!this.started && line === "<conntrack>") {
      this.started = true;

      return "<conntrack>\n";
    }

    if (this.started && !this.ended && line === "</conntrack>") {
      this.ended = true;

      return "</conntrack>\n";
    }

    if (
      !this.started ||
      this.ended ||
      !/^<flow(?:\s|>)/.test(line) ||
      !line.endsWith("</flow>")
    )
      throw Error("Connection snapshot framing is invalid");

    const sources = [
      ...line.matchAll(
        /<meta direction="(?:original|reply)">([\s\S]*?)<\/meta>/g,
      ),
    ].map((match) => {
      const address = /<layer3\b[^>]*>[\s\S]*?<src>([^<]+)<\/src>/.exec(
        match[1]!,
      );

      if (!address)
        throw new Error("Connection snapshot tuple identity is incomplete");

      return canonicalIp(address[1]!);
    });

    if (sources.length !== 2)
      throw Error("Connection snapshot tuple identity is incomplete");

    if (!sources.some((address) => this.instances.find(address))) return "";

    return line + "\n";
  }

  private line(value: string): string {
    const selected = this.select(value);
    this.bytes += Buffer.byteLength(JSON.stringify(selected)) - 2;

    if (this.bytes > this.maxBytes)
      throw new ServiceError(
        503,
        "connection_snapshot_capacity",
        "Managed connection snapshot exceeds its transport allocation",
      );

    return selected;
  }

  write(bytes: Buffer): Buffer {
    this.pending += this.decoder.write(bytes);
    const output: string[] = [];

    for (;;) {
      const end = this.pending.indexOf("\n");

      if (end < 0) break;
      output.push(this.line(this.pending.slice(0, end)));
      this.pending = this.pending.slice(end + 1);
    }

    if (Buffer.byteLength(this.pending) > MAX_MACHINE_FRAME_BYTES)
      throw Error("Connection record exceeds its framing limit");

    return Buffer.from(output.join(""));
  }

  end(): Buffer {
    this.pending += this.decoder.end();
    const tail = this.line(this.pending);
    this.pending = "";

    if (!this.started || !this.ended)
      throw Error("Connection snapshot ended before its complete document");

    return Buffer.from(tail);
  }
}
