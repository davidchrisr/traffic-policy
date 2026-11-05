import { StringDecoder } from "node:string_decoder";
import { MAX_MACHINE_FRAME_BYTES } from "@traffic-policy/contracts";

export class CommandFrame {
  private decoder = new StringDecoder("utf8");
  private receivedBytes = 0;
  private text = "";
  constructor(private readonly receive: (bytes: number) => void = () => {}) {}
  // oxlint-disable-next-line anti-slop/no-unknown-parameters -- JSON frames remain untrusted until their operation/envelope schema validates them.
  write(chunk: Buffer, accept: (value: unknown, bytes: number) => void) {
    let offset = 0;

    while (offset < chunk.length) {
      const newline = chunk.indexOf(10, offset);
      const end = newline < 0 ? chunk.length : newline + 1;
      const part = chunk.subarray(offset, end);

      if (this.receivedBytes + part.length > MAX_MACHINE_FRAME_BYTES)
        throw new Error("Enforcement frame exceeds its limit");
      this.receive(part.length);
      this.receivedBytes += part.length;
      this.text += this.decoder.write(part);
      offset = end;

      if (newline < 0) continue;
      const text = this.text + this.decoder.end();
      const bytes = this.receivedBytes;
      this.decoder = new StringDecoder("utf8");
      this.text = "";
      this.receivedBytes = 0;
      accept(JSON.parse(text), bytes);
    }
  }
  end(): void {
    if (this.receivedBytes)
      throw new Error("Enforcement connection ended before its complete frame");
  }
}
