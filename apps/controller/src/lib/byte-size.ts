const decimal = ["B", "KB", "MB", "GB", "TB", "PB", "EB"];

const binary = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];

const multipliers = new Map<string, bigint>([
  ...decimal.map((unit, index): [string, bigint] => [
    unit.toLowerCase(),
    1000n ** BigInt(index),
  ]),
  ...binary.map((unit, index): [string, bigint] => [
    unit.toLowerCase(),
    1024n ** BigInt(index),
  ]),
]);

const uint64Max = 18446744073709551615n;

export type ByteSize = { bytes: string } | { error: string };

// Reads "4 GiB", "500MB", or a bare byte count. GB is 1000³ bytes and GiB is 1024³; a bare K, M,
// or G names neither, so it is rejected instead of guessed.
export function parseByteSize(text: string): ByteSize {
  const match = /^(\d+)(?:\.(\d+))?\s*([a-z]*)$/iu.exec(text.trim());

  if (!match)
    return { error: "Enter a size such as 4 GiB, 500 MB, or 1048576." };
  const [, whole = "", fraction = "", unit = ""] = match;
  const multiplier = unit ? multipliers.get(unit.toLowerCase()) : 1n;

  if (multiplier === undefined)
    return /^[kmgtpe]$/iu.test(unit)
      ? { error: `Use ${unit.toUpperCase()}B or ${unit.toUpperCase()}iB.` }
      : { error: "Use B, KB, MB, GB, TB, KiB, MiB, GiB, or TiB." };

  const scale = 10n ** BigInt(fraction.length);
  const scaled = BigInt(whole + fraction) * multiplier;

  if (scaled % scale)
    return { error: "The size must be a whole number of bytes." };
  const bytes = scaled / scale;

  return bytes > uint64Max
    ? { error: "The size is too large." }
    : { bytes: String(bytes) };
}

function exact(bytes: bigint, base: bigint, units: string[]): string {
  let index = 0,
    value = bytes;

  while (value && value % base === 0n && index < units.length - 1) {
    value /= base;
    index++;
  }

  return `${value} ${units[index]}`;
}

// The shortest exact form, preferring binary units when both are as short.
export function formatByteSize(raw: string): string {
  const bytes = BigInt(raw);
  const inBinary = exact(bytes, 1024n, binary);
  const inDecimal = exact(bytes, 1000n, decimal);

  return inDecimal.length < inBinary.length ? inDecimal : inBinary;
}
