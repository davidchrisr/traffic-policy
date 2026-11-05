import { domainToASCII } from "node:url";
import { isIP } from "node:net";
import { publicSuffixData } from "./public-suffix-data.ts";

const exact = new Set<string>(),
  wildcard = new Set<string>(),
  exception = new Set<string>();

for (const row of publicSuffixData.split("\n")) {
  const rule = row.trim();

  if (!rule || rule.startsWith("//")) continue;

  const kind = rule.startsWith("!")
    ? exception
    : rule.startsWith("*.")
      ? wildcard
      : exact;

  kind.add(domainToASCII(rule.replace(/^!|^\*\./, "")).toLowerCase());
}

export function registrableDomain(name: string): string | null {
  const host = domainToASCII(name.replace(/\.$/, "")).toLowerCase();

  if (!host || isIP(host)) return null;
  const labels = host.split(".");
  let suffix = 1;

  for (let i = 0; i < labels.length; i++) {
    const candidate = labels.slice(i).join(".");

    if (exception.has(candidate)) return labels.slice(i).join(".");

    if (exact.has(candidate)) suffix = Math.max(suffix, labels.length - i);

    if (i > 0 && wildcard.has(candidate))
      suffix = Math.max(suffix, labels.length - i + 1);
  }

  return labels.length > suffix ? labels.slice(-suffix - 1).join(".") : null;
}
