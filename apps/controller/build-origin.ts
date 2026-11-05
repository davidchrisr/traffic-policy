export function requireBuildOrigin(value: string | undefined): string {
  if (!value)
    throw new Error("TP_PUBLIC_ORIGIN is required for production builds");
  let origin: URL;

  try {
    origin = new URL(value);
  } catch {
    throw new Error(
      "TP_PUBLIC_ORIGIN must be a canonical HTTP or HTTPS origin",
    );
  }

  if (!["http:", "https:"].includes(origin.protocol) || origin.origin !== value)
    throw new Error(
      "TP_PUBLIC_ORIGIN must be an HTTP or HTTPS origin without a path, credentials, query, fragment or whitespace",
    );

  return value;
}
