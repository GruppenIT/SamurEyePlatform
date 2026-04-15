/**
 * URL helpers shared across journey executors.
 */

export type WebScheme = "http" | "https";

/**
 * Build a canonical web-app URL.
 * Omits default ports (80 for http, 443 for https) so that URLs are deduplicated
 * across discovery and evaluation stages.
 *
 * @param host  FQDN or IP (without scheme or port)
 * @param port  Port number or string
 * @param scheme  "http" or "https"
 */
export function buildWebAppUrl(host: string, port: string | number, scheme: WebScheme): string {
  const portStr = String(port).replace(/\/(tcp|udp)$/i, "").trim();
  const isDefault =
    (scheme === "http" && portStr === "80") ||
    (scheme === "https" && portStr === "443");
  const suffix = isDefault ? "" : `:${portStr}`;
  return `${scheme}://${host}${suffix}`;
}

/**
 * Determine the scheme for a web service based on port + nmap service string.
 * Returns null if not a web service.
 */
export function detectWebScheme(port: string | number, service?: string): WebScheme | null {
  const portStr = String(port).replace(/\/(tcp|udp)$/i, "").trim();
  const svc = (service ?? "").toLowerCase();
  if (portStr === "443" || portStr === "8443" || svc.includes("https") || svc.includes("ssl")) return "https";
  const httpPorts = new Set(["80", "8080", "8000", "8888", "3000", "5000"]);
  const httpServiceNames = ["http", "http-alt", "http-proxy"];
  if (httpPorts.has(portStr) || httpServiceNames.some((n) => svc.includes(n))) return "http";
  return null;
}

/**
 * Validate and canonicalize a web target URL.
 * Returns a normalized URL string, or null if the input can't be parsed or
 * isn't an http/https URL.
 *
 * Canonicalization:
 *  - strips trailing slashes
 *  - removes default ports (80/443)
 *  - lowercases scheme and hostname
 */
export function normalizeTarget(value: string | null | undefined): string | null {
  if (!value) return null;
  try {
    const u = new URL(value.trim());
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    // Remove default ports
    const isDefault =
      (u.protocol === "http:" && u.port === "80") ||
      (u.protocol === "https:" && u.port === "443");
    if (isDefault) u.port = "";
    // Lowercase host (already done by URL), lowercase scheme (done by URL)
    // Strip trailing slash on root path only when there is no non-default port
    const hasNonDefaultPort = u.port !== "" &&
      !(u.protocol === "http:" && u.port === "80") &&
      !(u.protocol === "https:" && u.port === "443");
    let out = u.toString();
    if (!hasNonDefaultPort && out.endsWith("/") && u.pathname === "/") out = out.replace(/\/$/, "");
    return out;
  } catch {
    return null;
  }
}
