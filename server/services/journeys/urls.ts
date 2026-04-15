/**
 * URL helpers shared across journey executors.
 *
 * Policy: web_application URLs ALWAYS include the port, even the defaults
 * (80 for http, 443 for https). Rationale: SamurEye catalogs each listening
 * socket as a distinct asset, so explicit ports avoid ambiguity when a host
 * exposes the same scheme on multiple ports.
 */

export type WebScheme = "http" | "https";

function defaultPortFor(scheme: WebScheme): string {
  return scheme === "https" ? "443" : "80";
}

/**
 * Build a canonical web-app URL. Always includes the port.
 *
 * @param host  FQDN or IP (without scheme or port)
 * @param port  Port number or string
 * @param scheme  "http" or "https"
 */
export function buildWebAppUrl(host: string, port: string | number, scheme: WebScheme): string {
  const portStr = String(port).replace(/\/(tcp|udp)$/i, "").trim() || defaultPortFor(scheme);
  return `${scheme}://${host}:${portStr}`;
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
 * Validate and canonicalize a web target URL. Always emits an explicit port.
 * Returns null if the input can't be parsed or isn't an http/https URL.
 *
 * Canonicalization:
 *  - adds the default port (80/443) if missing, based on scheme
 *  - strips trailing slash on the root path
 *  - lowercases scheme and hostname (done by URL)
 */
export function normalizeTarget(value: string | null | undefined): string | null {
  if (!value) return null;
  try {
    const u = new URL(value.trim());
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    // Node's URL parser auto-strips default ports from `u.port`. We want them
    // explicit, so always reassemble the URL string manually instead of using
    // u.toString().
    const scheme = u.protocol === "https:" ? "https" : "http";
    const port = u.port || defaultPortFor(scheme);
    const pathAndQuery = u.pathname === "/" && !u.search && !u.hash ? "" : `${u.pathname}${u.search}${u.hash}`;
    return `${scheme}://${u.hostname}:${port}${pathAndQuery}`;
  } catch {
    return null;
  }
}
