import { existsSync } from "fs";
import { spawn, spawnSync } from "child_process";

const TEMPLATES_DIR = "/tmp/nuclei/nuclei-templates";
let cached: PreflightResult | null = null;

export interface PreflightResult {
  ok: boolean;
  binaryAvailable: boolean;
  templatesAvailable: boolean;
  reason?: string;
}

/**
 * Verifies that `nuclei` binary is available and templates exist.
 * If templates are missing, attempts `nuclei -update-templates` with 5 min timeout.
 *
 * Memoized per-process — result is cached after first successful call.
 * Call `resetNucleiPreflight()` in tests to reset.
 */
export async function preflightNuclei(log: { info: (msg: string) => void; warn: (msg: string, ...rest: any[]) => void; error: (msg: string, ...rest: any[]) => void }): Promise<PreflightResult> {
  if (cached) return cached;

  // Check binary
  const whichRes = spawnSync("which", ["nuclei"], { encoding: "utf8" });
  const binaryAvailable = whichRes.status === 0 && whichRes.stdout.trim().length > 0;
  if (!binaryAvailable) {
    cached = { ok: false, binaryAvailable: false, templatesAvailable: false, reason: "nuclei binary not found on PATH" };
    log.error(`❌ nuclei binary not available on PATH — web scans will produce zero findings`);
    return cached;
  }

  // Check templates dir
  if (!existsSync(TEMPLATES_DIR)) {
    log.info(`ℹ️  nuclei templates directory missing at ${TEMPLATES_DIR} — attempting auto-update`);
    const updated = await runNucleiUpdate(log);
    if (!updated) {
      cached = { ok: false, binaryAvailable: true, templatesAvailable: false, reason: "template auto-update failed" };
      log.warn(`⚠️ nuclei template auto-update failed — web scans will produce zero findings until templates exist`);
      return cached;
    }
  }

  cached = { ok: true, binaryAvailable: true, templatesAvailable: existsSync(TEMPLATES_DIR) };
  log.info(`✅ nuclei preflight ok (templates at ${TEMPLATES_DIR})`);
  return cached;
}

function runNucleiUpdate(log: { info: (msg: string) => void; warn: (msg: string, ...rest: any[]) => void; error: (msg: string, ...rest: any[]) => void }): Promise<boolean> {
  return new Promise((resolve) => {
    const child = spawn("nuclei", ["-update-templates", "-silent"], {
      stdio: ["ignore", "ignore", "pipe"],
      env: {
        ...process.env,
        HOME: "/tmp/nuclei",
        NUCLEI_CONFIG_DIR: "/tmp/nuclei/.config",
        XDG_CONFIG_HOME: "/tmp/nuclei/.config",
        XDG_CACHE_HOME: "/tmp/nuclei/.cache",
        NUCLEI_TEMPLATES_DIR: TEMPLATES_DIR,
      },
    });
    let stderr = "";
    child.stderr?.on("data", (d) => (stderr += d.toString()));
    const t = setTimeout(() => {
      try { child.kill("SIGKILL"); } catch {}
      log.warn(`⚠️ nuclei -update-templates timed out after 5 min`);
      resolve(false);
    }, 5 * 60 * 1000);
    child.on("close", (code) => {
      clearTimeout(t);
      if (code === 0 && existsSync(TEMPLATES_DIR)) {
        resolve(true);
      } else {
        log.warn(`⚠️ nuclei -update-templates exit=${code} stderr=${stderr.slice(-500)}`);
        resolve(false);
      }
    });
    child.on("error", (err) => {
      clearTimeout(t);
      log.error(`❌ nuclei -update-templates failed to spawn: ${String(err)}`);
      resolve(false);
    });
  });
}

/** Test-only: reset the memoized result. */
export function resetNucleiPreflight(): void {
  cached = null;
}
