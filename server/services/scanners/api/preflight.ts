// Phase 11 — Shared memoized preflight for Katana, httpx, Kiterunner, Arjun.
// Mirrors server/services/journeys/nucleiPreflight.ts pattern (cached per-process).
// Missing binary does NOT abort the pipeline — orchestrator skips the stage and logs.
import { spawnSync } from 'child_process';
import { existsSync } from 'fs';

export type ApiBinaryName = 'katana' | 'httpx' | 'kiterunner' | 'arjun';

export interface PreflightResult {
  ok: boolean;
  reason?: string;
  resolvedPath?: string;
}

const cached = new Map<ApiBinaryName, PreflightResult>();

// Absolute paths (Phase 8 install.sh targets). Falling back to PATH for dev environments.
const INSTALL_PATHS: Record<ApiBinaryName, string[]> = {
  katana:     ['/opt/samureye/bin/katana', 'katana'],
  httpx:      ['/opt/samureye/bin/httpx', 'httpx'],
  kiterunner: ['/opt/samureye/bin/kiterunner', 'kr', 'kiterunner'],  // archive binary is 'kr'
  arjun:      ['/opt/samureye/venv-security/bin/arjun'],              // venv only, never on PATH
};

export interface PreflightLogger {
  info: (msg: string) => void;
  error: (msg: string) => void;
}

export async function preflightApiBinary(name: ApiBinaryName, log: PreflightLogger): Promise<PreflightResult> {
  const hit = cached.get(name);
  if (hit) return hit;

  for (const candidate of INSTALL_PATHS[name]) {
    // Absolute path → existsSync check.
    if (candidate.startsWith('/')) {
      if (existsSync(candidate)) {
        const result: PreflightResult = { ok: true, resolvedPath: candidate };
        cached.set(name, result);
        log.info(`✅ ${name} preflight ok (${candidate})`);
        return result;
      }
      continue;
    }
    // Relative name → delegate to `which`.
    const res = spawnSync('which', [candidate], { encoding: 'utf8' });
    if (res.status === 0 && res.stdout.trim().length > 0) {
      const result: PreflightResult = { ok: true, resolvedPath: res.stdout.trim() };
      cached.set(name, result);
      log.info(`✅ ${name} preflight ok (${res.stdout.trim()})`);
      return result;
    }
  }

  const result: PreflightResult = {
    ok: false,
    reason: `${name} binary not available on PATH`,
  };
  cached.set(name, result);
  log.error(`❌ ${name} binary not available — stage will be skipped`);
  return result;
}

/** Test-only: reset the memoized results. */
export function resetApiBinaryPreflight(): void {
  cached.clear();
}
