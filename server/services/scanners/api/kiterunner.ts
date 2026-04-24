// Phase 11 DISC-05 — opt-in brute-force API route discovery.
// NOTE: -x is max-connection-per-host (NOT QPS) per RESEARCH.md Pitfall 3.
// Real QPS ceiling enforced by Phase 15 SAFE-01 governor, not here.
// Flags: -o json, explicit success/fail status codes so 401/403 count as hits.
import { spawn } from 'child_process';
import type { InsertApiEndpoint } from '@shared/schema';
import { createLogger } from '../../../lib/logger';
import { preflightApiBinary } from './preflight';
import { processTracker } from '../../processTracker';

const log = createLogger('scanners:api:kiterunner');

const KITERUNNER_WORDLIST = '/opt/samureye/wordlists/routes-large.kite';
const DEFAULT_TIMEOUT_MS = 300_000;
const DEFAULT_MAX_CONN_PER_HOST = 5;
const DEFAULT_MAX_PARALLEL_HOSTS = 100;
const SUCCESS_STATUSES = [200, 201, 204, 301, 302, 401, 403];

export interface KiterunnerOpts {
  /** -x connections-per-host (per CONTEXT.md — SAFE-01 global governor applies separately in Phase 15) */
  rateLimit?: number;
  wordlistPath?: string;
  timeoutMs?: number;
}

export interface KiterunnerContext {
  jobId?: string;
  apiId: string;
  signal?: AbortSignal;
}

export interface KiterunnerResult {
  endpoints: InsertApiEndpoint[];
  skipped?: { reason: string };
}

export async function runKiterunner(
  target: string,
  opts: KiterunnerOpts,
  ctx: KiterunnerContext,
): Promise<KiterunnerResult> {
  const preflight = await preflightApiBinary('kiterunner', log);
  if (!preflight.ok) {
    return { endpoints: [], skipped: { reason: `kiterunner binary not available: ${preflight.reason ?? 'kiterunner unavailable'}` } };
  }

  const wordlist = opts.wordlistPath ?? KITERUNNER_WORDLIST;
  const connPerHost = opts.rateLimit ?? DEFAULT_MAX_CONN_PER_HOST;

  const args: string[] = [
    'scan', target,
    '-w', wordlist,
    '-o', 'json',
    '-x', String(connPerHost),
    '-j', String(DEFAULT_MAX_PARALLEL_HOSTS),
    '--success-status-codes', SUCCESS_STATUSES.join(','),
    '--fail-status-codes', '404,501,502,400',
  ];

  const resolvedBin = preflight.resolvedPath ?? 'kr';
  const result = await spawnKiterunner(resolvedBin, args, {
    jobId: ctx.jobId,
    signal: ctx.signal,
    timeoutMs: opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
  });

  const endpoints = parseKiterunnerJsonl(result.stdout, ctx.apiId);
  log.info(
    { target, endpointCount: endpoints.length, connPerHost, stderrTail: result.stderr.slice(-200) },
    'kiterunner brute-force complete',
  );
  return { endpoints };
}

interface SpawnOutcome { stdout: string; stderr: string; code: number | null; }

function spawnKiterunner(
  bin: string,
  args: string[],
  ctx: { jobId?: string; signal?: AbortSignal; timeoutMs: number },
): Promise<SpawnOutcome> {
  return new Promise((resolve) => {
    const child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';

    if (!child.pid) {
      return resolve({ stdout, stderr: 'spawn failed: no PID', code: -1 });
    }

    if (ctx.jobId) {
      try {
        processTracker.register(ctx.jobId, 'kiterunner', child, 'api-discovery:kiterunner');
      } catch (e) {
        log.warn({ err: String(e) }, 'failed to register kiterunner with processTracker');
      }
    }

    child.stdout?.on('data', (d) => { stdout += d.toString(); });
    child.stderr?.on('data', (d) => { stderr += d.toString(); });

    const timer = setTimeout(() => {
      log.warn({ timeoutMs: ctx.timeoutMs }, 'kiterunner timeout — killing process');
      if (ctx.jobId && child.pid) {
        processTracker.kill(ctx.jobId, child.pid);
      } else {
        child.kill('SIGTERM');
        setTimeout(() => child.kill('SIGKILL'), 5000);
      }
    }, ctx.timeoutMs);

    const onAbort = () => {
      log.info({}, 'kiterunner aborted via AbortSignal');
      if (ctx.jobId && child.pid) {
        processTracker.kill(ctx.jobId, child.pid);
      } else {
        child.kill('SIGTERM');
        setTimeout(() => child.kill('SIGKILL'), 5000);
      }
    };
    ctx.signal?.addEventListener('abort', onAbort, { once: true });

    child.on('close', (code) => {
      clearTimeout(timer);
      ctx.signal?.removeEventListener('abort', onAbort);
      resolve({ stdout, stderr, code });
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      stderr += `spawn error: ${String(err)}\n`;
      resolve({ stdout, stderr, code: -1 });
    });
  });
}

function parseKiterunnerJsonl(stdout: string, apiId: string): InsertApiEndpoint[] {
  const endpoints: InsertApiEndpoint[] = [];
  const seen = new Set<string>();

  for (const line of stdout.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const entry = JSON.parse(trimmed) as { method?: string; path?: string; status_code?: number };
      if (!entry.path) continue;
      if (entry.status_code !== undefined && !SUCCESS_STATUSES.includes(entry.status_code)) continue;
      const method = (entry.method ?? 'GET').toUpperCase();
      const key = `${method}:${entry.path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      endpoints.push({
        apiId,
        method,
        path: entry.path,
        pathParams: [],
        queryParams: [],
        headerParams: [],
        discoverySources: ['kiterunner'],
      });
    } catch {
      // partial line / non-JSON stderr mix — skip
    }
  }
  return endpoints;
}
