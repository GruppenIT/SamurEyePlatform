// Phase 11 ENRH-01 + ENRH-02 — httpx wrapper for status/tech/TLS probing + tri-valor requiresAuth.
// Batching strategy: URLs fed via stdin (one per line); httpx streams JSON lines back.
// Tri-valor mapping (Pitfall 8): 401/403→true, 2xx/3xx→false, else→null.
import { spawn } from 'child_process';
import { createLogger } from '../../../lib/logger';
import { preflightApiBinary } from './preflight';
import { processTracker } from '../../processTracker';

const log = createLogger('scanners:api:httpx');

const HTTPX_BIN = '/opt/samureye/bin/httpx';
const DEFAULT_TIMEOUT_MS = 30_000;

export interface HttpxOpts {
  authHeader?: string;  // 'Bearer <jwt>' / 'Basic <b64>' / '<headerName>: <val>'
  timeoutMs?: number;
  rateLimit?: number;  // -rl flag; default 50 (Phase 15 enforces global ceiling)
}

export interface HttpxContext {
  jobId?: string;
  signal?: AbortSignal;
}

export interface HttpxTls {
  host?: string;
  port?: number;
  tls_version?: string;
  cipher?: string;
  not_after?: string;
  not_before?: string;
  subject_cn?: string;
  subject_san?: string[];
  issuer_cn?: string;
}

export interface HttpxEnrichment {
  url: string;
  inputUrl: string;
  status: number | null;
  contentType: string | null;
  tech: string[];
  tls: HttpxTls | null;
  requiresAuth: boolean | null;
}

export interface HttpxResult {
  results: HttpxEnrichment[];
  skipped?: { reason: string };
}

/**
 * Phase 11 ENRH-02 — tri-valor mapping (see Pitfall 8).
 * 401/403 → true (auth required)
 * 200/201/204/3xx → false (open)
 * everything else (400, 404, 5xx, 0/timeout, null/undefined) → null (unknown)
 */
export function mapRequiresAuth(status: number | null | undefined): boolean | null {
  if (status === 401 || status === 403) return true;
  if (status === 200 || status === 201 || status === 204) return false;
  if (typeof status === 'number' && status >= 300 && status < 400) return false;
  return null;
}

export async function runHttpx(urls: string[], opts: HttpxOpts, ctx: HttpxContext): Promise<HttpxResult> {
  if (urls.length === 0) return { results: [] };
  const preflight = await preflightApiBinary('httpx', log);
  if (!preflight.ok) return { results: [], skipped: { reason: preflight.reason ?? 'httpx unavailable' } };

  const rateLimit = opts.rateLimit ?? 50;
  const args: string[] = ['-json', '-silent', '-sc', '-ct', '-td', '-tls-grab', '-timeout', '10', '-rl', String(rateLimit)];
  if (opts.authHeader) {
    const header = opts.authHeader.startsWith('Authorization:')
      ? opts.authHeader
      : `Authorization: ${opts.authHeader}`;
    args.push('-H', header);
  }

  const resolvedBin = preflight.resolvedPath ?? HTTPX_BIN;
  const outcome = await spawnHttpx(resolvedBin, args, urls, {
    jobId: ctx.jobId,
    signal: ctx.signal,
    timeoutMs: opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
  });

  const results = parseHttpxJsonl(outcome.stdout);
  log.info({ urlCount: urls.length, resultCount: results.length, stderrTail: outcome.stderr.slice(-200) }, 'httpx probe complete');
  return { results };
}

interface SpawnOutcome { stdout: string; stderr: string; code: number | null; }

function spawnHttpx(
  bin: string,
  args: string[],
  urls: string[],
  ctx: { jobId?: string; signal?: AbortSignal; timeoutMs: number },
): Promise<SpawnOutcome> {
  return new Promise((resolve) => {
    const child = spawn(bin, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    if (!child.pid) return resolve({ stdout, stderr: 'spawn failed: no PID', code: -1 });

    if (ctx.jobId) {
      try { processTracker.register(ctx.jobId, 'httpx', child, 'api-discovery:httpx'); } catch (e) {
        log.warn({ err: String(e) }, 'failed to register httpx with processTracker');
      }
    }

    // Feed URLs to stdin
    child.stdin?.write(urls.join('\n') + '\n');
    child.stdin?.end();

    child.stdout?.on('data', (d) => { stdout += d.toString(); });
    child.stderr?.on('data', (d) => { stderr += d.toString(); });

    const timer = setTimeout(() => {
      log.warn({ timeoutMs: ctx.timeoutMs }, 'httpx timeout — killing process');
      if (ctx.jobId && child.pid) processTracker.kill(ctx.jobId, child.pid);
      else { child.kill('SIGTERM'); setTimeout(() => child.kill('SIGKILL'), 5000); }
    }, ctx.timeoutMs);

    const onAbort = () => {
      log.info({}, 'httpx aborted via AbortSignal');
      if (ctx.jobId && child.pid) processTracker.kill(ctx.jobId, child.pid);
      else { child.kill('SIGTERM'); setTimeout(() => child.kill('SIGKILL'), 5000); }
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

function parseHttpxJsonl(stdout: string): HttpxEnrichment[] {
  const results: HttpxEnrichment[] = [];
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const raw = JSON.parse(trimmed) as {
        url?: string;
        input?: string;
        status_code?: number;
        content_type?: string;
        tech?: string[];
        tls?: HttpxTls;
      };
      const url = raw.url ?? raw.input ?? '';
      if (!url) continue;
      const status = typeof raw.status_code === 'number' ? raw.status_code : null;
      results.push({
        url,
        inputUrl: raw.input ?? url,
        status,
        contentType: raw.content_type ?? null,
        tech: Array.isArray(raw.tech) ? raw.tech : [],
        tls: raw.tls ?? null,
        requiresAuth: mapRequiresAuth(status),
      });
    } catch {
      // skip partial/garbage lines
    }
  }
  return results;
}
