// Phase 11 ENRH-03 — Arjun hidden parameter discovery on user-selected GET endpoints.
// Output format is dict-keyed-by-URL (NOT array) per RESEARCH.md Pitfall 4.
// Validated via Zod schema. Tempfile cleanup via try/finally per Pitfall 9.
import { spawn } from 'child_process';
import { mkdtemp, readFile, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { z } from 'zod';
import { createLogger } from '../../../lib/logger';
import { preflightApiBinary } from './preflight';
import { processTracker } from '../../processTracker';

const log = createLogger('scanners:api:arjun');

const ARJUN_BIN = '/opt/samureye/venv-security/bin/arjun';
const DEFAULT_WORDLIST = '/opt/samureye/wordlists/arjun-extended-pt-en.txt';
const DEFAULT_TIMEOUT_MS = 60_000;

/**
 * Arjun JSON output is a dict keyed by URL, NOT an array. See RESEARCH.md Pitfall 4.
 * Source: arjun/core/exporter.py
 */
export const ArjunOutputSchema = z.record(z.string(), z.object({
  method: z.string(),
  params: z.array(z.string()),
  headers: z.record(z.string(), z.string()).optional(),
}));

export type ArjunOutput = z.infer<typeof ArjunOutputSchema>;

export interface ArjunOpts {
  wordlistPath?: string;
  timeoutMs?: number;
  threads?: number;       // -t (default 10)
  requestTimeout?: number; // -T (default 15)
}

export interface ArjunContext {
  jobId?: string;
  signal?: AbortSignal;
}

export interface ArjunResult {
  params: string[];
  skipped?: { reason: string };
}

export async function runArjun(url: string, opts: ArjunOpts, ctx: ArjunContext): Promise<ArjunResult> {
  const preflight = await preflightApiBinary('arjun', log);
  if (!preflight.ok) return { params: [], skipped: { reason: preflight.reason ?? 'arjun unavailable' } };

  const wordlist = opts.wordlistPath ?? DEFAULT_WORDLIST;
  const threads = opts.threads ?? 10;
  const requestTimeout = opts.requestTimeout ?? 15;

  // mkdtemp creates a fresh dir per run so cleanup removes both dir + file atomically
  const dir = await mkdtemp(join(tmpdir(), `api-discovery-${ctx.jobId ?? 'norun'}-`));
  const tempFile = join(dir, 'arjun.json');

  try {
    const args: string[] = [
      '-u', url,
      '-w', wordlist,
      '-oJ', tempFile,
      '-m', 'GET',
      '-t', String(threads),
      '-T', String(requestTimeout),
    ];

    const resolvedBin = preflight.resolvedPath ?? ARJUN_BIN;
    const outcome = await spawnArjun(resolvedBin, args, {
      jobId: ctx.jobId,
      signal: ctx.signal,
      timeoutMs: opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    });

    // Arjun may have been killed before writing → file absent. Read may throw; swallow.
    let raw: string;
    try {
      raw = await readFile(tempFile, 'utf8');
    } catch (err) {
      log.warn({ err: String(err), url, stderrTail: outcome.stderr.slice(-200) }, 'arjun output file missing');
      return { params: [] };
    }

    if (!raw.trim()) return { params: [] };

    let parsed: ArjunOutput;
    try {
      const json = JSON.parse(raw);
      parsed = ArjunOutputSchema.parse(json);
    } catch (err) {
      log.warn({ err: String(err), url }, 'arjun output parse/validation failed');
      return { params: [] };
    }

    const entry = parsed[url] ?? Object.values(parsed)[0];
    const params = entry?.params ?? [];
    log.info({ url, paramCount: params.length }, 'arjun parameter discovery complete');
    return { params };
  } finally {
    await rm(dir, { recursive: true, force: true }).catch((err) => {
      log.warn({ err: String(err), dir }, 'failed to clean arjun tempdir');
    });
  }
}

interface SpawnOutcome { stdout: string; stderr: string; code: number | null; }

function spawnArjun(
  bin: string,
  args: string[],
  ctx: { jobId?: string; signal?: AbortSignal; timeoutMs: number },
): Promise<SpawnOutcome> {
  return new Promise((resolve) => {
    const child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    if (!child.pid) return resolve({ stdout, stderr: 'spawn failed: no PID', code: -1 });

    if (ctx.jobId) {
      try { processTracker.register(ctx.jobId, 'arjun', child, 'api-discovery:arjun'); } catch (e) {
        log.warn({ err: String(e) }, 'failed to register arjun with processTracker');
      }
    }

    child.stdout?.on('data', (d) => { stdout += d.toString(); });
    child.stderr?.on('data', (d) => { stderr += d.toString(); });

    const timer = setTimeout(() => {
      log.warn({ timeoutMs: ctx.timeoutMs }, 'arjun timeout — killing process');
      if (ctx.jobId && child.pid) processTracker.kill(ctx.jobId, child.pid);
      else { child.kill('SIGTERM'); setTimeout(() => child.kill('SIGKILL'), 5000); }
    }, ctx.timeoutMs);

    const onAbort = () => {
      log.info({}, 'arjun aborted via AbortSignal');
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
