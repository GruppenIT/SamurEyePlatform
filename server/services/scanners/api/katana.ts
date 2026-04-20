// Phase 11 DISC-04 — Katana SPA crawler with XHR + Forms + JS endpoint extraction.
// Flags per RESEARCH.md Pitfall 2 correction: -xhr -fx -jc (NOT -em).
// Auth matrix per CONTEXT.md:
//   - header injection: api_key_header, bearer_jwt, basic → -H
//   - OAuth2: mint bearer pre-crawl, passes as Authorization: Bearer
//   - mTLS: tempfile cert/key/ca + -client-cert/-client-key/-ca-cert flags
//   - api_key_query, hmac: SKIP auth + warn (injection incompatible with crawler)
import { spawn, spawnSync } from 'child_process';
import { mkdtemp, writeFile, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import type { InsertApiEndpoint } from '@shared/schema';
import { createLogger } from '../../../lib/logger';
import { preflightApiBinary } from './preflight';
import { processTracker } from '../../processTracker';

const log = createLogger('scanners:api:katana');

const KATANA_BIN = '/opt/samureye/bin/katana';
const DEFAULT_DEPTH = 3;
const DEFAULT_TIMEOUT_MS = 120_000;

export interface KatanaOpts {
  depth?: number;
  headless?: boolean;
  credential?: KatanaCredential;
  timeoutMs?: number;
}

export type KatanaCredential =
  | { authType: 'api_key_header'; headerName: string; secret: string }
  | { authType: 'bearer_jwt'; secret: string }
  | { authType: 'basic'; secret: string } // secret is already base64(user:pass)
  | { authType: 'oauth2_client_credentials'; tokenUrl: string; clientId: string; clientSecret: string; scope?: string }
  | { authType: 'mtls'; credId: string; cert: string; key: string; ca?: string }
  | { authType: 'api_key_query'; paramName: string; secret: string }
  | { authType: 'hmac' };

export interface KatanaContext {
  jobId?: string;
  apiId: string;
  signal?: AbortSignal;
}

export interface KatanaResult {
  endpoints: InsertApiEndpoint[];
  skipped?: { reason: string };
}

export async function runKatana(
  target: string,
  opts: KatanaOpts,
  ctx: KatanaContext,
): Promise<KatanaResult> {
  const preflight = await preflightApiBinary('katana', log);
  if (!preflight.ok) {
    return { endpoints: [], skipped: { reason: `katana binary not available: ${preflight.reason ?? 'katana unavailable'}` } };
  }

  // Build base args
  const depth = opts.depth ?? DEFAULT_DEPTH;
  const args: string[] = [
    '-u', target,
    '-d', String(depth),
    '-fs', 'rdn',
    '-jc',
    '-xhr',
    '-fx',
    '-timeout', '10',
    '-jsonl',
    '-silent',
  ];

  // Headless toggle — requires Chrome
  if (opts.headless) {
    const chromeRes = spawnSync('which', ['chromium-browser'], { encoding: 'utf8' });
    if (chromeRes.status !== 0) {
      log.warn({ target }, 'katana headless requested but chromium-browser not found — degrading to non-headless');
    } else {
      args.push('-hl', '-sc');
    }
  }

  // Auth injection — tempfile dir only created for mtls
  let tempDir: string | undefined;
  try {
    await applyKatanaAuth(args, opts.credential, ctx, (dir) => { tempDir = dir; });

    const resolvedBin = preflight.resolvedPath ?? KATANA_BIN;
    const result = await spawnKatana(resolvedBin, args, {
      jobId: ctx.jobId,
      signal: ctx.signal,
      timeoutMs: opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    });

    const endpoints = parseKatanaJsonl(result.stdout, ctx.apiId);
    log.info({ target, endpointCount: endpoints.length, stderrTail: result.stderr.slice(-200) }, 'katana crawl complete');
    return { endpoints };
  } finally {
    if (tempDir) {
      await rm(tempDir, { recursive: true, force: true }).catch(() => { /* noop */ });
    }
  }
}

async function applyKatanaAuth(
  args: string[],
  cred: KatanaCredential | undefined,
  ctx: KatanaContext,
  onTempDir: (dir: string) => void,
): Promise<void> {
  if (!cred) return;
  switch (cred.authType) {
    case 'api_key_header':
      args.push('-H', `${cred.headerName}: ${cred.secret}`);
      return;
    case 'bearer_jwt':
      args.push('-H', `Authorization: Bearer ${cred.secret}`);
      return;
    case 'basic':
      args.push('-H', `Authorization: Basic ${cred.secret}`);
      return;
    case 'oauth2_client_credentials': {
      const token = await mintOAuth2Token(cred, ctx.signal);
      if (token) {
        args.push('-H', `Authorization: Bearer ${token}`);
      } else {
        log.warn({}, 'oauth2 token mint failed — crawling unauth');
      }
      return;
    }
    case 'mtls': {
      const dir = await mkdtemp(join(tmpdir(), `api-discovery-${ctx.jobId ?? 'norun'}-`));
      onTempDir(dir);
      const certPath = join(dir, `mtls-${cred.credId}.cert`);
      const keyPath = join(dir, `mtls-${cred.credId}.key`);
      await writeFile(certPath, cred.cert, { mode: 0o600 });
      await writeFile(keyPath, cred.key, { mode: 0o600 });
      args.push('-client-cert', certPath, '-client-key', keyPath);
      if (cred.ca) {
        const caPath = join(dir, `mtls-${cred.credId}.ca`);
        await writeFile(caPath, cred.ca, { mode: 0o600 });
        args.push('-ca-cert', caPath);
      }
      return;
    }
    case 'api_key_query':
      log.warn({ paramName: cred.paramName }, 'katana skipping auth for api_key_query — crawler cannot rewrite URLs per-request');
      return;
    case 'hmac':
      log.warn({}, 'katana skipping auth for hmac — per-request signing incompatible with crawler spawn');
      return;
  }
}

async function mintOAuth2Token(
  cred: { tokenUrl: string; clientId: string; clientSecret: string; scope?: string },
  signal?: AbortSignal,
): Promise<string | null> {
  try {
    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: cred.clientId,
      client_secret: cred.clientSecret,
      ...(cred.scope ? { scope: cred.scope } : {}),
    });
    const res = await fetch(cred.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal,
    });
    if (!res.ok) return null;
    const data = await res.json() as { access_token?: string };
    return data.access_token ?? null;
  } catch {
    return null;
  }
}

interface SpawnOutcome { stdout: string; stderr: string; code: number | null; }

function spawnKatana(
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
        processTracker.register(ctx.jobId, 'katana', child, 'api-discovery:katana');
      } catch (e) {
        log.warn({ err: String(e) }, 'failed to register katana with processTracker');
      }
    }

    child.stdout?.on('data', (d) => { stdout += d.toString(); });
    child.stderr?.on('data', (d) => { stderr += d.toString(); });

    const timer = setTimeout(() => {
      log.warn({ timeoutMs: ctx.timeoutMs }, 'katana timeout — killing process');
      if (ctx.jobId && child.pid) {
        processTracker.kill(ctx.jobId, child.pid);
      } else {
        child.kill('SIGTERM');
        setTimeout(() => child.kill('SIGKILL'), 5000);
      }
    }, ctx.timeoutMs);

    const onAbort = () => {
      log.info({}, 'katana aborted via AbortSignal');
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

function parseKatanaJsonl(stdout: string, apiId: string): InsertApiEndpoint[] {
  const endpoints: InsertApiEndpoint[] = [];
  const seen = new Set<string>(); // dedupe within single crawl: method:path

  for (const line of stdout.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const entry = JSON.parse(trimmed) as {
        request?: { method?: string; endpoint?: string };
        response?: { status_code?: number };
      };
      const method = (entry.request?.method ?? 'GET').toUpperCase();
      const rawUrl = entry.request?.endpoint;
      if (!rawUrl) continue;
      let pathname: string;
      try {
        pathname = new URL(rawUrl).pathname;
      } catch {
        continue;
      }
      const key = `${method}:${pathname}`;
      if (seen.has(key)) continue;
      seen.add(key);
      endpoints.push({
        apiId,
        method,
        path: pathname,
        pathParams: [],
        queryParams: [],
        headerParams: [],
        discoverySources: ['crawler'],
      });
    } catch {
      // partial line at EOF or non-JSON stderr mix — skip
    }
  }
  return endpoints;
}
