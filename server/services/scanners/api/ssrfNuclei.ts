/**
 * Phase 13 TEST-07 — SSRF scanner via Nuclei + interactsh.
 *
 * KEY DIFFERENCE from nucleiApi.ts (Phase 12):
 *   - Tags: '-tags ssrf' (only SSRF templates)
 *   - NO '-ni' flag (interactsh MUST be enabled for OOB detection)
 *   - Additional flags: '-interactions-poll-duration 5s -interactions-wait 10s
 *     -interactions-retries-count 3'
 *   - '-timeout 30' (longer for OOB callback wait)
 *   - Optional: '-interactsh-url <URL>' when INTERACTSH_URL env or opts.interactshUrl set
 *
 * SCOPE: Only params whose values are URL-like (3 heuristics OR):
 *   1. Name matches URL_LIKE_NAME_REGEX (locked list from CONTEXT.md)
 *   2. type==='url' OR format==='uri' OR format==='url'
 *   3. example parseable by new URL() without throw
 *
 * SAFE-06: log only paramName prefix-3+*** for interactsh URLs; never full callback URL.
 * NucleiFindingSchema camelCase: use safe.data.matchedAt (not 'matched-at').
 * interaction=true and interactsh-interaction-type come from raw parsed JSON (stripped by schema).
 */
import { spawn, type ChildProcess } from 'child_process';
import { createLogger } from '../../../lib/logger';
import { preflightNuclei } from '../../journeys/nucleiPreflight';
import { processTracker } from '../../processTracker';
import {
  NucleiFindingSchema,
  type ApiFindingEvidence,
} from '@shared/schema';
import { API_REMEDIATION_TEMPLATES } from '@shared/apiRemediationTemplates';

const log = createLogger('scanners:api:ssrfNuclei');

const NUCLEI_BIN = 'nuclei';
const TEMPLATES_DIR = '/tmp/nuclei/nuclei-templates';
const SSRF_TAGS = 'ssrf';
const BODY_SNIPPET_MAX = 8192;
const DEFAULT_RATE_LIMIT = 10;
const DEFAULT_TIMEOUT_SEC = 30; // longer for OOB callback
const DEFAULT_TOTAL_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes for SSRF stage

/**
 * URL-like param name regex (locked from CONTEXT.md §SSRF).
 * Matches common param names that accept URLs as values.
 */
export const URL_LIKE_NAME_REGEX =
  /^(url|redirect|redirect_uri|callback|callback_url|webhook|webhook_url|target|dest|destination|endpoint|uri|link|image_url|avatar_url|src|href|next|continue|returnTo|return_to|return)$/i;

export interface SsrfParam {
  name: string;
  type?: string;
  format?: string;
  example?: string;
}

export interface SsrfHit {
  endpointId: string;
  owaspCategory: 'api7_ssrf_2023';
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  remediation: string;
  evidence: ApiFindingEvidence;
}

export interface SsrfNucleiOpts {
  interactshUrl?: string;
  rateLimit?: number;
  timeoutSec?: number;
}

export interface SsrfNucleiCtx {
  jobId?: string;
  apiId: string;
  signal?: AbortSignal;
}

export interface SsrfNucleiResult {
  findings: SsrfHit[];
  skipped?: { reason: string };
}

/**
 * Single-param URL-like check (exported for unit testing).
 * OR-logic across 3 heuristics.
 */
export function isUrlLikeParam(param: SsrfParam): boolean {
  // Heuristic 1: name regex match
  if (URL_LIKE_NAME_REGEX.test(param.name)) return true;
  // Heuristic 2: type/format match
  if (param.type === 'url' || param.format === 'uri' || param.format === 'url') return true;
  // Heuristic 3: example parseable as URL
  if (param.example) {
    try { new URL(param.example); return true; } catch { /* not a URL */ }
  }
  return false;
}

/**
 * Identify URL-like parameters using 3-heuristic OR logic.
 * Returns params that match at least one heuristic.
 */
export function identifyUrlParams(params: SsrfParam[]): SsrfParam[] {
  return params.filter((p) => isUrlLikeParam(p));
}

/**
 * Build Nuclei CLI args for SSRF scan.
 * CRITICAL: NO -ni flag (interactsh must be active for OOB detection).
 * YES -interactions-* flags (OOB polling config per CONTEXT.md §SSRF).
 * -timeout 30 (longer wait for OOB callback).
 */
export function buildSsrfNucleiArgs(opts: SsrfNucleiOpts): string[] {
  const args = [
    '-tags', SSRF_TAGS,
    '-jsonl',
    '-silent',
    '-retries', '0',
    '-rl', String(opts.rateLimit ?? DEFAULT_RATE_LIMIT),
    '-timeout', String(opts.timeoutSec ?? DEFAULT_TIMEOUT_SEC),
    '-t', TEMPLATES_DIR,
    '-l', '/dev/stdin',
    // interactsh OOB polling config (CONTEXT.md §SSRF)
    '-interactions-poll-duration', '5s',
    '-interactions-wait', '10s',
    '-interactions-retries-count', '3',
  ];

  // Override interactsh server when env or opts provides URL (air-gapped support)
  const interactshUrl = opts.interactshUrl ?? process.env['INTERACTSH_URL'];
  if (interactshUrl) {
    args.push('-interactsh-url', interactshUrl);
  }
  // NOTE: NO '-ni' flag — interactsh MUST be active for SSRF OOB detection.

  return args;
}

/**
 * Map a Nuclei SSRF finding to SsrfHit.
 * CRITICAL: NucleiFindingSchema uses camelCase (safe.data.matchedAt, not 'matched-at').
 * interactsh-interaction-type comes from raw parsed JSON (stripped by schema .strip()).
 */
function mapSsrfFinding(
  parsed: unknown,
  endpointId: string,
  paramName: string,
): SsrfHit {
  // Access camelCase fields from Zod-parsed data
  const safe = NucleiFindingSchema.safeParse(parsed);
  const nucleiSeverity = safe.success ? (safe.data.info?.severity ?? 'info') : 'info';
  const severity = (nucleiSeverity === 'info' ? 'low' : nucleiSeverity) as SsrfHit['severity'];

  const title = `SSRF confirmado via interação out-of-band em parâmetro ${paramName}`;

  // matchedAt is camelCase per NucleiFindingSchema (STATE.md decision: NucleiFinding camelCase)
  const matchedAt = safe.success ? (safe.data.matchedAt ?? '') : '';

  // interactsh-interaction-type is a raw field stripped by schema — access from raw parsed
  const rawParsed = parsed as Record<string, unknown>;
  const interactionType = (rawParsed['interactsh-interaction-type'] ?? rawParsed.interactionType ?? 'unknown') as string;

  // SAFE-06: mask interactsh URL — prefix-3 + ***
  const interactshUrlMasked = matchedAt.length >= 3 ? matchedAt.slice(0, 3) + '***' : '***';

  // request/response are raw string fields (not in schema but may be in raw output)
  const requestRaw = typeof rawParsed.request === 'string' ? rawParsed.request : undefined;
  const responseRaw = typeof rawParsed.response === 'string' ? rawParsed.response : undefined;

  return {
    endpointId,
    owaspCategory: 'api7_ssrf_2023',
    severity,
    title,
    description: `SSRF out-of-band detectado no parâmetro '${paramName}'. Nuclei confirmou callback interactsh (${interactionType}).`,
    remediation: API_REMEDIATION_TEMPLATES.api7_ssrf_2023,
    evidence: {
      request: {
        method: 'GET',
        url: matchedAt || (safe.success ? (safe.data.host ?? 'unknown') : 'unknown'),
        bodySnippet: requestRaw?.slice(0, BODY_SNIPPET_MAX),
      },
      response: {
        status: 200,
        bodySnippet: responseRaw?.slice(0, BODY_SNIPPET_MAX),
      },
      extractedValues: {
        paramName,
        interactsh_interaction_type: interactionType,
        interactshUrl: interactshUrlMasked,
        templateId: safe.success ? safe.data.templateId : undefined,
      },
      context: 'SSRF OOB interaction confirmed via Nuclei interactsh',
    },
  };
}

/**
 * Run Nuclei SSRF scan against a batch of target URLs.
 * preflightNuclei must pass before spawn. Skip early if no targets.
 *
 * Finding criterion: JSONL line reports interaction=true OR
 * extractedResults contains interactsh callback URL pattern.
 */
export async function runSsrfNuclei(
  targetUrls: Array<{ url: string; endpointId: string; paramName: string }>,
  opts: SsrfNucleiOpts,
  ctx: SsrfNucleiCtx,
): Promise<SsrfNucleiResult> {
  if (targetUrls.length === 0) {
    return { findings: [], skipped: { reason: 'no URL-like params found' } };
  }

  const preflight = await preflightNuclei(log);
  if (!preflight.ok) {
    return { findings: [], skipped: { reason: preflight.reason ?? 'nuclei unavailable' } };
  }

  const args = buildSsrfNucleiArgs(opts);

  return new Promise((resolve) => {
    const child: ChildProcess = spawn(NUCLEI_BIN, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        HOME: '/tmp/nuclei',
        NUCLEI_CONFIG_DIR: '/tmp/nuclei/.config',
        XDG_CONFIG_HOME: '/tmp/nuclei/.config',
        XDG_CACHE_HOME: '/tmp/nuclei/.cache',
      },
    });

    if (ctx.jobId && child.pid) {
      processTracker.register(ctx.jobId, 'nuclei', child, 'api-ssrf:nuclei');
    }

    // URL → (endpointId, paramName) lookup
    const byUrl = new Map<string, { endpointId: string; paramName: string }>();
    targetUrls.forEach((t) => byUrl.set(t.url, { endpointId: t.endpointId, paramName: t.paramName }));

    child.stdin?.write(targetUrls.map((t) => t.url).join('\n') + '\n');
    child.stdin?.end();

    const findings: SsrfHit[] = [];
    let buf = '';

    child.stdout?.on('data', (chunk: Buffer) => {
      buf += chunk.toString('utf8');
      const lines = buf.split('\n');
      buf = lines.pop() ?? '';
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const parsed = JSON.parse(line);

          // Finding criterion: interaction=true OR extracted-results has interactsh callback URL
          const hasInteraction = (parsed.interaction === true) ||
            (Array.isArray(parsed['extracted-results']) &&
              (parsed['extracted-results'] as string[]).some((r) => r.includes('oast') || r.includes('interactsh')));
          if (!hasInteraction) continue;

          // Validate with schema (camelCase fields)
          const safe = NucleiFindingSchema.safeParse(parsed);
          if (!safe.success) {
            log.debug({ issue: safe.error.issues[0] }, 'ssrf nuclei jsonl line rejected by schema');
            continue;
          }

          // Match finding back to target URL (matchedAt is camelCase per Phase 12 STATE.md decision)
          const matchUrl = safe.data.matchedAt ?? safe.data.host ?? '';
          const entry = byUrl.get(matchUrl) ?? targetUrls.find((t) => matchUrl.startsWith(t.url));
          if (!entry) {
            log.debug({ matchUrl }, 'ssrf nuclei finding no matching target — skipped');
            continue;
          }

          findings.push(mapSsrfFinding(parsed, entry.endpointId, entry.paramName));
        } catch (err) {
          log.debug({ err: err instanceof Error ? err.message : err }, 'ssrf nuclei jsonl parse error');
        }
      }
    });

    child.stderr?.on('data', (chunk: Buffer) => {
      log.debug({ stderr: chunk.toString('utf8').slice(0, 500) }, 'ssrf nuclei stderr');
    });

    const totalTimeout = setTimeout(() => {
      log.warn({ apiId: ctx.apiId, jobId: ctx.jobId }, 'ssrf nuclei total timeout — SIGTERM');
      child.kill('SIGTERM');
    }, DEFAULT_TOTAL_TIMEOUT_MS);

    const onAbort = () => {
      log.info({ apiId: ctx.apiId, jobId: ctx.jobId }, 'ssrf nuclei aborted via signal');
      child.kill('SIGTERM');
    };
    ctx.signal?.addEventListener('abort', onAbort);

    child.on('close', (code) => {
      clearTimeout(totalTimeout);
      ctx.signal?.removeEventListener('abort', onAbort);
      log.info({ apiId: ctx.apiId, jobId: ctx.jobId, exitCode: code, findingsCount: findings.length }, 'ssrf nuclei scan complete');
      resolve({ findings });
    });

    child.on('error', (err) => {
      clearTimeout(totalTimeout);
      ctx.signal?.removeEventListener('abort', onAbort);
      log.error({ err }, 'ssrf nuclei spawn error');
      resolve({ findings, skipped: { reason: `spawn failed: ${err.message}` } });
    });
  });
}
