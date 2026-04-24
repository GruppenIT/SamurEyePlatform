/**
 * Phase 12 TEST-01 — Nuclei passive scanner.
 *
 * Wraps the existing Nuclei binary (v1.0) with a passive-only tag filter
 * (-tags misconfig,exposure,graphql,cors) per CONTEXT.md §Templates Nuclei.
 *
 * Single spawn per API: stdin batched with `baseUrl + endpoint.path` list.
 * JSONL streaming parse via NucleiFindingSchema.safeParse. Mapper converts
 * kebab→camel and truncates bodies to 8192 chars (Phase 14 FIND-02 sanitizes
 * further; Phase 12 is defensive-by-default).
 */
import { spawn, type ChildProcess } from 'child_process';
import { createLogger } from '../../../lib/logger';
import { preflightNuclei } from '../../journeys/nucleiPreflight';
import { processTracker } from '../../processTracker';
import {
  NucleiFindingSchema,
  type NucleiFinding,
  type ApiFindingEvidence,
} from '@shared/schema';
import { API_REMEDIATION_TEMPLATES } from '@shared/apiRemediationTemplates';

const log = createLogger('scanners:api:nuclei');

const NUCLEI_BIN = 'nuclei';
const TEMPLATES_DIR = '/tmp/nuclei/nuclei-templates';
const PASSIVE_TAGS = 'misconfig,exposure,graphql,cors';
const BODY_SNIPPET_MAX = 8192;
const DEFAULT_RATE_LIMIT = 10;
const DEFAULT_TIMEOUT_SEC = 10;
const DEFAULT_TOTAL_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes per API

export interface NucleiPassiveEndpoint {
  id: string;
  fullUrl: string; // baseUrl + endpoint.path (resolved at call site)
}

export interface NucleiPassiveOpts {
  rateLimit?: number;  // default 10
  timeoutSec?: number; // default 10
}

export interface NucleiPassiveCtx {
  jobId?: string;
  apiId: string;
  signal?: AbortSignal;
}

export interface NucleiPassiveHit {
  endpointId: string;
  owaspCategory: 'api8_misconfiguration_2023' | 'api9_inventory_2023';
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string | null;
  remediation: string;
  evidence: ApiFindingEvidence;
}

export interface NucleiPassiveResult {
  findings: NucleiPassiveHit[];
  skipped?: { reason: string };
}

/**
 * Build Nuclei CLI args for passive scan. Exported for unit testing.
 */
export function buildNucleiArgs(opts: NucleiPassiveOpts): string[] {
  return [
    '-tags', PASSIVE_TAGS,
    '-jsonl',
    '-silent',
    '-retries', '0',
    '-rl', String(opts.rateLimit ?? DEFAULT_RATE_LIMIT),
    '-timeout', String(opts.timeoutSec ?? DEFAULT_TIMEOUT_SEC),
    '-t', TEMPLATES_DIR,
    '-l', '/dev/stdin',
  ];
}

/**
 * Map a single NucleiFinding (parsed JSONL) to a partial ApiFinding
 * ready for dedupe upsert by the orchestrator.
 *
 * URL resolution: uses `matched-at` as the canonical endpoint URL.
 * OWASP category: `graphql` tag → api9; `misconfig/exposure/cors` → api8.
 * Severity mapping: Nuclei `info` downgrades to `low` (threat_severity_enum).
 */
export function mapNucleiJsonlToEvidence(
  finding: NucleiFinding,
  endpointId: string,
): NucleiPassiveHit {
  const tags = finding.info?.tags ?? [];
  const isGraphql = tags.includes('graphql');
  const owaspCategory: NucleiPassiveHit['owaspCategory'] = isGraphql
    ? 'api9_inventory_2023'
    : 'api8_misconfiguration_2023';

  // NucleiFinding.info.severity is z.string() (allows 'info' which is not in threat_severity_enum)
  const nucleiSeverity = finding.info?.severity ?? 'low';
  const severityRaw = nucleiSeverity === 'info' ? 'low' : nucleiSeverity;
  // Validate severity is one of the allowed values; default to 'low' for unexpected values
  const validSeverities: NucleiPassiveHit['severity'][] = ['low', 'medium', 'high', 'critical'];
  const severity: NucleiPassiveHit['severity'] = (validSeverities as string[]).includes(severityRaw)
    ? (severityRaw as NucleiPassiveHit['severity'])
    : 'low';

  const remediation = isGraphql
    ? API_REMEDIATION_TEMPLATES.api9_inventory_2023.graphql_introspection
    : API_REMEDIATION_TEMPLATES.api8_misconfiguration_2023;

  // NucleiFinding uses camelCase fields (matchedAt, matcherName, extractedResults, templateId)
  // request/response are not in the schema but may appear in raw data — use type assertion for extensibility
  const rawFinding = finding as NucleiFinding & { request?: string; response?: string };
  const requestBody = typeof rawFinding.request === 'string' ? rawFinding.request.slice(0, BODY_SNIPPET_MAX) : undefined;
  const responseBody = typeof rawFinding.response === 'string' ? rawFinding.response.slice(0, BODY_SNIPPET_MAX) : undefined;

  const evidence: ApiFindingEvidence = {
    request: {
      method: extractMethodFromRequest(rawFinding.request) ?? 'GET',
      url: finding.matchedAt ?? finding.host ?? 'unknown',
      headers: undefined,
      bodySnippet: requestBody,
    },
    response: {
      status: extractStatusFromResponse(rawFinding.response) ?? 0,
      headers: undefined,
      bodySnippet: responseBody,
    },
    extractedValues: {
      matcherName: finding.matcherName ?? null,
      extractedResults: finding.extractedResults ?? [],
      templateId: finding.templateId,
    },
    context: finding.info?.description ?? undefined,
  };

  return {
    endpointId,
    owaspCategory,
    severity,
    title: finding.info?.name ?? finding.templateId,
    description: finding.info?.description ?? null,
    remediation,
    evidence,
  };
}

function extractMethodFromRequest(raw: string | undefined): string | undefined {
  if (typeof raw !== 'string') return undefined;
  const m = raw.match(/^([A-Z]+)\s/);
  return m?.[1];
}

function extractStatusFromResponse(raw: string | undefined): number | undefined {
  if (typeof raw !== 'string') return undefined;
  const m = raw.match(/^HTTP\/\d\.\d\s(\d{3})/);
  return m ? Number(m[1]) : undefined;
}

/**
 * Run Nuclei against a batch of endpoints. Single spawn per API.
 * Respects preflight; registers process with tracker; aborts on signal.
 */
export async function runNucleiPassive(
  endpoints: NucleiPassiveEndpoint[],
  opts: NucleiPassiveOpts,
  ctx: NucleiPassiveCtx,
): Promise<NucleiPassiveResult> {
  const preflight = await preflightNuclei(log);
  if (!preflight.ok) {
    return { findings: [], skipped: { reason: preflight.reason ?? 'nuclei unavailable' } };
  }
  if (endpoints.length === 0) {
    return { findings: [], skipped: { reason: 'no endpoints' } };
  }

  const args = buildNucleiArgs(opts);

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
      processTracker.register(ctx.jobId, 'nuclei', child, 'api-passive:nuclei');
    }

    // URL → endpointId lookup for mapper
    const byUrl = new Map<string, string>();
    endpoints.forEach((e) => byUrl.set(e.fullUrl, e.id));

    // Write endpoint list via stdin
    child.stdin?.write(endpoints.map((e) => e.fullUrl).join('\n') + '\n');
    child.stdin?.end();

    const findings: NucleiPassiveHit[] = [];
    let buf = '';

    child.stdout?.on('data', (chunk: Buffer) => {
      buf += chunk.toString('utf8');
      const lines = buf.split('\n');
      buf = lines.pop() ?? '';
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const parsed = JSON.parse(line);
          const safe = NucleiFindingSchema.safeParse(parsed);
          if (!safe.success) {
            log.debug({ issue: safe.error.issues[0] }, 'nuclei jsonl line rejected by schema');
            continue;
          }
          // Match finding back to endpoint by URL
          const url = safe.data.matchedAt ?? safe.data.host ?? '';
          const endpointId = byUrl.get(url) ?? endpoints.find((e) => url.startsWith(e.fullUrl))?.id;
          if (!endpointId) {
            log.debug({ url }, 'nuclei finding has no matching endpoint — skipped');
            continue;
          }
          findings.push(mapNucleiJsonlToEvidence(safe.data, endpointId));
        } catch (err) {
          log.debug({ err: err instanceof Error ? err.message : err }, 'nuclei jsonl parse error');
        }
      }
    });

    child.stderr?.on('data', (chunk: Buffer) => {
      log.debug({ stderr: chunk.toString('utf8').slice(0, 500) }, 'nuclei stderr');
    });

    const totalTimeout = setTimeout(() => {
      log.warn({ apiId: ctx.apiId, jobId: ctx.jobId }, 'nuclei total timeout — SIGTERM');
      child.kill('SIGTERM');
    }, DEFAULT_TOTAL_TIMEOUT_MS);

    const onAbort = () => {
      log.info({ apiId: ctx.apiId, jobId: ctx.jobId }, 'nuclei aborted via signal');
      child.kill('SIGTERM');
    };
    ctx.signal?.addEventListener('abort', onAbort);

    child.on('close', (code) => {
      clearTimeout(totalTimeout);
      ctx.signal?.removeEventListener('abort', onAbort);
      log.info({ apiId: ctx.apiId, jobId: ctx.jobId, exitCode: code, findingsCount: findings.length }, 'nuclei passive complete');
      resolve({ findings });
    });

    child.on('error', (err) => {
      clearTimeout(totalTimeout);
      ctx.signal?.removeEventListener('abort', onAbort);
      log.error({ err }, 'nuclei spawn error');
      resolve({ findings, skipped: { reason: `spawn failed: ${err.message}` } });
    });
  });
}
