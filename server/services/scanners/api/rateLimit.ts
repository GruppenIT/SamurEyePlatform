/**
 * Phase 13 TEST-06 — Rate-Limit Absence scanner.
 *
 * OPT-IN: opts.stages.rateLimit must be explicitly true (default false).
 * The orchestrator checks this flag before calling into this scanner.
 *
 * Strategy:
 *   buildBurst: Promise.all of burstSize parallel GET requests (intentional saturation).
 *   detectThrottling: ALL-3-signals must be absent for a finding:
 *     1. No response has status=429.
 *     2. No response has Retry-After header.
 *     3. No response has a header matching /^x-ratelimit-/i.
 *     4. ≥90% responses have status<400 (confirms endpoint accepted load).
 *
 * Severity: medium (rate-limit absence is a posture signal, not an exploit).
 * Title: "Ausência de rate-limiting em endpoint autenticado"
 * burstSize default=20, max=50 (Zod ceiling SAFE-01; Phase 15 enforces globally).
 */
import { createLogger } from '../../../lib/logger';
import type { ApiFindingEvidence } from '@shared/schema';
import { API_REMEDIATION_TEMPLATES } from '@shared/apiRemediationTemplates';

const log = createLogger('scanners:api:rateLimit');

const RATE_LIMIT_TITLE = 'Ausência de rate-limiting em endpoint autenticado';
const X_RATELIMIT_HEADER_REGEX = /^x-ratelimit-/i;
const DEFAULT_BURST_SIZE = 20;
const MAX_BURST_SIZE = 50;

export interface RateLimitHit {
  endpointId: string;
  owaspCategory: 'api4_rate_limit_2023';
  severity: 'medium';
  title: string;
  description: string;
  remediation: string;
  evidence: ApiFindingEvidence;
}

export interface BurstResponse {
  status: number;
  headers: Record<string, string>;
}

/**
 * Issue burstSize parallel GET requests via Promise.all (intentional saturation).
 * Returns array of { status, headers } for detectThrottling analysis.
 * burstSize is capped at MAX_BURST_SIZE=50 (Phase 13 ceiling; SAFE-01 Phase 15 global ceiling).
 */
export async function buildBurst(params: {
  url: string;
  authHeaders: Record<string, string>;
  burstSize?: number;
}): Promise<BurstResponse[]> {
  const size = Math.min(params.burstSize ?? DEFAULT_BURST_SIZE, MAX_BURST_SIZE);

  const requests = Array.from({ length: size }, () =>
    fetch(params.url, { method: 'GET', headers: params.authHeaders })
      .then(async (resp) => {
        const headers: Record<string, string> = {};
        resp.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });
        return { status: resp.status, headers };
      })
      .catch(() => ({ status: 0, headers: {} as Record<string, string> })),
  );

  return Promise.all(requests);
}

/**
 * Analyze burst responses for absence of rate-limiting signals.
 * ALL-3-signals must be absent AND ≥90% responses must have status<400 for a finding.
 * Returns null when any throttling signal is detected (server correctly rate-limits).
 *
 * Detection criteria (ALL required):
 *   1. No status=429 in any response.
 *   2. No Retry-After header in any response.
 *   3. No /^x-ratelimit-/i header in any response.
 *   4. ≥90% of responses have status<400 (endpoint healthy under load).
 */
export function detectThrottling(params: {
  endpointId: string;
  endpointPath: string;
  endpointUrl: string;
  responses: BurstResponse[];
  burstSize: number;
  windowMs: number;
}): RateLimitHit | null {
  const { responses } = params;
  if (responses.length === 0) return null;

  let has429 = false;
  let hasRetryAfter = false;
  let hasXRateLimit = false;
  let successCount = 0;

  for (const r of responses) {
    if (r.status === 429) {
      has429 = true;
      break;
    }
    if (r.headers['retry-after']) hasRetryAfter = true;
    for (const header of Object.keys(r.headers)) {
      if (X_RATELIMIT_HEADER_REGEX.test(header)) {
        hasXRateLimit = true;
        break;
      }
    }
    if (r.status > 0 && r.status < 400) successCount++;
  }

  if (has429 || hasRetryAfter || hasXRateLimit) return null;

  const successRate = successCount / responses.length;
  if (successRate < 0.9) {
    log.debug({ endpointId: params.endpointId, successRate }, 'rateLimit: < 90% success — endpoint unhealthy, no finding');
    return null;
  }

  const throttledCount = responses.length - successCount;
  log.info(
    { endpointId: params.endpointId, successCount, throttledCount, successRate },
    'rate-limit absence finding',
  );

  return {
    endpointId: params.endpointId,
    owaspCategory: 'api4_rate_limit_2023',
    severity: 'medium',
    title: RATE_LIMIT_TITLE,
    description: `Endpoint ${params.endpointPath} aceitou ${successCount}/${responses.length} requisições em burst (${params.windowMs}ms) sem sinalizar 429, Retry-After, ou X-RateLimit-*. Rate limiting ausente ou insuficiente.`,
    remediation: API_REMEDIATION_TEMPLATES.api4_rate_limit_2023,
    evidence: {
      request: { method: 'GET', url: params.endpointUrl },
      response: { status: responses[0]?.status ?? 0 },
      extractedValues: {
        burstSize: params.burstSize,
        successCount,
        throttledCount,
        hasRetryAfter: false,
        hasXRateLimitHeaders: false,
        windowMs: params.windowMs,
        endpointPath: params.endpointPath,
      },
      context: `Rate-limit absence test — ${responses.length} parallel requests, no throttling signals`,
    },
  };
}
