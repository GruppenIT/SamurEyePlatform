/**
 * Phase 13 TEST-04 — BFLA (Broken Function Level Authorization) scanner.
 *
 * Strategy:
 *   1. identifyLowPrivCreds: OR-logic 3 signals:
 *      a. Highest priority int among creds (higher int = less privilege, Phase 10 convention).
 *      b. description contains /readonly|read-only|viewer|limited/i.
 *      c. Skip entire stage if only 1 cred (cannot contrast).
 *   2. matchAdminEndpoint: regex /(admin|manage|management|system|internal|sudo|superuser|root|console)(\b|\/|$)/i
 *   3. testPrivEscalation: GET admin-path with low-priv cred.
 *      - severity=high when low-priv gets < 400 AND not redirect-to-login (contrasting RBAC)
 *      - severity=medium when all creds return same status (RBAC ambiguous)
 *   4. isUniversalCred: low-priv cred that passes non-admin control endpoints → skip (false positive risk).
 *
 * CONTEXT.md constraints:
 *   - Method-based (PUT/PATCH/DELETE on non-admin-path) requires opts.destructiveEnabled=true.
 *   - Default: GET on admin-path only.
 *   - Request budget: 100 per API.
 *   - Title (deterministic): "Privilégio administrativo acessível via credencial de baixo privilégio"
 */
import { createLogger } from '../../../lib/logger';
import type { ApiFindingEvidence } from '@shared/schema';
import { API_REMEDIATION_TEMPLATES } from '@shared/apiRemediationTemplates';

const log = createLogger('scanners:api:bfla');

const BFLA_TITLE = 'Privilégio administrativo acessível via credencial de baixo privilégio';
const ADMIN_PATH_REGEX = /(admin|manage|management|system|internal|sudo|superuser|root|console)(\b|\/|$)/i;
const LOW_PRIV_DESC_REGEX = /readonly|read-only|viewer|limited/i;

export interface BflaHit {
  endpointId: string;
  owaspCategory: 'api5_bfla_2023';
  severity: 'high' | 'medium';
  title: string;
  description: string;
  remediation: string;
  evidence: ApiFindingEvidence;
}

export interface BflaCredentialSignal {
  id: string;
  priority: number;
  description: string | null;
  authType: string;
  signal: 'priority' | 'description';
}

/**
 * Identify low-privilege credentials using 3-signal OR-logic.
 * Returns empty array when fewer than 2 creds exist (cannot contrast — skip stage).
 * Signal priority: highest priority int first, then description pattern.
 */
export function identifyLowPrivCreds(
  creds: Array<{ id: string; priority: number; description: string | null; authType: string }>,
): BflaCredentialSignal[] {
  if (creds.length < 2) {
    log.warn({ credCount: creds.length }, 'bfla: insufficient creds to contrast — skipping stage');
    return [];
  }

  const maxPriority = Math.max(...creds.map((c) => c.priority));
  const result: BflaCredentialSignal[] = [];

  for (const cred of creds) {
    if (cred.priority === maxPriority) {
      result.push({ ...cred, signal: 'priority' });
    } else if (cred.description && LOW_PRIV_DESC_REGEX.test(cred.description)) {
      result.push({ ...cred, signal: 'description' });
    }
  }

  return result;
}

/**
 * Match an endpoint path against the admin-path heuristic.
 * Returns the matched keyword (lowercase) or null if no match.
 * Regex: /(admin|manage|management|system|internal|sudo|superuser|root|console)(\b|\/|$)/i
 *
 * Note: word boundary ensures /administrative-view does NOT match (no false positives).
 */
export function matchAdminEndpoint(path: string): string | null {
  const match = ADMIN_PATH_REGEX.exec(path);
  return match ? match[1].toLowerCase() : null;
}

/**
 * Test privilege escalation: low-priv cred accesses admin-path endpoint.
 * Returns BflaHit with severity=high (contrasting RBAC) or medium (RBAC absent).
 *
 * allCredResults: optional array with status results from ALL creds on this endpoint.
 * If all creds return same status → RBAC absent → severity=medium.
 */
export async function testPrivEscalation(params: {
  endpointId: string;
  endpointPath: string;
  endpointUrl: string;
  lowPrivCredId: string;
  lowPrivPriority: number;
  matchedPattern: string;
  lowPrivHeaders: Record<string, string>;
  allCredResults?: Array<{ credId: string; status: number }>;
}): Promise<BflaHit | null> {
  let status: number;
  let body: string;
  try {
    const resp = await fetch(params.endpointUrl, {
      method: 'GET',
      headers: params.lowPrivHeaders,
    });
    status = resp.status;
    body = (await resp.text()).slice(0, 8192);
  } catch (err) {
    log.debug({ err: err instanceof Error ? err.message : err, endpointId: params.endpointId }, 'bfla probe failed');
    return null;
  }

  // 3xx to login counts as rejected
  if (status >= 300) return null;

  // Determine severity: high if RBAC contrast exists, medium if all creds equal
  let severity: 'high' | 'medium' = 'high';
  if (params.allCredResults && params.allCredResults.length > 0) {
    const allSameStatus = params.allCredResults.every((r) => r.status === status);
    if (allSameStatus) {
      severity = 'medium';
      log.info({ endpointId: params.endpointId }, 'bfla: all creds same status — RBAC ambiguous (medium severity)');
    }
  }

  log.info(
    { endpointId: params.endpointId, status, severity, matchedPattern: params.matchedPattern },
    'bfla privilege escalation finding',
  );

  return {
    endpointId: params.endpointId,
    owaspCategory: 'api5_bfla_2023',
    severity,
    title: BFLA_TITLE,
    description: `Credencial de baixo privilégio (priority=${params.lowPrivPriority}) acessou endpoint administrativo ${params.endpointPath} com status ${status}. Pattern matched: ${params.matchedPattern}.`,
    remediation: API_REMEDIATION_TEMPLATES.api5_bfla_2023,
    evidence: {
      request: { method: 'GET', url: params.endpointUrl },
      response: { status, bodySnippet: body },
      extractedValues: {
        credentialId: params.lowPrivCredId,
        priorityLevel: params.lowPrivPriority,
        matchedPattern: params.matchedPattern,
        endpointPath: params.endpointPath,
      },
      context: 'BFLA — low-privilege credential accessed admin-level endpoint',
    },
  };
}

/**
 * Check if a low-priv credential is "universal" (passes non-admin endpoints too).
 * Samples up to 3 non-admin GET endpoints. Returns true if ≥2/3 succeed.
 * If true, caller should skip BFLA for this cred (false positive risk per CONTEXT.md skip condition).
 */
export async function isUniversalCred(params: {
  credHeaders: Record<string, string>;
  nonAdminEndpointUrls: string[];
}): Promise<boolean> {
  const sample = params.nonAdminEndpointUrls.slice(0, 3);
  if (sample.length === 0) return false;

  let successCount = 0;
  for (const url of sample) {
    try {
      const resp = await fetch(url, { method: 'GET', headers: params.credHeaders });
      if (resp.status < 400) successCount++;
    } catch {
      // network error — not a success
    }
  }

  return successCount >= 2;
}
