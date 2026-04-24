/**
 * Phase 13 TEST-05 — BOPLA / Mass Assignment scanner.
 *
 * DESTRUCTIVE GATE: This scanner modifies server state (PUT/PATCH with injected keys).
 * It MUST ONLY run when opts.destructiveEnabled === true. The gate check is the
 * caller's responsibility (orchestrator) — scanner trusts the gate was checked.
 *
 * Strategy:
 *   1. fetchSeedBody: GET same resource to capture current state (JSON).
 *   2. injectSensitiveKey: PUT/PATCH with { ...seed, [key]: injectedValue }.
 *      One request per key from BOPLA_SENSITIVE_KEYS (10 keys).
 *   3. verifyReflection: GET again; compare key before/after using deep key-path compare.
 *      Finding when key appears in after-body with different value.
 *
 * Severity: critical for is_admin/role/superuser; high for others.
 * Title template: "Campo sensível aceito em PUT/PATCH sem validação ({{key}})"
 * Title includes the specific key for dedupe variance (each key → distinct finding row).
 */
import { createLogger } from '../../../lib/logger';
import { BOPLA_SENSITIVE_KEYS, type ApiFindingEvidence } from '@shared/schema';
import { API_REMEDIATION_TEMPLATES } from '@shared/apiRemediationTemplates';

const log = createLogger('scanners:api:bopla');

const CRITICAL_KEYS = new Set(['is_admin', 'role', 'superuser']);

export interface BoplaHit {
  endpointId: string;
  owaspCategory: 'api3_bopla_2023';
  severity: 'critical' | 'high';
  title: string;
  description: string;
  remediation: string;
  evidence: ApiFindingEvidence;
}

/**
 * Fetch seed GET response body. Returns null when:
 * - GET status >= 400 (endpoint not accessible — test unreliable)
 * - Body is not a JSON object (array/primitive/form/XML out of scope Phase 13)
 */
export async function fetchSeedBody(
  resourceUrl: string,
  authHeaders: Record<string, string>,
): Promise<Record<string, unknown> | null> {
  let resp: Response;
  try {
    resp = await fetch(resourceUrl, { method: 'GET', headers: authHeaders });
  } catch (err) {
    log.debug({ err: err instanceof Error ? err.message : err, resourceUrl }, 'bopla seed fetch error');
    return null;
  }

  if (resp.status >= 400) {
    log.debug({ status: resp.status, resourceUrl }, 'bopla seed GET non-success — skipping endpoint');
    return null;
  }

  const text = await resp.text();
  try {
    const parsed = JSON.parse(text);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      log.debug({ resourceUrl }, 'bopla seed body is not a JSON object — skipping');
      return null;
    }
    return parsed as Record<string, unknown>;
  } catch {
    log.debug({ resourceUrl }, 'bopla seed body not JSON-parseable — skipping');
    return null;
  }
}

/**
 * Determine the injected value for a key based on seed body type inference.
 * boolean → true, string → 'admin', array → ['admin'], absent/other → true (default).
 */
export function resolveInjectedValue(
  seedBody: Record<string, unknown>,
  key: string,
): unknown {
  const existing = seedBody[key];
  if (existing === undefined) return true; // default for absent key
  if (typeof existing === 'boolean') return true;
  if (typeof existing === 'string') return 'admin';
  if (Array.isArray(existing)) return ['admin'];
  return true;
}

/**
 * Inject a single sensitive key into the seed body (spread — preserves structure).
 * Returns the new body object with the injected key added/overridden.
 * Does NOT replace existing structure — only adds/modifies the target key.
 */
export function injectSensitiveKey(
  seedBody: Record<string, unknown>,
  key: string,
): Record<string, unknown> {
  const injectedValue = resolveInjectedValue(seedBody, key);
  return { ...seedBody, [key]: injectedValue };
}

/**
 * Verify if the injected key is reflected in the after-GET response.
 * Uses key-path deep compare (NOT regex text match) to avoid false positives.
 * Returns BoplaHit when: PUT/PATCH status < 400 AND after-GET shows key with changed value.
 *
 * Detection logic: reflection confirmed when after-body[key] exists AND differs from seed-body[key].
 * If key was already present in seed with same value → not a finding (pre-existing field).
 */
export async function verifyReflection(params: {
  endpointId: string;
  resourceUrl: string;
  seedBody: Record<string, unknown>;
  key: string;
  authHeaders: Record<string, string>;
  method: 'PUT' | 'PATCH';
}): Promise<BoplaHit | null> {
  const injectedBody = injectSensitiveKey(params.seedBody, params.key);

  // Step 1: PUT/PATCH with injected key
  let putStatus: number;
  try {
    const putResp = await fetch(params.resourceUrl, {
      method: params.method,
      headers: { ...params.authHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify(injectedBody),
    });
    putStatus = putResp.status;
  } catch (err) {
    log.debug({ err: err instanceof Error ? err.message : err, endpointId: params.endpointId }, 'bopla PUT/PATCH failed');
    return null;
  }

  if (putStatus >= 400) return null;

  // Step 2: GET to verify reflection
  let afterBody: Record<string, unknown> | null = null;
  try {
    const getResp = await fetch(params.resourceUrl, { method: 'GET', headers: params.authHeaders });
    if (getResp.status >= 400) return null;
    const text = await getResp.text();
    const parsed = JSON.parse(text);
    afterBody = (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed))
      ? parsed as Record<string, unknown>
      : null;
  } catch {
    return null;
  }

  if (!afterBody) return null;

  // Deep key-path compare: reflection when key in after AND different from seed
  const beforeValue = params.seedBody[params.key];
  const afterValue = afterBody[params.key];

  if (afterValue === undefined) return null;
  if (beforeValue === afterValue) return null; // unchanged — likely pre-existing

  const severity = CRITICAL_KEYS.has(params.key) ? 'critical' : 'high';
  const title = `Campo sensível aceito em PUT/PATCH sem validação (${params.key})`;

  log.info(
    { endpointId: params.endpointId, key: params.key, severity },
    'bopla mass assignment reflection confirmed',
  );

  return {
    endpointId: params.endpointId,
    owaspCategory: 'api3_bopla_2023',
    severity,
    title,
    description: `O campo sensível '${params.key}' foi aceito via ${params.method} e refletido na resposta GET subsequente. Mass assignment confirmado.`,
    remediation: API_REMEDIATION_TEMPLATES.api3_bopla_2023,
    evidence: {
      request: { method: params.method, url: params.resourceUrl, bodySnippet: JSON.stringify(injectedBody).slice(0, 512) },
      response: { status: putStatus },
      extractedValues: {
        injectedKey: params.key,
        originalValue: beforeValue ?? null,
        reflectedValue: afterValue,
        endpointPath: new URL(params.resourceUrl).pathname,
      },
      context: `BOPLA mass assignment — key ${params.key} reflected after ${params.method}`,
    },
  };
}

// Re-export BOPLA_SENSITIVE_KEYS so orchestrator can import from this module
export { BOPLA_SENSITIVE_KEYS };
