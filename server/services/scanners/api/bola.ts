/**
 * Phase 13 TEST-03 — BOLA (Broken Object Level Authorization) scanner.
 *
 * Strategy:
 *   1. pairCredentials: C(n,2) ordered unique pairs (A→B only, no B→A mirror).
 *   2. harvestObjectIds: GET list-like endpoints with cred A; extract ≤3 IDs
 *      from JSON fields matching /^(id|uuid|pk)$/i.
 *   3. testCrossAccess: for each harvested ID, substitute into path template
 *      and GET with cred B. Finding when status < 400 AND body non-empty AND
 *      no forbidden-text.
 *
 * CONTEXT.md constraints:
 *   - maxCredentials = 4 default, max 6 (C(6,2) = 15 pairs max)
 *   - maxIdsPerEndpoint = 3 default, max 5
 *   - Only GET endpoints with requiresAuth=true are tested
 *   - Only "list-like" endpoints (path has no {param}) are used for harvest
 *   - Path template: OpenAPI {id} style only (Regex /\{(\w+)\}/g)
 *   - Severity: always 'high' (cross-identity object read confirmed)
 *   - Title (deterministic): "Acesso não autorizado a objeto via credencial secundária"
 *   - SAFE-06: never log harvested IDs or credential secrets; log only counts + endpointIds
 */
import { createLogger } from '../../../lib/logger';
import type { ApiFindingEvidence } from '@shared/schema';
import { API_REMEDIATION_TEMPLATES } from '@shared/apiRemediationTemplates';

const log = createLogger('scanners:api:bola');

const BOLA_TITLE = 'Acesso não autorizado a objeto via credencial secundária';
const FORBIDDEN_PATTERNS = /forbidden|unauthorized|permission denied/i;
const ID_FIELD_REGEX = /^(id|uuid|pk)$/i;
// Note: using string-based replace to avoid stateful regex lastIndex issues
const PATH_TEMPLATE_REGEX = /\{(\w+)\}/g;

export interface BolaHit {
  endpointId: string;
  owaspCategory: 'api1_bola_2023';
  severity: 'high';
  title: string;
  description: string;
  remediation: string;
  evidence: ApiFindingEvidence;
}

export interface BolaCredential {
  id: string;
  authType: string;
  authHeaders: Record<string, string>;
  queryParam?: { name: string; value: string };
}

/**
 * Generate C(n,2) ordered unique pairs without mirroring.
 * e.g. [A,B,C] → [(A,B), (A,C), (B,C)]  — no (B,A) etc.
 * Cap at maxCredentials (default 4, hard max 6 per CONTEXT.md).
 */
export function pairCredentials(
  creds: Array<{ id: string }>,
  maxCredentials: number = 4,
): Array<[{ id: string }, { id: string }]> {
  const capped = creds.slice(0, Math.min(maxCredentials, 6));
  const pairs: Array<[{ id: string }, { id: string }]> = [];
  for (let i = 0; i < capped.length; i++) {
    for (let j = i + 1; j < capped.length; j++) {
      pairs.push([capped[i], capped[j]]);
    }
  }
  return pairs;
}

/**
 * Extract up to maxIds unique IDs from a JSON response body.
 * Scans for keys matching /^(id|uuid|pk)$/i in objects/arrays.
 * Returns [] for non-object, null, or missing matching keys.
 */
export function harvestObjectIds(
  body: unknown,
  maxIds: number = 3,
): Array<string | number> {
  if (typeof body !== 'object' || body === null) return [];
  const ids: Array<string | number> = [];

  function scan(obj: Record<string, unknown>): void {
    for (const [key, val] of Object.entries(obj)) {
      if (ID_FIELD_REGEX.test(key) && (typeof val === 'string' || typeof val === 'number')) {
        if (!ids.includes(val)) {
          ids.push(val);
          if (ids.length >= maxIds) return;
        }
      }
    }
  }

  if (Array.isArray(body)) {
    for (const item of body) {
      if (typeof item === 'object' && item !== null) {
        scan(item as Record<string, unknown>);
      }
      if (ids.length >= maxIds) break;
    }
  } else {
    scan(body as Record<string, unknown>);
  }

  return ids.slice(0, maxIds);
}

/**
 * Substitute OpenAPI {param} tokens in pathTemplate with id.
 * Falls back to ?id=<val> appended as query param when no template tokens found.
 */
export function buildAccessUrl(baseUrl: string, pathTemplate: string, id: string | number): string {
  const strId = String(id);
  // Check for template tokens first (regex is global so must test separately)
  const hasTemplate = /\{\w+\}/.test(pathTemplate);
  if (!hasTemplate) {
    // No {param} tokens found — append as query param
    const sep = pathTemplate.includes('?') ? '&' : '?';
    return `${baseUrl}${pathTemplate}${sep}id=${encodeURIComponent(strId)}`;
  }
  const substituted = pathTemplate.replace(PATH_TEMPLATE_REGEX, strId);
  return `${baseUrl}${substituted}`;
}

/**
 * Determine if a path is "list-like" (suitable for harvest).
 * List-like: path has no {param} template tokens.
 * Non-list: /users/{id} or /items/{itemId} — detail endpoint, not useful for harvest.
 */
export function isListLikePath(path: string): boolean {
  return !/\{\w+\}/.test(path);
}

/**
 * Build fetch headers from a decrypted credential.
 * Supports: bearer_jwt, api_key_header, api_key_query, basic.
 * Throws for unsupported types (hmac/oauth2/mtls) — caller logs + skips.
 */
export function buildAuthHeaders(cred: {
  authType: string;
  secret: string;
  apiKeyHeaderName?: string | null;
  basicUsername?: string | null;
}): { headers: Record<string, string>; queryParam?: { name: string; value: string } } {
  switch (cred.authType) {
    case 'bearer_jwt':
      return { headers: { Authorization: `Bearer ${cred.secret}` } };
    case 'api_key_header':
      if (!cred.apiKeyHeaderName) throw new Error('api_key_header requires apiKeyHeaderName');
      return { headers: { [cred.apiKeyHeaderName]: cred.secret } };
    case 'basic': {
      const b64 = Buffer.from(`${cred.basicUsername ?? ''}:${cred.secret}`).toString('base64');
      return { headers: { Authorization: `Basic ${b64}` } };
    }
    case 'api_key_query':
      return { headers: {}, queryParam: { name: cred.apiKeyHeaderName ?? 'api_key', value: cred.secret } };
    default:
      throw new Error(`Auth type ${cred.authType} not supported by BOLA scanner (Phase 13)`);
  }
}

/**
 * Test cross-access: cred B fetches the object harvested by cred A.
 * Returns BolaHit when status < 400 AND body non-empty AND no forbidden text.
 * SAFE-06: masks object ID (prefix-3 + ***), never logs full IDs or secrets.
 */
export async function testCrossAccess(params: {
  endpointId: string;
  endpointPath: string;
  baseUrl: string;
  objectId: string | number;
  credentialAId: string;
  credentialBId: string;
  credentialBHeaders: Record<string, string>;
  credentialBQueryParam?: { name: string; value: string };
}): Promise<BolaHit | null> {
  let url = buildAccessUrl(params.baseUrl, params.endpointPath, params.objectId);
  if (params.credentialBQueryParam) {
    const sep = url.includes('?') ? '&' : '?';
    url = `${url}${sep}${encodeURIComponent(params.credentialBQueryParam.name)}=${encodeURIComponent(params.credentialBQueryParam.value)}`;
  }

  let status: number;
  let body: string;
  try {
    const resp = await fetch(url, { method: 'GET', headers: params.credentialBHeaders });
    status = resp.status;
    body = (await resp.text()).slice(0, 8192);
  } catch (err) {
    log.debug({ err: err instanceof Error ? err.message : err, endpointId: params.endpointId }, 'bola cross-access fetch failed');
    return null;
  }

  if (status >= 400) return null;
  if (!body || body.length === 0) return null;
  if (FORBIDDEN_PATTERNS.test(body)) return null;

  // SAFE-06: mask object ID — prefix-3 + ***
  const maskedObjectId = String(params.objectId).slice(0, 3) + '***';
  log.info(
    { endpointId: params.endpointId, status, credentialAId: params.credentialAId },
    'bola cross-access finding',
  );

  return {
    endpointId: params.endpointId,
    owaspCategory: 'api1_bola_2023',
    severity: 'high',
    title: BOLA_TITLE,
    description: `Credencial B acessou objeto de propriedade de credencial A com status ${status}. Cross-identity object access confirmado em ${params.endpointPath}.`,
    remediation: API_REMEDIATION_TEMPLATES.api1_bola_2023,
    evidence: {
      request: { method: 'GET', url },
      response: { status, bodySnippet: body },
      extractedValues: {
        credentialAId: params.credentialAId,
        credentialBId: params.credentialBId,
        objectId: maskedObjectId,
        endpointPath: params.endpointPath,
      },
      context: 'BOLA cross-identity object access — cred B obtained object owned by cred A',
    },
  };
}
