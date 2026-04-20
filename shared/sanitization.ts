import type { ApiFindingEvidence } from './schema';

// ============================================================================
// Constants (FIND-02)
// ============================================================================

/**
 * BODY_TRUNCATE_LIMIT — max bytes for evidence.request.bodySnippet and
 * evidence.response.bodySnippet. Carry-forward de Phase 9 ApiFindingEvidence
 * constraint (bodySnippet ≤ 8KB).
 */
export const BODY_TRUNCATE_LIMIT = 8192;

export const BODY_TRUNCATE_MARKER = '[... truncated ...]';

/**
 * REDACT_HEADERS — lista case-insensitive de headers de auth/token a serem
 * removidos de evidence.request.headers antes de persistência. Match é feito
 * via .toLowerCase() comparison (casos como "Authorization" e "authorization"
 * ambos removidos). Exato 9 entries conforme 14-CONTEXT.md decisions.
 */
export const REDACT_HEADERS = [
  'authorization',
  'x-api-key',
  'x-auth-token',
  'api-key',
  'apikey',
  'x-access-token',
  'cookie',
  'x-csrf-token',
  'token',
] as const;

/**
 * PII_PATTERNS — regex const compilados 1x no module init. Preserve context
 * onde aplicável (email preserva domain, credit card preserva last-4).
 *   - cpfFormatted: 11 dígitos brasileiros formatado ###.###.###-##
 *   - cpfPlain: 11 dígitos sem pontuação (matched after formatted to avoid overlap)
 *   - cnpj: 14 dígitos formatado ##.###.###/####-##
 *   - email: user@domain → ***@domain (preserva após @)
 *   - creditCardDashed: PAN 16 dígitos com separadores → preserve last 4
 *   - creditCardPlain: PAN 16 dígitos consecutivos → preserve last 4
 */
export const PII_PATTERNS = {
  cpfFormatted: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g,
  cpfPlain: /\b\d{11}\b/g,
  cnpj: /\b\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}\b/g,
  email: /([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g,
  creditCardDashed: /\b(\d{4})[- ](\d{4})[- ](\d{4})[- ](\d{4})\b/g,
  creditCardPlain: /\b\d{12}(\d{4})\b/g,
} as const;

// ============================================================================
// sanitizeApiFinding (FIND-02)
// ============================================================================

export interface SanitizeOptions {
  piiMaskPatterns?: RegExp[]; // override default patterns (optional, rarely used)
}

/**
 * sanitizeApiFinding — 3-layer protection before persistence:
 *   1. Redact auth headers (REDACT_HEADERS case-insensitive)
 *   2. Truncate bodySnippets to BODY_TRUNCATE_LIMIT (8KB) + append marker
 *   3. Mask PII (CPF, CNPJ, email, credit card) in bodySnippets + extractedValues
 *
 * Pure function: returns new object, does not mutate input.
 * Fail-open: on regex/parse error, logs warning (console.warn) and returns
 *   the original evidence unmodified. Findings MUST persist even if
 *   sanitization fails; blocking the journey is worse than best-effort sanitize.
 *
 * Scope fields processed:
 *   - evidence.request.headers (redaction only; no PII mask)
 *   - evidence.request.bodySnippet (truncate + PII mask)
 *   - evidence.response.bodySnippet (truncate + PII mask)
 *   - evidence.extractedValues.* (PII mask on string values; keys preserved)
 *
 * @example
 * // Wave 3 route handler invocation pattern:
 * const sanitized = findings.map(f => ({
 *   ...f,
 *   evidence: sanitizeApiFinding(f.evidence),
 * }));
 * for (const finding of sanitized) {
 *   await storage.upsertApiFindingByKey(finding);
 * }
 */
export function sanitizeApiFinding(
  evidence: ApiFindingEvidence,
  _options: SanitizeOptions = {},
): ApiFindingEvidence {
  try {
    const sanitized: ApiFindingEvidence = { ...evidence };

    // Layer 1: Header redaction (request.headers only — response headers not redacted per CONTEXT.md)
    if (evidence.request?.headers) {
      sanitized.request = {
        ...evidence.request,
        headers: redactAuthHeaders(evidence.request.headers),
      };
    }

    // Layer 2+3: Truncate + PII mask on request.bodySnippet
    if (evidence.request?.bodySnippet !== undefined) {
      sanitized.request = {
        ...(sanitized.request ?? evidence.request),
        bodySnippet: truncateAndMask(evidence.request.bodySnippet),
      };
    }

    // Layer 2+3: Truncate + PII mask on response.bodySnippet
    if (evidence.response?.bodySnippet !== undefined) {
      sanitized.response = {
        ...evidence.response,
        bodySnippet: truncateAndMask(evidence.response.bodySnippet),
      };
    }

    // Layer 3 only: extractedValues (no truncation — usually small keyed values)
    if (evidence.extractedValues) {
      sanitized.extractedValues = maskExtractedValues(evidence.extractedValues);
    }

    return sanitized;
  } catch (err) {
    // Fail-open: log + return original (findings must not be lost)
    // eslint-disable-next-line no-console
    console.warn('[sanitizeApiFinding] sanitization failed, using original evidence (fail-open)', {
      error: err instanceof Error ? err.message : String(err),
    });
    return evidence;
  }
}

// ============================================================================
// Internal helpers (not exported)
// ============================================================================

function redactAuthHeaders(headers: Record<string, string>): Record<string, string> {
  const result: Record<string, string> = {};
  const redactSet = new Set<string>(REDACT_HEADERS.map((h) => h.toLowerCase()));
  for (const [key, value] of Object.entries(headers)) {
    if (!redactSet.has(key.toLowerCase())) {
      result[key] = value;
    }
    // sensitive headers simply omitted (not replaced with '***' — avoids accidental leak in logs)
  }
  return result;
}

function truncateAndMask(input: string): string {
  let output = input;
  if (output.length > BODY_TRUNCATE_LIMIT) {
    output = output.slice(0, BODY_TRUNCATE_LIMIT) + BODY_TRUNCATE_MARKER;
  }
  return maskPiiInString(output);
}

function maskPiiInString(input: string): string {
  let output = input;
  // Order matters: formatted patterns first so plain \d{11} doesn't swallow CPF formatted.
  // Use source + flags to create fresh regex (avoids lastIndex statefulness on global /g).
  output = output.replace(new RegExp(PII_PATTERNS.cpfFormatted.source, 'g'), '***.***.***-**');
  output = output.replace(new RegExp(PII_PATTERNS.cnpj.source, 'g'), '**.***.***/****-**');
  output = output.replace(new RegExp(PII_PATTERNS.creditCardDashed.source, 'g'), '****-****-****-$4');
  output = output.replace(new RegExp(PII_PATTERNS.creditCardPlain.source, 'g'), '************$1');
  output = output.replace(new RegExp(PII_PATTERNS.email.source, 'g'), '***@$2');
  // cpfPlain last — avoids masking digits already replaced by cpfFormatted
  output = output.replace(new RegExp(PII_PATTERNS.cpfPlain.source, 'g'), '***********');
  return output;
}

function maskExtractedValues(values: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(values)) {
    if (typeof value === 'string') {
      result[key] = maskPiiInString(value);
    } else {
      // leave non-string values (numbers, booleans, nested objects) as-is;
      // deep traversal deferred (14-CONTEXT.md explicit — extractedValues is shallow by convention)
      result[key] = value;
    }
  }
  return result;
}
