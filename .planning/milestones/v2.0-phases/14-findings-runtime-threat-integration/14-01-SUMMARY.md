---
phase: 14-findings-runtime-threat-integration
plan: "01"
subsystem: sanitization
tags: [sanitization, pii, security, shared, pure-function, find-02]
dependency_graph:
  requires:
    - shared/schema.ts (ApiFindingEvidence type)
  provides:
    - shared/sanitization.ts (sanitizeApiFinding, PII_PATTERNS, REDACT_HEADERS, BODY_TRUNCATE_LIMIT)
  affects:
    - Wave 3 (14-04): server/routes/apis.ts POST /test/passive + POST /test/active handlers
tech_stack:
  added: []
  patterns:
    - pure function with fail-open error handling
    - module-level regex constants to avoid /g lastIndex statefulness
    - shallow clone via spread + field override (not deep clone)
key_files:
  created:
    - shared/sanitization.ts
    - server/__tests__/sanitization.test.ts
  modified: []
decisions:
  - "Use new RegExp(pattern.source, 'g') per call instead of reusing /g constants to avoid lastIndex statefulness bugs"
  - "console.warn in fail-open path (not pino) — shared/ is runtime-agnostic, no logger dependency"
  - "cpfFormatted applied before cpfPlain to prevent plain \b\d{11}\b from swallowing formatted CPF digits"
  - "extractedValues traversal is shallow only (non-string values passed through) — explicit per CONTEXT.md decisions"
metrics:
  duration: "4 minutes"
  completed: "2026-04-20"
  tasks: 3
  files: 2
---

# Phase 14 Plan 01: sanitizeApiFinding Foundation (FIND-02) Summary

Wave 0 sanitization foundation — pure function `sanitizeApiFinding()` in `shared/sanitization.ts` with header redaction, 8KB body truncation, and Brazilian PII masking (CPF/CNPJ/email/credit card). Test scaffold with 10 `it.todo` stubs ready for Wave 3 promotion.

## What Was Built

### Function Signature

```typescript
// shared/sanitization.ts
export function sanitizeApiFinding(
  evidence: ApiFindingEvidence,
  _options?: SanitizeOptions,
): ApiFindingEvidence
```

### Options Interface

```typescript
export interface SanitizeOptions {
  piiMaskPatterns?: RegExp[]; // override default patterns (optional, rarely used)
}
```

### Exported Constants

```typescript
export const BODY_TRUNCATE_LIMIT = 8192;
export const BODY_TRUNCATE_MARKER = '[... truncated ...]';
```

## REDACT_HEADERS (9 entries)

```typescript
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
```

Match is case-insensitive via `.toLowerCase()` comparison. Headers simply omitted from output (not replaced with `***`) to avoid accidental leakage in logs.

## PII Patterns (4 types, 6 regexes)

| Pattern | Regex | Replacement |
|---|---|---|
| CPF formatted | `/\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g` | `***.***.***-**` |
| CPF plain | `/\b\d{11}\b/g` | `***********` |
| CNPJ | `/\b\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}\b/g` | `**.***.***/****-**` |
| Email | `/([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g` | `***@$2` (domain preserved) |
| Credit card (dashed) | `/\b(\d{4})[- ](\d{4})[- ](\d{4})[- ](\d{4})\b/g` | `****-****-****-$4` (last-4 preserved) |
| Credit card (plain) | `/\b\d{12}(\d{4})\b/g` | `************$1` (last-4 preserved) |

Note: CPF formatted is applied before CPF plain to prevent the plain `\d{11}` pattern from matching digits inside an already-formatted CPF string.

## Wave 3 Invocation Pattern (Route Handler)

```typescript
// server/routes/apis.ts — POST /api/v1/apis/:id/test/passive (and /test/active)
import { sanitizeApiFinding } from '../../shared/sanitization';

const sanitized = findings.map(f => ({
  ...f,
  evidence: sanitizeApiFinding(f.evidence),
}));
for (const finding of sanitized) {
  await storage.upsertApiFindingByKey(finding);
}
```

## Known Limitations

1. **Shallow `extractedValues` traversal** — Only string-typed top-level values are masked. Nested objects, arrays, or numbers within `extractedValues` are passed through unchanged. This is explicit per CONTEXT.md decisions; recursive traversal deferred.
2. **Brazil-specific PII only** — CPF, CNPJ are Brazilian documents. No SSN (US), SIN (Canada), ABN (Australia), etc. Global deployment would require locale-configurable patterns.
3. **No response headers redaction** — Only `evidence.request.headers` are redacted. Response headers are left as-is (response headers rarely contain auth tokens by convention; can be extended if needed).
4. **Regex precision** — CPF plain (`\b\d{11}\b`) can theoretically match 11-digit numeric strings that are not CPFs (e.g., phone numbers). This is intentional conservative behavior — false-positive masking is preferable to false-negative leakage.
5. **No recursive `extractedValues` traversal** — Nested JSON within extracted values is not traversed. `maskPiiInString` only processes top-level string values.

## Test Scaffold

`server/__tests__/sanitization.test.ts` contains 10 `it.todo` stubs under `describe('sanitizeApiFinding (FIND-02)')`. Vitest collects 10 todo tests, 0 executable tests. Wave 3 (14-04) or subsequent plans can promote stubs to `it()` with real assertions.

## Smoke Verification

All 11 manual checks passed:
- Authorization, X-API-Key headers removed; User-Agent preserved
- CPF `123.456.789-00` → `***.***.***-**` in request body
- Email `foo@example.com` → `***@example.com` in request body
- Credit card `4532-1234-5678-9090` → `****-****-****-9090` in request body
- Response body (10KB) truncated to ≤8192 bytes + `[... truncated ...]` marker
- CNPJ `12.345.678/0001-99` → `**.***.***/****-**` in extractedValues
- Non-string `user_id: 42` preserved unchanged
- Input object NOT mutated (deep equality via JSON.stringify confirmed)

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED

- FOUND: shared/sanitization.ts (commit 7cb2489)
- FOUND: server/__tests__/sanitization.test.ts (commit 8805bfb)
- TypeScript: zero errors in sanitization files
- Vitest: 10 todo tests collected, 0 executable
- Smoke: SMOKE OK (all 11 checks true)
