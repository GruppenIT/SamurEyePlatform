---
phase: 13-security-testing-active
plan: "01"
subsystem: security-testing-active
tags: [schema, test-stubs, fixtures, zod, wave-0, nyquist]
dependency_graph:
  requires:
    - 12-01-SUMMARY.md (apiPassiveTestOptsSchema + PassiveTestResult as template)
  provides:
    - shared/schema.ts: apiActiveTestOptsSchema + ApiActiveTestOpts + ActiveTestResult + BOPLA_SENSITIVE_KEYS + BoplaSensitiveKey
    - server/__tests__/apiActive/: 10 stub files (139 it.todo)
    - server/__tests__/fixtures/api-active/: 6 deterministic dryRun fixtures
  affects:
    - Wave 1 (13-02): bola.ts + bfla.ts + bopla.ts + rateLimit.ts + ssrfNuclei.ts consume schema + stubs
    - Wave 2 (13-03): orchestrator imports ApiActiveTestOpts + ActiveTestResult
    - Wave 3 (13-04): route handler imports apiActiveTestOptsSchema for Zod validation
    - Phase 15: ActiveTestResult is the public journey contract
tech_stack:
  added: []
  patterns:
    - Nyquist Wave 0 — stubs before implementation (mirrors Phase 12 Wave 0)
    - TDD RED for Task 1 — stub file created before schema implementation
    - .strict() on all Zod sub-objects (root + stages + rateLimit + ssrf + bola = 5 occurrences)
    - as const array for BOPLA_SENSITIVE_KEYS — preserves tuple type inference
key_files:
  created:
    - shared/schema.ts (added 82 lines: BOPLA_SENSITIVE_KEYS + apiActiveTestOptsSchema + ApiActiveTestOpts + ActiveTestResult + BoplaSensitiveKey)
    - server/__tests__/apiActive/optsSchema.test.ts
    - server/__tests__/apiActive/bola.test.ts
    - server/__tests__/apiActive/bfla.test.ts
    - server/__tests__/apiActive/bopla.test.ts
    - server/__tests__/apiActive/rateLimit.test.ts
    - server/__tests__/apiActive/ssrfNuclei.test.ts
    - server/__tests__/apiActive/orchestrator.test.ts
    - server/__tests__/apiActive/route.test.ts
    - server/__tests__/apiActive/remediation.test.ts
    - server/__tests__/apiActive/credentialsHelper.test.ts
    - server/__tests__/fixtures/api-active/bola-crossaccess-response.json
    - server/__tests__/fixtures/api-active/bfla-admin-success.json
    - server/__tests__/fixtures/api-active/bopla-reflection-before.json
    - server/__tests__/fixtures/api-active/bopla-reflection-after.json
    - server/__tests__/fixtures/api-active/rate-limit-burst-responses.json
    - server/__tests__/fixtures/api-active/ssrf-nuclei-interaction.jsonl
  modified: []
decisions:
  - "stagesRun uses snake_case 'rate_limit' (not camelCase rateLimit) for consistency with Phase 12 PassiveTestResult stage-name convention"
  - "BOPLA_SENSITIVE_KEYS declared as const array (not enum) — preserves literal tuple type for BoplaSensitiveKey derivation"
  - "ActiveTestResult as TypeScript interface (not z.infer) — allows extension by Waves 1-3 without changing Zod schema boundary (mirrors Phase 12 PassiveTestResult pattern)"
  - "describedBy fields in fixtures avoid test-string contamination (e.g., '429', 'Retry-After', 'is_admin' not in before fixture) to pass grep-based acceptance criteria"
metrics:
  duration: "5m"
  completed_date: "2026-04-20"
  tasks_completed: 3
  files_created: 17
  files_modified: 1
  total_files: 18
---

# Phase 13 Plan 01: Active Testing Wave 0 Foundation Summary

**One-liner:** Zod schema `apiActiveTestOptsSchema` + `BOPLA_SENSITIVE_KEYS` const + 10 `it.todo` stub files + 6 dryRun fixtures — scaffolding for 5 active security scanners (BOLA/BFLA/BOPLA/RateLimit/SSRF).

## What Was Built

Wave 0 Nyquist foundation for Phase 13. Zero business logic — pure scaffolding for Waves 1-3.

### Task 1: Zod Schema + Types + Constant (shared/schema.ts)

Added at end of `shared/schema.ts` after the Phase 12 `PassiveTestResult` block:

- **`BOPLA_SENSITIVE_KEYS`** — `as const` array of exactly 10 sensitive property names (`is_admin`, `isAdmin`, `admin`, `role`, `roles`, `permissions`, `superuser`, `owner`, `verified`, `email_verified`). Source-of-truth shared between `bopla.ts` scanner and tests.
- **`BoplaSensitiveKey`** — derived type `typeof BOPLA_SENSITIVE_KEYS[number]`.
- **`apiActiveTestOptsSchema`** — Zod schema with `.strict()` on root + all 4 sub-objects (`stages`, `rateLimit`, `ssrf`, `bola`). Mirrors `apiPassiveTestOptsSchema` Phase 12 pattern. Contains 5 stage toggles + `destructiveEnabled` gate + ceiling-enforced numeric caps (`burstSize` max 50, `maxCredentials` max 6, `maxIdsPerEndpoint` max 5, `rateLimit.endpointIds` max 5).
- **`ApiActiveTestOpts`** — type via `z.infer`.
- **`ActiveTestResult`** — TypeScript interface (not `z.infer`) with `credentialsUsed` field in addition to the standard result shape. `stagesRun` union uses snake_case `'rate_limit'` for consistency.

`tsc --noEmit` clean — zero new errors.

### Task 2: 10 Test Stub Files (server/__tests__/apiActive/)

10 files, 139 `it.todo` stubs (Phase 12 had 69 — 2× coverage density for 5 vectors). Each file maps to a Wave 1-3 implementation target:

| File | Stubs | Wave | Requirement |
|------|-------|------|-------------|
| optsSchema.test.ts | 16 | 0 | TEST-03..07 |
| bola.test.ts | 16 | 1 | TEST-03 |
| bfla.test.ts | 14 | 1 | TEST-04 |
| bopla.test.ts | 16 | 1 | TEST-05 |
| rateLimit.test.ts | 14 | 1 | TEST-06 |
| ssrfNuclei.test.ts | 18 | 1 | TEST-07 |
| orchestrator.test.ts | 15 | 2 | TEST-03..07 |
| route.test.ts | 16 | 3 | TEST-03..07 |
| remediation.test.ts | 7 | 1 | TEST-03..07 |
| credentialsHelper.test.ts | 7 | 1/2 | TEST-03..04 |

`npx vitest run server/__tests__/apiActive` → 10 files skipped, 139 todo, 0 errors.

### Task 3: 6 dryRun Fixtures (server/__tests__/fixtures/api-active/)

| File | Purpose | Scanner |
|------|---------|---------|
| bola-crossaccess-response.json | BOLA positive: cred B sees cred A's object (status 200, populated body) | BOLA |
| bfla-admin-success.json | BFLA positive: low-priv cred on `/admin/users` returns 200 | BFLA |
| bopla-reflection-before.json | Seed response before injection (no sensitive keys) | BOPLA |
| bopla-reflection-after.json | After PUT with `is_admin:true` injection — key reflected | BOPLA |
| rate-limit-burst-responses.json | 20 x 200 responses, no throttle signals in headers/status | RateLimit |
| ssrf-nuclei-interaction.jsonl | 1 valid Nuclei JSONL line with `interactsh-server` + `interaction-type=http` | SSRF |

All 5 JSON files pass `JSON.parse`. JSONL has exactly 1 valid JSON line.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed test-string contamination from fixture `describedBy` fields**
- **Found during:** Task 3 acceptance verification
- **Issue:** Plan provided exact `describedBy` strings that contained `"429"`, `"Retry-After"`, `"X-RateLimit-*"` in `rate-limit-burst-responses.json` and `"is_admin"` in `bopla-reflection-before.json`. These caused the plan's own grep-based acceptance criteria (`grep -c "429\|Retry-After\|X-RateLimit..." = 0`) to fail.
- **Fix:** Rewrote `describedBy` to use neutral language without the strings being tested for absence. Semantics preserved.
- **Files modified:** `rate-limit-burst-responses.json`, `bopla-reflection-before.json`
- **Commit:** eae7cea

## Self-Check: PASSED

| Check | Result |
|-------|--------|
| shared/schema.ts exists | FOUND |
| server/__tests__/apiActive/ exists | FOUND |
| server/__tests__/fixtures/api-active/ exists | FOUND |
| 10 stub files | VERIFIED |
| 6 fixture files | VERIFIED |
| apiActiveTestOptsSchema exported (line 1975) | VERIFIED |
| ApiActiveTestOpts exported (line 2001) | VERIFIED |
| ActiveTestResult exported (line 2010) | VERIFIED |
| BOPLA_SENSITIVE_KEYS exported (line 1947) | VERIFIED |
| BoplaSensitiveKey exported (line 1960) | VERIFIED |
| tsc --noEmit clean | VERIFIED |
| vitest run 139 todo 0 errors | VERIFIED |
| Commits d789f1b + 0a164b5 + eae7cea | VERIFIED |
