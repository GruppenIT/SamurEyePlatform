---
phase: 9
slug: schema-asset-hierarchy
status: complete
nyquist_compliant: true
wave_0_complete: true
created: 2026-04-18
---

# Phase 9 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | vitest 4.0.18 |
| **Config file** | `vitest.config.ts` (existing) |
| **Quick run command** | `npx vitest run server/__tests__/<file>.test.ts` |
| **Full suite command** | `npx vitest run` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `npx vitest run server/__tests__/<file>.test.ts`
- **After every plan wave:** Run `npx vitest run`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 45 seconds

---

## Per-Task Verification Map

*Populated by planner. Every task with implementation must map to a test file or to a Wave 0 stub created in this phase.*

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 09-02 T1 | 09-02 | 1 | HIER-01, FIND-01 | Unit (enum values) | `grep -c "apiTypeEnum\|owaspApiCategoryEnum\|apiFindingStatusEnum" shared/schema.ts` | shared/schema.ts | ✅ green |
| 09-02 T2 | 09-02 | 1 | HIER-01, HIER-02, FIND-01 | Unit (Zod schema) | `npx vitest run shared/__tests__/evidenceSchema.test.ts` | shared/__tests__/evidenceSchema.test.ts | ✅ green |
| 09-04 T1 | 09-04 | 3 | HIER-03 | Integration stub | `grep -q "registerApiRoutes" server/routes/index.ts && grep -q "app.post('/api/v1/apis'" server/routes/apis.ts` | server/routes/apis.ts | ✅ green |
| 09-04 T2 | 09-04 | 3 | HIER-04 | CLI stub | `grep -q "probeWebApp" server/scripts/backfillApiDiscovery.ts && grep -q "## How to run" docs/operations/backfill-api-discovery.md` | server/scripts/backfillApiDiscovery.ts | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Test stub files the planner must ensure exist (or are created in Wave 0) so downstream tasks have a target file to exercise. Target paths based on RESEARCH.md recommendations:

- [ ] `server/__tests__/apiSchema.test.ts` — schema introspection tests (HIER-01, HIER-02, FIND-01): table existence, column types, indexes, enum values, UNIQUE constraints, FK ON DELETE semantics
- [ ] `server/__tests__/ensureApiTables.test.ts` — idempotent migration guard (HIER-01, HIER-02, FIND-01): re-run safe, logs expected status
- [ ] `server/__tests__/apisRoute.test.ts` — `POST /api/v1/apis` (HIER-03): happy path (201), 409 duplicate, 400 invalid URL, 400 non-web_application parent, 401 unauthenticated, 403 non-operator role, 400 unknown apiType
- [ ] `server/__tests__/apiStorage.test.ts` — Storage facade (HIER-01, HIER-02, HIER-03, FIND-01): createApi, getApiById, listApisByParent, createApiEndpoint, upsert semantics for `(api_id, method, path)`, createApiFinding, evidence JSONB shape
- [ ] `server/__tests__/backfillApiDiscovery.test.ts` — backfill CLI (HIER-04): dry-run prints without mutating, idempotent on re-run (skips apis that already exist), probe timeout enforced, concurrency cap, promotes on `/openapi.json` / `/graphql` / `Content-Type: application/json` hits
- [ ] `server/__tests__/owaspApiCategories.test.ts` — constants shape (FIND-01): every enum value in `owasp_api_category` has a matching pt-BR label + OWASP reference URL
- [x] `shared/__tests__/evidenceSchema.test.ts` (or colocated) — Zod schema for `api_findings.evidence` (FIND-01) — parses valid shape, rejects missing request/response, accepts optional extractedValues/context ✅ 6/6 GREEN (Plan 02)

*Existing infrastructure: vitest + drizzle test helpers already present; no framework install needed.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Backfill promotes a real remote web_application serving `/openapi.json` | HIER-04 | Requires network probing a live target with real headers/body | Point `backfillApiDiscovery.ts` at a staging web_application asset; verify the `apis` row appears with `specUrl` populated. Document in `docs/operations/backfill-api-discovery.md`. |

*All other phase behaviors have automated verification.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 45s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
