---
phase: 13
slug: security-testing-active
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-20
---

# Phase 13 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | vitest 4.x (existing) |
| **Config file** | `vitest.config.ts` (root) |
| **Quick run command** | `npx vitest run server/__tests__/apiActive --reporter=default` |
| **Full suite command** | `npx vitest run --reporter=default` |
| **Estimated runtime** | ~45s quick / ~3-4min full |

---

## Sampling Rate

- **After every task commit:** Run `npx vitest run server/__tests__/apiActive --reporter=default`
- **After every plan wave:** Run `npx vitest run server/__tests__/apiActive server/__tests__/apiPassive server/__tests__/apiDiscovery`
- **Before `/gsd:verify-work`:** Full suite must be green + `npx tsc --noEmit` clean in Phase 13 files
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

Plans TBD by planner — this scaffold populates during planning. Expected shape per Phase 12 precedent:

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 13-01-* | 01 | 0 | Nyquist | stubs | `npx vitest run server/__tests__/apiActive` | ❌ W0 | ⬜ pending |
| 13-02-* | 02 | 1 | TEST-03,04,05 | unit | `npx vitest run server/__tests__/apiActive/bola.test.ts server/__tests__/apiActive/bfla.test.ts server/__tests__/apiActive/bopla.test.ts` | ❌ W0 | ⬜ pending |
| 13-03-* | 03 | 1 | TEST-06,07 | unit | `npx vitest run server/__tests__/apiActive/rateLimit.test.ts server/__tests__/apiActive/ssrfNuclei.test.ts` | ❌ W0 | ⬜ pending |
| 13-04-* | 04 | 2 | Orchestrator | integration | `npx vitest run server/__tests__/apiActive/orchestrator.test.ts` | ❌ W0 | ⬜ pending |
| 13-05-* | 05 | 3 | Route + CLI | route/integration | `npx vitest run server/__tests__/apiActive/route.test.ts` + human UAT | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Following Phase 12 pattern (70 it.todo stubs across 10 files + 5 fixtures). Wave 0 installs:

- [ ] `server/__tests__/apiActive/bola.test.ts` — BOLA pair generation, ID harvest, cross-access finding (TEST-03)
- [ ] `server/__tests__/apiActive/bfla.test.ts` — low-priv heuristics, admin path regex, priv escalation (TEST-04)
- [ ] `server/__tests__/apiActive/bopla.test.ts` — seed GET, sensitive key injection, reflection detect, destructive gate (TEST-05)
- [ ] `server/__tests__/apiActive/rateLimit.test.ts` — burst parallelism, 3-signal detection (no 429 / no Retry-After / no X-RateLimit-*) (TEST-06)
- [ ] `server/__tests__/apiActive/ssrfNuclei.test.ts` — URL-like param identification, interactsh URL injection, nuclei args (TEST-07)
- [ ] `server/__tests__/apiActive/orchestrator.test.ts` — stages order + cancel + dryRun integration
- [ ] `server/__tests__/apiActive/optsSchema.test.ts` — `apiActiveTestOptsSchema` defaults, cap ceiling, destructive gate
- [ ] `server/__tests__/apiActive/route.test.ts` — POST /api/v1/apis/:id/test/active (RBAC, Zod validation, 404/400/201)
- [ ] `server/__tests__/apiActive/remediation.test.ts` — 5 new `API_REMEDIATION_TEMPLATES` entries (api1/api3/api4/api5/api7)
- [ ] `server/__tests__/apiActive/credentialsHelper.test.ts` — `listApiCredentials({apiId})` consumer contract (BOLA cred pairing)
- [ ] `server/__tests__/fixtures/api-active/bola-crossaccess-response.json` — mock body with "foreign" object data for cred B
- [ ] `server/__tests__/fixtures/api-active/bfla-admin-success.json` — 200 response on admin-path endpoint
- [ ] `server/__tests__/fixtures/api-active/bopla-reflection-before.json` + `.../bopla-reflection-after.json` — pair showing injection reflected
- [ ] `server/__tests__/fixtures/api-active/rate-limit-burst-responses.json` — 20 x 200 responses without throttle headers
- [ ] `server/__tests__/fixtures/api-active/ssrf-nuclei-interaction.jsonl` — 1 JSONL with `interaction=true` + interactsh-server match

**Framework install:** not needed — vitest 4.x already installed, `vitest.config.ts` already includes `server/**/*.test.ts` pattern.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| BOLA cross-identity finding on real target | TEST-03 | Requires 2 real credentials on a live API with shared object namespace; automated tests can only prove the algorithm against fixtures | 1. Create 2 API creds with different `priority` in same URL pattern. 2. `npx tsx server/scripts/runApiActiveTests.ts --api=<id> --credential=<A> --credential=<B>`. 3. Verify 1+ API1 finding created with evidencing request pair |
| SSRF interactsh callback fires | TEST-07 | Requires outbound network to `oast.me` (ProjectDiscovery public) OR self-hosted interactsh server reachable from appliance | 1. Ensure outbound DNS/HTTP from appliance. 2. Find API endpoint with `url`/`callback`/`webhook` param. 3. Run `npx tsx server/scripts/runApiActiveTests.ts --api=<id>` with default interactsh. 4. Wait up to 30s. 5. Verify API7 finding if SSRF exploitable |
| Rate-limit absence confirmed on real endpoint | TEST-06 | Requires real endpoint that genuinely lacks rate limiting (dev environments often do; production usually has nginx/cloudflare) | 1. Identify authenticated GET endpoint in dev/staging target. 2. Run with `--rate-limit` flag. 3. Verify API4 finding only if all 3 signals absent |
| Destructive gate prevents unintended writes | TEST-05 | Requires confirming BOPLA PUT with `is_admin: true` does NOT fire without `destructiveEnabled=true` | 1. Run `--dry-run` without `--destructive` → BOPLA stage skipped. 2. Run without `--dry-run` without `--destructive` → BOPLA stage skipped with log. 3. Run `--destructive --dry-run` → BOPLA fires against fixtures only |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (15 stubs + 6 fixtures)
- [ ] No watch-mode flags in commands (use `vitest run`, not `vitest`)
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter after planner validation

**Approval:** pending
