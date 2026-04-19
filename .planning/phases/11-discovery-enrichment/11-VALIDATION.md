---
phase: 11
slug: discovery-enrichment
status: planned
nyquist_compliant: true
wave_0_complete: false
created: 2026-04-19
---

# Phase 11 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | vitest 4.0.18 |
| **Config file** | vitest.config.ts |
| **Quick run command** | `npm test -- --run server/__tests__/apiDiscovery/` |
| **Full suite command** | `npm test` |
| **Estimated runtime** | ~45 seconds full suite; ~5s per apiDiscovery sub-file |

---

## Sampling Rate

- **After every task commit:** Run `npm test -- --run server/__tests__/apiDiscovery/<changed>.test.ts` (< 5 seconds)
- **After every plan wave:** Run `npm test -- --run server/__tests__/apiDiscovery/ shared/__tests__/discoverApiOptsSchema.test.ts` (< 15 seconds)
- **Before `/gsd:verify-work`:** Full `npm test` must be green
- **Max feedback latency:** 15 seconds per wave

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 11-01-T1 | 01 | 0 | DISC-01..06 + ENRH-01..03 | unit (stubs) | `npm test -- --run server/__tests__/apiDiscovery/` | Task creates | ⬜ |
| 11-01-T2 | 01 | 0 | (opts schema) | unit | `npm test -- --run shared/__tests__/discoverApiOptsSchema.test.ts` | Task creates | ⬜ |
| 11-01-T3 | 01 | 0 | ENRH-01 (columns) | type-check | `npm test` | Task creates | ⬜ |
| 11-02-T1 | 02 | 1 | (shared infra) | unit | `npm test -- --run server/__tests__/apiDiscovery/preflight.test.ts` | Task creates | ⬜ |
| 11-02-T2 | 02 | 1 | DISC-06 | unit | `npm test -- --run server/__tests__/apiDiscovery/specHash.test.ts` | Plan 11-01 creates | ⬜ |
| 11-02-T3 | 02 | 1 | DISC-04 (dedupe) + ENRH-01/02/03 (persist) | unit | `npm test -- --run server/__tests__/apiDiscovery/dedupeUpsert.test.ts` | Plan 11-01 creates | ⬜ |
| 11-03-T1 | 03 | 2 | DISC-01 + DISC-02 | unit + integration | `npm test -- --run server/__tests__/apiDiscovery/specFetch.test.ts server/__tests__/apiDiscovery/openapi.test.ts` | Plan 11-01 creates | ⬜ |
| 11-03-T2 | 03 | 2 | DISC-03 | unit | `npm test -- --run server/__tests__/apiDiscovery/graphql.test.ts` | Plan 11-01 creates | ⬜ |
| 11-04-T1 | 04 | 2 | DISC-04 | unit (mocked spawn) | `npm test -- --run server/__tests__/apiDiscovery/katana.test.ts` | Plan 11-01 creates | ⬜ |
| 11-04-T2 | 04 | 2 | DISC-05 | unit (mocked spawn) | `npm test -- --run server/__tests__/apiDiscovery/kiterunner.test.ts` | Plan 11-01 creates | ⬜ |
| 11-05-T1 | 05 | 2 | ENRH-01 + ENRH-02 | unit (mocked spawn) | `npm test -- --run server/__tests__/apiDiscovery/httpx.test.ts` | Plan 11-01 creates | ⬜ |
| 11-05-T2 | 05 | 2 | ENRH-03 | unit (mocked spawn + fs) | `npm test -- --run server/__tests__/apiDiscovery/arjun.test.ts` | Plan 11-01 creates | ⬜ |
| 11-06-T1 | 06 | 3 | DISC-01..06 + ENRH-01..03 (orchestration) | integration (mocked scanners) | `npm test -- --run server/__tests__/apiDiscovery/orchestrator.test.ts` | Plan 11-01 creates | ⬜ |
| 11-06-T2 | 06 | 3 | DISC-06 (drift) | integration (mocked scanners) | `npm test -- --run server/__tests__/apiDiscovery/drift.test.ts` | Plan 11-01 creates | ⬜ |
| 11-07-T1 | 07 | 4 | (route) | route (in-process express) | `npm test -- --run server/__tests__/apiDiscovery/route.test.ts` | Plan 11-01 creates | ⬜ |
| 11-07-T2 | 07 | 4 | (CLI + docs) | file existence + CLI smoke | `ls server/scripts/runApiDiscovery.ts docs/operations/run-api-discovery.md && npx tsx --env-file=.env server/scripts/runApiDiscovery.ts --help` | Task creates | ⬜ |
| 11-07-T3 | 07 | 4 | DISC-01..06 + ENRH-01..03 (e2e) | manual smoke (checkpoint) | 6-step curl/CLI verification against petstore3.swagger.io | N/A | ⬜ |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

**13 test files + 7 fixtures + 1 shared schema test — all created by Plan 11-01 Task 1:**

- [ ] `server/__tests__/apiDiscovery/specFetch.test.ts` (7 it.todo → DISC-01)
- [ ] `server/__tests__/apiDiscovery/openapi.test.ts` (7 it.todo → DISC-02)
- [ ] `server/__tests__/apiDiscovery/graphql.test.ts` (6 it.todo → DISC-03)
- [ ] `server/__tests__/apiDiscovery/katana.test.ts` (8 it.todo → DISC-04)
- [ ] `server/__tests__/apiDiscovery/kiterunner.test.ts` (6 it.todo → DISC-05)
- [ ] `server/__tests__/apiDiscovery/specHash.test.ts` (5 it.todo → DISC-06 hash)
- [ ] `server/__tests__/apiDiscovery/drift.test.ts` (4 it.todo → DISC-06 drift)
- [ ] `server/__tests__/apiDiscovery/httpx.test.ts` (8 it.todo → ENRH-01 + ENRH-02)
- [ ] `server/__tests__/apiDiscovery/arjun.test.ts` (6 it.todo → ENRH-03)
- [ ] `server/__tests__/apiDiscovery/orchestrator.test.ts` (7 it.todo → cross-cutting)
- [ ] `server/__tests__/apiDiscovery/dedupeUpsert.test.ts` (6 it.todo → storage dedupe)
- [ ] `server/__tests__/apiDiscovery/route.test.ts` (8 it.todo → route)
- [ ] `shared/__tests__/discoverApiOptsSchema.test.ts` (7 it.todo → Zod schema)
- [ ] Fixture: `openapi-2.0.json` (~40 lines)
- [ ] Fixture: `openapi-3.0.json` (~50 lines with nullable + oneOf)
- [ ] Fixture: `openapi-3.1.json` (~40 lines with type:[string,null])
- [ ] Fixture: `graphql-introspection.json` (~60 lines with Query+Mutation+types)
- [ ] Fixture: `katana-jsonl.txt` (5 JSONL lines)
- [ ] Fixture: `httpx-json.txt` (5 JSONL lines, mix of status codes)
- [ ] Fixture: `kiterunner-json.txt` (5 JSONL lines with 200/401/403 hits)
- [ ] Fixture: `arjun-output.json` (dict-keyed-by-URL, 3+ params)

Plus a new test file created by Plan 11-02 Task 1: `server/__tests__/apiDiscovery/preflight.test.ts` (3 tests).

**Total Wave 0 artifacts: 14 test files + 7 fixtures = 21 files.**

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| End-to-end pipeline against real target | DISC-01..06 + ENRH-01..03 | Binary behavior varies by network + target; automated tests mock spawn | Plan 11-07 Task 3 checkpoint: register petstore3.swagger.io API, run `runApiDiscovery.ts --api=<id> --dry-run`, assert endpoints materialized |
| No secrets in logs | SAFE-06 (pre-phase) | Pino redaction covers known paths; visual audit required to catch leaks | `grep -Ei 'bearer [a-z0-9.]+\|eyJ[a-z0-9._-]+' logs/*.log` returns no matches after a discovery run with OAuth2/bearer cred |
| `routes-large.kite` present and usable | DISC-05 (Phase 8 handoff) | Manual disk check — not worth automating in every test | `ls -la /opt/samureye/wordlists/routes-large.kite` exits 0 and size ≥ 100MB |
| Chromium installed for headless katana | DISC-04 (optional) | Install-time concern; not a runtime test | `which chromium-browser` exits 0 before using `--katana-headless` |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (14 test files + 7 fixtures declared in Plan 11-01)
- [x] No watch-mode flags (every automated command uses `--run`)
- [x] Feedback latency < 45s (apiDiscovery subsuite < 15s; full suite < 45s)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved — 2026-04-19
