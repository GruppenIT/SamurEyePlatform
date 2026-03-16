---
phase: 1
slug: parser-foundation
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-16
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | vitest ^4.0.18 |
| **Config file** | `vitest.config.ts` (root) |
| **Quick run command** | `npx vitest run server/__tests__/<relevant>.test.ts` |
| **Full suite command** | `npx vitest run` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `npx vitest run server/__tests__/<relevant>.test.ts`
- **After every plan wave:** Run `npx vitest run`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 01-01-01 | 01 | 1 | PARS-11 | snapshot | `npx vitest run` | ❌ W0 | ⬜ pending |
| 01-01-02 | 01 | 1 | PARS-01 | unit | `npx vitest run server/__tests__/nmapParser.test.ts` | ❌ W0 | ⬜ pending |
| 01-01-03 | 01 | 1 | PARS-03 | unit (snapshot) | `npx vitest run server/__tests__/nmapParser.test.ts` | ❌ W0 | ⬜ pending |
| 01-01-04 | 01 | 1 | PARS-04 | unit (snapshot) | `npx vitest run server/__tests__/nmapParser.test.ts` | ❌ W0 | ⬜ pending |
| 01-02-01 | 02 | 1 | PARS-02 | unit (snapshot) | `npx vitest run server/__tests__/nmapParser.test.ts` | ❌ W0 | ⬜ pending |
| 01-02-02 | 02 | 1 | PARS-05 | unit | `npx vitest run server/__tests__/nucleiParser.test.ts` | ❌ W0 | ⬜ pending |
| 01-02-03 | 02 | 1 | PARS-06 | unit (snapshot) | `npx vitest run server/__tests__/nucleiParser.test.ts` | ❌ W0 | ⬜ pending |
| 01-03-01 | 03 | 2 | PARS-07 | unit (fixture) | `npx vitest run server/__tests__/adParser.test.ts` | ❌ W0 | ⬜ pending |
| 01-03-02 | 03 | 2 | PARS-08 | unit (snapshot) | `npx vitest run server/__tests__/adParser.test.ts` | ❌ W0 | ⬜ pending |
| 01-03-03 | 03 | 2 | PARS-09 | unit (snapshot) | `npx vitest run server/__tests__/edrParser.test.ts` | ❌ W0 | ⬜ pending |
| 01-03-04 | 03 | 2 | PARS-10 | unit | `npx vitest run` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `npm install fast-xml-parser` — not yet in package.json
- [ ] `server/__tests__/fixtures/nmap/` — directory + synthetic XML files
- [ ] `server/__tests__/fixtures/nuclei/` — directory + synthetic JSONL files
- [ ] `server/__tests__/fixtures/ad/` — directory + synthetic JSON files
- [ ] `server/__tests__/fixtures/edr/` — directory + synthetic JSON files
- [ ] `server/__tests__/nmapParser.test.ts` — baseline snapshots (PARS-11, MUST be first)
- [ ] `server/__tests__/nucleiParser.test.ts` — nuclei parser tests
- [ ] `server/__tests__/adParser.test.ts` — AD parser tests
- [ ] `server/__tests__/edrParser.test.ts` — EDR parser tests

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| nmap `-O` requires root/privileged | PARS-03 | OS detection needs raw sockets; CI has no root | Verify OS fields are optional and gracefully absent |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
