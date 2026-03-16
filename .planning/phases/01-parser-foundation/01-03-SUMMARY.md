---
phase: 01-parser-foundation
plan: 03
subsystem: testing
tags: [ad, edr, zod, threat-engine, snapshot-tests, parser]

requires:
  - 01-01
  - 01-02

provides:
  - AdFindingSchema Zod schema in shared/schema.ts
  - EdrFindingSchema with timeline array in shared/schema.ts
  - NormalizedFindingSchema discriminated union across all scanner types
  - 28 threat rule snapshot tests covering all 25 engine rules
  - AD fixture set (15 JSON files covering all AD rule variants)
  - EDR fixture set (3 JSON files: success, failure, timeout)

key-files:
  created:
    - server/__tests__/threatRuleSnapshots.test.ts
    - server/__tests__/adParser.test.ts
    - server/__tests__/edrParser.test.ts
    - server/__tests__/fixtures/ad/ (15 fixtures)
    - server/__tests__/fixtures/edr/ (3 fixtures)
  modified:
    - shared/schema.ts
    - server/services/scanners/adScanner.ts
    - server/services/scanners/edrAvScanner.ts
---

## What was built

1. **AdFindingSchema** — Zod schema with type literal `'ad_misconfiguration'` | `'ad_user'`, covering groups, passwordAge, passwordNeverExpires, and all AD-specific fields used by threat rules.

2. **EdrFindingSchema** — Zod schema with type `'edr'`, eicarRemoved boolean, timeline array for detection events.

3. **NormalizedFindingSchema** — Discriminated union (`z.union`) combining NmapFinding, NmapVulnFinding, NucleiFinding, AdFinding, and EdrFinding. Single type for all parser output.

4. **AD Scanner patch** — Added `-Depth 10` to LDAP search for nested group resolution.

5. **EDR Scanner patch** — Added timeline array to detection results for temporal analysis.

6. **Comprehensive threat rule snapshot tests** — 28 tests covering all 25 threat engine rules. Each test loads a fixture, parses through the appropriate schema, verifies rule matcher returns truthy, and snapshots the createThreat output.

## Deviations

- Test `testRule` helper uses `toBeTruthy()` instead of `toBe(true)` because some rule matchers return truthy strings (e.g., CVE IDs) rather than boolean `true`.
- Added `vi.mock` for db/storage/hostService/notificationService modules to isolate threat engine tests from database dependency.

## Self-Check: PASSED
- All 28 threat rule snapshot tests pass
- TypeScript compiles (pre-existing errors in threatEngine.ts unrelated to our changes)
- 200/207 tests pass suite-wide (7 pre-existing failures in edrAvScanner.test.ts due to Windows /tmp path)
