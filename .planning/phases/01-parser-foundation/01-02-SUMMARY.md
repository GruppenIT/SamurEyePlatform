---
phase: 01-parser-foundation
plan: 02
subsystem: parser
tags: [nuclei, nmap, zod, schema, journeyExecutor, refactor, tdd]
dependency_graph:
  requires:
    - 01-01-SUMMARY.md (BaseFindingSchema, NseScriptSchema, NmapFindingSchema, NmapVulnFindingSchema)
  provides:
    - NucleiFindingSchema in shared/schema.ts
    - parseNuclei() public method in vulnScanner.ts
    - parseNmapXml() public method in networkScanner.ts
    - scanVulns() public method in networkScanner.ts
    - journeyExecutor delegation (no duplicate parsers)
  affects:
    - threatEngine (finding shapes unchanged, type literals preserved)
    - journeyExecutor (delegates to scanner classes)
tech_stack:
  added:
    - fast-xml-parser (XML parsing for nmap -oX output)
  patterns:
    - TDD (RED: failing tests first, GREEN: implement, snapshot tests)
    - Zod safeParse with skip-and-log for invalid lines (PARS-05)
    - kebab-case to camelCase field mapping for nuclei JSONL
key_files:
  created:
    - server/__tests__/fixtures/nuclei/xss-with-matcher.jsonl
    - server/__tests__/fixtures/nuclei/cve-with-classification.jsonl
    - server/__tests__/fixtures/nuclei/info-severity-with-tags.jsonl
    - server/__tests__/fixtures/nuclei/malformed-mixed-lines.jsonl
    - server/__tests__/fixtures/nmap/vuln-ms17-010.xml
    - server/__tests__/nucleiParser.test.ts
    - server/__tests__/nmapNse.test.ts
    - server/__tests__/__snapshots__/nucleiParser.test.ts.snap
    - server/__tests__/__snapshots__/nmapNse.test.ts.snap
  modified:
    - shared/schema.ts (added NucleiFindingSchema, NucleiFinding type)
    - server/services/scanners/vulnScanner.ts (added parseNuclei(), mapNucleiSeverityZod())
    - server/services/scanners/networkScanner.ts (added parseNmapXml(), scanVulns())
    - server/services/journeyExecutor.ts (deleted duplicate parsers, wired delegation)
decisions:
  - "NucleiFindingSchema uses type literal 'nuclei' and .strip() to match plan spec"
  - "info severity maps to 'low' (not 'info') because BaseFindingSchema enum is ['low','medium','high','critical']"
  - "parseNmapXml skips non-open ports (open ports only per PARS-01 spec)"
  - "removed ensureNucleiTemplates from journeyExecutor since vulnScanner manages templates internally"
metrics:
  duration: "9 minutes"
  completed_date: "2026-03-16"
  tasks_completed: 2
  files_modified: 9
  files_created: 9
---

# Phase 01 Plan 02: Nuclei Zod Schema, NSE Capture, and journeyExecutor Delegation Summary

NucleiFindingSchema with Zod-validated nuclei parser (PARS-05/PARS-06), XML-based nmap NSE script capture with CVE extraction (PARS-02), and elimination of duplicate parsers from journeyExecutor via delegation to scanner classes.

## Tasks Completed

### Task 1: NucleiFindingSchema, parseNuclei(), fixtures, and snapshot tests (TDD)

**RED phase:** Created 4 nuclei JSONL fixtures and 1 nmap XML fixture, wrote failing snapshot tests.

**GREEN phase:**
- Added `NucleiFindingSchema` to `shared/schema.ts` extending `BaseFindingSchema` with type literal `'nuclei'`, `templateId`, `matchedAt`, plus PARS-06 fields: `matcherName`, `extractedResults`, `curlCommand`; `info` block with `classification` (cveId/cweId), `tags`, `references`, `remediation`. Exported with `.strip()`.
- Implemented `parseNuclei(stdout: string): NucleiFinding[]` in `VulnerabilityScanner`: splits on newlines, JSON.parse in try-catch (logs warn + skips on failure), maps nuclei kebab-case fields (`matcher-name`, `extracted-results`, `curl-command`, `template-id`, `matched-at`) to camelCase, runs `NucleiFindingSchema.safeParse()` on each mapped object.
- All 5 snapshot tests pass: matcher-name/extracted-results/curl-command, CVE/CWE classification, tag capture, malformed-line skipping (returns 2 of 3 lines).

### Task 2: parseNmapXml, scanVulns, journeyExecutor wiring, NSE tests

- Added `parseNmapXml(xml, target): NmapFinding[]` to `NetworkScanner`: uses `fast-xml-parser` with `isArray` hints for proper XML array handling, extracts NSE script blocks with `id`, `output`, CVE references (regex on output text), exploit state. Zod-validates each port finding via `NmapFindingSchema.safeParse()`.
- Added `scanVulns(target, ports?, jobId?): Promise<NmapVulnFinding[]>` to `NetworkScanner`: spawns `nmap --script=vuln --script-args vulns.showall -oX -`, delegates to `parseNmapXml()`, re-validates as `NmapVulnFindingSchema` (type `'nmap_vuln'`) for threatEngine `cve-detected` rule compatibility.
- Deleted from `journeyExecutor.ts`: `parseNmapVulnOutput`, `extractVulnerabilityFromBuffer`, `parseNucleiOutput`, `mapNucleiSeverity`, `ensureNucleiTemplates`.
- Wired `runNmapVulnScripts` to delegate to `networkScanner.scanVulns()`.
- Wired `runNucleiWebScan` parse call to `vulnScanner.parseNuclei(result)`.
- Created `nmapNse.test.ts`: 3 tests confirm NSE script capture from `vuln-ms17-010.xml` fixture — `nseScripts` array populated, `id: 'smb-vuln-ms17-010'`, `output` contains `'VULNERABLE'`, `cves` contains `'CVE-2017-0144'`.

## Test Results

```
nucleiParser.test.ts: 5/5 tests pass
nmapNse.test.ts: 3/3 tests pass
nmapParser.test.ts: 18/18 tests pass (plan 01-01 tests, no regression)
```

## Verification

```
grep "parseNmapVulnOutput\|parseNucleiOutput" server/services/journeyExecutor.ts
# Returns 0 matches — CLEAN
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocker] plan 01-01 ran concurrently and committed schema + vulnScanner changes**
- **Found during:** Task 1 GREEN implementation
- **Issue:** `NucleiFindingSchema`, `BaseFindingSchema`, and the `parseNuclei` method were already in the committed state from plan 01-01 running in parallel. The RED test commit captured the correct state before 01-01 landed.
- **Fix:** Verified that my implementation was consistent with what 01-01 added. Tests confirmed correctness.
- **Files modified:** No extra changes needed.

**2. [Rule 2 - Missing functionality] ensureNucleiTemplates deletion left broken call site**
- **Found during:** Task 2 deletion of duplicate methods
- **Issue:** After deleting `ensureNucleiTemplates` from journeyExecutor, `runNucleiWebScan` still called `this.ensureNucleiTemplates()`.
- **Fix:** Removed the call from `runNucleiWebScan`. Template management is handled by `vulnScanner` internally when it spawns nuclei.
- **Files modified:** `server/services/journeyExecutor.ts`

**3. [Rule 1 - Bug] Set spread TypeScript error in networkScanner parseNmapXml**
- **Found during:** Task 2 TypeScript check
- **Issue:** Linter auto-rewrote `[...new Set<string>(cveMatches)]` which caused TS2802 (Set iteration requires es2015 target or downlevelIteration).
- **Fix:** Changed to `Array.from(new Set<string>(cveMatches))` which is always safe.
- **Files modified:** `server/services/scanners/networkScanner.ts`

## Self-Check

Checking created files...
- nucleiParser.test.ts: FOUND
- nmapNse.test.ts: FOUND
- xss-with-matcher.jsonl: FOUND
- vuln-ms17-010.xml: FOUND
- nucleiParser.snap: FOUND
- nmapNse.snap: FOUND
- Commits ef796cc and a87f88c: FOUND

## Self-Check: PASSED
