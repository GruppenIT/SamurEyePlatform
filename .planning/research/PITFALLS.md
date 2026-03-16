# Domain Pitfalls

**Domain:** Adversarial Exposure Validation platform revision
**Researched:** 2026-03-16
**Confidence:** HIGH — derived from direct codebase analysis of existing implementation

---

## Critical Pitfalls

Mistakes that cause rewrites, data corruption, or silent misclassification at scale.

---

### Pitfall 1: Parser Improvement Breaks the Threat Lifecycle (Data Contract Violation)

**What goes wrong:** The threat engine's rules, correlation keys, and deduplication logic all depend on precise field names and type shapes from parsers (`finding.type`, `finding.port`, `finding.cve`, `finding.evidence.url`, etc.). Improving a parser — even to capture more data — changes the shape of findings objects. Rules that previously matched now silently fail to fire. Threats stop being created for real findings, or duplicate threats are created because `computeCorrelationKey()` generates different keys for the same logical finding.

**Why it happens:** The parser output contract is implicit. There is no shared type definition between the scanner output and `ThreatRule.matcher()` — both sides use `any`. When `vulnScanner.ts` changes how it sets `finding.evidence.source` or `networkScanner.ts` changes how it encodes `finding.type`, nothing catches the breakage at compile time. The threat engine processes 30+ rules silently.

**Consequences:**
- Findings parsed correctly but no threat is created ("phantom findings")
- Correlation key changes cause threat explosion: every re-scan creates new duplicates rather than updating existing threats
- `auto-closure` post-processing closes threats that are still real because the `observedKeys` set is computed from new key format while stored threats have old-format keys
- Dashboard posture score collapses to perfect (no open threats) even though real vulnerabilities exist

**Warning signs:**
- After parser change: job completes but threat count from that job is zero or abnormally low
- Re-running a journey produces double the threats rather than updating existing ones
- Logs show "Nenhuma regra correspondeu ao achado" for finding types that previously matched

**Prevention:**
- Define explicit TypeScript interfaces for every finding type (replace `any` in `ThreatRule.matcher`, `createThreat`, and `analyzeFindings`). The parser output and the rule matcher must share the same type.
- Write a snapshot test for each rule: given a known input finding, assert the exact threat title, severity, and correlation key produced. Run these before and after every parser change.
- Treat correlation key format as a versioned contract. If a parser change would alter the key, write a migration that updates stored threat `correlationKey` fields before deploying.
- Address this before any parser improvement phase begins.

**Phase:** Parser improvement phase (all four parsers); must be resolved in Phase 1 before other work.

---

### Pitfall 2: Threat Grouping Logic Becomes the Deduplication System

**What goes wrong:** The request is to consolidate "multiple ports on same host" into one "exposed service" threat. The current system creates one threat per port (`as:svc:{host}:{port}`). Changing the grouping to one threat per host (or per service category) seems straightforward — but the system's auto-closure logic, notification service, risk score recalculation, and remediation tracking all operate at the per-threat level. Grouping N threats into 1 doesn't just change counts — it means the new "group threat" carries evidence for multiple ports, and marking it "mitigated" claims all ports are fixed when only one may have been.

**Why it happens:** The grouping decision is made in `computeCorrelationKey()`, which determines what is "same threat" for upsert logic. Changing the key to group by host instead of host:port silently collapses distinct issues. Users who previously tracked "RDP port 3389 mitigated" and "SMB port 445 open" as separate items now see one merged item. Partial remediation becomes invisible.

**Consequences:**
- Risk scores change dramatically from a schema change, not from actual security improvement — confusing users
- Mitigating one port marks all grouped ports as mitigated (false sense of security)
- Notification service sends single alert for what was previously multiple alerts
- Previously closed (mitigated) threats get re-opened under a different correlation key, corrupting the history

**Warning signs:**
- After grouping change: total threat count drops significantly in one migration step
- Users report they marked a threat resolved but it re-appeared after next scan
- Host risk scores spike or collapse without any new scan

**Prevention:**
- Do not change correlation key format for existing finding types. Add grouping as a UI-layer aggregation (a "threat group" view that groups by host/category), not as a change to the underlying 1-threat-per-finding storage model.
- If grouping must happen at the engine level, model it explicitly: create a `threat_groups` table that links related threat IDs, keep individual threats intact for remediation tracking.
- Before any grouping change, export the current threat distribution (threats per journey, per host, per severity) as a baseline to compare against after migration.

**Phase:** Threat grouping phase; do not combine with parser improvement in the same sprint.

---

### Pitfall 3: Contextual Scoring Diverges from the Score Users See

**What goes wrong:** Adding contextual scoring (asset criticality, compensating controls) means the computed severity for a finding can differ from the stored `severity` column in the `threats` table. If the score is computed at display time, the dashboard and the threat list show different values. If it's computed at write time, historical scores become inconsistent when criticality settings change. Either way, users see numbers that don't add up.

**Why it happens:** The current schema stores severity as a `pgEnum` (low/medium/high/critical), not a numeric score. The `riskScore` on `hosts` is a plain `integer`. There is no `adjusted_severity` or `contextual_score` column for threats. Adding contextual adjustments on top of the existing model without a clear place to store the adjusted value means the logic gets split across the API, the threat engine, and the frontend — all independently.

**Consequences:**
- Dashboard score says "High risk" but the threat list shows most threats as "Low"
- Re-scoring old threats (because asset criticality changed) looks like a mass reclassification event to users reviewing history
- Remediation priority list changes ranking after every score tweak, even without new findings — users lose trust in the ordering

**Warning signs:**
- Severity badges on threats differ between the dashboard widget and the threat detail view
- "Critical threats" count on the executive dashboard doesn't match the threats table filter for critical

**Prevention:**
- Add a `score` (numeric, 0-100) column to the threats table alongside the existing severity enum. The enum stays for display bucketing; the score drives ordering and posture calculation.
- Score is set at threat creation time from a pure function that takes `(baseSeverity, assetCriticality, compensatingControls)`. It is never recomputed retroactively unless the user explicitly triggers a re-score.
- The posture API (`/api/posture/score`) must use the `score` column, not re-derive from severity enum aggregation.
- Document the scoring formula in code as a named, tested function before implementing the UI for it.

**Phase:** Contextual severity scoring phase; schema migration must be additive (new column, not replacing severity enum).

---

### Pitfall 4: nmap Text Parsing Breaks on Format Variations

**What goes wrong:** The current `parseNmapOutput()` is a text-line parser (split on `\n`, regex match per line). nmap's text output format varies depending on: `-sV` version scan presence, `-O` OS detection, `--script` output format (multi-line script results), and whether the target is a hostname or IP. Improvements to capture script output and OS detection require adding more regex patterns to an already fragile line-by-line parser. Each new pattern can misfire on lines it wasn't designed for.

**Why it happens:** nmap supports both XML output (`-oX`) and normal text output. The codebase currently passes no `-oX` flag — it parses normal text output. The `vulnerabilityBuffer` and multi-line state in the parser (`currentPort`, `osInfo`) are ad-hoc state variables without a formal state machine, which means edge cases (a script output that looks like a port line) corrupt the parse state for subsequent entries.

**Consequences:**
- OS detection data silently not captured when nmap uses a different format string for the OS guess
- Script output (vuln check results) attributed to the wrong port because buffer isn't flushed properly
- Version strings with parentheses or slashes produce malformed `PortScanResult.version` values that poison CVE matching downstream

**Warning signs:**
- After adding `-sV` or `--script` flags: some ports show no version even though nmap output contains version data
- OS info appears for one host but not others in the same scan
- CVE lookups fail for specific services despite correct version detection in other scans

**Prevention:**
- Switch nmap invocation to use `-oX -` (XML output to stdout) and parse XML. The nmap XML DTD is versioned and stable. Use a proper XML parser, not regex. This is the correct approach for any serious nmap integration.
- If text parsing must be preserved as a fallback, treat the text parser as read-only legacy code. Add the XML parser as the primary path and only fall through to text parsing when XML flag fails.
- Add regression tests using captured nmap output files: one for each profile (fast, comprehensive, stealth) and one for each feature (OS detection, version scan, vuln scripts, hostname-vs-IP, IPv6).

**Phase:** nmap parser improvement phase; switching to XML output is the architectural fix, not adding more regex.

---

### Pitfall 5: Nuclei JSONL Parser Drops Lines Without Warning

**What goes wrong:** Nuclei outputs one JSON object per line (`-jsonl`). The current parser processes `stdout` as a single accumulated string, then splits on newlines. If nuclei emits a malformed or partial JSON line (network truncation, binary in output, progress messages mixed in), `JSON.parse()` throws and the entire output is discarded silently — or only the lines before the bad line are processed.

**Why it happens:** `nucleiScanUrl()` collects all stdout in a buffer and calls `parseNucleiOutput(stdout, targetUrl)` once at the end. There is no per-line error handling. Nuclei occasionally emits status lines or ANSI escape sequences even with `-silent -nc` flags depending on version and terminal detection.

**Consequences:**
- A single malformed line from nuclei = zero findings reported for that URL
- Partial parse: findings before the bad line are captured, findings after are silently dropped
- `evidence.extractedResults`, `evidence.matcher`, `evidence.curl` fields are missing when nuclei changes its JSONL schema between template updates

**Warning signs:**
- Nuclei scan "completed" with 0 findings for a target that previously showed findings
- Findings count varies dramatically between two runs against the same target
- Log shows "Nuclei completado" but no threats created

**Prevention:**
- Parse JSONL line-by-line with per-line try/catch. A bad line logs a warning and is skipped; it does not abort the whole result set.
- Log the raw line (first 200 chars) on parse failure for debugging.
- Define an explicit TypeScript interface for the expected nuclei JSONL output fields. Use a Zod schema to validate each line, and use `safeParse()` so failed validation doesn't throw.
- Pin nuclei template directory to a known version at deployment time; do not auto-update templates during a production scan run.

**Phase:** nuclei parser improvement phase; line-by-line parsing is the prerequisite for any evidence preservation work.

---

### Pitfall 6: PowerShell Parser Assumes JSON but AD Returns Mixed Formats

**What goes wrong:** `adScanner.ts` assumes PowerShell scripts return JSON (`JSON.parse()` called on stdout). PowerShell's `ConvertTo-Json` has undocumented depth limits: objects nested deeper than the default depth (2 for older PowerShell versions) are silently converted to the object's `.ToString()` value (e.g., `"System.Collections.ArrayList"`). Group membership chains and GPO link objects are nested structures — exactly what the improvement aims to capture — and they are precisely what PowerShell truncates.

**Why it happens:** PowerShell's `ConvertTo-Json` default depth is 2. When capturing group membership chains (user → group → nested group → group) or GPO links (OU → linked GPOs → GPO settings), the structure exceeds depth 2 and silently degrades. The parser receives what looks like valid JSON but with string artifacts instead of nested objects.

**Consequences:**
- Group membership chains appear truncated — only the immediate parent group is captured, not the chain
- GPO link data shows `"System.Collections.Generic.List\`1[...]"` instead of actual settings
- AD findings for Kerberos delegation trust attributes (nested AD attribute structures) silently contain strings instead of objects

**Warning signs:**
- Group membership in evidence shows only one level even for users in nested groups
- AD test for inactive accounts shows fewer accounts than expected for the domain
- Evidence objects for AD findings contain strings like `"Microsoft.ActiveDirectory..."` or `"System.Object[]"`

**Prevention:**
- All PowerShell scripts that output objects must use `-Depth 10` (or appropriate depth) with `ConvertTo-Json`. Add this as a validation step: if the parser encounters a string value that matches `System\.\w+\[\]` pattern, log a depth-truncation warning.
- Add schema validation for PowerShell output using Zod before parsing. Schema defines which fields are required arrays vs. strings.
- For group membership chains specifically: collect membership in PowerShell as a flat array of all transitive members, not a nested tree. This avoids the depth issue entirely and is easier to display.

**Phase:** AD PowerShell parser improvement phase.

---

## Moderate Pitfalls

### Pitfall 7: Remediation Recommendations Repeat Generic Advice Already Known to Users

**What goes wrong:** The target user is a sysadmin or junior analyst. Generic recommendations like "disable RDP" or "enforce password policy" are already known. What they need is the specific host, port, service version, and the exact command or GPO setting for their environment. If the contextual remediation system generates text like "Consider restricting access to port 3389" without naming the specific host or providing the firewall rule command, it fails the core product promise — "priorized, actionable plans."

**Why it happens:** Template-based recommendation systems default to safe, generic language. When the template author doesn't know which specific asset will trigger the rule, they write for the general case. The evidence fields that carry specific context (host IP, service version, exact AD object name) are stored in `threat.evidence` as JSONB but are not referenced in the recommendation template.

**Consequences:**
- Users dismiss recommendations as noise ("I already know this")
- Remediation tracking adoption is low — users don't mark things "done" because the action item isn't specific enough to execute
- Product fails its core differentiation: it becomes another "wall of findings" with labels

**Warning signs:**
- Recommendation text contains no hostname, IP, port number, or specific configuration value
- Same recommendation text appears for 10 different threats with different hosts
- User testing: user reads recommendation and still has to look up which host it applies to

**Prevention:**
- Every remediation template must have required variable slots: `{{host}}`, `{{port}}`, `{{service}}`, `{{version}}`. Templates without all applicable slots should fail a linting check.
- Include an executable artifact in the recommendation: a firewall rule command, a PowerShell snippet, a GPO path. Not a description of what to do — the actual thing to run.
- Test each template against 3 real finding samples and verify the output contains the specific values, not placeholders or generic descriptions.

**Phase:** Remediation recommendation phase.

---

### Pitfall 8: Redesigned Dashboard Creates Data Freshness Confusion

**What goes wrong:** The executive dashboard will show exposure score, trend over time, and top risks. If the data comes from different endpoints with different refresh intervals (the current posture page uses 60s for score, 30s for activity feed, 10s for jobs), a completed scan can update the "running jobs" widget but the exposure score doesn't update for another 60 seconds. Users see "scan completed" and "score unchanged" simultaneously and conclude the scan found nothing.

**Why it happens:** Each `useQuery` has its own `refetchInterval`. The WebSocket messages trigger toast notifications but do not invalidate specific query cache keys. There is no coordinated "scan completed → refresh all dashboard data" event.

**Consequences:**
- Users distrust the dashboard score ("the scan ran 2 minutes ago and the score hasn't changed")
- Support burden: users re-run scans to force a refresh, creating unnecessary load
- Executive stakeholders seeing the dashboard during/after a scan see inconsistent numbers

**Warning signs:**
- After a journey completes, the threat count in the threats table and the "open threats" count on the dashboard differ for more than 60 seconds
- "Score trend" chart shows gaps or flat segments that don't correspond to actual scan intervals

**Prevention:**
- Use WebSocket `jobUpdate` messages (already emitted) to trigger targeted React Query cache invalidation for all dashboard data when a job transitions to `completed`.
- Design the dashboard around a single "snapshot" API endpoint that returns all dashboard metrics in one response with a `snapshotAt` timestamp, so all widgets show data from the same moment.
- Display "as of {time}" on the score to make staleness explicit rather than hiding it.

**Phase:** Executive dashboard phase.

---

### Pitfall 9: Impact Visualization ("What Improves If I Fix This") Uses Wrong Baseline

**What goes wrong:** Showing projected score improvement after fixing a threat requires calculating "score with this threat closed." If the posture score is calculated at query time from open threat counts and severities, the projected improvement is easy to compute. But if the score also depends on journey coverage (which journeys have run), asset count, and last-scan recency, then closing one threat may improve the score by a different amount than the projection suggests — because the full formula isn't known to the frontend.

**Why it happens:** The posture score formula is currently computed server-side in `/api/posture/score`. The frontend can't replicate it without knowing the formula. If the formula changes (as it will when contextual scoring is added), the projected improvement becomes stale or wrong.

**Consequences:**
- "Fix this to improve your score by 15 points" → user fixes it → score improves by 3 points → user distrust
- Projected improvement numbers become a liability rather than a feature

**Warning signs:**
- Projected score improvement for a "critical" threat is less than for a "medium" threat in the same environment
- After fixing a threat, actual score change differs from projection by more than a rounding error

**Prevention:**
- Implement a `/api/posture/simulate` endpoint that accepts a list of threat IDs to hypothetically close and returns the projected score. This keeps the formula server-side and consistent.
- The frontend only calls the simulate endpoint; it never replicates the formula.
- Round projected improvements to nearest 5-point bucket to avoid false precision ("~15 point improvement" not "14.7 points").

**Phase:** Impact visualization phase; depends on contextual scoring being stable first.

---

### Pitfall 10: Refactoring Large Files Without Test Coverage Causes Silent Regression

**What goes wrong:** `threatEngine.ts` (1832 lines), `adScanner.ts` (1937 lines), and `journeyExecutor.ts` (1812 lines) will all be touched in this revision. When a 1800-line file is split into modules or reorganized, functions that were implicitly tested through integration tests may lose their test coverage entirely. The split creates new module boundaries that aren't covered by the old tests. The most dangerous regression is the silent one: the refactored code runs without error but produces different output.

**Why it happens:** The existing test coverage explicitly has gaps in nmap XML parsing edge cases, AD test result parsing variations, and threat rule matching (per CONCERNS.md). These gaps mean that any refactor in these areas — even renaming a variable or changing where a `break` statement lives — has no automated safety net.

**Consequences:**
- Threat deduplication logic silently changes: correlation keys computed slightly differently in new module structure
- Journey stage transitions skip an `onProgress` call after refactor, causing WebSocket progress to stall
- Refactored AD scanner runs all tests sequentially when the original ran them with category gating

**Warning signs:**
- Post-refactor: a previously-passing integration test now times out
- Threat count for a known test scan drops or increases unexpectedly
- Journey progress stuck at specific percentage after refactor

**Prevention:**
- Before touching any large file: write snapshot/characterization tests. Run the current code against 3-5 known inputs, capture the exact output, and commit those outputs as test fixtures. These tests pass before refactoring and must still pass after.
- Refactor in strict extract-don't-change mode: move code to new location first, no logic changes, verify tests pass, then improve the logic.
- Never combine "move code" and "change behavior" in the same commit.

**Phase:** Any phase touching `threatEngine.ts`, `adScanner.ts`, or `journeyExecutor.ts`.

---

### Pitfall 11: Additive Schema Migrations That Create Query N+1 Problems

**What goes wrong:** Adding columns for contextual scoring, remediation tracking, or threat grouping (e.g., `score` on threats, `remediationStatus` on threats, `threatGroupId` foreign key) is safe from a data integrity standpoint. But new JOIN relationships or new columns that need to be populated in query results can turn previously-efficient queries into N+1 queries — particularly in `threats.tsx` which already fetches all threats for filtering/display.

**Why it happens:** The Drizzle ORM queries for threats currently select from a single table. Adding a `threatGroupId` FK means the threats page may want to show group context, triggering a group lookup per threat. Adding a `score` column means the posture API must aggregate scores rather than count by severity — a different query shape.

**Consequences:**
- Threats page performance degrades from ~50ms to 2-5s for environments with 1000+ threats
- Database CPU spikes when re-calculating posture scores after each scan

**Warning signs:**
- After migration: threats page load time increases by more than 2x
- Query logs show repeated identical queries differing only by threat ID

**Prevention:**
- For any new column that will be used in aggregate queries (scoring, grouping), add a database index at migration time.
- Add the `/api/threats` endpoint response time to the integration test baseline before any schema change.
- Use Drizzle's `select()` to explicitly name returned columns rather than `select *`, so new columns aren't accidentally fetched everywhere.

**Phase:** Any schema migration phase.

---

## Minor Pitfalls

### Pitfall 12: Navigation Redesign Breaks Existing Deep Links

**What goes wrong:** Streamlining navigation from dashboard → journey results → threat → remediation may involve changing URL structures (e.g., `/threats?jobId=xxx` becoming `/journeys/xxx/threats`). Existing users may have bookmarks or notification email links pointing to old URLs. The notification service (`notificationService.ts`) likely generates absolute URLs for threat alerts — those URLs break if the route changes.

**Prevention:**
- Audit all URL generation in `notificationService.ts` and email templates before renaming routes.
- Add HTTP 301 redirects for any changed URLs.
- If URL changes are required, make them in a single phase and update notification templates at the same time.

**Phase:** Navigation improvement phase.

---

### Pitfall 13: "Mark as Done" Remediation Tracking Conflates User Action with Re-Scan Validation

**What goes wrong:** Allowing users to mark a remediation action as "done" without a re-scan creates a false closed state. The threat lifecycle already has `mitigated` and `closed` statuses. Adding "remediation done" as a separate user-controlled flag alongside the existing status creates two competing sources of truth for whether something is fixed.

**Prevention:**
- "Mark as done" should set threat status to `mitigated` (not a new status). The next scan either confirms it (auto-closes via correlation key absence) or re-opens it (re-creates the threat).
- Display the distinction clearly: "Marked as mitigated by user — pending scan confirmation" vs "Verified closed by re-scan."

**Phase:** Remediation tracking phase.

---

### Pitfall 14: Findings Detail Redesign Loses Evidence That Downstream Tooling Expects

**What goes wrong:** The findings/threat detail view restructure (problem → impact → fix hierarchy) may involve changing how `threat.evidence` JSONB is accessed or displayed. If the redesign also changes how evidence is written (to make it cleaner), existing threats in the database with the old evidence schema will render incorrectly in the new view.

**Prevention:**
- The detail view redesign must be display-only: read from `threat.evidence` without assuming field presence. Use optional chaining everywhere.
- Schema changes to evidence structure go in new fields only, never removing or renaming existing ones.
- Test the new detail view against threats created by the old parsers (from existing data), not just newly-created test data.

**Phase:** Findings detail redesign phase.

---

## Phase-Specific Warnings

| Phase Topic | Likely Pitfall | Mitigation |
|-------------|---------------|------------|
| nmap parser improvement | Text regex breaks on new output formats (Pitfall 4) | Switch to XML output (`-oX -`) before adding new field capture |
| nuclei parser improvement | Malformed JSONL line drops entire result (Pitfall 5) | Line-by-line parsing with per-line try/catch as first change |
| AD PowerShell parser | `ConvertTo-Json` depth truncates nested structures (Pitfall 6) | Add `-Depth 10` to all PS scripts; validate with Zod schema |
| Threat grouping logic | Correlation key change breaks auto-closure history (Pitfall 2) | UI-layer aggregation only; no key format changes for existing types |
| Contextual severity scoring | Diverging score values across views (Pitfall 3) | Additive `score` column; single computation path server-side |
| Remediation recommendations | Generic text that ignores specific context (Pitfall 7) | Template validation requiring host/port/service variable slots |
| Executive dashboard | Data freshness confusion after scan completes (Pitfall 8) | WebSocket-triggered cache invalidation on job completion |
| Impact visualization | Projected improvement diverges from actual (Pitfall 9) | Server-side simulate endpoint, never replicate formula in frontend |
| Any refactor of large files | Silent regression from missing test coverage (Pitfall 10) | Characterization tests before any large-file modification |
| Schema migrations | N+1 queries from new FK relationships (Pitfall 11) | Index new columns; measure query time before and after migration |
| Navigation redesign | Broken notification email links (Pitfall 12) | Audit URL generation in notificationService before route changes |

---

## Sources

- Direct codebase analysis: `server/services/threatEngine.ts`, `server/services/scanners/networkScanner.ts`, `server/services/scanners/vulnScanner.ts`, `server/services/scanners/adScanner.ts`, `client/src/pages/postura.tsx`, `client/src/pages/threats.tsx`
- `.planning/codebase/CONCERNS.md` — identified test coverage gaps and known fragile areas
- `.planning/PROJECT.md` — scope constraints and active requirements
- Confidence: HIGH for all pitfalls — each derived from concrete code evidence, not speculation
