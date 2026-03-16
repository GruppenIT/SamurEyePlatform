# Project Research Summary

**Project:** SamurEye Platform Revision
**Domain:** Adversarial Exposure Validation (AEV) / Exposure Management
**Researched:** 2026-03-16
**Confidence:** HIGH

## Executive Summary

SamurEye is an Adversarial Exposure Validation platform for medium businesses (50-500 employees) — a category occupied by Tenable, Qualys, Rapid7, and newer BAS/CTEM tools. The codebase already has a structurally sound monolith (React 18/Express/PostgreSQL) and a working scanner pipeline across 4 journey types (Attack Surface, AD Security, EDR/AV, Web Application). The problem is not architecture — it is pipeline fidelity and intelligence. Parsers truncate rich tool output, the threat engine creates one finding per raw result instead of grouped clusters, scoring is CVSS-only with no context, and the platform generates findings but no actionable remediation content. Users get a wall of 87 unrelated findings after a scan and cannot act on them.

The recommended approach is a strict 4-stage pipeline deepening within the existing monolith: (1) replace regex-based parsers with typed, structured parsers (nmap XML, nuclei JSONL, AD PowerShell Zod schemas), (2) extend the threat engine with cluster-based grouping so multiple related findings consolidate into one parent threat, (3) add a contextual scoring engine that weights asset criticality and exposure context alongside base severity, and (4) build a static recommendation template engine that interpolates actual host/port/service data into specific, executable fix instructions. No new npm packages are required beyond promoting fast-xml-parser from transitive to direct dependency. No architectural restructuring — no new services, message queues, or microservices.

The primary risk is the existing implicit data contract between parsers and the threat engine's 30+ detection rules. Improving parsers changes the shape of finding objects that rules match against, which can silently break rule firing, corrupt correlation keys, and cause deduplication failures. This must be addressed first: define typed interfaces for all parser outputs, write snapshot tests for each rule, and treat correlation key format as a versioned contract. All subsequent work depends on parser output being stable and correct.

---

## Key Findings

### Recommended Stack

No new npm packages are needed for this revision — the existing dependency set covers all capability gaps. fast-xml-parser 5.4.1 is already in the lockfile as a transitive dependency and should be promoted to a direct dependency (`npm install fast-xml-parser`) to parse nmap `-oX` XML output. Zod (already installed) should be extended to validate parser output at the parse boundary rather than only at API layer. Recharts 2.15.2 (already installed, already used in hosts.tsx) covers all new chart types required for the executive dashboard. All threat scoring, template rendering, and recommendation generation are TypeScript functions — no library dependency is appropriate or needed.

**Core technologies:**
- `fast-xml-parser` 5.4.1: Parse nmap XML output (`-oX -`) — already in lockfile, zero install cost, TypeScript types, stable nmap DTD
- `zod` 3.24.2: Schema validation at parser output boundaries — already installed, extend from API layer to parsers
- `recharts` 2.15.2: Executive dashboard charts (AreaChart for trend, RadialBarChart for exposure gauge, BarChart for severity distribution) — already installed and wrapped in `components/ui/chart.tsx`
- Plain TypeScript functions: Threat scoring (weight table + multipliers) and recommendation templates (one function per threat type) — correct architectural decision, no library adds value here
- `vitest` (already installed): Extend to unit test all parser output with snapshot fixtures

### Expected Features

Based on codebase analysis against AEV category patterns (Tenable, Qualys, Rapid7, Pentera, Cymulate), the revision must deliver the following to remove the core user pain of "I get findings but cannot act."

**Must have (table stakes):**
- Threat grouping/consolidation — multiple related findings become one parent threat with child evidence; eliminates "wall of 87 findings" problem
- Contextual severity scoring — CVSS plus host criticality multipliers, exploitability confirmation factor, and service category weight; scores must be explainable
- Specific, host-referencing remediation — templates that name actual hosts, ports, versions and include executable commands; not generic text
- Prioritized action plan view — post-journey screen answering "what do I fix first and why" with projected score impact per fix
- Finding evidence redesign — problem/impact/fix hierarchy replacing raw JSON evidence blob; human-readable, not data dump
- Posture score trend over time — score history reliably populated and displayed with date-labeled sparkline

**Should have (competitive differentiators):**
- Impact visualization ("fix this → score improves by X") — `projectedScoreAfterFix` per threat group, surfaced in action plan view
- Journey comparison across runs — delta view showing new failures vs previous run; "AD Security: 3 new failures"
- Remediation effort estimation — effort tag per fix (minutes/hours/days) and required role (sysadmin/developer/vendor)
- Executive summary dashboard — CISO-facing view with 3 metrics, top 3 risks, trend arrow

**Defer (v2+):**
- Compensating control detection (requires network topology awareness — out of scope)
- Ticket system integration (Jira, ServiceNow — adds surface area, not needed for single-appliance model)
- AI/LLM-generated remediation (offline appliance constraints, cost, hallucination risk — explicitly excluded by product decision)
- New journey types (existing 4 need depth, not breadth)
- Compliance report builder (ISO 27001/PCI-DSS mapping — high complexity, distraction from core findings quality)

**Critical dependency chain for this revision:**
```
Improved parsers → Threat grouping + Contextual scoring → Remediation templates → Action plan → Impact visualization
```
All UI features depend on data quality improvements upstream. Parser improvements unblock everything.

### Architecture Approach

The revision deepens the existing 4-stage pipeline within the monolith: parsers produce `NormalizedFinding[]`, the grouping engine produces `ThreatCluster[]` keyed by `(host, serviceFamily)` or `(cveId)` depending on journey type, the scoring engine adds `contextualScore` and `projectedScoreAfterFix` to produce `ScoredThreat[]`, and the recommendation engine selects and renders a TypeScript template function per threat type. Parsers are pure functions (no DB access, independently testable). Grouping and scoring operate in batch mode at end-of-scan — grouping requires whole-set visibility to form correct clusters. A new `recommendations` table and `posture_snapshots` table are added; the threats table gains `contextual_score`, `score_breakdown jsonb`, and `projected_score_after_fix` columns. All schema changes are additive.

**Major components:**
1. `server/services/parsers/` (new directory) — Pure parser functions: `nmapParser.ts`, `nucleiParser.ts`, `adParser.ts`, `edrParser.ts`; each returns `ParserResult<T>` with findings array and warnings
2. `server/services/threatEngine.ts` (extend, not rewrite) — Add `groupFindings(findings: NormalizedFinding[]): ThreatCluster[]` method; keep existing 30+ detection rules; correlation key versioned as contract
3. `server/services/scoringEngine.ts` (new file) — Weighted scoring across base severity (40%), asset criticality (25%), exposure context (20%), compensating controls (15%); stores `score_breakdown` as persisted JSONB
4. `server/services/recommendationEngine.ts` (new file) + `server/services/recommendations/templates/` — TypeScript template functions per threat type, organized by journey; renders with live `ScoredThreat` context
5. Schema additions — `recommendations` table, `posture_snapshots` table, new columns on `threats`; all additive via Drizzle migrations

### Critical Pitfalls

1. **Parser improvement breaks threat rule matching (implicit data contract)** — Changing parser output shape silently breaks `ThreatRule.matcher()` functions that depend on exact field names. Prevention: define explicit TypeScript interfaces for all parser outputs before changing any parser, write snapshot tests for each rule, treat correlation key format as a versioned contract with explicit migration if changed.

2. **Threat grouping changes corrupt remediation tracking history** — Changing the `correlationKey` grouping granularity (from per-port to per-host) causes auto-closure to re-open previously mitigated threats under new key format, and merges distinct remediation states. Prevention: implement grouping as a UI-layer aggregation view over unchanged per-finding storage, or use an explicit `threat_groups` table linking related threat IDs while keeping individual threat records intact.

3. **Contextual scoring diverges across views** — If score is computed at display time in multiple places, dashboard and threat list show different values. Prevention: `contextualScore` computed once at persistence time by `scoringEngine`; all display reads the stored `score` column; single server-side `/api/posture/simulate` endpoint for projections (never replicate formula in frontend).

4. **nmap text parser breaks on output format variations** — Current regex line-parser is fragile to `-sV`, `--script`, OS detection format differences. Prevention: switch nmap invocation to `-oX -` (XML to stdout) and parse with fast-xml-parser; XML format is versioned and stable since nmap 3.x.

5. **Large file refactoring causes silent regression** — `threatEngine.ts` (1832 lines), `adScanner.ts` (1937 lines), `journeyExecutor.ts` (1812 lines) all require modification. Prevention: write characterization/snapshot tests against known inputs before touching any large file; refactor in strict extract-don't-change mode (move code first, verify tests pass, then change behavior in a separate commit).

---

## Implications for Roadmap

Based on the feature dependency chain and build order identified across all four research files, the revision requires 7-8 phases with strict sequential dependencies in the first half and partial parallelism possible in the later UI phases.

### Phase 1: Parser Foundation
**Rationale:** Every downstream component — grouping, scoring, recommendations — depends on richer, correctly-typed parser output. This must come first and be stable before any other phase begins. The implicit data contract between parsers and `threatEngine.ts` rules must be made explicit here or all subsequent phases risk silent regression.
**Delivers:** Typed `NormalizedFinding` interfaces for all 4 scanner types; nmap switched to `-oX` XML; nuclei JSONL line-by-line parsing with per-line `safeParse`; AD PowerShell scripts with `-Depth 10`; Zod schemas at parser boundaries; snapshot tests for all 30+ threat rules.
**Addresses:** Table stakes — finding evidence redesign (upstream data quality), all other features indirectly.
**Avoids:** Pitfall 1 (data contract), Pitfall 4 (nmap text parser fragility), Pitfall 5 (nuclei JSONL dropping lines), Pitfall 6 (PowerShell depth truncation), Pitfall 10 (large file refactor regression).

### Phase 2: Schema Migrations
**Rationale:** New columns and tables must exist before grouping, scoring, and recommendation services can write to them. Schema shape is determined by parser output (Phase 1 informs column types). Migrations are additive only — no destructive changes to existing columns or tables.
**Delivers:** `threats.contextual_score` (numeric), `threats.score_breakdown` (jsonb), `threats.projected_score_after_fix` (numeric); `recommendations` table; `posture_snapshots` table; database indexes on all new columns used in aggregate queries.
**Avoids:** Pitfall 3 (scoring divergence — having the column means score is stored, not recomputed), Pitfall 11 (N+1 queries from new FK relationships — add indexes at migration time).

### Phase 3: Threat Grouping Engine
**Rationale:** The single highest-impact UX change — eliminates the "wall of findings" problem. Must come before recommendations (templates operate on clusters, not individual findings) and before impact visualization (score delta is per cluster). Implement as extension of existing `threatEngine.ts`, not a rewrite, to preserve 30+ detection rules.
**Delivers:** `groupFindings(findings: NormalizedFinding[]): ThreatCluster[]` method; grouping keys by journey type (`hostId + serviceFamily` for Attack Surface, `cveId` for multi-host CVE, `adCheckCategory` for AD, `hostId` for EDR); threat count reduction from per-finding to per-cluster.
**Addresses:** Must-have — threat grouping/consolidation; enables action plan view and impact visualization.
**Avoids:** Pitfall 2 (correlation key change breaking history — use UI aggregation or explicit `threat_groups` table; never change key format for existing finding types).

### Phase 4: Contextual Scoring Engine
**Rationale:** Required before recommendations (templates need `projectedScoreAfterFix`) and before the executive dashboard (posture snapshots need contextual scores). Formula must be finalized and stable before impact visualization is built.
**Delivers:** `scoringEngine.ts` with weighted scoring (base severity 40%, asset criticality 25%, exposure context 20%, compensating controls 15%); `scoreBreakdown` array as persisted JSONB; `postureSnapshot` records written per journey completion; `/api/posture/simulate` endpoint for projection queries.
**Addresses:** Must-have — contextual severity scoring; enables impact visualization and executive dashboard.
**Avoids:** Pitfall 3 (single computation path server-side; stored at write time; simulate endpoint keeps formula server-side for projections), Pitfall 9 (wrong baseline for impact visualization).

### Phase 5: Recommendation Engine
**Rationale:** The core product promise — "specific, actionable fix for this host." Depends on scored threat clusters (Phase 3 + 4) to have real host/port/service data for template interpolation. Templates must have required variable slots (`{{host}}`, `{{port}}`, `{{service}}`) enforced by TypeScript types.
**Delivers:** `recommendationEngine.ts`; static TypeScript template functions organized by journey type and threat category; `Recommendation` records persisted to DB linked to threats; effort estimation and required role tags per template; projected score change from scoring engine.
**Addresses:** Must-have — specific host-referencing remediation; enables prioritized action plan.
**Avoids:** Pitfall 7 (generic text without specific context — template types enforce variable slot presence).

### Phase 6: Threat Detail and Action Plan UI
**Rationale:** UI surface for the new data model. Depends on `Recommendation` records existing in DB (Phase 5). The finding detail redesign (problem/impact/fix hierarchy) and the prioritized action plan view are the primary user-facing deliverables of the revision.
**Delivers:** Redesigned threat detail view (problem → impact → fix hierarchy, not raw JSON evidence blob); post-journey action plan view showing top threats ordered by contextual score with fix preview, effort tag, and projected score delta; impact visualization per threat group.
**Addresses:** Must-have — finding evidence redesign, prioritized action plan; should-have — impact visualization.
**Avoids:** Pitfall 14 (detail view redesign must be display-only against existing evidence; use optional chaining; no evidence field removal).
**Uses:** recharts RadialBarChart and BarChart (existing installation).

### Phase 7: Executive Dashboard and Posture Trend
**Rationale:** Can begin partially in parallel with Phase 6 once `posture_snapshots` table is populated (Phase 4). Dashboard redesign delivers the CISO-facing view and corrects data freshness issues from mismatched query refresh intervals.
**Delivers:** Posture hero with score + delta arrow + date-labeled trend sparkline; top 3 action items from action plan; journey coverage grid with last-run date; WebSocket-triggered React Query cache invalidation on job completion; `snapshotAt` timestamp on dashboard API response; "as of {time}" display label.
**Addresses:** Must-have — posture score trend over time; should-have — executive summary dashboard.
**Avoids:** Pitfall 8 (data freshness confusion — single snapshot endpoint + WebSocket invalidation on job completion).
**Uses:** recharts AreaChart for trend, recharts PieChart for journey coverage (existing installation).

### Phase 8: Remediation Tracking and Journey Comparison
**Rationale:** Enhancement tier — the remediation lifecycle already exists (mitigated/closed). This phase surfaces it more prominently, connects it to the recommendation records from Phase 5, and adds journey delta comparison.
**Delivers:** "Mark as mitigated — pending scan confirmation" user action; "Verified closed by re-scan" auto-confirmation via correlation key absence on next scan; journey delta view ("3 new failures vs. last week"); per-run comparison for all 4 journey types.
**Addresses:** Table stakes — remediation tracking close-the-loop; should-have — journey comparison.
**Avoids:** Pitfall 13 (mark-as-done must use existing `mitigated` status, not a new competing flag).

---

### Phase Ordering Rationale

The first half (Phases 1-5) is strictly sequential by data dependency: parsers produce findings, schema holds the data, grouping creates clusters, scoring enriches clusters, recommendations render against scored clusters. No phase can be started meaningfully before its predecessor is stable.

The second half (Phases 6-8) is primarily UI surface over the new data model. Phase 7 can begin once Phase 4 is writing posture snapshots, making it partially parallel with Phase 6. Phase 8 is a standalone enhancement that does not block any other phase.

The biggest risk to phase sequencing is the data contract problem in Phase 1. If parser output types are left implicit and a rule breaks silently, it will not be discovered until Phase 3 when threat counts appear wrong — at which point the regression is hard to isolate. Snapshot tests for all 30+ rules in Phase 1 prevent this.

### Research Flags

Phases that will benefit from deeper research during planning (via `/gsd:research-phase`):

- **Phase 1 (Parser Foundation):** The nmap XML DTD has edge cases (IPv6 hosts, combined OS + script output, hop-by-hop traceroute data) that should be validated against real nmap output samples before the typed interfaces are finalized. Nuclei JSONL schema changes between template versions need a compatibility matrix.
- **Phase 3 (Threat Grouping):** The grouping key strategy for the Web Application journey (what constitutes the right cluster boundary for nuclei template matches) needs validation against a real web application scan output. The interaction between the new `groupFindings()` method and the existing `auto-closure` post-processing in threatEngine needs explicit test coverage.
- **Phase 4 (Contextual Scoring):** The specific multiplier values (DC gets 1.5x, confirmed vuln script gets 1.3x, admin services get 1.2x) should be calibrated against real scan data from target environment types before being hardcoded. These are product decisions, not engineering ones.

Phases with well-established patterns (safe to skip `/gsd:research-phase`):

- **Phase 2 (Schema Migrations):** Drizzle additive migrations are well-documented and the schema additions are fully specified by Phase 1 output.
- **Phase 5 (Recommendation Engine):** Static TypeScript template functions are standard engineering; content (the actual fix instructions per threat type) is domain knowledge already documented in FEATURES.md's remediation coverage table.
- **Phase 6 (UI — Threat Detail + Action Plan):** recharts patterns are established in the codebase; the problem/impact/fix hierarchy is a standard UI pattern.
- **Phase 7 (Dashboard):** recharts chart types needed are fully documented; WebSocket cache invalidation with React Query is a known pattern.
- **Phase 8 (Remediation Tracking):** The existing threat lifecycle handles this; Phase 8 is surfacing and clarifying existing behavior, not implementing new systems.

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All package versions verified from lockfile and source; decisions are architectural (no new dependencies needed), not library selection guesses |
| Features | HIGH | Based on direct codebase analysis of current feature state plus domain knowledge of AEV category (Tenable/Qualys/Rapid7 patterns well-established pre-August 2025); web search unavailable but category patterns are stable |
| Architecture | HIGH | Based on direct codebase analysis of `journeyExecutor.ts`, `threatEngine.ts`, `shared/schema.ts`; pipeline deepening approach is conservative and well-matched to existing structure |
| Pitfalls | HIGH | All pitfalls derived from concrete code evidence (line-specific references to `threatEngine.ts`, `adScanner.ts`, `vulnScanner.ts`); no speculative pitfalls included |

**Overall confidence:** HIGH

### Gaps to Address

- **Nuclei JSONL schema stability:** The nuclei template ecosystem updates frequently. The specific fields captured (`matcher-name`, `extracted-results`, `curl-command`) may vary by template version. During Phase 1, pin the nuclei template directory to a known version and validate the Zod schema against that version's actual output before finalizing the typed interface.
- **Grouping multiplier calibration:** The contextual scoring multipliers (Phase 4) are reasonable starting values but are estimates, not empirically calibrated. After Phase 4 ships, score distribution across real scan results should be reviewed and multipliers adjusted if the score spread is too narrow or too wide.
- **PowerShell AD script inventory:** The AD parser improvement (Phase 1) requires auditing all PowerShell scripts to add `-Depth 10` to `ConvertTo-Json` calls. The exact number of scripts and their locations in `adScanner.ts` should be inventoried at Phase 1 start.
- **Recommendation template content coverage:** FEATURES.md documents that 30+ threat rules need remediation templates. The effort to write the actual fix content (PowerShell commands, firewall rules, GPO paths) for all 30+ rules is a content writing task, not just engineering. This should be planned as a separate work item within Phase 5.

---

## Sources

### Primary (HIGH confidence)
- `/package-lock.json` — package versions verified (fast-xml-parser 5.4.1, recharts 2.15.2, zod 3.24.2, vitest 4.0.18)
- `server/services/threatEngine.ts` — 30+ threat rules, correlation key logic, scoring model
- `server/services/scanners/networkScanner.ts`, `vulnScanner.ts`, `adScanner.ts` — parser implementation gaps (direct code analysis)
- `client/src/pages/postura.tsx`, `threats.tsx`, `relatorios.tsx` — current feature state
- `shared/schema.ts` — data model (threats table, riskScore, correlationKey, evidence JSONB)
- `.planning/PROJECT.md` — active requirements, stated weaknesses, out-of-scope items, key decisions
- `.planning/codebase/ARCHITECTURE.md` — existing architecture documentation
- `.planning/codebase/CONCERNS.md` — identified test coverage gaps and known fragile areas
- `SAMUREYE_PRODUTO.md` — competitive analysis, target users, product decisions

### Secondary (MEDIUM confidence)
- Domain knowledge: Gartner CTEM framework, AEV/BAS product category patterns (Tenable, Qualys, Rapid7, Pentera, Cymulate) — from training data, pre-August 2025 cutoff; category patterns well-established and stable
- Nmap XML DTD format — stable since nmap 3.x; standard for programmatic nmap integration
- OpenVAS/Tenable template-driven remediation pattern — established domain pattern for static recommendation systems

### Tertiary (LOW confidence)
- Specific multiplier values for contextual scoring (DC host: 1.5x, confirmed vuln script: 1.3x, admin services: 1.2x) — reasonable estimates requiring calibration against real scan data

---

*Research completed: 2026-03-16*
*Ready for roadmap: yes*
