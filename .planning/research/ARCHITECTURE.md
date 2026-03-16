# Architecture Patterns

**Domain:** Adversarial Exposure Validation (AEV) platform — security tool output parsing, threat correlation, contextual scoring, remediation recommendation
**Researched:** 2026-03-16
**Confidence:** HIGH (based on direct codebase analysis + well-established domain patterns)

---

## Context: What We Are Improving

The existing monolith is structurally sound. The problem is not architectural — it is **pipeline fidelity and intelligence**. The current flow loses data early (parsers truncate), groups poorly (n findings per finding instead of 1 threat per cluster), scores naively (CVSS without context), and recommends generically (static strings without host/service substitution).

The revision does not restructure the monolith. It deepens the existing pipeline at four specific points:

1. Parser layer — richer structured output extraction
2. Threat grouping engine — correlation before persistence
3. Scoring system — contextual weighting at score computation time
4. Recommendation engine — template rendering against live finding data

Everything stays within the Express/PostgreSQL monolith. No new services, no message queues, no microservices. Service-oriented design within the same process.

---

## Recommended Architecture

### The Four-Stage Pipeline

```
Raw Tool Output
      |
      v
[1. Parser Layer]
      |
      v
Normalized Finding (rich structured object)
      |
      v
[2. Threat Grouping Engine]
      |
      v
Threat Cluster (grouped, deduplicated)
      |
      v
[3. Contextual Scoring Engine]
      |
      v
Scored Threat (severity + posture score contribution)
      |
      v
[4. Recommendation Engine]
      |
      v
Actionable Recommendation (host/service/command substituted)
      |
      v
PostgreSQL persistence → API routes → React UI
```

Each stage is a discrete service module callable from `journeyExecutor`. No stage knows about the previous or next stage's internals — they communicate via typed data contracts.

---

## Component Boundaries

### Component 1: Parser Layer

**Location:** `server/services/parsers/` (new directory)
**Responsibility:** Convert raw tool output bytes into normalized, fully-structured finding objects. All data extraction happens here — nothing downstream should need to re-parse strings.

| Sub-component | Input | Output |
|---------------|-------|--------|
| `nmapParser.ts` | nmap XML or JSONL stdout | `NmapFinding[]` with ports, services, OS detection, script outputs, CVE refs |
| `nucleiParser.ts` | nuclei JSONL lines | `Nucleifinding[]` with template ID, matcher name, extracted evidence, severity, matched-at URL |
| `adParser.ts` | PowerShell JSON blocks | `ADFinding[]` with check category, affected object DN, group chains, GPO links, trust attributes |
| `edrParser.ts` | SMB EICAR result objects | `EDRFinding[]` with per-host sample results, detection timeline, prevention vs. detection outcome |

**Key design decisions:**

- Parsers return typed objects, never raw strings downstream.
- Parsers are pure functions (input → output, no DB calls, no side effects). This makes them independently testable.
- Parsers must preserve ALL data the tool emitted. Fields that existing code ignores must now be captured in the typed output — `extras?: Record<string, unknown>` as escape hatch for unexpected fields.
- Failure mode: parser emits a `ParseWarning` alongside partial results rather than throwing. Pipeline continues with what was successfully extracted.

**Interface contract:**

```typescript
interface ParserResult<T> {
  findings: T[];
  warnings: ParseWarning[];
  rawOutputRef?: string; // path or truncated for audit
}
```

**Communicates with:** journeyExecutor (consumes), ThreatGroupingEngine (produces for)

---

### Component 2: Threat Grouping Engine

**Location:** `server/services/threatEngine.ts` (existing — extend, do not rewrite)
**Responsibility:** Accept a batch of normalized findings from a single scan, apply grouping rules, and emit threat clusters. One cluster = one persisted threat record. Deduplication against existing threats happens here.

**Grouping strategy by journey type:**

| Journey | Grouping key | Example cluster |
|---------|-------------|-----------------|
| Attack Surface | `(hostId, serviceFamily)` | All open ports on host 10.0.0.5 running HTTP variants → one "Exposed HTTP Services" threat |
| Attack Surface | `(cveId)` | Same CVE across 3 hosts → one threat with `affectedHosts[]` |
| Web Application | `(templateCategory, domain)` | All injection findings on same domain → one "Injection Vulnerabilities" threat |
| AD Security | `(adCheckCategory)` | All Kerberoastable accounts → one "Kerberoasting Exposure" threat |
| EDR/AV | `(hostId, outcome)` | Per-host EDR bypass outcome → one "EDR Gap" threat per failing host |

**Grouping algorithm:**

```
For each finding batch:
  1. Assign correlation key per finding (deterministic function of grouping dimensions)
  2. Bucket findings by correlation key
  3. For each bucket: check if matching open threat exists in DB (same key, same journey type)
     - EXISTS: merge new findings into existing threat (additive update)
     - NOT EXISTS: create new threat from bucket
  4. Emit ThreatCluster[] — one per bucket
```

**Interface contract:**

```typescript
interface ThreatCluster {
  correlationKey: string;
  threatType: ThreatType;
  title: string;
  findings: NormalizedFinding[]; // all findings in this cluster
  affectedHosts: string[];
  affectedServices: string[];
  rawEvidence: Evidence[];
}
```

**Communicates with:** Parser layer (consumes findings), ScoringEngine (produces clusters for), Storage layer (deduplication lookup)

---

### Component 3: Contextual Scoring Engine

**Location:** `server/services/scoringEngine.ts` (new file, called from threatEngine or journeyExecutor)
**Responsibility:** Compute a contextual severity score for each threat cluster. Not pure CVSS — weighted by asset criticality, compensating controls, and exposure context.

**Scoring dimensions:**

| Dimension | Source | Weight |
|-----------|--------|--------|
| Base severity | CVE CVSS / nuclei severity / AD check baseline | 40% |
| Asset criticality | Asset record `criticality` field (critical/high/medium/low) | 25% |
| Exposure context | Internet-facing vs. internal-only flag on host/asset | 20% |
| Compensating control | EDR active, host patched recently, network segmented | 15% |

**Score output:**
- `contextualScore` (0–10 float): replaces or augments existing `severity` enum
- `scoreBreakdown`: array of scored dimensions for UI explainability ("Why is this score 8.5?")
- `projectedScoreAfterFix`: score if this threat is mitigated — feeds "impact visualization" feature

**Posture score aggregation:**

- Journey-level posture score = weighted average of `contextualScore` across all open threats for that journey
- Platform-level exposure score = weighted average across all journeys (journey weights configurable per organization)
- Stored as a `postureSnapshot` record per journey completion — enables trend chart over time

**Interface contract:**

```typescript
interface ScoredThreat extends ThreatCluster {
  contextualScore: number;
  scoreBreakdown: ScoreDimension[];
  projectedScoreAfterFix: number;
}
```

**Communicates with:** ThreatGroupingEngine (consumes clusters), RecommendationEngine (passes scored threats), Storage (writes posture snapshots)

---

### Component 4: Recommendation Engine

**Location:** `server/services/recommendationEngine.ts` (new file)
**Responsibility:** For each scored threat, select and render the appropriate remediation template. Output is a fully contextualized recommendation — commands, configs, and references that name actual hosts, ports, and services found.

**Template system (static, not AI):**

```
server/services/recommendations/
  templates/
    attack_surface/
      exposed-ports.ts
      cve-critical.ts
      weak-service-config.ts
    ad_security/
      kerberoasting.ts
      inactive-accounts.ts
      gpo-misconfiguration.ts
    edr_av/
      edr-bypass.ts
      no-coverage.ts
    web_application/
      injection-findings.ts
      missing-headers.ts
```

Each template is a TypeScript function:

```typescript
type RecommendationTemplate = (
  threat: ScoredThreat,
  context: RecommendationContext
) => Recommendation;

interface RecommendationContext {
  affectedHosts: Host[];
  affectedServices: Service[];
  assetCriticality: string;
  existingControls: string[];
}

interface Recommendation {
  summary: string;        // "Disable SMBv1 on 3 hosts"
  impact: string;         // "Eliminates lateral movement via EternalBlue"
  steps: RemedStep[];     // ordered list of specific actions
  estimatedEffort: 'minutes' | 'hours' | 'days';
  projectedScoreChange: number; // from scoringEngine
  references: string[];   // CVE links, MS KB articles, CIS benchmark IDs
}

interface RemedStep {
  order: number;
  action: string;         // "Run on DC01: Set-SmbServerConfiguration -EnableSMB1Protocol $false"
  hosts?: string[];       // actual hostnames/IPs substituted from findings
  command?: string;       // copy-pasteable command with real values
  verification?: string;  // how to confirm it worked
}
```

**Template selection logic:**

```
threatType → templateCategory → select template function
template function called with (scoredThreat, resolvedContext)
rendered Recommendation stored in DB linked to threat
```

**Communicates with:** ScoringEngine (consumes scored threats), Storage (reads host/asset context, writes recommendations), Routes (serves recommendations to UI)

---

## Data Flow: Finding → Threat → Recommendation

```
journeyExecutor.ts
  |
  ├── spawns subprocess (nmap/nuclei/PowerShell/EICAR)
  |
  ├── streams stdout to parser
  |        nmapParser / nucleiParser / adParser / edrParser
  |        → NormalizedFinding[]
  |
  ├── passes findings to threatEngine (batch, end of scan)
  |        correlate → deduplicate → ThreatCluster[]
  |
  ├── passes clusters to scoringEngine
  |        score dimensions → contextualScore + projectedScoreAfterFix
  |        → ScoredThreat[]
  |
  ├── passes scored threats to recommendationEngine
  |        select template → render with live context
  |        → Recommendation[]
  |
  ├── persist to PostgreSQL
  |   threats table ← ScoredThreat fields
  |   recommendations table ← Recommendation per threat
  |   posture_snapshots table ← journey-level score
  |
  └── emit jobUpdate via WebSocket → UI re-queries
```

**Important: batch vs. streaming**

The parser operates in streaming mode (processes output as subprocess emits lines). The threat grouping, scoring, and recommendation engines operate in **batch mode** at end-of-scan — they receive the complete finding set for the journey. This is intentional: grouping requires seeing all findings to form clusters; scoring requires knowing all affected hosts; recommendations require complete cluster context. Real-time progress updates during scan show raw finding counts, not grouped threats.

---

## Schema Additions (Additive Only)

New tables / columns required by this architecture. All additive — no destructive changes.

| Table | Change | Purpose |
|-------|--------|---------|
| `threats` | Add `correlation_key`, `contextual_score`, `score_breakdown jsonb`, `projected_score_after_fix` | Scoring and grouping data |
| `threats` | Add `raw_evidence jsonb` | Preserve full finding data in threat record |
| `recommendations` | New table: `id, threat_id, summary, impact, steps jsonb, estimated_effort, projected_score_change, references jsonb` | Per-threat remediation |
| `posture_snapshots` | New table: `id, journey_id, score, breakdown jsonb, captured_at` | Trend data for executive dashboard |
| `findings` | New table (optional): `id, journey_id, tool, raw_data jsonb, normalized_data jsonb, parsed_at` | Audit trail for parser output |

The `findings` table is optional for v1 — threat `raw_evidence` may be sufficient. Include it if re-processing historical data is a roadmap requirement.

---

## Build Order (Phase Dependencies)

The components have strict dependency ordering. Each phase must be complete before the next is meaningful:

```
Phase 1: Parser Layer improvements
  → Required before: everything else
  → Reason: All downstream components depend on richer normalized data
  → Risk: Regression in existing journey execution — needs careful testing

Phase 2: Schema additions
  → Required before: Grouping, scoring, recommendation persistence
  → Reason: New columns/tables must exist before services write to them
  → Dependency on: Phase 1 (know what fields to add based on parser output shape)

Phase 3: Threat Grouping Engine
  → Required before: Scoring (needs cluster shape), Recommendations (needs cluster)
  → Dependency on: Phase 1 (normalized findings), Phase 2 (schema)
  → Note: Extend existing threatEngine.ts — do not rewrite

Phase 4: Contextual Scoring Engine
  → Required before: Recommendations (needs projectedScoreAfterFix), Executive dashboard (needs posture scores)
  → Dependency on: Phase 3 (ThreatCluster shape)

Phase 5: Recommendation Engine
  → Required before: Remediation tracking UI, Impact visualization
  → Dependency on: Phase 4 (ScoredThreat with projected score)

Phase 6: UI — Threat detail view, Action plan view
  → Required before: Remediation tracking feature
  → Dependency on: Phase 5 (Recommendation records exist in DB)

Phase 7: Executive Dashboard + Trend tracking
  → Can be partially parallel with Phase 6
  → Dependency on: Phase 4 (posture_snapshots table populated)

Phase 8: Remediation Tracking
  → Dependency on: Phase 6 (UI exists), Phase 5 (recommendations marked as done)
```

---

## Patterns to Follow

### Pattern 1: Pure Parser Functions

**What:** Parsers are stateless pure functions — `(rawOutput: string) => ParserResult<T>`. No DB access, no network calls, no side effects.

**When:** Any time tool output needs to be converted to structured data.

**Why:** Testable in isolation. Given nmap XML → assert NmapFinding[]. No mocking needed. This is the highest-leverage testing surface in the pipeline.

### Pattern 2: Batch-at-Boundary Processing

**What:** Stream subprocess stdout through the parser during scan. Accumulate normalized findings in memory. At scan completion, pass the full batch to grouping/scoring/recommendation in sequence.

**When:** Any multi-step processing that requires whole-set visibility (grouping, scoring).

**Why:** Grouping requires seeing all ports on a host before forming a cluster. Scoring requires knowing all affected hosts. Processing incrementally would produce incorrect cluster boundaries.

**Memory note:** nmap scans on medium business networks (50-500 hosts) produce findings sets that are safely held in memory. For a 500-host scan with 50 ports/host, that's 25,000 raw findings — well within process memory limits for a server process.

### Pattern 3: Template-Over-Generation for Recommendations

**What:** Recommendations are rendered TypeScript template functions, not dynamically generated text. Each template is a named function in a known location, taking `ScoredThreat` + `RecommendationContext` and returning `Recommendation`.

**When:** Any remediation guidance generation.

**Why:** Static templates are auditable, testable, versionable, and reliable. No latency, no API cost, no hallucination risk. Templates can reference actual host names, IPs, and commands because they receive live finding data as input.

### Pattern 4: Score Breakdown as First-Class Data

**What:** Store `score_breakdown` as a JSONB column alongside `contextual_score`. Breakdown is an array of `{dimension, value, weight, contribution}`.

**When:** Any scoring operation.

**Why:** The UI needs to answer "why is this score 8.5?" for the sysadmin audience. If breakdown is not persisted, it must be recomputed at read time, which couples the UI to scoring logic. Persisting it decouples rendering from computation.

---

## Anti-Patterns to Avoid

### Anti-Pattern 1: Inline Parsing in journeyExecutor

**What:** Calling `.split('\n').filter(...)` inside journeyExecutor to extract finding data.

**Why bad:** Journey executor already does this — it's why parsers lose data. Logic mixed with orchestration is untestable and fragile to tool output format changes.

**Instead:** Move all string manipulation into the typed parser module. journeyExecutor calls `parseNmapOutput(stdout)` and trusts the result.

### Anti-Pattern 2: Severity Computed at Display Time

**What:** Mapping severity enum to a number in React components or API serializers.

**Why bad:** Inconsistent scores across dashboard, detail view, and reports. Any change requires hunting all display sites.

**Instead:** `contextualScore` is computed once at persistence time by scoringEngine. All display reads the same stored value.

### Anti-Pattern 3: Per-Finding Threats (Current State)

**What:** One threat record created per individual finding — one threat per open port, one per nuclei template match.

**Why bad:** "87 threats found" for a single scan overwhelms users. The sysadmin cannot triage 87 items. Grouping is a product-level requirement, not a UI concern.

**Instead:** ThreatCluster approach — one threat per correlated group. The findings array on the threat record contains all supporting evidence.

### Anti-Pattern 4: Recommendation as a String Field on Threat

**What:** `threats.recommendation TEXT` column with a static string like "Update your software."

**Why bad:** Cannot include actual host names. Cannot have ordered steps. Cannot track completion. Cannot project score change.

**Instead:** Separate `recommendations` table with full structure, linked to threat by `threat_id`.

### Anti-Pattern 5: Rewriting threatEngine from Scratch

**What:** Discarding the existing 30+ detection rules and correlation logic to rebuild a "better" engine.

**Why bad:** Existing rules represent domain knowledge. Existing deduplication prevents duplicate threats across re-scans. A rewrite risks losing both, with regression risk across all journey types.

**Instead:** Extend `threatEngine.ts`. Add grouping logic as a new method `groupFindings(findings: NormalizedFinding[]): ThreatCluster[]`. Keep existing `detectThreats()` callable but have it delegate to the new grouping layer.

---

## Scalability Considerations

This is a single-tenant appliance for medium businesses (50-500 employees). Scalability concerns are about operational ceiling, not distributed systems.

| Concern | At current scale (50-500 hosts) | At upper ceiling (1000 hosts) |
|---------|--------------------------------|-------------------------------|
| Parser memory | Safe — findings batch < 50MB | Safe — linear growth |
| Grouping computation | In-memory hashtable, milliseconds | Still milliseconds for < 100K findings |
| Recommendation rendering | Synchronous template call, microseconds | Not a bottleneck |
| Posture snapshot query | Single aggregation query on indexed `journey_id` | Add `captured_at` index if slow |
| DB growth (findings table) | Optional — only add if audit trail needed | If added, partition by `journey_id` |

No async worker queue needed for recommendation or scoring. These are fast synchronous operations that run as part of the existing job pipeline. The job queue boundary (where async matters) is at the subprocess execution level, which already exists.

---

## Integration Points with Existing Architecture

| Existing Component | Integration | Notes |
|-------------------|-------------|-------|
| `journeyExecutor.ts` | Calls parsers, passes results to grouping/scoring/recommendation | Central orchestration point — all pipeline stages invoked here |
| `threatEngine.ts` | Extended with grouping capability | Preserve existing detection rules, add `groupFindings()` |
| `jobQueue.ts` | No change | Still emits `jobUpdate` after pipeline completes |
| `cveService.ts` | Feeds CVE CVSS into scoringEngine base severity dimension | Pass enriched CVE data to scoring input |
| `hostEnricher.ts` | Feeds asset criticality + patch status into scoringEngine | Enrichment must run before scoring |
| WebSocket broadcast | No change | Fires after full pipeline, not during grouping/scoring |
| Storage `IStorage` | Add new operation groups: `recommendations`, `postureSnapshots` | Extend interface, not replace |
| React routes | New routes: `/api/threats/:id/recommendation`, `/api/journeys/:id/posture` | Additive route additions |

---

## Sources

- Direct codebase analysis: `.planning/codebase/ARCHITECTURE.md` (HIGH confidence)
- Project requirements: `.planning/PROJECT.md` (HIGH confidence)
- Domain patterns: Security pipeline design in vulnerability management tools — SIEM correlation principles, CVSS contextual scoring extensions, template-driven remediation (OpenVAS, Tenable pattern analysis) — MEDIUM confidence (from training knowledge, architecture is well-established in domain)
