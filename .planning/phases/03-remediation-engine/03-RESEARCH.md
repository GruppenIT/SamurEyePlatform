# Phase 3: Remediation Engine - Research

**Researched:** 2026-03-16
**Domain:** TypeScript template engine, recommendation persistence, threat lifecycle integration
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Template content structure**
- Exact commands: copy-paste ready shell/PowerShell commands with interpolated host IP, port, service version
- OS-aware branching: template checks hostFamily from host enrichment — Windows → PowerShell, Linux → bash, unknown → generic guidance
- 1:1 mapping: every threat rule ID gets its own template function (30+ templates in `server/services/remediation-templates/`)
- Each template exports a `generate()` function producing: whatIsWrong, businessImpact, fixSteps[], verificationStep, references[]
- CVE templates: NVD references + static fallback — link to vendor advisory URLs from cveService enrichment data, fix steps are static ("apply vendor patch, verify version")

**Effort & role tagging**
- 4-tier effort: minutes, hours, days, weeks — hardcoded per template as constants
- Exposed-service effort varies by SERVICE_CATEGORIES category: admin=minutes, database=hours, sharing=minutes, web=minutes, email=hours, infrastructure=minutes, other=minutes
- 4 roles: sysadmin (infra changes, patching, AD config), developer (web vulns, app misconfig), security (policy, credentials, risk decisions), vendor (firmware, SaaS patches, license-gated)
- Effort and role hardcoded per template — not computed from evidence

**Remediation lifecycle flow**
- Use existing 'mitigated' threat status for REMD-06 — no new status needed. Existing processReactivationLogic already handles auto-close (not found) and reactivation (found)
- Phase 3 adds "Mark as mitigated" action on recommendation, which sets threat status to 'mitigated' via existing PATCH /api/threats/:id/status
- Recommendations link to parent threats (one recommendation per group). Ungrouped/standalone threats also get their own recommendation — 100% coverage
- On reactivation: keep existing recommendation, mark status as 'failed' — user sees "fix attempted, threat persists"
- Recommendation status column added: pending → applied → verified | failed (→ reset to pending)

**Generation timing & triggers**
- Generates in processJobResults pipeline: findings → threats → grouping → scoring → **recommendations** → posture snapshot
- Upsert on re-scan: update recommendation with fresh evidence if threat still open, keep as historical record if closed. Key: templateId + threatId
- Pipeline only + read API — no manual regeneration endpoint
- API surface: GET /api/threats/:id/recommendation, GET /api/recommendations (with effortTag, roleRequired, journeyType filters), existing PATCH /api/threats/:id/status for mitigation

### Claude's Discretion
- Template file organization and naming within `server/services/remediation-templates/`
- Exact interpolation mechanism for {{host}}, {{port}}, {{service}} variables
- How to aggregate child finding evidence into parent recommendation's hostSpecificData
- Recommendation status sync logic (how threat status changes propagate to recommendation status)
- Storage operations design for recommendations CRUD
- Test strategy for template output validation

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| REMD-01 | Each of the 30+ threat rules has a static remediation template with host-specific commands/configs | 25 rule IDs catalogued from threatEngine.ts; template module structure defined |
| REMD-02 | Templates reference actual host, port, service, and version data from the finding evidence | evidence JSONB fields documented per rule; interpolation pattern designed |
| REMD-03 | Each remediation includes: what is wrong (1 sentence), business impact, fix steps, verification step, references | recommendations table schema already exists with these exact columns |
| REMD-04 | Each remediation has an effort tag (minutes/hours/days/weeks) and required role (sysadmin/developer/vendor/security) | effortTag and roleRequired columns exist in schema; mapping by SERVICE_CATEGORIES confirmed |
| REMD-05 | Recommendations are persisted in a dedicated `recommendations` table linked to threats | Table pre-defined in schema.ts; only missing `status` column for lifecycle |
| REMD-06 | User can mark a remediation as "mitigated — pending scan confirmation" | Existing PATCH /api/threats/:id/status accepts 'mitigated'; no new endpoint needed |
| REMD-07 | Re-scan automatically confirms closure when correlation key is absent in new results | processReactivationLogic already closes mitigated threats not found in re-scan |
</phase_requirements>

## Summary

Phase 3 builds atop a fully pre-wired foundation. The `recommendations` table is already defined in `shared/schema.ts` (created during Phase 2 to avoid a second migration). The processJobResults pipeline already orchestrates findings → threats → grouping → scoring; Phase 3 inserts a `generateRecommendations()` call after `computeProjectedScores()` and before `writePostureSnapshot()`. The lifecycle machinery (processReactivationLogic, updateThreatStatus) already handles mitigated → closed and mitigated → reactivated transitions — Phase 3 only needs to sync recommendation status alongside threat status changes.

The main work is template authorship: 25 distinct threat rule IDs exist in threatEngine.ts, each requiring a `generate()` function in `server/services/remediation-templates/`. Templates receive evidence JSONB from the parent (or standalone) threat and produce structured output matching the recommendations table columns. A recommendation status lifecycle column (`pending | applied | verified | failed`) must be added via a schema migration.

**Primary recommendation:** Implement `recommendationEngine.ts` as a class-based singleton (matching existing service pattern) that dispatches to per-rule template modules; add a `status` column to the recommendations table; hook recommendation status sync into the existing `updateThreatStatus` path.

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| TypeScript (project stdlib) | — | Template type safety — typed generate() signatures prevent missing fields | Already project language; types enforce {{host}}/{{port}}/{{service}} slots |
| Drizzle ORM | (project version) | Recommendation CRUD; upsert on templateId+threatId | Already used for all DB operations in project |
| Zod | (project version) | Input validation for recommendation API query params | Already used at parse boundary for all schemas |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| vitest | ^4.0.18 | Unit tests for template generate() functions | All template output validation |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Static TypeScript template functions | Handlebars/Mustache template strings | String templates lose type safety; TS functions get autocomplete and compile-time errors for missing slots |
| Singleton class pattern | Plain exported functions | Singleton matches scoringEngine, threatEngine patterns already in codebase |

**Installation:**
No new packages required. All dependencies already in project.

## Architecture Patterns

### Recommended Project Structure
```
server/services/
├── recommendationEngine.ts          # Singleton class — dispatches to templates
├── remediation-templates/
│   ├── index.ts                     # Re-exports all templates; dispatch map: ruleId → template
│   ├── types.ts                     # Shared types: RecommendationContext, GeneratedRecommendation
│   ├── exposed-service.ts           # Template for exposed-service rule
│   ├── cve-detected.ts              # Template for cve-detected rule
│   ├── nuclei-vulnerability.ts      # Template for nuclei-vulnerability rule
│   ├── web-vulnerability.ts         # Template for web-vulnerability rule
│   ├── edr-av-failure.ts            # Template for edr-av-failure rule
│   ├── ad-security-generic.ts       # Template for ad-security-generic rule
│   ├── ad-users-password-never-expires.ts
│   ├── ad-domain-controller-not-found.ts
│   ├── ad-inactive-users.ts
│   ├── ad-users-old-passwords.ts
│   ├── ad-privileged-group-members.ts
│   ├── ad-obsolete-os.ts
│   ├── ad-inactive-computers.ts
│   ├── ad-weak-password-policy.ts
│   ├── domain-admin-critical-password-expired.ts
│   ├── specific-inactive-user.ts
│   ├── privileged-group-too-many-members.ts
│   ├── password-complexity-disabled.ts
│   ├── password-history-insufficient.ts
│   ├── passwords-never-expire.ts
│   ├── inactive-computer-detected.ts
│   ├── obsolete-operating-system.ts
│   ├── bidirectional-trust-detected.ts
│   ├── domain-admin-old-password.ts
│   └── password-never-expires.ts
server/storage/
└── recommendations.ts               # CRUD operations for recommendations table
```

### Pattern 1: Template Module Shape

**What:** Every template file exports a single `generate()` function with typed inputs and outputs.

**When to use:** For every threat rule ID (25 total). One file per rule ID.

```typescript
// Source: server/services/remediation-templates/types.ts
export type EffortTag = 'minutes' | 'hours' | 'days' | 'weeks';
export type RoleRequired = 'sysadmin' | 'developer' | 'security' | 'vendor';
export type HostFamily = 'linux' | 'windows_server' | 'windows_desktop' | 'fortios' | 'network_os' | 'other';

export interface RecommendationContext {
  threat: Threat;
  host?: Host;              // undefined for ungrouped threats without host link
  hostFamily: HostFamily;  // from host.family; 'other' if no host
  evidence: Record<string, any>; // threat.evidence JSONB
  childEvidences?: Array<Record<string, any>>; // aggregated from child threats
}

export interface GeneratedRecommendation {
  title: string;
  whatIsWrong: string;       // 1 sentence
  businessImpact: string;
  fixSteps: string[];        // copy-paste ready commands
  verificationStep: string;
  references: string[];
  effortTag: EffortTag;
  roleRequired: RoleRequired;
  hostSpecificData: Record<string, any>; // extracted slots: host, port, service, version
}

export type TemplateGenerator = (ctx: RecommendationContext) => GeneratedRecommendation;
```

### Pattern 2: OS-Aware Branching Inside Templates

**What:** Templates switch on `ctx.hostFamily` to emit the right fix commands.

**When to use:** Any template where the fix command differs between Windows and Linux (RDP, SSH, SMB, patches).

```typescript
// Example: exposed-service.ts (admin category)
const rdpFixSteps = (host: string, port: string): string[] => {
  if (ctx.hostFamily === 'linux') {
    return [
      `# No host ${host}:`,
      `systemctl stop xrdp`,
      `systemctl disable xrdp`,
      `ufw deny ${port}/tcp`,
    ];
  }
  if (ctx.hostFamily.startsWith('windows')) {
    return [
      `# No host ${host} (PowerShell como Administrador):`,
      `Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1`,
      `netsh advfirewall firewall set rule group="remote desktop" new enable=No`,
    ];
  }
  // generic fallback
  return [`Desabilite o serviço de área de trabalho remota exposto em ${host}:${port}.`];
};
```

### Pattern 3: RecommendationEngine Singleton

**What:** Class-based singleton that dispatches to template modules, upserts records, syncs status.

**When to use:** Called from `processJobResults()` after `computeProjectedScores()`.

```typescript
// Source: pattern follows scoringEngine.ts and threatEngine.ts
class RecommendationEngine {
  async generateForJob(jobId: string): Promise<void> {
    // 1. Fetch all parent threats for this job (isNull(parentThreatId) OR groupingKey IS NOT NULL)
    // 2. Also fetch standalone threats (no parentThreatId, no groupingKey) for 100% coverage
    // 3. For each threat: resolve templateId from threat rule, aggregate child evidence
    // 4. Call template generate(ctx)
    // 5. Upsert recommendation (key: threatId — one per threat, templateId stored for audit)
  }

  async syncRecommendationStatus(threatId: string, newThreatStatus: string): Promise<void> {
    // Called from updateThreatStatus hook
    // 'mitigated' → recommendation.status = 'applied'
    // 'open' (reactivated from mitigated) → recommendation.status = 'failed'
    // 'closed' (system) → recommendation.status = 'verified'
  }
}

export const recommendationEngine = new RecommendationEngine();
```

### Pattern 4: Recommendation Status Column Migration

**What:** Add `status` column to existing `recommendations` table. Additive-only (project design decision).

**When to use:** Wave 0 of Plan 03-01.

```typescript
// In shared/schema.ts — add to recommendations table:
status: text("status").default('pending').notNull(),
// Values: 'pending' | 'applied' | 'verified' | 'failed'
// NOT a pgEnum — text column avoids migration complexity for status extensions
```

```sql
-- Migration SQL (run in Wave 0):
ALTER TABLE recommendations ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending';
```

### Pattern 5: Evidence Aggregation for Parent Threats

**What:** Parent threats have their own evidence JSONB (summary-level). Child threats have per-finding evidence with host/port/service details. Templates need both.

**When to use:** When building RecommendationContext for a parent threat.

```typescript
// Aggregate child evidence into hostSpecificData
const childThreats = await getChildThreats(parentThreatId);
const hostSpecificData = {
  hosts: childThreats.map(c => ({
    host: c.evidence?.host,
    ip: c.evidence?.ip,
    port: c.evidence?.port,
    service: c.evidence?.service,
    version: c.evidence?.version,
  })).filter(h => h.host || h.ip),
};
```

### Anti-Patterns to Avoid

- **One recommendation per child threat:** Requirements specify one per group (parent threat). Ungrouped/standalone threats get their own recommendation — not children.
- **Regenerating recommendations on every API read:** Generate only in pipeline; API is read-only.
- **New status values for mitigated-pending:** CONTEXT.md locked this — use existing 'mitigated' threat status.
- **Manual regeneration endpoint:** CONTEXT.md locked this — pipeline only.
- **Separate recommendation table per journey type:** Single unified recommendations table; templateId encodes the origin.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Upsert logic | Custom insert+update+check | Drizzle `onConflictDoUpdate` on `threat_id` | Same pattern as upsertParentThreat; handles concurrent runs |
| Template dispatch | Giant if/else or switch over rule IDs | Lookup map: `Record<string, TemplateGenerator>` | O(1) dispatch; tree-shakeable; testable per-template |
| Status transition validation | Custom state machine | Inline logic in syncRecommendationStatus | Status transitions are simple linear chain; full FSM is overkill |
| DB migration | Manual SQL in ad hoc script | Drizzle push / existing migration pattern | Project uses Drizzle schema; keep additive pattern |

**Key insight:** The recommendations table, the lifecycle logic (processReactivationLogic), and the status change mechanism (updateThreatStatus) are all already built. Phase 3 is mostly authoring template functions and wiring them into existing extension points.

## Common Pitfalls

### Pitfall 1: Wrong upsert key for recommendations

**What goes wrong:** Using `templateId` alone as the upsert key creates duplicate recommendations when a threat has been seen before with the same template. Using `threatId` alone is correct — one recommendation per threat, templateId is metadata.

**Why it happens:** CONTEXT.md says "Key: templateId + threatId" but the intent is uniqueness per-threat (one rec per threat). templateId is stored for audit trail, not for uniqueness.

**How to avoid:** Unique index on `threat_id` in the recommendations table. The `templateId` column records which template was used, but the row is keyed by `threatId`.

**Warning signs:** Duplicate recommendations for the same threat after two scans.

### Pitfall 2: Applying recommendations to child threats instead of parents

**What goes wrong:** Iterating all threats for a job (including children) and generating a recommendation per row. This creates one recommendation per port finding instead of one per group.

**Why it happens:** `getThreats({ jobId })` returns both parents and children.

**How to avoid:** Query only threats where `parentThreatId IS NULL` — these are either standalone (no grouping) or parent threats (groupingKey IS NOT NULL). Children always have parentThreatId set.

**Warning signs:** Recommendation count equals raw finding count instead of threat group count.

### Pitfall 3: Evidence fields missing in parent threat

**What goes wrong:** Parent threats created by `upsertParentThreat` have summary-level evidence (derived from the first child), not the full per-host port/service/version data. Template interpolation produces empty {{host}} slots.

**Why it happens:** Parent evidence is a rollup. The host/port/service detail lives in child threats.

**How to avoid:** Always call `getChildThreats(parentThreatId)` and aggregate `hostSpecificData` from children. Pass aggregated data to the template context. For standalone threats (no children), use `threat.evidence` directly.

**Warning signs:** fixSteps contain literal "undefined" or empty strings for host variables.

### Pitfall 4: Recommendation status out of sync with threat status

**What goes wrong:** Threat status changes to 'mitigated' via PATCH /api/threats/:id/status but recommendation.status stays 'pending'.

**Why it happens:** The route handler updates the threat directly without triggering recommendation sync.

**How to avoid:** Hook `syncRecommendationStatus()` inside `updateThreatStatus()` in threatEngine.ts (the private method already called by closeThreatAutomatically and reactivateThreat). The route handler uses `storage.updateThreat()` directly — this path also needs to call sync. Best approach: call sync inside the route handler after status update, or refactor the route to use `threatEngine.updateThreatStatus()`.

**Warning signs:** Threat shows 'mitigated' but recommendation shows 'pending' after user action.

### Pitfall 5: Missing coverage for ad-security-generic vs. specific AD rules

**What goes wrong:** Two templates are needed for generic AD findings that don't match a specific rule. The `ad-security-generic` rule is a catch-all that fires when no specific AD rule matches. If the specific rule also matches, both fire.

**Why it happens:** Multiple rules can match the same finding (the rules engine does NOT break on first match — it iterates all rules). Generic + specific = two threats for the same finding.

**How to avoid:** The generic AD template (`ad-security-generic`) should have a simple fallback generate() that uses `evidence.recommendation` (existing Portuguese strings from adScanner) as a fix step, with generic effort/role tags. Specific templates override with precise commands.

**Warning signs:** Two threats (and thus two recommendations) for the same AD finding.

## Code Examples

Verified patterns from existing codebase:

### Existing recommendations table schema (schema.ts lines 339-357)
```typescript
// Source: shared/schema.ts Phase 2 definition
export const recommendations = pgTable("recommendations", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  threatId: varchar("threat_id").references(() => threats.id).notNull(),
  templateId: text("template_id").notNull(),
  title: text("title").notNull(),
  whatIsWrong: text("what_is_wrong").notNull(),
  businessImpact: text("business_impact").notNull(),
  fixSteps: jsonb("fix_steps").$type<string[]>().default([]).notNull(),
  verificationStep: text("verification_step"),
  references: jsonb("references").$type<string[]>().default([]),
  effortTag: text("effort_tag"),
  roleRequired: text("role_required"),
  hostSpecificData: jsonb("host_specific_data").$type<Record<string, any>>().default({}),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
  // status column MISSING — must be added in Wave 0
});
```

### processJobResults pipeline insertion point (threatEngine.ts line 839-847)
```typescript
// Source: server/services/threatEngine.ts — Phase 3 insertion after line 844
await scoringEngine.scoreAllThreatsForJob(jobId);
await scoringEngine.computeProjectedScores(jobId);
// INSERT HERE:
await recommendationEngine.generateForJob(jobId);
// THEN:
await scoringEngine.writePostureSnapshot(jobId, job.journeyId);
```

### Existing updateThreatStatus (threatEngine.ts line 1837) — hook point
```typescript
// Source: server/services/threatEngine.ts
private async updateThreatStatus(threatId, newStatus, justification, changedBy, hibernatedUntil?): Promise<void> {
  // ... existing: create history, update threat, recalculate host risk score
  // Phase 3: add after existing logic:
  await recommendationEngine.syncRecommendationStatus(threatId, newStatus);
}
```

### Existing evidence JSONB fields available in templates

**exposed-service evidence:**
```
host, ip, port, service, state, version, banner, osInfo, serviceCategory, serviceCategoryLabel
```

**cve-detected evidence:**
```
cve, cvssScore, service, version, port, host, publishedDate, remediation, detectionMethod, nmapValidated, details
```

**ad rules evidence:**
```
target, category, testId, command, stdout, stderr, exitCode, recommendation (Portuguese string)
```

**edr-av-failure evidence:**
```
hostname, filePath, deploymentMethod, testDuration, timestamp, eicarPersisted, recommendation
```

### Drizzle upsert pattern (matching upsertParentThreat in storage/threats.ts)
```typescript
// Source: server/storage/threats.ts upsertParentThreat pattern
await db
  .insert(recommendations)
  .values({ ...data, updatedAt: new Date() })
  .onConflictDoUpdate({
    target: recommendations.threatId,  // unique index on threat_id
    set: {
      fixSteps: data.fixSteps,
      hostSpecificData: data.hostSpecificData,
      updatedAt: new Date(),
      // Keep status unless explicitly overriding
    },
  });
```

## Complete Threat Rule ID Catalogue

All 25 rule IDs found in `server/services/threatEngine.ts`:

| Rule ID | Journey | Category | Effort | Role |
|---------|---------|---------|--------|------|
| `exposed-service` | attack_surface | varies by SERVICE_CATEGORIES | admin/sharing/infra=minutes; db/email=hours; web=minutes | sysadmin |
| `cve-detected` | attack_surface | CVE | days | sysadmin or vendor |
| `nuclei-vulnerability` | web_application | web | hours | developer |
| `web-vulnerability` | web_application | web | hours | developer |
| `edr-av-failure` | edr_av | endpoint | hours | sysadmin |
| `ad-security-generic` | ad_security | ad (catch-all) | hours | sysadmin |
| `ad-users-password-never-expires` | ad_security | ad | minutes | sysadmin |
| `ad-domain-controller-not-found` | ad_security | ad | days | sysadmin |
| `ad-inactive-users` | ad_security | ad | minutes | sysadmin |
| `ad-users-old-passwords` | ad_security | ad | minutes | security |
| `ad-privileged-group-members` | ad_security | ad | hours | security |
| `ad-obsolete-os` | ad_security | ad | weeks | sysadmin |
| `ad-inactive-computers` | ad_security | ad | minutes | sysadmin |
| `ad-weak-password-policy` | ad_security | ad | minutes | sysadmin |
| `domain-admin-critical-password-expired` | ad_security | ad | minutes | security |
| `specific-inactive-user` | ad_security | ad | minutes | sysadmin |
| `privileged-group-too-many-members` | ad_security | ad | hours | security |
| `password-complexity-disabled` | ad_security | ad | minutes | sysadmin |
| `password-history-insufficient` | ad_security | ad | minutes | sysadmin |
| `passwords-never-expire` | ad_security | ad | minutes | sysadmin |
| `inactive-computer-detected` | ad_security | ad | minutes | sysadmin |
| `obsolete-operating-system` | ad_security | ad | weeks | sysadmin |
| `bidirectional-trust-detected` | ad_security | ad | days | security |
| `domain-admin-old-password` | ad_security | ad | minutes | security |
| `password-never-expires` | ad_security | ad | minutes | sysadmin |

Note: 25 rules catalogued. The 30+ mentioned in REMD-01 likely refers to including sub-categories of `exposed-service` (admin, database, sharing, web, email, infrastructure, other) counted as logical variants, not separate rule IDs. The `exposed-service` template handles all sub-categories via internal branching on `serviceCategory`.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| No recommendations table | recommendations table pre-defined in schema.ts | Phase 2 (migration already applied) | Zero migration work for table creation; only status column needs adding |
| Separate status per phase | Status lifecycle uses existing threatStatusEnum | Design decision pre-Phase 3 | Recommendation status is a separate text column, not reusing threat status enum |

**Deprecated/outdated:**
- Generating recommendations at display time: CONTEXT.md locked against this. Pipeline only.
- Manual regeneration endpoint: locked out of scope.

## Open Questions

1. **Recommendation uniqueness index**
   - What we know: recommendations table has `IDX_recommendations_threat_id` (non-unique index, line 355-357 of schema.ts)
   - What's unclear: Whether a unique index on `threat_id` exists or needs to be added for the upsert to work
   - Recommendation: Add `uniqueIndex("UQ_recommendations_threat_id").on(table.threatId)` in Wave 0 migration alongside the `status` column addition

2. **Template for `ad-security-generic` vs. specific AD rules overlap**
   - What we know: Rules engine iterates all rules without break-on-match; generic and specific rules can both fire on same finding
   - What's unclear: Whether specific AD rule threats also get matched by `ad-security-generic` in practice
   - Recommendation: Examine matcher conditions — specific rules use `finding.name === 'exact string'` while generic uses type match only. In practice they can co-fire. The `ad-security-generic` template should produce lowest-fidelity output (uses existing Portuguese recommendation string), while specific templates produce high-fidelity output. Both are valid recommendations for their respective threats.

3. **Route handler sync for user-initiated status changes**
   - What we know: `/api/threats/:id/status` route calls `storage.updateThreat()` directly, bypassing `threatEngine.updateThreatStatus()`
   - What's unclear: Whether to refactor the route to use the engine method, or add sync call to the route handler
   - Recommendation: Add explicit `await recommendationEngine.syncRecommendationStatus(id, status)` in the route handler after `storage.updateThreat()` to avoid refactoring existing working code

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | vitest ^4.0.18 |
| Config file | `vitest.config.ts` (root) |
| Quick run command | `npm test -- --reporter=verbose server/__tests__/recommendationEngine.test.ts` |
| Full suite command | `npm test` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| REMD-01 | Each of 25 rule IDs has a template that returns a GeneratedRecommendation | unit | `npm test -- server/__tests__/recommendationEngine.test.ts` | Wave 0 |
| REMD-02 | Template interpolates host/port/service/version into fixSteps | unit | `npm test -- server/__tests__/recommendationEngine.test.ts` | Wave 0 |
| REMD-03 | Generated output has whatIsWrong, businessImpact, fixSteps[], verificationStep, references[] | unit | `npm test -- server/__tests__/recommendationEngine.test.ts` | Wave 0 |
| REMD-04 | Generated output has effortTag in [minutes, hours, days, weeks] and roleRequired in [sysadmin, developer, security, vendor] | unit | `npm test -- server/__tests__/recommendationEngine.test.ts` | Wave 0 |
| REMD-05 | upsertRecommendation creates and updates row, keyed on threatId | unit | `npm test -- server/__tests__/recommendationEngine.test.ts` | Wave 0 |
| REMD-06 | syncRecommendationStatus('mitigated') sets status to 'applied' | unit | `npm test -- server/__tests__/recommendationEngine.test.ts` | Wave 0 |
| REMD-07 | processReactivationLogic closes mitigated threat not found in re-scan (already tested in threatEngine) | integration | `npm test -- server/__tests__/threatEngine.test.ts` (if exists) | Verify existing |

### Sampling Rate
- **Per task commit:** `npm test -- server/__tests__/recommendationEngine.test.ts`
- **Per wave merge:** `npm test`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `server/__tests__/recommendationEngine.test.ts` — covers REMD-01 through REMD-06; follows scoringEngine.test.ts pattern (vi.mock for DB, pure function tests)
- [ ] `server/services/remediation-templates/types.ts` — shared types needed before any template file
- [ ] Schema migration: `status TEXT NOT NULL DEFAULT 'pending'` column on recommendations + unique index on `threat_id`

*(Existing test infrastructure: vitest configured, 14 test files in `server/__tests__/`, DB mocked via `vi.mock('../db', () => ({ db: {}, pool: {} }))`)*

## Sources

### Primary (HIGH confidence)
- `shared/schema.ts` lines 339-357 — recommendations table definition, confirmed all columns
- `server/services/threatEngine.ts` lines 109-752 — all 25 rule IDs, evidence JSONB fields per rule, processJobResults pipeline
- `server/storage/threats.ts` — upsert patterns, updateThreatStatus hook point
- `server/routes/threats.ts` — PATCH /api/threats/:id/status route, status change flow
- `server/services/scoringEngine.ts` — singleton class pattern, pipeline integration model
- `server/__tests__/scoringEngine.test.ts` — test pattern: vi.mock for DB/storage, pure function tests
- `.planning/phases/03-remediation-engine/03-CONTEXT.md` — all locked decisions

### Secondary (MEDIUM confidence)
- `server/services/cveService.ts` — CVEResult.remediation field structure for cve-detected template input
- `server/__tests__/threatGrouping.test.ts` — confirms child/parent threat structure and evidence fields

### Tertiary (LOW confidence)
- None

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all dependencies confirmed present in project
- Architecture: HIGH — all integration points verified in source code
- Pitfalls: HIGH — derived from actual code reading (rules engine behavior, evidence JSONB structure, route handler bypass)
- Template content: MEDIUM — exact Portuguese command text not verified; functional structure is HIGH

**Research date:** 2026-03-16
**Valid until:** 2026-04-16 (stable domain — TypeScript template pattern, Drizzle ORM, project architecture is fixed)
