# Phase 6: Calibration and Quality - Research

**Researched:** 2026-03-17
**Domain:** Test suite health, scoring calibration, TypeScript CLI scripting (Vitest + Drizzle ORM)
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Calibration runs against the live production database using the same `DATABASE_URL` from `.env`
- Reusable CLI script at `scripts/calibrate.ts` — can be re-run anytime against any DB
- Single script run validates all three components together: weights (THRT-06), criticality multipliers (THRT-08), exploitability (THRT-09)
- Read-write auto-patch: script queries DB, detects inversions, patches `scoringEngine.ts` constants directly, then re-runs to verify
- Outputs results to both stdout and a report file
- Strict ordering: any case where a lower-severity finding scores higher than a higher-severity finding of the same type is an inversion
- No adjustment limits — script adjusts weights/multipliers to whatever value eliminates the inversion
- THRT-08 validation: strict hierarchy must hold — domain (1.5) > server/firewall/router (1.2) > desktop/switch/other (1.0). Same finding on a DC must always score higher than on a desktop
- THRT-09 validation: both ordering check (confirmed > unconfirmed) AND exact 1.3x ratio verification for exploitability multiplier
- QUAL-01 (edrAvScanner failures): verify current state — if 0 failures, mark resolved. No investigation of root cause needed
- PARS-11 (25 rule snapshots): verify completeness of existing `.snap` file entries — if all 25 present and current, mark done
- QUAL-02 (zero failures): ensure `npx vitest run` exits 0 with existing tests, PLUS add calibration regression tests that encode scoring hierarchy as permanent test cases
- Calibration regression tests go in `scoringEngine.test.ts` to prevent future inversions
- Report stored in `.planning/phases/06-calibration-and-quality/CALIBRATION-REPORT.md`
- Summary format: pass/fail per component, inversions found, changes made
- Script outputs to both stdout during execution and writes the report file

### Claude's Discretion
- Calibration script implementation details (how to query, how to detect inversions algorithmically)
- Exact format of regression test assertions
- How to patch scoringEngine.ts constants programmatically
- Error handling for DB connection failures in the script

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| THRT-06 | Scoring component weight distribution (40/25/20/15) validated against real scan data and adjusted if inversions found | Calibration script queries threats table with scoreBreakdown JSONB field; existing `computeContextualScore()` is pure and re-runnable for validation |
| THRT-08 | Host type criticality multipliers (domain 1.5, server/firewall/router 1.2) validated against real scan data | `getThreatsWithHosts()` in storage/threats.ts already joins threats with hosts, exposing hostType for per-type score analysis |
| THRT-09 | Exploitability multiplier (1.3x for confirmed) validated against real scan data | `scoreBreakdown.exploitabilityMultiplier` is stored in DB JSONB; script queries by source='nmap_vuln' or evidence.confirmed=true vs unconfirmed |
| PARS-11 | Snapshot files generated and committed for all 25 threat rule tests | VERIFIED COMPLETE: snap file at `server/__tests__/__snapshots__/threatRuleSnapshots.test.ts.snap` contains exactly 25 entries; no action needed |
| QUAL-01 | edrAvScanner.test.ts 7 pre-existing failures resolved | VERIFIED RESOLVED: `npx vitest run` exits 0 with 293 passing tests across 17 files — edrAvScanner.test.ts passes; no action needed |
| QUAL-02 | All existing test suites pass with zero failures before milestone close | VERIFIED BASELINE: 293 tests pass now; requires adding calibration regression tests to scoringEngine.test.ts without breaking existing suite |
</phase_requirements>

---

## Summary

Phase 6 has two work streams: test suite health verification and scoring calibration. The critical insight is that **PARS-11 and QUAL-01 are already resolved** — the snapshot file has exactly 25 entries matching all required rule IDs, and the full test suite exits 0 with 293 passing tests across 17 files (including edrAvScanner.test.ts). The planner should verify these conditions at task start and mark them complete immediately.

The substantive work is the calibration CLI at `scripts/calibrate.ts`. This script must connect to the live DB via `DATABASE_URL`, query `threats` joined with `hosts`, detect severity inversions across each scoring component, auto-patch the constant maps in `scoringEngine.ts` via string replacement, re-run verification, and write a report. The script then drives addition of calibration regression tests in `scoringEngine.test.ts` that permanently encode the correct hierarchy.

The scoring system is a pure function (`computeContextualScore`) operating on named constant maps (`SEVERITY_WEIGHTS`, `CRITICALITY_MULTIPLIERS`, `EXPOSURE_FACTORS`). These constants are the only patch targets. The DB stores `scoreBreakdown` as typed JSONB with all 7 breakdown fields, enabling direct analysis of each component's behavior across real data.

**Primary recommendation:** Write `scripts/calibrate.ts` first as a standalone verification tool, derive test cases from its findings, then add regression tests to lock the validated hierarchy permanently.

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| vitest | ^4.0.18 | Test runner for all tests and snapshots | Already the project standard; `npm test` runs `vitest run` |
| drizzle-orm | ^0.39.1 | ORM for DB queries in calibrate.ts | Already used throughout server/storage/*.ts |
| tsx | ^4.19.1 | Run TypeScript scripts directly | Already in devDependencies; used for seed.ts pattern |
| pg (node-postgres) | already installed | DB pool for calibrate.ts | Used in server/db.ts via drizzle |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| fs/promises (Node built-in) | built-in | Write CALIBRATION-REPORT.md | Writing report file from calibrate.ts |
| readline (Node built-in) | built-in | Only if interactive mode needed | Not needed — script is non-interactive |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| tsx for calibrate.ts | ts-node | tsx is already in devDependencies; ts-node would be an unnecessary addition |
| Direct fs string-patch of scoringEngine.ts | AST transformation (ts-morph) | String replacement on named constant blocks is simpler, safer, and sufficient |

**Run command for calibrate.ts:**
```bash
npx tsx scripts/calibrate.ts
```

**Test suite command:**
```bash
npm test           # vitest run
npx vitest run     # equivalent
```

---

## Architecture Patterns

### Recommended Project Structure
```
scripts/
└── calibrate.ts         # New CLI calibration script
server/
├── services/
│   └── scoringEngine.ts  # Patch target for constant maps
└── __tests__/
    └── scoringEngine.test.ts  # Add calibration regression tests here
.planning/phases/06-calibration-and-quality/
└── CALIBRATION-REPORT.md  # Written by calibrate.ts
```

### Pattern 1: Drizzle DB Connection in Scripts (mirrors server/db.ts)

**What:** Scripts use the same DATABASE_URL env var and same drizzle initialization as the server.

**When to use:** Any script that needs DB access outside the server process.

```typescript
// Source: server/db.ts pattern
import { Pool } from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import * as schema from '../shared/schema';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const db = drizzle({ client: pool, schema });
```

Note: The calibrate.ts script lives in `scripts/` so path to `shared/schema` will be `'../shared/schema'`.

### Pattern 2: getThreatsWithHosts Query (existing storage function)

The storage already has `getThreatsWithHosts()` in `server/storage/threats.ts` which joins threats with hosts and exposes `hostType`. The calibration script should either import this or replicate the join directly.

```typescript
// From server/storage/threats.ts
import { getThreatsWithHosts } from '../server/storage/threats';
// Returns objects with: severity, contextualScore, scoreBreakdown, hostType, source, evidence
```

**Inversion detection algorithm:**
```typescript
// Group threats by (severity, hostType) pairs
// For THRT-06 (severity weights): check that avg score for critical > high > medium > low
// For THRT-08 (criticality): check that for same severity, domain avg > server avg > desktop avg
// For THRT-09 (exploitability): check that nmap_vuln/confirmed avg is 1.3x non-confirmed avg
```

### Pattern 3: Patching scoringEngine.ts Constants

The constant maps in scoringEngine.ts are named clearly. String replacement on the specific constant block is reliable:

```typescript
// Pattern: read file, regex-replace the constant value, write back
import { readFileSync, writeFileSync } from 'fs';

const filePath = 'server/services/scoringEngine.ts';
let source = readFileSync(filePath, 'utf-8');

// Replace SEVERITY_WEIGHTS block
source = source.replace(
  /const SEVERITY_WEIGHTS: Record<string, number> = \{[^}]+\}/,
  `const SEVERITY_WEIGHTS: Record<string, number> = {\n  critical: ${newCritical},\n  high: ${newHigh},\n  medium: ${newMedium},\n  low: ${newLow},\n}`
);

writeFileSync(filePath, source, 'utf-8');
```

**Important:** After patching, the calibrate.ts script must re-import (or re-compute using) the new values to verify the inversion is resolved. Since Node.js caches modules, verification should use the new constant values directly (passed as parameters) rather than re-importing.

### Pattern 4: Vitest Regression Tests for Scoring Hierarchy

New tests should be added to the **existing** `server/__tests__/scoringEngine.test.ts` (not a new file). They follow the same `makeThreat()`/`makeHost()` helper pattern already established.

```typescript
// Source: scoringEngine.test.ts existing patterns
describe('Calibration regression: scoring hierarchy (THRT-06, THRT-08, THRT-09)', () => {
  it('severity ordering: critical > high > medium > low (THRT-06)', () => {
    const engine = new ScoringEngineService();
    const critical = engine.computeContextualScore(makeThreat({ severity: 'critical' }), undefined, 'attack_surface', 'unknown');
    const high = engine.computeContextualScore(makeThreat({ severity: 'high' }), undefined, 'attack_surface', 'unknown');
    const medium = engine.computeContextualScore(makeThreat({ severity: 'medium' }), undefined, 'attack_surface', 'unknown');
    const low = engine.computeContextualScore(makeThreat({ severity: 'low' }), undefined, 'attack_surface', 'unknown');
    expect(critical.rawScore).toBeGreaterThan(high.rawScore);
    expect(high.rawScore).toBeGreaterThan(medium.rawScore);
    expect(medium.rawScore).toBeGreaterThan(low.rawScore);
  });

  it('host criticality ordering: domain > server > desktop (THRT-08)', () => {
    // same severity, different host types
  });

  it('exploitability: nmap_vuln score is exactly 1.3x non-confirmed (THRT-09)', () => {
    // verify ratio, not just ordering
  });
});
```

### Anti-Patterns to Avoid

- **Importing scoringEngine.ts into calibrate.ts at module level:** Module-level imports cache constants at load time. If the script patches constants and then re-imports, it reads the cached (pre-patch) values. Instead, re-compute post-patch scores by constructing the formula inline with the new values.
- **Using `getThreats()` without filtering `contextualScore IS NOT NULL`:** The threats table may contain threats that were never scored. Filter to only threats where `contextualScore` is not null for calibration analysis.
- **Patching constants without a backup:** The script should log the old values before patching so the report documents what changed.
- **Running calibration against an empty DB:** Guard against zero scored threats — if there is no data, report "no data available for calibration" rather than applying arbitrary adjustments.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| DB connection | Custom pg client | Existing `server/db.ts` pattern (Pool + drizzle) | Tested, handles connection lifecycle |
| Threat+host join | Manual JOIN SQL | `getThreatsWithHosts()` from `server/storage/threats.ts` or replicate its drizzle pattern | Already handles all field mapping |
| Running scripts with TypeScript | ts-node compilation | `npx tsx scripts/calibrate.ts` | tsx is already installed and used in project |

---

## Common Pitfalls

### Pitfall 1: QUAL-01 and PARS-11 May Already Be Done

**What goes wrong:** Planner creates tasks to fix edrAvScanner failures and generate snapshots when both are already resolved.

**Why it happens:** REQUIREMENTS.md marks them as pending, but the actual test run shows 293/293 passing and the snap file has exactly 25 entries.

**How to avoid:** Both plan tasks (06-01 and 06-02) should START by verifying the current state with `npx vitest run` and `grep -c "^exports\[" server/__tests__/__snapshots__/threatRuleSnapshots.test.ts.snap`. If counts match, skip straight to adding calibration regression tests.

**Warning signs:** If a task action assumes failures exist without verifying first.

### Pitfall 2: Empty Database

**What goes wrong:** calibrate.ts runs against a DB with no scored threats (development environment, fresh install), reports false "no inversions" because there's no data to analyze.

**Why it happens:** The calibrate.ts script reads live DB data — in environments without real scan data, the analysis is vacuous.

**How to avoid:** Add a guard: if `scoredThreatsCount === 0`, write report with status "SKIPPED: no scored threats in database" and exit 0 without patching any constants.

**Warning signs:** Script reports all components pass immediately on a fresh environment.

### Pitfall 3: Module Caching Breaks Post-Patch Verification

**What goes wrong:** Script patches scoringEngine.ts constants, then tries to re-import to verify — but gets cached pre-patch values.

**Why it happens:** Node.js module caching means `require()`/dynamic `import()` in the same process returns the already-loaded module.

**How to avoid:** Do not re-import scoringEngine.ts for post-patch verification. Instead, inline the scoring formula in calibrate.ts using the new constant values, or spawn a child process for post-verification.

### Pitfall 4: Regex Failing to Match Constant Block

**What goes wrong:** The regex to replace `SEVERITY_WEIGHTS` or `CRITICALITY_MULTIPLIERS` in scoringEngine.ts fails because of whitespace or formatting differences.

**Why it happens:** Multiline regex matching requires careful flags in JavaScript.

**How to avoid:** Use `/s` flag (dotAll) for multiline matching and verify the regex matches before writing. Test against the actual file content shown in this research.

---

## Code Examples

### Calibration Script Skeleton

```typescript
// scripts/calibrate.ts
// Source: server/db.ts pattern + server/storage/threats.ts getThreatsWithHosts pattern
import { Pool } from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import { eq, isNotNull, and } from 'drizzle-orm';
import * as schema from '../shared/schema';
import { readFileSync, writeFileSync } from 'fs';
import { writeFile } from 'fs/promises';

async function main() {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL! });
  const db = drizzle({ client: pool, schema });

  // Query threats with host type (JOIN)
  const rows = await db
    .select({
      severity: schema.threats.severity,
      source: schema.threats.source,
      evidence: schema.threats.evidence,
      contextualScore: schema.threats.contextualScore,
      scoreBreakdown: schema.threats.scoreBreakdown,
      hostType: schema.hosts.type,
    })
    .from(schema.threats)
    .leftJoin(schema.hosts, eq(schema.threats.hostId, schema.hosts.id))
    .where(isNotNull(schema.threats.contextualScore));

  if (rows.length === 0) {
    console.log('SKIPPED: no scored threats in database');
    await writeFile('...', 'SKIPPED: no data');
    await pool.end();
    return;
  }

  // ... detection and patching logic ...
  await pool.end();
}

main().catch(console.error);
```

### Inversion Detection for THRT-06 (Severity Weights)

```typescript
// Group by severity, compute average rawScore
const bySeverity = { critical: [] as number[], high: [] as number[], medium: [] as number[], low: [] as number[] };
for (const row of rows) {
  const breakdown = row.scoreBreakdown as any;
  if (breakdown?.rawScore != null) {
    bySeverity[row.severity as keyof typeof bySeverity]?.push(breakdown.rawScore);
  }
}
const avg = (arr: number[]) => arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : null;
const invertions: string[] = [];
if (avg(bySeverity.critical)! <= avg(bySeverity.high)!) invertions.push('INVERSION: critical avg <= high avg');
// ... etc
```

### THRT-09 Ratio Check

```typescript
// exploitability: confirmed threats should score 1.3x non-confirmed
const confirmed = rows.filter(r =>
  r.source === 'nmap_vuln' || (r.evidence as any)?.nucleiMatch || (r.evidence as any)?.confirmed
);
const unconfirmed = rows.filter(r =>
  r.source !== 'nmap_vuln' && !(r.evidence as any)?.nucleiMatch && !(r.evidence as any)?.confirmed
);
// For same severity level, compare average scores
// Expected: confirmedAvg / unconfirmedAvg ≈ 1.3
```

### Calibration Regression Test (appended to scoringEngine.test.ts)

```typescript
// Source: existing scoringEngine.test.ts pattern (makeThreat, makeHost, ScoringEngineService)
describe('Calibration regression: hierarchy invariants', () => {
  let engine: ScoringEngineService;
  beforeEach(() => { engine = new ScoringEngineService(); });

  it('THRT-06: severity rawScore hierarchy critical > high > medium > low', () => {
    const journeyType = 'attack_surface';
    const scores = (['critical', 'high', 'medium', 'low'] as const).map(s =>
      engine.computeContextualScore(makeThreat({ severity: s }), undefined, journeyType, 'unknown').rawScore
    );
    expect(scores[0]).toBeGreaterThan(scores[1]);
    expect(scores[1]).toBeGreaterThan(scores[2]);
    expect(scores[2]).toBeGreaterThan(scores[3]);
  });

  it('THRT-08: same severity scores domain > server > desktop', () => {
    const t = makeThreat({ severity: 'high' });
    const domain = engine.computeContextualScore(t, makeHost({ type: 'domain' }), 'attack_surface', 'unknown').rawScore;
    const server = engine.computeContextualScore(t, makeHost({ type: 'server' }), 'attack_surface', 'unknown').rawScore;
    const desktop = engine.computeContextualScore(t, makeHost({ type: 'desktop' }), 'attack_surface', 'unknown').rawScore;
    expect(domain).toBeGreaterThan(server);
    expect(server).toBeGreaterThan(desktop);
  });

  it('THRT-09: nmap_vuln rawScore is exactly 1.3x non-confirmed', () => {
    const base = engine.computeContextualScore(makeThreat({ severity: 'high', source: 'journey' }), undefined, 'attack_surface', 'unknown').rawScore;
    const confirmed = engine.computeContextualScore(makeThreat({ severity: 'high', source: 'nmap_vuln' }), undefined, 'attack_surface', 'unknown').rawScore;
    expect(confirmed / base).toBeCloseTo(1.3, 5);
  });
});
```

---

## State of the Art (Current Findings)

| Status | Finding | Implication |
|--------|---------|-------------|
| VERIFIED COMPLETE | PARS-11: snap file has exactly 25 entries (`grep -c "^exports\["` = 25) | Plan 06-01 verifies and closes immediately |
| VERIFIED PASSING | QUAL-01: edrAvScanner.test.ts has 0 failures (293/293 pass) | Plan 06-01 verifies and closes immediately |
| VERIFIED BASELINE | QUAL-02: `npx vitest run` exits 0 before any phase 6 changes | Plan 06-01 establishes baseline, 06-02 adds regression tests |
| PENDING | THRT-06/08/09: No calibration script exists yet | Plan 06-02 creates scripts/calibrate.ts |
| PENDING | Calibration regression tests: not yet in scoringEngine.test.ts | Plan 06-02 adds hierarchy invariant tests |

**Existing constants (verified from scoringEngine.ts):**
- `SEVERITY_WEIGHTS`: critical=100, high=75, medium=50, low=25
- `CRITICALITY_MULTIPLIERS`: domain=1.5, server/firewall/router=1.2, desktop/switch/other=1.0
- `EXPOSURE_FACTORS`: attack_surface=1.3, ad_security=1.0, edr_av=0.9, web_application=1.2
- Exploitability multiplier: 1.3 for `nmap_vuln` source or `evidence.nucleiMatch`/`evidence.confirmed`

These constants already encode the correct hierarchy. Calibration validates that real DB data confirms or refutes them.

---

## Open Questions

1. **Database availability during plan execution**
   - What we know: calibrate.ts needs `DATABASE_URL` pointing to a DB with scored threats
   - What's unclear: Whether the development environment has real scan data with scored threats
   - Recommendation: Script should handle empty DB gracefully (skip with status log) — see Pitfall 2

2. **Constant patch scope**
   - What we know: Current constants already encode correct hierarchy
   - What's unclear: Whether real data will reveal actual inversions requiring patch
   - Recommendation: Script must handle the "no inversions found" case gracefully — log pass for each component

---

## Validation Architecture

> `workflow.nyquist_validation` is `true` in `.planning/config.json` — validation section included.

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Vitest ^4.0.18 |
| Config file | `vitest.config.ts` (project root) |
| Quick run command | `npx vitest run server/__tests__/scoringEngine.test.ts` |
| Full suite command | `npm test` (alias for `npx vitest run`) |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| THRT-06 | Severity weight hierarchy: critical > high > medium > low | unit regression | `npx vitest run server/__tests__/scoringEngine.test.ts` | ❌ Wave 0 (add to existing file) |
| THRT-08 | Host criticality hierarchy: domain > server > desktop (same severity) | unit regression | `npx vitest run server/__tests__/scoringEngine.test.ts` | ❌ Wave 0 (add to existing file) |
| THRT-09 | Exploitability: confirmed score = 1.3x unconfirmed (exact ratio) | unit regression | `npx vitest run server/__tests__/scoringEngine.test.ts` | ❌ Wave 0 (add to existing file) |
| PARS-11 | All 25 snapshot entries present and current | snapshot | `npx vitest run server/__tests__/threatRuleSnapshots.test.ts` | ✅ Already passing |
| QUAL-01 | edrAvScanner.test.ts 0 failures | unit | `npx vitest run server/__tests__/edrAvScanner.test.ts` | ✅ Already passing |
| QUAL-02 | Full suite exits 0 | all | `npm test` | ✅ Baseline 293/293 — must remain green after additions |

### Sampling Rate
- **Per task commit:** `npx vitest run server/__tests__/scoringEngine.test.ts`
- **Per wave merge:** `npm test`
- **Phase gate:** `npm test` green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] Calibration regression tests in `server/__tests__/scoringEngine.test.ts` — covers THRT-06, THRT-08, THRT-09 (add to existing file, not a new file)

*(No new test files needed — tests are added to the existing `scoringEngine.test.ts`. No framework install needed — Vitest 4.0.18 already installed.)*

---

## Sources

### Primary (HIGH confidence)
- Direct file reads: `server/services/scoringEngine.ts` — confirmed constant values and formula
- Direct file reads: `server/__tests__/scoringEngine.test.ts` — confirmed test patterns, makeThreat/makeHost helpers
- Direct file reads: `server/__tests__/threatRuleSnapshots.test.ts` — confirmed 25 rule IDs
- Direct file reads: `server/__tests__/__snapshots__/threatRuleSnapshots.test.ts.snap` — confirmed 25 entries
- Live test run: `npx vitest run` — confirmed 293 passing, 0 failing
- Direct file reads: `vitest.config.ts`, `package.json` — confirmed versions and run commands
- Direct file reads: `server/db.ts`, `server/storage/threats.ts` — confirmed Drizzle patterns

### Secondary (MEDIUM confidence)
- `shared/schema.ts` — confirmed `scoreBreakdown` JSONB field, host type enum values

### Tertiary (LOW confidence)
- None

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all packages verified in package.json with actual versions
- Architecture: HIGH — all patterns verified against actual source files
- Pitfalls: HIGH — derived from direct code analysis and live test run
- Current test status: HIGH — verified by running actual test suite

**Research date:** 2026-03-17
**Valid until:** 2026-04-17 (stable codebase; constants and test patterns unlikely to change)
