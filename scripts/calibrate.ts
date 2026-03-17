/**
 * Calibration CLI script for SamurEye scoring engine.
 * Queries the live database, detects scoring inversions across all three components:
 *   - THRT-06: Severity weight hierarchy (critical > high > medium > low)
 *   - THRT-08: Host criticality multiplier hierarchy (domain > server/firewall/router > desktop/switch/other)
 *   - THRT-09: Exploitability multiplier (confirmed = 1.3x unconfirmed)
 *
 * If inversions found, auto-patches scoringEngine.ts constants and re-verifies.
 * Writes a calibration report to .planning/phases/06-calibration-and-quality/CALIBRATION-REPORT.md
 *
 * Run: npx tsx scripts/calibrate.ts
 * Requires: DATABASE_URL env var
 */

import { Pool } from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import { eq, isNotNull } from 'drizzle-orm';
import * as schema from '../shared/schema';
import { readFileSync, writeFileSync } from 'fs';
import { writeFile } from 'fs/promises';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ─── Constants ───────────────────────────────────────────────────────────────

const REPORT_PATH = resolve(
  __dirname,
  '../.planning/phases/06-calibration-and-quality/CALIBRATION-REPORT.md'
);
const SCORING_ENGINE_PATH = resolve(__dirname, '../server/services/scoringEngine.ts');

// ─── Types ────────────────────────────────────────────────────────────────────

interface ScoreRow {
  severity: string;
  source: string;
  evidence: unknown;
  contextualScore: number | null;
  scoreBreakdown: unknown;
  hostType: string | null;
}

interface ComponentResult {
  status: 'PASS' | 'FAIL' | 'SKIPPED' | 'INSUFFICIENT_DATA';
  detail: string;
  inversions: string[];
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function avg(arr: number[]): number | null {
  if (arr.length === 0) return null;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function log(msg: string): void {
  console.log(`[calibrate] ${msg}`);
}

function getRawScore(row: ScoreRow): number | null {
  const breakdown = row.scoreBreakdown as any;
  if (breakdown?.rawScore != null) return breakdown.rawScore as number;
  return null;
}

function isConfirmed(row: ScoreRow): boolean {
  const evidence = row.evidence as any;
  return (
    row.source === 'nmap_vuln' ||
    Boolean(evidence?.nucleiMatch) ||
    Boolean(evidence?.confirmed)
  );
}

// Inline scoring formula to verify post-patch without re-importing cached module
function computeRawScore(
  severity: string,
  hostType: string | null,
  exploitabilityMult: number,
  severityWeights: Record<string, number>,
  criticalityMultipliers: Record<string, number>
): number {
  const baseSeverityWeight = severityWeights[severity] ?? 50;
  const criticalityMultiplier = criticalityMultipliers[hostType ?? 'other'] ?? 1.0;
  // Use neutral values for other factors when verifying constant patches
  const exposureFactor = 1.0;
  const controlsReductionFactor = 1.0;

  const rawScore =
    (baseSeverityWeight * 0.40
      + baseSeverityWeight * criticalityMultiplier * 0.25
      + baseSeverityWeight * exposureFactor * 0.20
      + baseSeverityWeight * controlsReductionFactor * 0.15)
    * exploitabilityMult;

  return rawScore;
}

// ─── THRT-06: Severity Weight Validation ────────────────────────────────────

function validateThrt06(rows: ScoreRow[]): ComponentResult {
  const bySeverity: Record<string, number[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };

  for (const row of rows) {
    const rawScore = getRawScore(row);
    if (rawScore != null && row.severity in bySeverity) {
      bySeverity[row.severity].push(rawScore);
    }
  }

  const avgCritical = avg(bySeverity.critical);
  const avgHigh = avg(bySeverity.high);
  const avgMedium = avg(bySeverity.medium);
  const avgLow = avg(bySeverity.low);

  const detail = [
    `critical avg rawScore: ${avgCritical?.toFixed(2) ?? 'N/A'} (n=${bySeverity.critical.length})`,
    `high avg rawScore: ${avgHigh?.toFixed(2) ?? 'N/A'} (n=${bySeverity.high.length})`,
    `medium avg rawScore: ${avgMedium?.toFixed(2) ?? 'N/A'} (n=${bySeverity.medium.length})`,
    `low avg rawScore: ${avgLow?.toFixed(2) ?? 'N/A'} (n=${bySeverity.low.length})`,
  ].join('\n');

  const inversions: string[] = [];

  if (avgCritical === null || avgHigh === null || avgMedium === null || avgLow === null) {
    return {
      status: 'INSUFFICIENT_DATA',
      detail: detail + '\nInsufficient data for all severity levels.',
      inversions: [],
    };
  }

  if (avgCritical <= avgHigh) {
    inversions.push(`critical avg (${avgCritical.toFixed(2)}) <= high avg (${avgHigh.toFixed(2)})`);
  }
  if (avgHigh <= avgMedium) {
    inversions.push(`high avg (${avgHigh.toFixed(2)}) <= medium avg (${avgMedium.toFixed(2)})`);
  }
  if (avgMedium <= avgLow) {
    inversions.push(`medium avg (${avgMedium.toFixed(2)}) <= low avg (${avgLow.toFixed(2)})`);
  }

  if (inversions.length > 0) {
    log(`THRT-06: FAIL — ${inversions.join('; ')}`);
    return { status: 'FAIL', detail, inversions };
  }

  log('THRT-06: PASS');
  return { status: 'PASS', detail, inversions: [] };
}

// ─── THRT-08: Host Criticality Validation ───────────────────────────────────

function validateThrt08(rows: ScoreRow[]): ComponentResult {
  // For same severity, check domain > server/firewall/router > desktop/switch/other
  const severities = ['critical', 'high', 'medium', 'low'];
  const groupScores: Record<string, Record<string, number[]>> = {};

  for (const sev of severities) {
    groupScores[sev] = { domain: [], server: [], desktop: [] };
  }

  for (const row of rows) {
    const rawScore = getRawScore(row);
    if (rawScore == null) continue;
    if (!severities.includes(row.severity)) continue;

    const hostType = row.hostType ?? 'other';
    const group =
      hostType === 'domain'
        ? 'domain'
        : ['server', 'firewall', 'router'].includes(hostType)
        ? 'server'
        : 'desktop';

    groupScores[row.severity][group].push(rawScore);
  }

  const inversions: string[] = [];
  const detailLines: string[] = [];

  for (const sev of severities) {
    const avgDomain = avg(groupScores[sev].domain);
    const avgServer = avg(groupScores[sev].server);
    const avgDesktop = avg(groupScores[sev].desktop);

    detailLines.push(
      `${sev}: domain=${avgDomain?.toFixed(2) ?? 'N/A'} (n=${groupScores[sev].domain.length}), ` +
      `server=${avgServer?.toFixed(2) ?? 'N/A'} (n=${groupScores[sev].server.length}), ` +
      `desktop=${avgDesktop?.toFixed(2) ?? 'N/A'} (n=${groupScores[sev].desktop.length})`
    );

    if (avgDomain !== null && avgServer !== null && avgDomain <= avgServer) {
      inversions.push(`[${sev}] domain avg (${avgDomain.toFixed(2)}) <= server avg (${avgServer.toFixed(2)})`);
    }
    if (avgServer !== null && avgDesktop !== null && avgServer <= avgDesktop) {
      inversions.push(`[${sev}] server avg (${avgServer.toFixed(2)}) <= desktop avg (${avgDesktop.toFixed(2)})`);
    }
    if (avgDomain !== null && avgDesktop !== null && avgDomain <= avgDesktop) {
      inversions.push(`[${sev}] domain avg (${avgDomain.toFixed(2)}) <= desktop avg (${avgDesktop.toFixed(2)})`);
    }
  }

  const detail = detailLines.join('\n');

  // Check if we had any data across all severity groups
  const hasData = severities.some(
    sev =>
      groupScores[sev].domain.length > 0 ||
      groupScores[sev].server.length > 0 ||
      groupScores[sev].desktop.length > 0
  );

  if (!hasData) {
    return {
      status: 'INSUFFICIENT_DATA',
      detail: detail + '\nInsufficient data for host type comparison.',
      inversions: [],
    };
  }

  if (inversions.length > 0) {
    log(`THRT-08: FAIL — ${inversions.join('; ')}`);
    return { status: 'FAIL', detail, inversions };
  }

  log('THRT-08: PASS');
  return { status: 'PASS', detail, inversions: [] };
}

// ─── THRT-09: Exploitability Validation ──────────────────────────────────────

function validateThrt09(rows: ScoreRow[]): ComponentResult {
  const severities = ['critical', 'high', 'medium', 'low'];
  const confirmedScores: Record<string, number[]> = {};
  const unconfirmedScores: Record<string, number[]> = {};

  for (const sev of severities) {
    confirmedScores[sev] = [];
    unconfirmedScores[sev] = [];
  }

  for (const row of rows) {
    const rawScore = getRawScore(row);
    if (rawScore == null) continue;
    if (!severities.includes(row.severity)) continue;

    if (isConfirmed(row)) {
      confirmedScores[row.severity].push(rawScore);
    } else {
      unconfirmedScores[row.severity].push(rawScore);
    }
  }

  const inversions: string[] = [];
  const ratioChecks: string[] = [];
  const detailLines: string[] = [];

  for (const sev of severities) {
    const confirmedAvg = avg(confirmedScores[sev]);
    const unconfirmedAvg = avg(unconfirmedScores[sev]);

    detailLines.push(
      `${sev}: confirmed=${confirmedAvg?.toFixed(2) ?? 'N/A'} (n=${confirmedScores[sev].length}), ` +
      `unconfirmed=${unconfirmedAvg?.toFixed(2) ?? 'N/A'} (n=${unconfirmedScores[sev].length})`
    );

    if (confirmedAvg !== null && unconfirmedAvg !== null) {
      if (confirmedAvg <= unconfirmedAvg) {
        inversions.push(`[${sev}] confirmed avg (${confirmedAvg.toFixed(2)}) <= unconfirmed avg (${unconfirmedAvg.toFixed(2)})`);
      } else {
        const ratio = confirmedAvg / unconfirmedAvg;
        // Expected ratio: 1.3 ± 10% tolerance (1.17 to 1.43)
        if (ratio < 1.17 || ratio > 1.43) {
          ratioChecks.push(`[${sev}] exploitability ratio ${ratio.toFixed(3)} outside [1.17, 1.43]`);
        }
      }
    }
  }

  const detail = detailLines.join('\n');

  const allIssues = [...inversions, ...ratioChecks];

  if (allIssues.length > 0) {
    log(`THRT-09: FAIL — ${allIssues.join('; ')}`);
    return { status: 'FAIL', detail, inversions: allIssues };
  }

  // Check if there was any data at all
  const hasData = severities.some(
    sev => confirmedScores[sev].length > 0 || unconfirmedScores[sev].length > 0
  );

  if (!hasData) {
    return {
      status: 'INSUFFICIENT_DATA',
      detail: detail + '\nInsufficient data for exploitability comparison.',
      inversions: [],
    };
  }

  log('THRT-09: PASS');
  return { status: 'PASS', detail, inversions: [] };
}

// ─── Auto-patch scoringEngine.ts ──────────────────────────────────────────────

interface PatchResult {
  changed: boolean;
  changes: string[];
  newSeverityWeights: Record<string, number>;
  newCriticalityMultipliers: Record<string, number>;
  newExploitabilityMultiplier: number;
}

function patchScoringEngine(
  thrt06Result: ComponentResult,
  thrt08Result: ComponentResult,
  thrt09Result: ComponentResult,
  rows: ScoreRow[]
): PatchResult {
  let source = readFileSync(SCORING_ENGINE_PATH, 'utf-8');
  const changes: string[] = [];
  let changed = false;

  // Current values (for logging and inline re-verification)
  let newSeverityWeights: Record<string, number> = { critical: 100, high: 75, medium: 50, low: 25 };
  let newCriticalityMultipliers: Record<string, number> = {
    domain: 1.5, server: 1.2, firewall: 1.2, router: 1.2, desktop: 1.0, switch: 1.0, other: 1.0,
  };
  let newExploitabilityMultiplier = 1.3;

  // ── THRT-06: Patch SEVERITY_WEIGHTS if inversions found ──────────────────
  if (thrt06Result.status === 'FAIL') {
    // Compute new weights based on actual averages to maintain strict ordering
    // Use progressive gaps to ensure strict hierarchy
    const bySeverity: Record<string, number[]> = { critical: [], high: [], medium: [], low: [] };
    for (const row of rows) {
      const rawScore = getRawScore(row);
      if (rawScore != null && row.severity in bySeverity) {
        bySeverity[row.severity].push(rawScore);
      }
    }

    const avgCritical = avg(bySeverity.critical) ?? 100;
    const avgHigh = avg(bySeverity.high) ?? 75;
    const avgMedium = avg(bySeverity.medium) ?? 50;
    const avgLow = avg(bySeverity.low) ?? 25;

    // Compute target weights: scale to maintain proportions while ensuring ordering
    const maxAvg = Math.max(avgCritical, avgHigh, avgMedium, avgLow);
    let newCritical = Math.round((avgCritical / maxAvg) * 100);
    let newHigh = Math.round((avgHigh / maxAvg) * 100);
    let newMedium = Math.round((avgMedium / maxAvg) * 100);
    let newLow = Math.round((avgLow / maxAvg) * 100);

    // Enforce strict ordering with minimum gaps
    if (newCritical <= newHigh) newCritical = newHigh + 25;
    if (newHigh <= newMedium) newHigh = newMedium + 25;
    if (newMedium <= newLow) newMedium = newLow + 25;
    if (newLow < 1) newLow = 1;

    const oldWeights = `{ critical: ${newSeverityWeights.critical}, high: ${newSeverityWeights.high}, medium: ${newSeverityWeights.medium}, low: ${newSeverityWeights.low} }`;
    newSeverityWeights = { critical: newCritical, high: newHigh, medium: newMedium, low: newLow };

    changes.push(`CHANGED: SEVERITY_WEIGHTS.critical ${newSeverityWeights.critical} (was part of ${oldWeights})`);
    log(`CHANGED: SEVERITY_WEIGHTS.critical ${newSeverityWeights.critical}`);
    log(`CHANGED: SEVERITY_WEIGHTS.high ${newSeverityWeights.high}`);
    log(`CHANGED: SEVERITY_WEIGHTS.medium ${newSeverityWeights.medium}`);
    log(`CHANGED: SEVERITY_WEIGHTS.low ${newSeverityWeights.low}`);

    const newBlock = `const SEVERITY_WEIGHTS: Record<string, number> = {\n  critical: ${newCritical},\n  high: ${newHigh},\n  medium: ${newMedium},\n  low: ${newLow},\n}`;
    source = source.replace(
      /const SEVERITY_WEIGHTS: Record<string, number> = \{[^}]+\}/s,
      newBlock
    );
    changed = true;
  }

  // ── THRT-08: Patch CRITICALITY_MULTIPLIERS if inversions found ───────────
  if (thrt08Result.status === 'FAIL') {
    // Compute new multipliers based on detected averages for a given severity level
    const severities = ['critical', 'high', 'medium', 'low'];
    const domainScores: number[] = [];
    const serverScores: number[] = [];
    const desktopScores: number[] = [];

    for (const row of rows) {
      const rawScore = getRawScore(row);
      if (rawScore == null) continue;
      if (!severities.includes(row.severity)) continue;

      const hostType = row.hostType ?? 'other';
      if (hostType === 'domain') domainScores.push(rawScore);
      else if (['server', 'firewall', 'router'].includes(hostType)) serverScores.push(rawScore);
      else desktopScores.push(rawScore);
    }

    const avgDomain = avg(domainScores) ?? 1.5;
    const avgServer = avg(serverScores) ?? 1.2;
    const avgDesktop = avg(desktopScores) ?? 1.0;

    // Compute relative multipliers, normalized to desktop=1.0
    const base = avgDesktop > 0 ? avgDesktop : 1;
    let newDomain = Math.round((avgDomain / base) * 100) / 100;
    let newServer = Math.round((avgServer / base) * 100) / 100;
    const newDesktop = 1.0;

    // Ensure strict ordering
    if (newDomain <= newServer) newDomain = newServer + 0.3;
    if (newServer <= newDesktop) newServer = newDesktop + 0.2;

    const oldDomain = newCriticalityMultipliers.domain;
    const oldServer = newCriticalityMultipliers.server;

    newCriticalityMultipliers = {
      domain: newDomain,
      server: newServer,
      firewall: newServer,
      router: newServer,
      desktop: 1.0,
      switch: 1.0,
      other: 1.0,
    };

    changes.push(`CHANGED: CRITICALITY_MULTIPLIERS.domain ${oldDomain} -> ${newDomain}`);
    changes.push(`CHANGED: CRITICALITY_MULTIPLIERS.server/firewall/router ${oldServer} -> ${newServer}`);
    log(`CHANGED: CRITICALITY_MULTIPLIERS.domain ${oldDomain} -> ${newDomain}`);
    log(`CHANGED: CRITICALITY_MULTIPLIERS.server/firewall/router ${oldServer} -> ${newServer}`);

    const newBlock = `const CRITICALITY_MULTIPLIERS: Record<string, number> = {\n  domain: ${newDomain},      // Domain Controller\n  server: ${newServer},\n  firewall: ${newServer},\n  router: ${newServer},\n  desktop: 1.0,\n  switch: 1.0,\n  other: 1.0,\n}`;
    source = source.replace(
      /const CRITICALITY_MULTIPLIERS: Record<string, number> = \{[^}]+\}/s,
      newBlock
    );
    changed = true;
  }

  // ── THRT-09: Patch exploitability multiplier if needed ───────────────────
  if (thrt09Result.status === 'FAIL') {
    const severities = ['critical', 'high', 'medium', 'low'];
    const confirmedScoresBySev: Record<string, number[]> = {};
    const unconfirmedScoresBySev: Record<string, number[]> = {};

    for (const sev of severities) {
      confirmedScoresBySev[sev] = [];
      unconfirmedScoresBySev[sev] = [];
    }

    for (const row of rows) {
      const rawScore = getRawScore(row);
      if (rawScore == null) continue;
      if (!severities.includes(row.severity)) continue;

      if (isConfirmed(row)) {
        confirmedScoresBySev[row.severity].push(rawScore);
      } else {
        unconfirmedScoresBySev[row.severity].push(rawScore);
      }
    }

    // Compute target ratio from actual data
    let totalConfirmed = 0;
    let totalUnconfirmed = 0;
    let count = 0;

    for (const sev of severities) {
      const confirmedAvg = avg(confirmedScoresBySev[sev]);
      const unconfirmedAvg = avg(unconfirmedScoresBySev[sev]);
      if (confirmedAvg !== null && unconfirmedAvg !== null && unconfirmedAvg > 0) {
        totalConfirmed += confirmedAvg;
        totalUnconfirmed += unconfirmedAvg;
        count++;
      }
    }

    let newMultiplier = count > 0 ? totalConfirmed / totalUnconfirmed : 1.3;

    // Clamp to reasonable range
    newMultiplier = Math.max(1.1, Math.min(2.0, newMultiplier));
    newMultiplier = Math.round(newMultiplier * 100) / 100;

    const oldMultiplier = newExploitabilityMultiplier;
    newExploitabilityMultiplier = newMultiplier;

    changes.push(`CHANGED: exploitabilityMultiplier ${oldMultiplier} -> ${newMultiplier}`);
    log(`CHANGED: exploitabilityMultiplier ${oldMultiplier} -> ${newMultiplier}`);

    // Replace the hardcoded 1.3 in the ternary expression
    source = source.replace(
      /threat\.source === 'nmap_vuln' \|\| hasNucleiConfirmation \? 1\.3 : 1\.0/,
      `threat.source === 'nmap_vuln' || hasNucleiConfirmation ? ${newMultiplier} : 1.0`
    );
    changed = true;
  }

  if (changed) {
    writeFileSync(SCORING_ENGINE_PATH, source, 'utf-8');
    log(`scoringEngine.ts patched with ${changes.length} change(s)`);
  }

  return { changed, changes, newSeverityWeights, newCriticalityMultipliers, newExploitabilityMultiplier };
}

// ─── Post-patch re-verification ───────────────────────────────────────────────

function reverifyAfterPatch(
  rows: ScoreRow[],
  patch: PatchResult
): { thrt06Ok: boolean; thrt08Ok: boolean; thrt09Ok: boolean } {
  const sw = patch.newSeverityWeights;
  const cm = patch.newCriticalityMultipliers;
  const em = patch.newExploitabilityMultiplier;

  // Re-verify THRT-06 using inline formula
  const severityGroups: Record<string, number[]> = { critical: [], high: [], medium: [], low: [] };
  for (const row of rows) {
    if (row.severity in severityGroups) {
      const score = computeRawScore(row.severity, null, 1.0, sw, cm);
      severityGroups[row.severity].push(score);
    }
  }

  const avgC = avg(severityGroups.critical);
  const avgH = avg(severityGroups.high);
  const avgM = avg(severityGroups.medium);
  const avgL = avg(severityGroups.low);

  const thrt06Ok =
    avgC !== null && avgH !== null && avgM !== null && avgL !== null &&
    avgC > avgH && avgH > avgM && avgM > avgL;

  // Re-verify THRT-08
  const hostGroups: Record<string, Record<string, number[]>> = {};
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    hostGroups[sev] = { domain: [], server: [], desktop: [] };
  }

  for (const row of rows) {
    if (!['critical', 'high', 'medium', 'low'].includes(row.severity)) continue;
    const hostType = row.hostType ?? 'other';
    const group = hostType === 'domain' ? 'domain'
      : ['server', 'firewall', 'router'].includes(hostType) ? 'server'
      : 'desktop';
    const score = computeRawScore(row.severity, hostType, 1.0, sw, cm);
    hostGroups[row.severity][group].push(score);
  }

  let thrt08Ok = true;
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    const d = avg(hostGroups[sev].domain);
    const s = avg(hostGroups[sev].server);
    const dt = avg(hostGroups[sev].desktop);
    if (d !== null && s !== null && d <= s) { thrt08Ok = false; break; }
    if (s !== null && dt !== null && s <= dt) { thrt08Ok = false; break; }
  }

  // Re-verify THRT-09
  const confirmedScores: number[] = [];
  const unconfirmedScores: number[] = [];

  for (const row of rows) {
    const score = computeRawScore(row.severity, row.hostType, isConfirmed(row) ? em : 1.0, sw, cm);
    if (isConfirmed(row)) confirmedScores.push(score);
    else unconfirmedScores.push(score);
  }

  const confirmedAvg = avg(confirmedScores);
  const unconfirmedAvg = avg(unconfirmedScores);
  const thrt09Ok = confirmedAvg !== null && unconfirmedAvg !== null &&
    confirmedAvg > unconfirmedAvg &&
    confirmedAvg / unconfirmedAvg >= 1.17 &&
    confirmedAvg / unconfirmedAvg <= 1.43;

  return { thrt06Ok, thrt08Ok, thrt09Ok };
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  if (!process.env.DATABASE_URL) {
    log('ERROR: DATABASE_URL not set');
    process.exit(1);
  }

  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  const db = drizzle({ client: pool, schema });

  try {
    log('Connecting to database...');

    // Query threats joined with hosts where contextualScore IS NOT NULL
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

    log(`Found ${rows.length} scored threat(s) in database`);

    // Empty DB guard
    if (rows.length === 0) {
      log('SKIPPED: no scored threats in database');

      const reportContent = `# Calibration Report -- ${new Date().toISOString()}

## Summary
- THRT-06 (Severity Weights): SKIPPED
- THRT-08 (Host Criticality): SKIPPED
- THRT-09 (Exploitability): SKIPPED

## Data Summary
- Total scored threats analyzed: 0
- SKIPPED: no scored threats in database

## Component Details

### THRT-06: Severity Weights
SKIPPED: no scored threats in database

### THRT-08: Host Criticality Multipliers
SKIPPED: no scored threats in database

### THRT-09: Exploitability Multiplier
SKIPPED: no scored threats in database

## Changes Made
NO CHANGES -- no data available for calibration
`;

      await writeFile(REPORT_PATH, reportContent, 'utf-8');
      log(`Report written to ${REPORT_PATH}`);
      await pool.end();
      return;
    }

    // Compute severity distribution
    const severityCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    const hostTypeCounts: Record<string, number> = { domain: 0, server: 0, desktop: 0, other: 0 };

    for (const row of rows) {
      if (row.severity in severityCounts) severityCounts[row.severity]++;
      const ht = row.hostType ?? 'other';
      if (ht === 'domain') hostTypeCounts.domain++;
      else if (['server', 'firewall', 'router'].includes(ht)) hostTypeCounts.server++;
      else if (['desktop', 'switch'].includes(ht)) hostTypeCounts.desktop++;
      else hostTypeCounts.other++;
    }

    // Run validations
    log('Running THRT-06 validation (severity weights)...');
    const thrt06 = validateThrt06(rows);

    log('Running THRT-08 validation (host criticality)...');
    const thrt08 = validateThrt08(rows);

    log('Running THRT-09 validation (exploitability)...');
    const thrt09 = validateThrt09(rows);

    const anyFail = [thrt06, thrt08, thrt09].some(r => r.status === 'FAIL');

    // Auto-patch if any component failed
    let patchResult: PatchResult | null = null;
    let reverifyResult: { thrt06Ok: boolean; thrt08Ok: boolean; thrt09Ok: boolean } | null = null;

    if (anyFail) {
      log('Inversions detected — auto-patching scoringEngine.ts...');
      patchResult = patchScoringEngine(thrt06, thrt08, thrt09, rows);

      if (patchResult.changed) {
        log('Re-verifying with patched constants (inline formula — no module cache)...');
        reverifyResult = reverifyAfterPatch(rows, patchResult);

        log(`Re-verify THRT-06: ${reverifyResult.thrt06Ok ? 'OK' : 'STILL FAILING'}`);
        log(`Re-verify THRT-08: ${reverifyResult.thrt08Ok ? 'OK' : 'STILL FAILING'}`);
        log(`Re-verify THRT-09: ${reverifyResult.thrt09Ok ? 'OK' : 'STILL FAILING'}`);
      }
    }

    // Build report
    const thrt06Status = thrt06.status === 'INSUFFICIENT_DATA' ? 'SKIPPED (insufficient data)' : thrt06.status;
    const thrt08Status = thrt08.status === 'INSUFFICIENT_DATA' ? 'SKIPPED (insufficient data)' : thrt08.status;
    const thrt09Status = thrt09.status === 'INSUFFICIENT_DATA' ? 'SKIPPED (insufficient data)' : thrt09.status;

    let changesSection: string;
    if (!patchResult || !patchResult.changed) {
      changesSection = 'NO CHANGES -- all components passed';
    } else {
      changesSection = patchResult.changes.join('\n');
      if (reverifyResult) {
        changesSection += '\n\n### Re-verification after patch\n';
        changesSection += `- THRT-06: ${reverifyResult.thrt06Ok ? 'VERIFIED OK' : 'WARNING: still failing'}\n`;
        changesSection += `- THRT-08: ${reverifyResult.thrt08Ok ? 'VERIFIED OK' : 'WARNING: still failing'}\n`;
        changesSection += `- THRT-09: ${reverifyResult.thrt09Ok ? 'VERIFIED OK' : 'WARNING: still failing'}\n`;
      }
    }

    const thrt06Inversions = thrt06.inversions.length > 0
      ? '\n\n**Inversions found:**\n' + thrt06.inversions.map(i => `- ${i}`).join('\n')
      : '';

    const thrt08Inversions = thrt08.inversions.length > 0
      ? '\n\n**Inversions found:**\n' + thrt08.inversions.map(i => `- ${i}`).join('\n')
      : '';

    const thrt09Inversions = thrt09.inversions.length > 0
      ? '\n\n**Issues found:**\n' + thrt09.inversions.map(i => `- ${i}`).join('\n')
      : '';

    const reportContent = `# Calibration Report -- ${new Date().toISOString()}

## Summary
- THRT-06 (Severity Weights): ${thrt06Status}
- THRT-08 (Host Criticality): ${thrt08Status}
- THRT-09 (Exploitability): ${thrt09Status}

## Data Summary
- Total scored threats analyzed: ${rows.length}
- Severity distribution: critical=${severityCounts.critical}, high=${severityCounts.high}, medium=${severityCounts.medium}, low=${severityCounts.low}
- Host type distribution: domain=${hostTypeCounts.domain}, server=${hostTypeCounts.server}, desktop=${hostTypeCounts.desktop}, other=${hostTypeCounts.other}

## Component Details

### THRT-06: Severity Weights
${thrt06.detail}${thrt06Inversions}

### THRT-08: Host Criticality Multipliers
${thrt08.detail}${thrt08Inversions}

### THRT-09: Exploitability Multiplier
${thrt09.detail}${thrt09Inversions}

## Changes Made
${changesSection}
`;

    await writeFile(REPORT_PATH, reportContent, 'utf-8');
    log(`Report written to ${REPORT_PATH}`);

  } catch (err: any) {
    log(`ERROR: DB connection failed -- ${err.message}`);
    await pool.end();
    process.exit(1);
  }

  await pool.end();
  log('Done.');
}

main().catch((err) => {
  console.error(`[calibrate] FATAL: ${err.message}`);
  process.exit(1);
});
