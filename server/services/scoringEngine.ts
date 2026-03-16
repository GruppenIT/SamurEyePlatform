import { storage } from '../storage';
import { getThreats, updateThreat } from '../storage/threats';
import { writePostureSnapshot } from '../storage/posture';
import {
  type Threat,
  type Host,
  type ScoreBreakdownRecord,
} from '@shared/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('scoringEngine');

// Base severity weights (locked decision — matches plan spec)
const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 100,
  high: 75,
  medium: 50,
  low: 25,
};

// Host type → criticality multiplier (THRT-08)
const CRITICALITY_MULTIPLIERS: Record<string, number> = {
  domain: 1.5,      // Domain Controller
  server: 1.2,
  firewall: 1.2,
  router: 1.2,
  desktop: 1.0,
  switch: 1.0,
  other: 1.0,
};

// Journey type → exposure factor (THRT-06)
const EXPOSURE_FACTORS: Record<string, number> = {
  attack_surface: 1.3,
  ad_security: 1.0,
  edr_av: 0.9,
  web_application: 1.2,
};

export class ScoringEngineService {
  /**
   * Computes the contextual score for a single threat.
   * Pure function — no DB access.
   *
   * Score formula (locked — THRT-06):
   *   rawScore = baseSeverity * 0.40
   *            + (baseSeverity * criticalityMult) * 0.25
   *            + (baseSeverity * exposureFact) * 0.20
   *            + (baseSeverity * controlsFact) * 0.15
   *   rawScore *= exploitabilityMultiplier
   *   normalizedScore = clamp(rawScore, 0, 100)
   */
  computeContextualScore(
    threat: Threat,
    host: Host | undefined,
    journeyType: string,
    edrStatus: 'passed' | 'unknown',
  ): ScoreBreakdownRecord {
    const baseSeverityWeight = SEVERITY_WEIGHTS[threat.severity] ?? 50;

    // Criticality multiplier from host type
    const hostType = host?.type ?? 'other';
    const criticalityMultiplier = CRITICALITY_MULTIPLIERS[hostType] ?? 1.0;

    // Exposure factor from journey type
    const exposureFactor = EXPOSURE_FACTORS[journeyType] ?? 1.0;

    // Controls reduction: EICAR/EDR passed → 0.85, else 1.0
    const controlsReductionFactor = edrStatus === 'passed' ? 0.85 : 1.0;

    // Exploitability: nmap_vuln source or nuclei match confirmation
    const hasNucleiConfirmation = Boolean(
      (threat.evidence as any)?.nucleiMatch ||
      (threat.evidence as any)?.confirmed
    );
    const exploitabilityMultiplier =
      threat.source === 'nmap_vuln' || hasNucleiConfirmation ? 1.3 : 1.0;

    // Weighted formula
    const rawScore =
      (baseSeverityWeight * 0.40
        + baseSeverityWeight * criticalityMultiplier * 0.25
        + baseSeverityWeight * exposureFactor * 0.20
        + baseSeverityWeight * controlsReductionFactor * 0.15)
      * exploitabilityMultiplier;

    const normalizedScore = Math.max(0, Math.min(100, rawScore));

    return {
      baseSeverityWeight,
      criticalityMultiplier,
      exposureFactor,
      controlsReductionFactor,
      exploitabilityMultiplier,
      rawScore,
      normalizedScore,
    };
  }

  /**
   * Computes overall posture score from a list of threats.
   * Only open threats contribute. Returns 100 if no open threats.
   *
   * Formula: posture = 100 - (sum(contextualScores) / (count * 100)) * 100
   * Clamped to [0, 100].
   */
  computePostureFromThreats(threats: Threat[]): number {
    const openThreats = threats.filter(t => t.status === 'open');

    if (openThreats.length === 0) {
      return 100;
    }

    const sum = openThreats.reduce((acc, t) => acc + (t.contextualScore ?? 50), 0);
    const posture = 100 - (sum / (openThreats.length * 100)) * 100;

    return Math.max(0, Math.min(100, posture));
  }

  /**
   * Scores all threats for a given job.
   * For each threat: fetches host, determines EDR status, computes and persists score.
   */
  async scoreAllThreatsForJob(jobId: string): Promise<void> {
    const job = await storage.getJob(jobId);
    if (!job) {
      log.warn({ jobId }, 'scoreAllThreatsForJob: job not found');
      return;
    }

    const journey = await storage.getJourney(job.journeyId);
    if (!journey) {
      log.warn({ jobId, journeyId: job.journeyId }, 'scoreAllThreatsForJob: journey not found');
      return;
    }

    const jobThreats = await getThreats({ jobId });
    log.info({ jobId, threatCount: jobThreats.length, journeyType: journey.type }, 'scoring threats for job');

    for (const threat of jobThreats) {
      try {
        // Resolve host
        let host: Host | undefined;
        if (threat.hostId) {
          host = await storage.getHost(threat.hostId) ?? undefined;
        }

        // Determine EDR status: check for closed edr_av threat with same host
        const edrStatus = await this._resolveEdrStatus(threat, job.journeyId);

        const breakdown = this.computeContextualScore(threat, host, journey.type, edrStatus);

        await updateThreat(threat.id, {
          contextualScore: breakdown.normalizedScore,
          scoreBreakdown: breakdown,
        });
      } catch (err) {
        log.error({ err, threatId: threat.id }, 'failed to score threat');
      }
    }

    log.info({ jobId, threatCount: jobThreats.length }, 'finished scoring threats');
  }

  /**
   * Computes projected posture score delta for each parent threat group.
   * projectedScoreAfterFix = posture(without children) - posture(all open)
   */
  async computeProjectedScores(jobId: string): Promise<void> {
    const job = await storage.getJob(jobId);
    if (!job) return;

    // All currently open threats across the system (not just this job — for global posture)
    const allOpenThreats = await getThreats({ status: 'open' });
    const currentPosture = this.computePostureFromThreats(allOpenThreats);

    // Get job threats to find parents
    const jobThreats = await getThreats({ jobId });
    const parentThreats = jobThreats.filter(t => !t.parentThreatId);

    for (const parent of parentThreats) {
      try {
        // Find children of this parent (threats from this job that point to this parent)
        const children = jobThreats.filter(t => t.parentThreatId === parent.id);
        const idsToRemove = new Set([parent.id, ...children.map(c => c.id)]);

        const remainingThreats = allOpenThreats.filter(t => !idsToRemove.has(t.id));
        const projectedPosture = this.computePostureFromThreats(remainingThreats);

        const projectedScoreAfterFix = projectedPosture - currentPosture;

        await updateThreat(parent.id, { projectedScoreAfterFix });
      } catch (err) {
        log.error({ err, parentId: parent.id }, 'failed to compute projected score for parent threat');
      }
    }
  }

  /**
   * Writes a posture snapshot after scoring completes.
   */
  async writePostureSnapshot(jobId: string, journeyId: string): Promise<void> {
    try {
      const allOpenThreats = await getThreats({ status: 'open' });
      const score = this.computePostureFromThreats(allOpenThreats);

      let criticalCount = 0;
      let highCount = 0;
      let mediumCount = 0;
      let lowCount = 0;

      for (const t of allOpenThreats) {
        if (t.severity === 'critical') criticalCount++;
        else if (t.severity === 'high') highCount++;
        else if (t.severity === 'medium') mediumCount++;
        else if (t.severity === 'low') lowCount++;
      }

      await writePostureSnapshot({
        jobId,
        journeyId,
        score,
        openThreatCount: allOpenThreats.length,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        scoredAt: new Date(),
      });

      log.info({ jobId, journeyId, score, openThreatCount: allOpenThreats.length }, 'posture snapshot written');
    } catch (err) {
      log.error({ err, jobId }, 'failed to write posture snapshot');
    }
  }

  /**
   * Determines EDR status for a threat by looking for a closed edr_av threat
   * with correlationKey matching `edr:{hostname}:%`.
   */
  private async _resolveEdrStatus(threat: Threat, _journeyId: string): Promise<'passed' | 'unknown'> {
    try {
      // Only meaningful if the threat has host context
      if (!threat.hostId) return 'unknown';

      // Look for closed EDR threat for this host
      const edrThreats = await getThreats({ hostId: threat.hostId, status: 'closed', category: 'edr_av' });
      if (edrThreats.length > 0) {
        return 'passed';
      }
    } catch (_err) {
      // Non-fatal — default to unknown
    }
    return 'unknown';
  }
}

export const scoringEngine = new ScoringEngineService();
