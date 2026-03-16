import { storage } from '../storage';
import { getThreats, getChildThreats } from '../storage/threats';
import { upsertRecommendation, getRecommendationByThreatId } from '../storage/recommendations';
import { templateMap, getTemplate } from './remediation-templates/index';
import type { RecommendationContext } from './remediation-templates/types';
import type { Threat } from '@shared/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('recommendationEngine');

export class RecommendationEngine {
  /**
   * Generates recommendations for all parent/standalone threats in a job.
   * Called in processJobResults pipeline after scoring, before posture snapshot.
   */
  async generateForJob(jobId: string): Promise<void> {
    const job = await storage.getJob(jobId);
    if (!job) {
      log.warn({ jobId }, 'generateForJob: job not found, skipping');
      return;
    }

    // Fetch only parent/standalone threats (not child threats)
    const threats = await getThreats({ jobId });
    const parentAndStandalone = threats.filter(t => t.parentThreatId === null);

    let generated = 0;
    let skipped = 0;

    for (const threat of parentAndStandalone) {
      try {
        const ruleId = (threat as any).ruleId || threat.category;
        const templateFn = ruleId ? getTemplate(ruleId) : undefined;

        if (!templateFn) {
          log.warn({ threatId: threat.id, ruleId }, 'no template found for threat rule, skipping');
          skipped++;
          continue;
        }

        // Resolve host if available
        const host = threat.hostId ? await storage.getHost(threat.hostId) : undefined;
        const hostFamily = (host as any)?.family || 'other';

        // Build evidence from threat itself
        let evidence: Record<string, any> = (threat.evidence as Record<string, any>) || {};
        let childEvidences: Array<Record<string, any>> | undefined;

        // If parent group threat, aggregate child evidences
        if (threat.groupingKey) {
          const children = await getChildThreats(threat.id);
          childEvidences = children.map(c => (c.evidence as Record<string, any>) || {});
          // Merge first child evidence as base if parent evidence is empty
          if (!evidence.host && childEvidences.length > 0) {
            evidence = { ...childEvidences[0], ...evidence };
          }
        }

        const ctx: RecommendationContext = {
          threat,
          host: host as any,
          hostFamily,
          evidence,
          childEvidences,
        };

        const generated_rec = templateFn(ctx);

        await upsertRecommendation({
          threatId: threat.id,
          templateId: ruleId || 'unknown',
          title: generated_rec.title,
          whatIsWrong: generated_rec.whatIsWrong,
          businessImpact: generated_rec.businessImpact,
          fixSteps: generated_rec.fixSteps,
          verificationStep: generated_rec.verificationStep,
          references: generated_rec.references,
          effortTag: generated_rec.effortTag,
          roleRequired: generated_rec.roleRequired,
          hostSpecificData: generated_rec.hostSpecificData,
        } as any);

        generated++;
      } catch (err) {
        log.error({ err, threatId: threat.id }, 'error generating recommendation for threat');
        skipped++;
      }
    }

    log.info({ jobId, generated, skipped }, 'recommendation generation complete');
  }

  /**
   * Syncs recommendation status when a threat status changes.
   * Status transitions:
   *   mitigated -> applied
   *   closed    -> verified
   *   open      -> failed (reactivation)
   *
   * Other statuses (investigating, hibernated) are no-ops.
   */
  async syncRecommendationStatus(threatId: string, newThreatStatus: string): Promise<void> {
    const STATUS_MAP: Record<string, string> = {
      mitigated: 'applied',
      closed: 'verified',
      open: 'failed',
    };

    const recommendationStatus = STATUS_MAP[newThreatStatus];
    if (!recommendationStatus) {
      // No-op for statuses not in the lifecycle map
      return;
    }

    const existing = await getRecommendationByThreatId(threatId);
    if (!existing) {
      // No recommendation exists for this threat — silently return
      return;
    }

    await upsertRecommendation({
      ...existing,
      status: recommendationStatus,
      updatedAt: new Date(),
    } as any);

    log.info({ threatId, newThreatStatus, recommendationStatus }, 'recommendation status synced');
  }
}

export const recommendationEngine = new RecommendationEngine();
