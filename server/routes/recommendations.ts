import type { Express } from "express";
import { z } from "zod";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { getRecommendationByThreatId, getRecommendations } from "../storage/recommendations";
import { createLogger } from "../lib/logger";
import { db } from "../db";
import { recommendations, threats } from "@shared/schema";
import { eq, and, desc, isNull } from "drizzle-orm";

const log = createLogger('routes:recommendations');

const EFFORT_TAGS = ['minutes', 'hours', 'days', 'weeks'] as const;
const ROLES_REQUIRED = ['sysadmin', 'developer', 'security', 'vendor'] as const;
const STATUSES = ['pending', 'applied', 'verified', 'failed'] as const;

const recommendationFiltersSchema = z.object({
  effortTag: z.enum(EFFORT_TAGS).optional(),
  roleRequired: z.enum(ROLES_REQUIRED).optional(),
  status: z.enum(STATUSES).optional(),
  journeyType: z.string().optional(),
});

export function registerRecommendationRoutes(app: Express) {
  /**
   * GET /api/threats/:id/recommendation
   * Returns the recommendation for a specific threat.
   * Auth: isAuthenticatedWithPasswordCheck (read-only)
   */
  app.get('/api/threats/:id/recommendation', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { id } = req.params;
      const recommendation = await getRecommendationByThreatId(id);

      if (!recommendation) {
        return res.status(404).json({ message: "Recomendacao nao encontrada para esta ameaca" });
      }

      res.json(recommendation);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch recommendation for threat');
      res.status(500).json({ message: "Falha ao buscar recomendacao" });
    }
  });

  /**
   * GET /api/recommendations
   * Returns a filterable list of recommendations.
   * Query params: effortTag, roleRequired, status, journeyType (all optional)
   * Auth: isAuthenticatedWithPasswordCheck
   */
  app.get('/api/recommendations', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const parseResult = recommendationFiltersSchema.safeParse(req.query);
      if (!parseResult.success) {
        return res.status(400).json({
          message: parseResult.error.issues.map(i => i.message).join(', ')
        });
      }

      const { effortTag, roleRequired, status } = parseResult.data;
      const filters: { effortTag?: string; roleRequired?: string; status?: string } = {};

      if (effortTag) filters.effortTag = effortTag;
      if (roleRequired) filters.roleRequired = roleRequired;
      if (status) filters.status = status;

      const recommendations = await getRecommendations(
        Object.keys(filters).length > 0 ? filters : undefined
      );

      res.json(recommendations);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch recommendations');
      res.status(500).json({ message: "Falha ao buscar recomendacoes" });
    }
  });

  /**
   * GET /api/recommendations/top
   * Returns prioritized remediation actions joined with threat data.
   * Replaces legacy GET /api/action-plan endpoint.
   * Query params: effortTag, roleRequired, category, limit (default 10, max 50)
   * Auth: isAuthenticatedWithPasswordCheck
   */
  app.get('/api/recommendations/top', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { effortTag, roleRequired, category } = req.query as Record<string, string | undefined>;
      const rawLimit = parseInt((req.query.limit as string) ?? '10', 10);
      const limit = isNaN(rawLimit) ? 10 : Math.min(Math.max(rawLimit, 1), 50);

      const conditions = [
        eq(threats.status, 'open'),
        isNull(threats.parentThreatId),
      ];

      if (effortTag) conditions.push(eq(recommendations.effortTag, effortTag));
      if (roleRequired) conditions.push(eq(recommendations.roleRequired, roleRequired));
      if (category) conditions.push(eq(threats.category, category));

      const rows = await db
        .select({
          recommendationId: recommendations.id,
          threatId: threats.id,
          threatTitle: threats.title,
          threatSeverity: threats.severity,
          threatCategory: threats.category,
          contextualScore: threats.contextualScore,
          projectedScoreAfterFix: threats.projectedScoreAfterFix,
          whatIsWrong: recommendations.whatIsWrong,
          fixSteps: recommendations.fixSteps,
          effortTag: recommendations.effortTag,
          roleRequired: recommendations.roleRequired,
          status: recommendations.status,
        })
        .from(recommendations)
        .innerJoin(threats, eq(recommendations.threatId, threats.id))
        .where(and(...conditions))
        .orderBy(desc(threats.contextualScore))
        .limit(limit);

      const result = rows.map(r => ({
        recommendationId: r.recommendationId,
        threatId: r.threatId,
        threatTitle: r.threatTitle,
        threatSeverity: r.threatSeverity,
        threatCategory: r.threatCategory,
        contextualScore: r.contextualScore,
        projectedScoreAfterFix: r.projectedScoreAfterFix,
        whatIsWrong: r.whatIsWrong,
        fixPreview: Array.isArray(r.fixSteps) && r.fixSteps.length > 0 ? r.fixSteps[0] : '',
        effortTag: r.effortTag,
        roleRequired: r.roleRequired,
        status: r.status,
      }));

      res.json(result);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch top recommendations');
      res.status(500).json({ message: "Falha ao buscar recomendações prioritárias" });
    }
  });
}
