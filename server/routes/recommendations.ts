import type { Express } from "express";
import { z } from "zod";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { getRecommendationByThreatId, getRecommendations } from "../storage/recommendations";
import { createLogger } from "../lib/logger";

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
}
