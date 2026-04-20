/**
 * Phase 12 — API Findings read path.
 *
 * GET /api/v1/api-findings — list findings with filters (RBAC inclui
 * readonly_analyst pois é read-only).
 *
 * Phase 14 (FIND-02) centralizará sanitização de evidence globally.
 * Phase 16 adicionará UI de drill-down; Phase 12 entrega apenas o read path
 * para uso interno e UAT.
 */
import type { Express } from 'express';
import { z } from 'zod';
import { storage } from '../storage';
import { isAuthenticatedWithPasswordCheck } from '../localAuth';
import { requireAnyRole } from './middleware';
import { createLogger } from '../lib/logger';

const log = createLogger('routes:apiFindings');

/**
 * Zod schema for GET /api/v1/api-findings query string. .strict() prevents
 * typos/unknown params silently ignored. At least one of apiId/endpointId/
 * jobId MUST be present (refine below).
 */
const listFindingsQuerySchema = z
  .object({
    apiId: z.string().uuid().optional(),
    endpointId: z.string().uuid().optional(),
    jobId: z.string().uuid().optional(),
    owaspCategory: z
      .enum([
        'api1_bola_2023',
        'api2_broken_auth_2023',
        'api3_bopla_2023',
        'api4_rate_limit_2023',
        'api5_bfla_2023',
        'api6_business_flow_2023',
        'api7_ssrf_2023',
        'api8_misconfiguration_2023',
        'api9_inventory_2023',
        'api10_unsafe_consumption_2023',
      ])
      .optional(),
    severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
    status: z.enum(['open', 'triaged', 'false_positive', 'closed']).optional(),
    limit: z.coerce.number().int().min(1).max(500).optional(),
    offset: z.coerce.number().int().min(0).optional(),
  })
  .strict()
  .refine((q) => !!(q.apiId || q.endpointId || q.jobId), {
    message: 'Forneça ao menos um filtro: apiId, endpointId ou jobId',
  });

export function registerApiFindingsRoutes(app: Express) {
  /**
   * GET /api/v1/api-findings
   * Query params: apiId | endpointId | jobId (at least one required),
   *               owaspCategory, severity, status, limit, offset.
   * RBAC: requireAnyRole (inclui readonly_analyst — este read path é
   *       auditoria interna).
   */
  app.get(
    '/api/v1/api-findings',
    isAuthenticatedWithPasswordCheck,
    requireAnyRole,
    async (req: any, res) => {
      let parsed: z.infer<typeof listFindingsQuerySchema>;
      try {
        parsed = listFindingsQuerySchema.parse(req.query);
      } catch (err: any) {
        log.info({ err, query: req.query }, 'api-findings query rejected by Zod');
        return res.status(400).json({
          message: err?.errors?.[0]?.message ?? 'Parâmetros de filtro inválidos',
          details: err?.errors ?? undefined,
        });
      }

      try {
        const findings = await storage.listApiFindings({
          apiId: parsed.apiId,
          endpointId: parsed.endpointId,
          jobId: parsed.jobId,
          owaspCategory: parsed.owaspCategory,
          severity: parsed.severity,
          status: parsed.status,
          limit: parsed.limit ?? 50,
          offset: parsed.offset ?? 0,
        });
        log.info(
          {
            userId: req.user.id,
            filterKeys: Object.keys(parsed),
            resultCount: findings.length,
          },
          'api findings listed',
        );
        return res.json(findings);
      } catch (err) {
        log.error({ err }, 'failed to list api findings');
        return res.status(500).json({ message: 'Falha ao listar findings de API' });
      }
    },
  );
}
