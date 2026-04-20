import { randomUUID } from 'crypto';
import type { Express } from "express";
import { storage } from "../storage";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { requireOperator } from "./middleware";
import { insertApiSchema, discoverApiOptsSchema, apiPassiveTestOptsSchema } from "@shared/schema";
import { normalizeTarget } from "../services/journeys/urls";
import { createLogger } from '../lib/logger';
import { discoverApi } from "../services/journeys/apiDiscovery";
import { runApiPassiveTests } from "../services/journeys/apiPassiveTests";

const log = createLogger('routes:apis');

export function registerApiRoutes(app: Express) {
  /**
   * POST /api/v1/apis — HIER-03 manual API registration.
   *
   * Body: { parentAssetId, baseUrl, apiType, name?, description?, specUrl? }
   * Parent must be an existing asset of type='web_application'.
   * baseUrl is normalized via normalizeTarget() before persistence.
   * Returns 201 with the created row. 409 on duplicate (parent_asset_id, base_url).
   */
  app.post('/api/v1/apis', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    let body: ReturnType<typeof insertApiSchema.parse>;
    try {
      body = insertApiSchema.parse(req.body);
    } catch (err: any) {
      // Zod parse failure — shape-level error. Emit a concise pt-BR message.
      log.info({ err }, 'api registration rejected by Zod');
      return res.status(400).json({
        message: "Dados de API inválidos",
        details: err?.errors ?? undefined,
      });
    }

    try {
      const userId = req.user.id;

      // Cross-DB validation: parent must exist and be web_application.
      const parent = await storage.getAsset(body.parentAssetId);
      if (!parent) {
        return res.status(400).json({ message: "Ativo pai não encontrado" });
      }
      if (parent.type !== 'web_application') {
        return res.status(400).json({
          message: "Apenas ativos do tipo web_application podem hospedar uma API",
        });
      }

      // URL normalization — reuse existing helper so apis.base_url matches assets.value shape.
      const normalized = normalizeTarget(body.baseUrl);
      if (!normalized) {
        return res.status(400).json({ message: "URL base inválida" });
      }

      const api = await storage.createApi(
        { ...body, baseUrl: normalized } as any,
        userId,
      );

      await storage.logAudit({
        actorId: userId,
        action: 'create',
        objectType: 'api',
        objectId: api.id,
        before: null,
        after: api,
      });

      log.info({
        apiId: api.id,
        parentAssetId: body.parentAssetId,
        baseUrl: normalized,
        apiType: body.apiType,
      }, 'api registered manually');

      return res.status(201).json(api);
    } catch (error: any) {
      // Postgres unique_violation = 23505.
      if (error?.code === '23505') {
        return res.status(409).json({
          message: "API já cadastrada para esse ativo com essa URL base",
        });
      }
      log.error({ err: error }, 'failed to create api');
      return res.status(400).json({ message: "Falha ao cadastrar API" });
    }
  });

  /**
   * POST /api/v1/apis/:id/discover — DISC-01..06, ENRH-01..03.
   *
   * Body: DiscoverApiOpts (validated by discoverApiOptsSchema).
   * RBAC: operator + global_administrator (via requireOperator).
   * Returns 202 Accepted with { jobId, result: DiscoveryResult } on success.
   * Phase 15 will wire jobQueue; Phase 11 generates a synthetic jobId.
   */
  app.post('/api/v1/apis/:id/discover', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    const apiId = req.params.id;

    let opts: ReturnType<typeof discoverApiOptsSchema.parse>;
    try {
      opts = discoverApiOptsSchema.parse(req.body ?? {});
    } catch (err: any) {
      log.info({ err, apiId }, 'discovery opts rejected by Zod');
      return res.status(400).json({
        message: "Dados inválidos para discovery",
        details: err?.errors ?? undefined,
      });
    }

    try {
      const api = await storage.getApi(apiId);
      if (!api) {
        return res.status(404).json({ message: "API não encontrada" });
      }

      const jobId = randomUUID();
      const userId = req.user.id;

      log.info({
        apiId,
        userId,
        jobId,
        stages: opts.stages,
        dryRun: opts.dryRun,
        hasArjun: opts.stages.arjun,
        hasKiterunner: opts.stages.kiterunner,
      }, 'discovery requested');

      const result = await discoverApi(apiId, opts, jobId);

      await storage.logAudit({
        actorId: userId,
        action: 'discover',
        objectType: 'api',
        objectId: apiId,
        before: null,
        after: {
          stagesRun: result.stagesRun,
          endpointsDiscovered: result.endpointsDiscovered,
          endpointsUpdated: result.endpointsUpdated,
          durationMs: result.durationMs,
        },
      });

      return res.status(202).json({ jobId, result });
    } catch (error: any) {
      log.error({ err: error, apiId }, 'failed to execute discovery');
      return res.status(500).json({ message: "Falha ao executar discovery" });
    }
  });

  /**
   * POST /api/v1/apis/:id/test/passive — Phase 12 TEST-01/TEST-02 entrypoint.
   *
   * Body: ApiPassiveTestOpts (see shared/schema.ts apiPassiveTestOptsSchema).
   * RBAC: operator + global_administrator (requireOperator).
   * Returns 201 with PassiveTestResult. 404 if API not found. 400 on Zod fail.
   *
   * Phase 15 will replace synthetic jobId with real jobQueue.enqueue().
   */
  app.post(
    '/api/v1/apis/:id/test/passive',
    isAuthenticatedWithPasswordCheck,
    requireOperator,
    async (req: any, res) => {
      let opts: ReturnType<typeof apiPassiveTestOptsSchema.parse>;
      try {
        opts = apiPassiveTestOptsSchema.parse(req.body ?? {});
      } catch (err: any) {
        log.info({ err, apiId: req.params.id }, 'passive test request rejected by Zod');
        return res.status(400).json({
          message: 'Opções de teste passivo inválidas',
          details: err?.errors ?? undefined,
        });
      }

      const apiId = req.params.id;
      const api = await storage.getApi(apiId);
      if (!api) {
        return res.status(404).json({ message: 'API não encontrada' });
      }

      // Synthetic jobId — Phase 15 replaces with real jobQueue.enqueue().
      const jobId = randomUUID();

      try {
        await storage.logAudit({
          actorId: req.user.id,
          action: 'api_passive_test_started',
          objectType: 'api',
          objectId: apiId,
          before: null,
          after: { jobId, dryRun: opts.dryRun ?? false, stages: opts.stages ?? {} },
        });
      } catch (err) {
        log.warn({ err, apiId, jobId }, 'failed to write audit log for passive test start — continuing');
      }

      try {
        const result = await runApiPassiveTests(apiId, opts, jobId);
        log.info(
          {
            apiId,
            jobId,
            userId: req.user.id,
            stagesRun: result.stagesRun.length,
            findingsCreated: result.findingsCreated,
            findingsUpdated: result.findingsUpdated,
            cancelled: result.cancelled,
            dryRun: result.dryRun,
          },
          'api passive tests executed via route',
        );
        return res.status(201).json(result);
      } catch (err) {
        log.error({ err, apiId, jobId }, 'api passive tests failed');
        return res.status(500).json({
          message: 'Falha ao executar testes passivos',
        });
      }
    },
  );
}
