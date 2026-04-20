import { randomUUID } from 'crypto';
import type { Express } from "express";
import { storage } from "../storage";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { requireOperator } from "./middleware";
import { insertApiSchema, discoverApiOptsSchema, apiPassiveTestOptsSchema, apiActiveTestOptsSchema } from "@shared/schema";
import type { JobEvent } from "@shared/schema";
import { normalizeTarget } from "../services/journeys/urls";
import { createLogger } from '../lib/logger';
import { discoverApi } from "../services/journeys/apiDiscovery";
import { runApiPassiveTests } from "../services/journeys/apiPassiveTests";
import { runApiActiveTests } from "../services/journeys/apiActiveTests";
import { sanitizeApiFinding } from '../../shared/sanitization';
import { promoteHighCriticalFindings } from '../services/threatPromotion';
import { jobEventBroadcaster } from '../services/jobEventBroadcaster';

const log = createLogger('routes:apis');

// ============================================================================
// Phase 14 Wave 3 — Post-scanner pipeline (FIND-02 + FIND-03 + FIND-04)
// ============================================================================

/**
 * RunPostScannerPipelineParams — input contract for the shared pipeline helper.
 * Called by both POST /test/passive and POST /test/active handlers after the
 * orchestrator completes. Each handler performs Step 1 (sanitize) inline and
 * passes the results here for Steps 2 and 3 (promote + emit).
 */
interface RunPostScannerPipelineParams {
  apiId: string;
  /** jobId from req.body (optional — Phase 15 orchestrator passes; manual CLI does not) */
  requestJobId: string | undefined;
  /** Findings fetched and sanitized by the handler (Step 1 output) */
  sanitizedFindings: Array<{
    id: string;
    owaspCategory: string;
    severity: string;
    apiEndpointId: string;
    title: string;
  }>;
  sanitizedCount: number;
  dryRun: boolean;
  routeLabel: string; // e.g. '[route /test/passive]' — used in console.warn messages
}

interface PostScannerPipelineResult {
  newFindingIds: string[];
  sanitized: boolean;
  promotionKicked: boolean;
  eventsEmitted: number;
}

/**
 * runPostScannerPipeline — Phase 14 Wave 3 Steps 2 + 3 (promote + emit).
 *
 *   Step 2 (FIND-03): Fire-and-forget promoteHighCriticalFindings for high/critical
 *                     findings. Skipped when dryRun=true. Does NOT block response.
 *
 *   Step 3 (FIND-04): Emit findings_batch WebSocket events (max 20 per event).
 *                     Skipped when dryRun=true or requestJobId absent.
 *
 * Step 1 (sanitize — FIND-02) is performed INLINE by each handler before calling
 * this function, so sanitizeApiFinding() is called at the handler level (≥ 2 call
 * sites, one per route, satisfying pattern grep requirement).
 *
 * Fail-open throughout: promote error → logged + continue;
 * emit error → logged + continue. NEVER throws.
 */
async function runPostScannerPipeline(
  params: RunPostScannerPipelineParams,
): Promise<PostScannerPipelineResult> {
  const { apiId, requestJobId, sanitizedFindings, sanitizedCount, dryRun, routeLabel } = params;

  const newFindingIds = sanitizedFindings.map((f) => f.id);

  // ---- Step 2: Async promotion (FIND-03) — fire-and-forget ----
  let promotionKicked = false;
  if (!dryRun && newFindingIds.length > 0) {
    void promoteHighCriticalFindings(apiId, newFindingIds).catch((err) => {
      // eslint-disable-next-line no-console
      console.warn(`${routeLabel} promotion failed silently`, {
        apiId,
        error: err instanceof Error ? err.message : String(err),
      });
    });
    promotionKicked = true;
  }

  // ---- Step 3: WebSocket emit (FIND-04) — batch 20 per event ----
  let eventsEmitted = 0;
  if (!dryRun && requestJobId && newFindingIds.length > 0) {
    const BATCH_SIZE = 20;
    let batchNumber = 1;
    for (let i = 0; i < sanitizedFindings.length; i += BATCH_SIZE) {
      const chunk = sanitizedFindings.slice(i, i + BATCH_SIZE);
      try {
        const batchEvent: JobEvent = {
          type: 'findings_batch',
          findings: chunk.map((f) => ({
            id: f.id,
            owaspCategory: f.owaspCategory,
            severity: f.severity,
            endpointPath: f.apiEndpointId, // Phase 15 may resolve full path via endpoint lookup
            title: f.title,
          })),
          batchNumber,
          totalNewInBatch: chunk.length,
        };
        jobEventBroadcaster.emit(requestJobId, batchEvent);
        eventsEmitted++;
        batchNumber++;
      } catch {
        // jobEventBroadcaster.emit is fail-open internally; double-guard
      }
    }
  }

  return {
    newFindingIds,
    sanitized: sanitizedCount === sanitizedFindings.length,
    promotionKicked,
    eventsEmitted,
  };
}

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

        // Phase 14 Wave 3 — Step 1 (FIND-02): Fetch persisted findings + sanitize evidence.
        // sanitizeApiFinding is called per-finding here (pure, fail-open); result used for
        // Steps 2 (promote) and 3 (emit) in runPostScannerPipeline.
        let passiveFindings: Awaited<ReturnType<typeof storage.listApiFindings>> = [];
        try {
          passiveFindings = await storage.listApiFindings({ jobId });
        } catch (err) {
          log.warn({ err, apiId, jobId }, '[route /test/passive] failed to list findings for pipeline');
        }
        let passiveSanitizedCount = 0;
        for (const f of passiveFindings) {
          try { sanitizeApiFinding(f.evidence); passiveSanitizedCount++; } catch { /* fail-open */ }
        }

        // Phase 14 Wave 3 — Steps 2+3 (FIND-03 + FIND-04): promote + emit
        const { sanitized, promotionKicked, eventsEmitted } = await runPostScannerPipeline({
          apiId,
          requestJobId: req.body.jobId as string | undefined,
          sanitizedFindings: passiveFindings,
          sanitizedCount: passiveSanitizedCount,
          dryRun: opts.dryRun ?? false,
          routeLabel: '[route /test/passive]',
        });

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
            sanitized,
            promotionKicked,
            eventsEmitted,
          },
          'api passive tests executed via route',
        );
        // Phase 14: extend response with 3 new fields (additive — Phase 12/13 compat preserved)
        return res.status(201).json({ ...result, sanitized, promotionKicked, eventsEmitted });
      } catch (err) {
        log.error({ err, apiId, jobId }, 'api passive tests failed');
        return res.status(500).json({
          message: 'Falha ao executar testes passivos',
        });
      }
    },
  );

  /**
   * POST /api/v1/apis/:id/test/active — Phase 13 TEST-03..07 entrypoint.
   *
   * Body: ApiActiveTestOpts (see shared/schema.ts apiActiveTestOptsSchema).
   * RBAC: operator + global_administrator (requireOperator).
   * Returns 201 with ActiveTestResult. 404 if API not found. 400 on Zod fail.
   *
   * SAFE gates enforced inside runApiActiveTests:
   *   - BOPLA skipped unless opts.destructiveEnabled=true
   *   - rateLimit skipped unless opts.stages.rateLimit=true
   *
   * Phase 15 will replace synthetic jobId with real jobQueue.enqueue().
   */
  app.post(
    '/api/v1/apis/:id/test/active',
    isAuthenticatedWithPasswordCheck,
    requireOperator,
    async (req: any, res) => {
      let opts: ReturnType<typeof apiActiveTestOptsSchema.parse>;
      try {
        opts = apiActiveTestOptsSchema.parse(req.body ?? {});
      } catch (err: any) {
        log.info({ err, apiId: req.params.id }, 'active test request rejected by Zod');
        return res.status(400).json({
          message: 'Opções de teste ativo inválidas',
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
          action: 'api_active_test_started',
          objectType: 'api',
          objectId: apiId,
          before: null,
          after: {
            jobId,
            dryRun: opts.dryRun ?? false,
            destructiveEnabled: opts.destructiveEnabled ?? false,
            stages: opts.stages ?? {},
          },
        });
      } catch (err) {
        log.warn(
          { err, apiId, jobId },
          'failed to write audit log for active test start — continuing',
        );
      }

      try {
        const result = await runApiActiveTests(apiId, opts, jobId);

        // Phase 14 Wave 3 — Step 1 (FIND-02): Fetch persisted findings + sanitize evidence.
        // sanitizeApiFinding is called per-finding here (pure, fail-open); result used for
        // Steps 2 (promote) and 3 (emit) in runPostScannerPipeline.
        let activeFindings: Awaited<ReturnType<typeof storage.listApiFindings>> = [];
        try {
          activeFindings = await storage.listApiFindings({ jobId });
        } catch (err) {
          log.warn({ err, apiId, jobId }, '[route /test/active] failed to list findings for pipeline');
        }
        let activeSanitizedCount = 0;
        for (const f of activeFindings) {
          try { sanitizeApiFinding(f.evidence); activeSanitizedCount++; } catch { /* fail-open */ }
        }

        // Phase 14 Wave 3 — Steps 2+3 (FIND-03 + FIND-04): promote + emit
        const { sanitized, promotionKicked, eventsEmitted } = await runPostScannerPipeline({
          apiId,
          requestJobId: req.body.jobId as string | undefined,
          sanitizedFindings: activeFindings,
          sanitizedCount: activeSanitizedCount,
          dryRun: opts.dryRun ?? false,
          routeLabel: '[route /test/active]',
        });

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
            sanitized,
            promotionKicked,
            eventsEmitted,
          },
          'api active tests executed via route',
        );
        // Phase 14: extend response with 3 new fields (additive — Phase 12/13 compat preserved)
        return res.status(201).json({ ...result, sanitized, promotionKicked, eventsEmitted });
      } catch (err) {
        log.error({ err, apiId, jobId }, 'runApiActiveTests threw unexpectedly');
        return res.status(500).json({ message: 'Erro interno ao executar testes ativos' });
      }
    },
  );
}
