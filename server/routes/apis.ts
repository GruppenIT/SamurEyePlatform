import type { Express } from "express";
import { storage } from "../storage";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { requireOperator } from "./middleware";
import { insertApiSchema } from "@shared/schema";
import { normalizeTarget } from "../services/journeys/urls";
import { createLogger } from '../lib/logger';

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
}
