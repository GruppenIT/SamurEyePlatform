import type { Express } from "express";
import { storage } from "../storage";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { requireOperator, patchAssetSchema } from "./middleware";
import { insertAssetSchema } from "@shared/schema";
import { createLogger } from '../lib/logger';

const log = createLogger('routes:assets');

export function registerAssetRoutes(app: Express) {
  app.get('/api/assets', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const flat = String((req.query as any).flat ?? "") === "1";
      const assets = flat ? await storage.getAssets() : await storage.getAssetsTree();
      res.json(assets);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch assets');
      res.status(500).json({ message: "Falha ao buscar ativos" });
    }
  });

  app.get('/api/assets/tags/unique', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const tags = await storage.getUniqueTags();
      res.json(tags);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch unique tags');
      res.status(500).json({ message: "Falha ao buscar TAGs únicas" });
    }
  });

  app.get('/api/assets/by-type/:type', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { type } = req.params;
      const assets = await storage.getAssetsByType(type);
      res.json(assets);
    } catch (error) {
      log.error({ err: error, type: req.params.type }, 'failed to fetch assets by type');
      res.status(500).json({ message: "Falha ao buscar ativos por tipo" });
    }
  });

  app.post('/api/assets', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const assetData = insertAssetSchema.parse(req.body);
      const asset = await storage.createAsset(assetData, userId);

      // Log audit
      await storage.logAudit({
        actorId: userId,
        action: 'create',
        objectType: 'asset',
        objectId: asset.id,
        before: null,
        after: asset,
      });

      res.status(201).json(asset);
    } catch (error) {
      log.error({ err: error }, 'failed to create asset');
      res.status(400).json({ message: "Falha ao criar ativo" });
    }
  });

  app.patch('/api/assets/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      // Validate allowed fields only
      const updates = patchAssetSchema.parse(req.body);

      const beforeAsset = await storage.getAsset(id);
      if (!beforeAsset) {
        return res.status(404).json({ message: "Ativo não encontrado" });
      }
      const asset = await storage.updateAsset(id, updates);

      await storage.logAudit({
        actorId: userId,
        action: 'update',
        objectType: 'asset',
        objectId: id,
        before: beforeAsset || null,
        after: asset,
      });

      res.json(asset);
    } catch (error) {
      log.error({ err: error }, 'failed to update asset');
      res.status(400).json({ message: "Falha ao atualizar ativo" });
    }
  });

  app.delete('/api/assets/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      const beforeAsset = await storage.getAsset(id);
      await storage.deleteAsset(id);

      await storage.logAudit({
        actorId: userId,
        action: 'delete',
        objectType: 'asset',
        objectId: id,
        before: beforeAsset || null,
        after: null,
      });

      res.status(204).send();
    } catch (error) {
      log.error({ err: error }, 'failed to delete asset');
      res.status(400).json({ message: "Falha ao excluir ativo" });
    }
  });
}
