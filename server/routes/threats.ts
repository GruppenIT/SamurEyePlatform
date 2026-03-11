import type { Express } from "express";
import { storage } from "../storage";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { requireOperator, patchThreatSchema } from "./middleware";
import { changeThreatStatusSchema } from "@shared/schema";
import { threatEngine } from "../services/threatEngine";
import { notificationService } from "../services/notificationService";
import { createLogger } from '../lib/logger';

const log = createLogger('routes:threats');

export function registerThreatRoutes(app: Express) {
  app.get('/api/threats', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { severity, status, assetId, hostId } = req.query;
      const filters: any = {};

      if (severity) filters.severity = severity as string;
      if (status) filters.status = status as string;
      if (assetId) filters.assetId = assetId as string;
      if (hostId) filters.hostId = hostId as string;

      const threats = await storage.getThreatsWithHosts(filters);
      res.json(threats);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch threats');
      res.status(500).json({ message: "Falha ao buscar ameaças" });
    }
  });

  app.patch('/api/threats/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      // Validate allowed fields only (no status change here - use /status endpoint)
      const updates = patchThreatSchema.parse(req.body);

      const beforeThreat = await storage.getThreat(id);
      if (!beforeThreat) {
        return res.status(404).json({ message: "Ameaça não encontrada" });
      }
      const threat = await storage.updateThreat(id, updates);

      await storage.logAudit({
        actorId: userId,
        action: 'update',
        objectType: 'threat',
        objectId: id,
        before: beforeThreat || null,
        after: threat,
      });

      res.json(threat);
    } catch (error) {
      log.error({ err: error }, 'failed to update threat');
      res.status(400).json({ message: "Falha ao atualizar ameaça" });
    }
  });

  // Change threat status with justification
  app.patch('/api/threats/:id/status', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      // Validate input using Zod schema
      const validationResult = changeThreatStatusSchema.safeParse(req.body);
      if (!validationResult.success) {
        log.info({ issues: validationResult.error.issues }, 'validation failed for status change');
        return res.status(400).json({
          message: validationResult.error.issues.map(i => i.message).join(', ')
        });
      }

      const { status, justification, hibernatedUntil } = validationResult.data;

      const beforeThreat = await storage.getThreat(id);
      if (!beforeThreat) {
        return res.status(404).json({ message: "Ameaça não encontrada" });
      }

      // Update threat with new status
      const updates: any = {
        status,
        statusChangedBy: userId,
        statusChangedAt: new Date(),
        statusJustification: justification,
        updatedAt: new Date(),
      };

      if (status === 'hibernated' && hibernatedUntil) {
        updates.hibernatedUntil = new Date(hibernatedUntil);
      } else {
        updates.hibernatedUntil = null;
      }

      const threat = await storage.updateThreat(id, updates);

      // Create status history entry
      await storage.createThreatStatusHistory({
        threatId: id,
        fromStatus: beforeThreat.status,
        toStatus: status,
        justification,
        hibernatedUntil: status === 'hibernated' && hibernatedUntil ? new Date(hibernatedUntil) : null,
        changedBy: userId,
      });

      // Log audit
      await storage.logAudit({
        actorId: userId,
        action: 'change_status',
        objectType: 'threat',
        objectId: id,
        before: { status: beforeThreat.status },
        after: { status, justification },
      });

      // Send notifications for status change
      try {
        const user = await storage.getUser(userId);
        if (user) {
          await notificationService.notifyThreatStatusChanged(
            threat,
            beforeThreat.status,
            status,
            user,
            justification
          );
        }
      } catch (notifError) {
        log.error({ err: notifError, threatId: id }, 'failed to send status change notifications');
        // Don't fail status change if notification fails
      }

      // Recalculate host risk score after status change
      if (threat.hostId) {
        try {
          await threatEngine.recalculateHostRiskScore(threat.hostId);
          log.info({ hostId: threat.hostId }, 'risk score recalculated after status change');
        } catch (riskError) {
          log.error({ err: riskError, hostId: threat.hostId }, 'failed to recalculate host risk score');
          // Don't fail status change if risk recalculation fails
        }
      }

      res.json(threat);
    } catch (error) {
      log.error({ err: error }, 'failed to change threat status');
      res.status(400).json({ message: "Falha ao alterar status da ameaça" });
    }
  });

  // Get threat status history
  app.get('/api/threats/:id/history', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { id } = req.params;
      const history = await storage.getThreatStatusHistory(id);
      res.json(history);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch threat history');
      res.status(500).json({ message: "Falha ao buscar histórico" });
    }
  });

  app.get('/api/threats/stats', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const stats = await storage.getThreatStats();
      res.json(stats);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch threat stats');
      res.status(500).json({ message: "Falha ao buscar estatísticas" });
    }
  });
}
