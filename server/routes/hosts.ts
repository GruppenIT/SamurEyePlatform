import type { Express } from "express";
import { storage } from "../storage";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { requireOperator } from "./middleware";
import { insertHostSchema } from "@shared/schema";
import { createLogger } from '../lib/logger';

const log = createLogger('routes:hosts');

export function registerHostRoutes(app: Express) {
  app.get('/api/hosts', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      // Extract query parameters for filtering and sorting
      const { type, family, search, sortBy } = req.query;

      const filters: any = {};
      if (type) filters.type = type as string;
      if (family) filters.family = family as string;
      if (search) filters.search = search as string;
      if (sortBy) filters.sortBy = sortBy as string;

      const hosts = await storage.getHosts(filters);
      res.json(hosts);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch hosts');
      res.status(500).json({ message: "Falha ao buscar hosts" });
    }
  });

  app.get('/api/hosts/:id', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { id } = req.params;
      const host = await storage.getHost(id);

      if (!host) {
        return res.status(404).json({ message: "Host não encontrado" });
      }

      res.json(host);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch host');
      res.status(500).json({ message: "Falha ao buscar host" });
    }
  });

  app.get('/api/hosts/:id/risk-history', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { id } = req.params;
      const { limit } = req.query;

      const history = await storage.getHostRiskHistory(id, limit ? parseInt(limit as string) : undefined);
      res.json(history);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch risk score history');
      res.status(500).json({ message: "Falha ao buscar histórico de risk score" });
    }
  });

  app.get('/api/hosts/:id/ad-tests', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { id } = req.params;

      // Check if host exists
      const host = await storage.getHost(id);
      if (!host) {
        return res.status(404).json({ message: "Host não encontrado" });
      }

      // Get AD Security test results for this host (latest results)
      const testResults = await storage.getAdSecurityLatestTestResults(id);
      res.json(testResults);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch AD security test results');
      res.status(500).json({ message: "Falha ao buscar resultados dos testes AD Security" });
    }
  });

  // AD Security Scorecard - aggregated security metrics from latest test results
  app.get('/api/hosts/:id/ad-scorecard', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { id } = req.params;

      const host = await storage.getHost(id);
      if (!host) {
        return res.status(404).json({ message: "Host não encontrado" });
      }

      const testResults = await storage.getAdSecurityLatestTestResults(id);
      if (testResults.length === 0) {
        return res.json(null);
      }

      // Severity weights for score calculation
      const severityWeight: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

      // Aggregate per category
      const categories: Record<string, { total: number; passed: number; failed: number; error: number; skipped: number; maxWeight: number; failedWeight: number }> = {};
      let totalWeighted = 0;
      let failedWeighted = 0;
      let totalPassed = 0;
      let totalFailed = 0;
      let totalError = 0;
      let totalSkipped = 0;

      for (const test of testResults) {
        const cat = test.category;
        if (!categories[cat]) {
          categories[cat] = { total: 0, passed: 0, failed: 0, error: 0, skipped: 0, maxWeight: 0, failedWeight: 0 };
        }
        const w = severityWeight[test.severityHint] || 1;
        categories[cat].total++;
        categories[cat].maxWeight += w;
        totalWeighted += w;

        if (test.status === 'pass') {
          categories[cat].passed++;
          totalPassed++;
        } else if (test.status === 'fail') {
          categories[cat].failed++;
          categories[cat].failedWeight += w;
          failedWeighted += w;
          totalFailed++;
        } else if (test.status === 'error') {
          categories[cat].error++;
          totalError++;
        } else {
          categories[cat].skipped++;
          totalSkipped++;
        }
      }

      // Overall score: 0-100, higher is better
      const overallScore = totalWeighted > 0
        ? Math.round(((totalWeighted - failedWeighted) / totalWeighted) * 100)
        : 0;

      // Per-category scores
      const categoryScores = Object.entries(categories).map(([name, data]) => ({
        name,
        total: data.total,
        passed: data.passed,
        failed: data.failed,
        error: data.error,
        skipped: data.skipped,
        score: data.maxWeight > 0
          ? Math.round(((data.maxWeight - data.failedWeight) / data.maxWeight) * 100)
          : 0,
      }));

      // Severity distribution of failures
      const failedBySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const test of testResults) {
        if (test.status === 'fail') {
          failedBySeverity[test.severityHint] = (failedBySeverity[test.severityHint] || 0) + 1;
        }
      }

      res.json({
        overallScore,
        totalTests: testResults.length,
        totalPassed,
        totalFailed,
        totalError,
        totalSkipped,
        failedBySeverity,
        categories: categoryScores,
        executedAt: testResults[0]?.executedAt,
        jobId: testResults[0]?.jobId,
      });
    } catch (error) {
      log.error({ err: error }, 'failed to calculate AD scorecard');
      res.status(500).json({ message: "Falha ao calcular scorecard de segurança AD" });
    }
  });

  app.get('/api/hosts/:id/enrichments', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { id } = req.params;

      // Check if host exists
      const host = await storage.getHost(id);
      if (!host) {
        return res.status(404).json({ message: "Host não encontrado" });
      }

      // Get latest successful enrichment data for this host
      const enrichment = await storage.getLatestHostEnrichment(id);
      res.json(enrichment || null);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch enrichment data');
      res.status(500).json({ message: "Falha ao buscar dados de enriquecimento" });
    }
  });

  app.patch('/api/hosts/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      // Validate updates using partial host schema (only allow certain fields)
      const allowedUpdates = insertHostSchema.partial().pick({
        name: true,
        description: true,
        aliases: true,
      });
      const updates = allowedUpdates.parse(req.body);

      const beforeHost = await storage.getHost(id);
      if (!beforeHost) {
        return res.status(404).json({ message: "Host não encontrado" });
      }

      const host = await storage.updateHost(id, updates);

      await storage.logAudit({
        actorId: userId,
        action: 'update',
        objectType: 'host',
        objectId: id,
        before: beforeHost || null,
        after: host,
      });

      res.json(host);
    } catch (error) {
      log.error({ err: error }, 'failed to update host');
      res.status(400).json({ message: "Falha ao atualizar host" });
    }
  });
}
