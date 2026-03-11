import type { Express } from "express";
import { storage } from "../storage";
import { db } from "../db";
import { sql } from "drizzle-orm";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { createLogger } from '../lib/logger';

const log = createLogger('routes:dashboard');

export function registerDashboardRoutes(app: Express) {
  // Dashboard routes (legacy - kept for backward compat)
  app.get('/api/dashboard/metrics', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const metrics = await storage.getDashboardMetrics();
      res.json(metrics);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch metrics');
      res.status(500).json({ message: "Falha ao buscar métricas" });
    }
  });

  app.get('/api/dashboard/running-jobs', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const jobs = await storage.getRunningJobs();
      res.json(jobs);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch running jobs');
      res.status(500).json({ message: "Falha ao buscar jobs" });
    }
  });

  app.get('/api/dashboard/recent-threats', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const threats = await storage.getThreats();
      const recentThreats = threats.slice(0, 10); // Last 10 threats
      res.json(recentThreats);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch recent threats');
      res.status(500).json({ message: "Falha ao buscar ameaças" });
    }
  });

  // Posture score: consolidated risk score + 30-day history
  app.get('/api/posture/score', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const hosts = await storage.getHosts();
      const hostsWithRisk = hosts.filter(h => h.riskScore != null && h.riskScore > 0);
      const avgRisk = hostsWithRisk.length > 0
        ? hostsWithRisk.reduce((sum, h) => sum + (h.riskScore || 0), 0) / hostsWithRisk.length
        : 0;
      const postureScore = Math.round(100 - avgRisk);

      // 30-day history from host_risk_history
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const historyRows = await db.execute(sql`
        SELECT DATE(recorded_at) as day, AVG(risk_score) as avg_risk
        FROM host_risk_history
        WHERE recorded_at >= ${thirtyDaysAgo}
        GROUP BY DATE(recorded_at)
        ORDER BY day ASC
      `);

      const history = (historyRows.rows || []).map((r: any) => ({
        day: r.day,
        score: Math.round(100 - Number(r.avg_risk || 0)),
      }));

      res.json({
        score: postureScore,
        totalHosts: hosts.length,
        hostsAtRisk: hostsWithRisk.length,
        history,
      });
    } catch (error) {
      log.error({ err: error }, 'failed to calculate posture');
      res.status(500).json({ message: "Falha ao calcular postura" });
    }
  });

  // Threat stats grouped by category + severity
  app.get('/api/threats/stats-by-category', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const rows = await db.execute(sql`
        SELECT
          COALESCE(category, 'uncategorized') as category,
          severity,
          status,
          COUNT(*)::int as count
        FROM threats
        GROUP BY category, severity, status
      `);
      // Organize into { category: { severity: { status: count } } }
      const result: Record<string, any> = {};
      for (const r of (rows.rows || []) as any[]) {
        if (!result[r.category]) result[r.category] = { open: 0, total: 0, critical: 0, high: 0 };
        const cat = result[r.category];
        cat.total += r.count;
        if (r.status === 'open') cat.open += r.count;
        if (r.severity === 'critical') cat.critical += r.count;
        if (r.severity === 'high') cat.high += r.count;
      }
      res.json(result);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch stats by category');
      res.status(500).json({ message: "Falha ao buscar stats" });
    }
  });

  // Activity feed: unified recent activity
  app.get('/api/activity/feed', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 15;

      // Recent threats (critical/high)
      const recentThreats = await db.execute(sql`
        SELECT id, title, severity, status, created_at as "createdAt", 'threat' as type
        FROM threats
        WHERE severity IN ('critical', 'high')
        ORDER BY created_at DESC
        LIMIT ${Math.ceil(limit / 2)}
      `);

      // Recent jobs
      const recentJobs = await db.execute(sql`
        SELECT id, status, current_task as "currentTask", journey_id as "journeyId",
               started_at as "startedAt", finished_at as "finishedAt", 'job' as type
        FROM jobs
        ORDER BY created_at DESC
        LIMIT ${Math.ceil(limit / 2)}
      `);

      // Merge and sort by date
      const feed = [
        ...(recentThreats.rows || []).map((r: any) => ({
          type: 'threat' as const,
          id: r.id,
          title: r.title,
          severity: r.severity,
          status: r.status,
          timestamp: r.createdAt,
        })),
        ...(recentJobs.rows || []).map((r: any) => ({
          type: 'job' as const,
          id: r.id,
          status: r.status,
          task: r.currentTask,
          journeyId: r.journeyId,
          timestamp: r.finishedAt || r.startedAt,
        })),
      ]
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(0, limit);

      res.json(feed);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch feed');
      res.status(500).json({ message: "Falha ao buscar feed" });
    }
  });
}
