import type { Express } from "express";
import { db } from "../db";
import { sql } from "drizzle-orm";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { createLogger } from '../lib/logger';

const log = createLogger('routes:reports');

export function registerReportRoutes(app: Express) {
  // Threat trend: count by day/week grouped by severity
  app.get('/api/reports/threat-trend', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const periodDays = parseInt(req.query.period as string) || 30;
      const since = new Date(Date.now() - periodDays * 24 * 60 * 60 * 1000);

      const rows = await db.execute(sql`
        SELECT DATE(created_at) as day, severity, COUNT(*)::int as count
        FROM threats
        WHERE created_at >= ${since}
        GROUP BY DATE(created_at), severity
        ORDER BY day ASC
      `);

      // Group by day
      const byDay: Record<string, Record<string, number>> = {};
      for (const r of (rows.rows || []) as any[]) {
        const dayStr = String(r.day).slice(0, 10);
        if (!byDay[dayStr]) byDay[dayStr] = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        byDay[dayStr][r.severity] = r.count;
      }

      const trend = Object.entries(byDay).map(([day, counts]) => ({ day, ...counts }));
      res.json(trend);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch trend');
      res.status(500).json({ message: "Falha ao buscar trend" });
    }
  });

  // Summary by journey type with MTTR
  app.get('/api/reports/summary-by-journey', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const periodDays = parseInt(req.query.period as string) || 30;
      const since = new Date(Date.now() - periodDays * 24 * 60 * 60 * 1000);

      const rows = await db.execute(sql`
        SELECT
          COALESCE(category, 'uncategorized') as category,
          COUNT(*)::int as total,
          COUNT(*) FILTER (WHERE status = 'open')::int as open,
          COUNT(*) FILTER (WHERE severity = 'critical')::int as critical,
          COUNT(*) FILTER (WHERE severity = 'high')::int as high,
          COUNT(*) FILTER (WHERE status IN ('closed', 'mitigated') AND created_at >= ${since})::int as resolved,
          AVG(EXTRACT(EPOCH FROM (status_changed_at - created_at)) / 86400)
            FILTER (WHERE status IN ('closed', 'mitigated') AND created_at >= ${since}) as mttr_days
        FROM threats
        GROUP BY category
      `);

      const summary = (rows.rows || []).map((r: any) => ({
        category: r.category,
        total: r.total,
        open: r.open,
        critical: r.critical,
        high: r.high,
        resolved: r.resolved,
        mttrDays: r.mttr_days ? Math.round(Number(r.mttr_days) * 10) / 10 : null,
      }));

      res.json(summary);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch summary');
      res.status(500).json({ message: "Falha ao buscar summary" });
    }
  });

  // AD Security history: score evolution per execution
  app.get('/api/reports/ad-security/history', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const rows = await db.execute(sql`
        SELECT
          r.job_id as "jobId",
          j.started_at as "executedAt",
          COUNT(*)::int as total_tests,
          COUNT(*) FILTER (WHERE r.status = 'pass')::int as passed,
          COUNT(*) FILTER (WHERE r.status = 'fail')::int as failed,
          COUNT(*) FILTER (WHERE r.severity = 'critical' AND r.status = 'fail')::int as critical_failures
        FROM ad_security_test_results r
        JOIN jobs j ON j.id = r.job_id
        GROUP BY r.job_id, j.started_at
        ORDER BY j.started_at DESC
        LIMIT 20
      `);

      const history = (rows.rows || []).map((r: any) => ({
        jobId: r.jobId,
        executedAt: r.executedAt,
        totalTests: r.total_tests,
        passed: r.passed,
        failed: r.failed,
        criticalFailures: r.critical_failures,
        score: r.total_tests > 0 ? Math.round((r.passed / r.total_tests) * 100) : 0,
      }));

      res.json(history);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch AD history');
      res.status(500).json({ message: "Falha ao buscar histórico AD" });
    }
  });

  // EDR/AV coverage: detection rates per execution
  app.get('/api/reports/edr-coverage', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      // Get edr_av jobs with their results
      const rows = await db.execute(sql`
        SELECT
          j.id as "jobId",
          j.started_at as "executedAt",
          jr.artifacts
        FROM jobs j
        JOIN journeys jy ON jy.id = j.journey_id
        LEFT JOIN job_results jr ON jr.job_id = j.id
        WHERE jy.type = 'edr_av' AND j.status = 'completed'
        ORDER BY j.started_at DESC
        LIMIT 20
      `);

      const history = (rows.rows || []).map((r: any) => {
        const stats = r.artifacts?.statistics || {};
        return {
          jobId: r.jobId,
          executedAt: r.executedAt,
          totalDiscovered: stats.totalDiscovered || 0,
          tested: stats.successfulDeployments || 0,
          protected: stats.eicarRemovedCount || 0,
          unprotected: stats.eicarPersistedCount || 0,
          rate: stats.successfulDeployments > 0
            ? Math.round((stats.eicarRemovedCount || 0) / stats.successfulDeployments * 100)
            : 0,
        };
      });

      res.json(history);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch EDR coverage');
      res.status(500).json({ message: "Falha ao buscar cobertura EDR" });
    }
  });
}
