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

  // Category-specific threat trend (for per-tab trend charts)
  app.get('/api/reports/category-trend', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const category = req.query.category as string | undefined;
      const periodDays = parseInt(req.query.period as string) || 30;
      const since = new Date(Date.now() - periodDays * 24 * 60 * 60 * 1000);

      const rows = await db.execute(
        category
          ? sql`SELECT DATE(created_at) as day, severity, COUNT(*)::int as count
                FROM threats WHERE created_at >= ${since} AND category = ${category}
                GROUP BY DATE(created_at), severity ORDER BY day ASC`
          : sql`SELECT DATE(created_at) as day, severity, COUNT(*)::int as count
                FROM threats WHERE created_at >= ${since}
                GROUP BY DATE(created_at), severity ORDER BY day ASC`,
      );

      const byDay: Record<string, Record<string, number>> = {};
      for (const r of (rows.rows || []) as any[]) {
        const dayStr = String(r.day).slice(0, 10);
        if (!byDay[dayStr]) byDay[dayStr] = { critical: 0, high: 0, medium: 0, low: 0 };
        byDay[dayStr][r.severity] = Number(r.count);
      }
      res.json(Object.entries(byDay).map(([day, counts]) => ({ day, ...counts })));
    } catch (error) {
      log.error({ err: error }, 'failed to fetch category trend');
      res.status(500).json({ message: "Falha ao buscar tendência" });
    }
  });

  // Attack surface: service distribution + top CVEs
  app.get('/api/reports/attack-surface/stats', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const periodDays = parseInt(req.query.period as string) || 30;
      const since = new Date(Date.now() - periodDays * 24 * 60 * 60 * 1000);

      const [serviceRows, cveRows, severityRows] = await Promise.all([
        db.execute(sql`
          SELECT
            COALESCE(
              NULLIF(TRIM(evidence->>'service'), ''),
              NULLIF(TRIM(evidence->>'port_name'), ''),
              CASE WHEN (evidence->>'port') IS NOT NULL
                   THEN 'Port ' || (evidence->>'port') ELSE NULL END,
              'Outros'
            ) as service,
            COUNT(*)::int as total,
            COUNT(*) FILTER (WHERE severity = 'critical')::int as critical,
            COUNT(*) FILTER (WHERE severity = 'high')::int as high,
            COUNT(*) FILTER (WHERE severity = 'medium')::int as medium,
            COUNT(*) FILTER (WHERE severity = 'low')::int as low,
            COUNT(DISTINCT host_id)::int as host_count
          FROM threats
          WHERE category = 'attack_surface' AND created_at >= ${since}
          GROUP BY service ORDER BY total DESC LIMIT 15
        `),
        db.execute(sql`
          SELECT
            evidence->>'cve' as cve,
            MAX(CAST(COALESCE(NULLIF(evidence->>'cvss',''), NULLIF(evidence->>'cvssScore',''), '0') AS FLOAT))::float as cvss,
            COUNT(DISTINCT host_id)::int as host_count,
            severity,
            COUNT(*) FILTER (WHERE status = 'open')::int as open_count
          FROM threats
          WHERE category = 'attack_surface'
            AND evidence->>'cve' IS NOT NULL
            AND evidence->>'cve' != ''
            AND created_at >= ${since}
          GROUP BY evidence->>'cve', severity
          ORDER BY cvss DESC, host_count DESC LIMIT 20
        `),
        db.execute(sql`
          SELECT severity, COUNT(*)::int as count
          FROM threats WHERE category = 'attack_surface' AND created_at >= ${since}
          GROUP BY severity
        `),
      ]);

      res.json({
        services: serviceRows.rows || [],
        topCves: cveRows.rows || [],
        severity: severityRows.rows || [],
      });
    } catch (error) {
      log.error({ err: error }, 'failed to fetch attack surface stats');
      res.status(500).json({ message: "Falha ao buscar dados de Attack Surface" });
    }
  });

  // Web application stats: severity distribution + top findings by rule
  app.get('/api/reports/web-application/stats', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const periodDays = parseInt(req.query.period as string) || 30;
      const since = new Date(Date.now() - periodDays * 24 * 60 * 60 * 1000);

      const [severityRows, topFindings] = await Promise.all([
        db.execute(sql`
          SELECT severity, COUNT(*)::int as count
          FROM threats WHERE category = 'web_application' AND created_at >= ${since}
          GROUP BY severity
        `),
        db.execute(sql`
          SELECT
            COALESCE(NULLIF(TRIM(rule_id), ''), LEFT(title, 60)) as rule,
            COUNT(*)::int as total,
            COUNT(*) FILTER (WHERE severity IN ('critical','high'))::int as high_sev,
            COUNT(*) FILTER (WHERE status = 'open')::int as open_count,
            severity as top_severity
          FROM threats
          WHERE category = 'web_application' AND created_at >= ${since}
          GROUP BY rule, severity
          ORDER BY total DESC LIMIT 15
        `),
      ]);

      res.json({
        severity: severityRows.rows || [],
        topFindings: topFindings.rows || [],
      });
    } catch (error) {
      log.error({ err: error }, 'failed to fetch web application stats');
      res.status(500).json({ message: "Falha ao buscar dados de Web Application" });
    }
  });

  // API security stats: OWASP API Top 10 counts + severity trend
  app.get('/api/reports/api-security/stats', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const periodDays = parseInt(req.query.period as string) || 30;
      const since = new Date(Date.now() - periodDays * 24 * 60 * 60 * 1000);

      const [owaspRows, trendRows, summaryRows] = await Promise.all([
        db.execute(sql`
          SELECT
            af.owasp_category as category,
            af.severity,
            af.status,
            COUNT(*)::int as count
          FROM api_findings af
          JOIN jobs j ON j.id = af.job_id
          JOIN journeys jy ON jy.id = j.journey_id
          WHERE jy.type = 'api_security' AND j.started_at >= ${since}
          GROUP BY af.owasp_category, af.severity, af.status
        `),
        db.execute(sql`
          SELECT
            DATE(j.started_at) as day,
            af.severity,
            COUNT(*)::int as count
          FROM api_findings af
          JOIN jobs j ON j.id = af.job_id
          JOIN journeys jy ON jy.id = j.journey_id
          WHERE jy.type = 'api_security' AND j.started_at >= ${since}
          GROUP BY DATE(j.started_at), af.severity
          ORDER BY day ASC
        `),
        db.execute(sql`
          SELECT
            COUNT(*)::int as total,
            COUNT(*) FILTER (WHERE af.severity = 'critical')::int as critical,
            COUNT(*) FILTER (WHERE af.severity = 'high')::int as high,
            COUNT(*) FILTER (WHERE af.status = 'open')::int as open_count
          FROM api_findings af
          JOIN jobs j ON j.id = af.job_id
          JOIN journeys jy ON jy.id = j.journey_id
          WHERE jy.type = 'api_security' AND j.started_at >= ${since}
        `),
      ]);

      const byDay: Record<string, Record<string, number>> = {};
      for (const r of (trendRows.rows || []) as any[]) {
        const dayStr = String(r.day).slice(0, 10);
        if (!byDay[dayStr]) byDay[dayStr] = { critical: 0, high: 0, medium: 0, low: 0 };
        byDay[dayStr][r.severity] = Number(r.count);
      }

      res.json({
        byCategory: owaspRows.rows || [],
        trend: Object.entries(byDay).map(([day, counts]) => ({ day, ...counts })),
        summary: summaryRows.rows?.[0] || { total: 0, critical: 0, high: 0, open_count: 0 },
      });
    } catch (error) {
      log.error({ err: error }, 'failed to fetch API security stats');
      res.status(500).json({ message: "Falha ao buscar dados de API Security" });
    }
  });

  // Journey execution history per type
  app.get('/api/reports/journey-history', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const journeyType = req.query.type as string;
      const periodDays = parseInt(req.query.period as string) || 30;
      const since = new Date(Date.now() - periodDays * 24 * 60 * 60 * 1000);

      if (!journeyType) {
        return res.status(400).json({ message: 'Parâmetro type é obrigatório' });
      }

      const rows = await db.execute(sql`
        SELECT
          j.id as "jobId",
          j.started_at as "startedAt",
          j.finished_at as "finishedAt",
          j.status,
          j.progress,
          j.error,
          jy.name as "journeyName",
          jy.id as "journeyId",
          EXTRACT(EPOCH FROM (COALESCE(j.finished_at, NOW()) - COALESCE(j.started_at, j.created_at)))::int as "durationSecs"
        FROM jobs j
        JOIN journeys jy ON jy.id = j.journey_id
        WHERE jy.type = ${journeyType}
          AND COALESCE(j.started_at, j.created_at) >= ${since}
        ORDER BY COALESCE(j.started_at, j.created_at) DESC
        LIMIT 20
      `);

      res.json(rows.rows || []);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch journey history');
      res.status(500).json({ message: "Falha ao buscar histórico de execuções" });
    }
  });
}
