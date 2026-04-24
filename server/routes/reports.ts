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

  // API security inventory: per-API endpoint counts, method distribution, recent discoveries
  app.get('/api/reports/api-security/inventory', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const periodDays = parseInt(req.query.period as string) || 30;
      const since = new Date(Date.now() - periodDays * 24 * 60 * 60 * 1000);
      const assetId = req.query.assetId as string | undefined;
      // Build optional asset filter as a raw SQL fragment to avoid pg type-inference issues with null params
      const assetFilter = assetId ? sql`AND ast.id = ${assetId}` : sql``;
      const assetFilterW = assetId ? sql`WHERE ast.id = ${assetId}` : sql``;

      const [apiRows, methodRows, recentRows, totalsRows, sourceRows] = await Promise.all([
        db.execute(sql`
          SELECT
            a.id as api_id,
            a.base_url,
            a.api_type,
            a.spec_url,
            ast.id as asset_id,
            ast.value as asset_name,
            COUNT(DISTINCT ae.id)::int as endpoint_count,
            COUNT(DISTINCT ae.id) FILTER (WHERE ae.requires_auth = false)::int as unauth_count,
            COUNT(DISTINCT ae.id) FILTER (WHERE ae.requires_auth = true)::int as auth_count,
            COUNT(DISTINCT ae.id) FILTER (WHERE ae.requires_auth IS NULL)::int as unknown_auth_count,
            COUNT(DISTINCT ae.id) FILTER (WHERE ae.method = 'GET')::int as method_get,
            COUNT(DISTINCT ae.id) FILTER (WHERE ae.method = 'POST')::int as method_post,
            COUNT(DISTINCT ae.id) FILTER (WHERE ae.method = 'PUT')::int as method_put,
            COUNT(DISTINCT ae.id) FILTER (WHERE ae.method = 'PATCH')::int as method_patch,
            COUNT(DISTINCT ae.id) FILTER (WHERE ae.method = 'DELETE')::int as method_delete,
            COUNT(DISTINCT ae.id) FILTER (WHERE ae.method NOT IN ('GET','POST','PUT','PATCH','DELETE'))::int as method_other,
            MAX(j.finished_at) as last_scanned_at,
            COUNT(DISTINCT af.id) FILTER (WHERE af.status != 'closed')::int as open_finding_count,
            COUNT(DISTINCT af.id) FILTER (WHERE af.severity IN ('critical','high') AND af.status = 'open')::int as high_risk_count
          FROM apis a
          LEFT JOIN assets ast ON ast.id = a.parent_asset_id
          LEFT JOIN api_endpoints ae ON ae.api_id = a.id
          LEFT JOIN api_findings af ON af.api_endpoint_id = ae.id
          LEFT JOIN jobs j ON j.id = af.job_id
          WHERE 1=1 ${assetFilter}
          GROUP BY a.id, a.base_url, a.api_type, a.spec_url, ast.id, ast.value
          ORDER BY endpoint_count DESC, a.base_url
        `),
        db.execute(sql`
          SELECT ae.method, COUNT(*)::int as count
          FROM api_endpoints ae
          JOIN apis a ON a.id = ae.api_id
          LEFT JOIN assets ast ON ast.id = a.parent_asset_id
          ${assetFilterW}
          GROUP BY ae.method
          ORDER BY count DESC
        `),
        db.execute(sql`
          SELECT ae.method, ae.path, ae.created_at, a.base_url, a.id as api_id, ast.value as asset_name
          FROM api_endpoints ae
          JOIN apis a ON a.id = ae.api_id
          LEFT JOIN assets ast ON ast.id = a.parent_asset_id
          WHERE ae.created_at >= ${since} ${assetFilter}
          ORDER BY ae.created_at DESC
          LIMIT 25
        `),
        db.execute(sql`
          SELECT
            COUNT(DISTINCT a.id)::int as total_apis,
            COUNT(DISTINCT ae.id)::int as total_endpoints,
            COUNT(DISTINCT ae.id) FILTER (WHERE ae.requires_auth = false)::int as unauth_endpoints,
            COUNT(DISTINCT ae.id) FILTER (WHERE ae.requires_auth = true)::int as auth_endpoints,
            COUNT(DISTINCT ae.id) FILTER (WHERE ae.requires_auth IS NULL)::int as unknown_auth_endpoints
          FROM apis a
          LEFT JOIN api_endpoints ae ON ae.api_id = a.id
          LEFT JOIN assets ast ON ast.id = a.parent_asset_id
          WHERE 1=1 ${assetFilter}
        `),
        db.execute(sql`
          SELECT
            src as source,
            COUNT(*)::int as count
          FROM api_endpoints ae
          JOIN apis a ON a.id = ae.api_id
          LEFT JOIN assets ast ON ast.id = a.parent_asset_id
          CROSS JOIN LATERAL unnest(COALESCE(ae.discovery_sources, '{}')) AS src
          WHERE 1=1 ${assetFilter}
          GROUP BY src
          ORDER BY count DESC
        `),
      ]);

      res.json({
        apis: (apiRows.rows || []).map((r: any) => ({
          apiId: r.api_id,
          baseUrl: r.base_url,
          apiType: r.api_type,
          specUrl: r.spec_url,
          assetId: r.asset_id,
          assetName: r.asset_name,
          endpointCount: r.endpoint_count,
          unauthCount: r.unauth_count,
          authCount: r.auth_count,
          unknownAuthCount: r.unknown_auth_count,
          methods: {
            GET: r.method_get,
            POST: r.method_post,
            PUT: r.method_put,
            PATCH: r.method_patch,
            DELETE: r.method_delete,
            OTHER: r.method_other,
          },
          lastScannedAt: r.last_scanned_at,
          openFindingCount: r.open_finding_count,
          highRiskCount: r.high_risk_count,
        })),
        methodTotals: Object.fromEntries((methodRows.rows || []).map((r: any) => [r.method, r.count])),
        recentDiscoveries: (recentRows.rows || []).map((r: any) => ({
          method: r.method,
          path: r.path,
          baseUrl: r.base_url,
          apiId: r.api_id,
          assetName: r.asset_name,
          discoveredAt: r.created_at,
        })),
        totals: totalsRows.rows?.[0] ?? { total_apis: 0, total_endpoints: 0, unauth_endpoints: 0, auth_endpoints: 0, unknown_auth_endpoints: 0 },
        sourceCounts: (sourceRows.rows || []).map((r: any) => ({ source: r.source, count: r.count })),
      });
    } catch (error) {
      log.error({ err: error }, 'failed to fetch API security inventory');
      res.status(500).json({ message: "Falha ao buscar inventário de APIs" });
    }
  });

  // API security stats: OWASP API Top 10 counts + severity trend
  app.get('/api/reports/api-security/stats', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const periodDays = parseInt(req.query.period as string) || 30;
      const since = new Date(Date.now() - periodDays * 24 * 60 * 60 * 1000);
      const apiId = req.query.apiId as string | undefined;
      const apiFilter = apiId ? sql`AND ae.api_id = ${apiId}` : sql``;

      const [owaspRows, trendRows, summaryRows] = await Promise.all([
        db.execute(sql`
          SELECT
            af.owasp_category as category,
            af.severity,
            af.status,
            COUNT(*)::int as count
          FROM api_findings af
          JOIN api_endpoints ae ON ae.id = af.api_endpoint_id
          JOIN jobs j ON j.id = af.job_id
          JOIN journeys jy ON jy.id = j.journey_id
          WHERE jy.type = 'api_security' AND j.started_at >= ${since}
            ${apiFilter}
          GROUP BY af.owasp_category, af.severity, af.status
        `),
        db.execute(sql`
          SELECT
            DATE(j.started_at) as day,
            af.severity,
            COUNT(*)::int as count
          FROM api_findings af
          JOIN api_endpoints ae ON ae.id = af.api_endpoint_id
          JOIN jobs j ON j.id = af.job_id
          JOIN journeys jy ON jy.id = j.journey_id
          WHERE jy.type = 'api_security' AND j.started_at >= ${since}
            ${apiFilter}
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
          JOIN api_endpoints ae ON ae.id = af.api_endpoint_id
          JOIN jobs j ON j.id = af.job_id
          JOIN journeys jy ON jy.id = j.journey_id
          WHERE jy.type = 'api_security' AND j.started_at >= ${since}
            ${apiFilter}
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
