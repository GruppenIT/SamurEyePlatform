import * as os from 'os';
import { db } from '../db';
import { threats, hosts, assets, jobs, users, activeSessions, loginAttempts } from '@shared/schema';
import { sql, and, eq } from 'drizzle-orm';
import type { HeartbeatRequest } from '@shared/schema';

/**
 * TelemetryService
 *
 * Collects appliance metrics for the central console heartbeat.
 * Never sends sensitive data (threat content, host names, credentials).
 * Only sends aggregate counts and performance metrics.
 */
class TelemetryService {

  /**
   * Collect all telemetry data for the heartbeat payload
   */
  async collect(applianceId: string): Promise<HeartbeatRequest> {
    const [performance, threatStats, usage] = await Promise.all([
      this.collectPerformance(),
      this.collectThreatStats(),
      this.collectUsage(),
    ]);

    return {
      applianceId,
      version: process.env.APP_VERSION || '1.0.0',
      timestamp: new Date().toISOString(),
      performance,
      threatStats,
      usage,
    };
  }

  /**
   * Performance: uptime, host count, asset count
   */
  private async collectPerformance(): Promise<HeartbeatRequest['performance']> {
    const [hostResult, assetResult] = await Promise.all([
      db.select({ count: sql<number>`count(*)::int` }).from(hosts),
      db.select({ count: sql<number>`count(*)::int` }).from(assets),
    ]);

    return {
      uptimeSeconds: Math.floor(process.uptime()),
      hostCount: hostResult[0]?.count || 0,
      assetCount: assetResult[0]?.count || 0,
    };
  }

  /**
   * Threat stats: counts by severity, category, status (no content)
   */
  private async collectThreatStats(): Promise<HeartbeatRequest['threatStats']> {
    const [totalResult, severityRows, categoryRows, statusRows] = await Promise.all([
      db.select({ count: sql<number>`count(*)::int` }).from(threats),
      db.select({
        severity: threats.severity,
        count: sql<number>`count(*)::int`,
      }).from(threats).groupBy(threats.severity),
      db.select({
        category: threats.category,
        count: sql<number>`count(*)::int`,
      }).from(threats).groupBy(threats.category),
      db.select({
        status: threats.status,
        count: sql<number>`count(*)::int`,
      }).from(threats).groupBy(threats.status),
    ]);

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const row of severityRows) {
      if (row.severity in bySeverity) {
        bySeverity[row.severity as keyof typeof bySeverity] = row.count;
      }
    }

    const byCategory: Record<string, number> = {};
    for (const row of categoryRows) {
      if (row.category) byCategory[row.category] = row.count;
    }

    const byStatus: Record<string, number> = {};
    for (const row of statusRows) {
      byStatus[row.status] = row.count;
    }

    return {
      total: totalResult[0]?.count || 0,
      bySeverity,
      byCategory,
      byStatus,
    };
  }

  /**
   * Usage/engagement: active users, jobs executed, logins (last 24h)
   */
  private async collectUsage(): Promise<HeartbeatRequest['usage']> {
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);

    const [activeUsersResult, jobsResult, loginsResult] = await Promise.all([
      // Active users: users with sessions active in last 24h
      db.select({ count: sql<number>`count(DISTINCT user_id)::int` })
        .from(activeSessions)
        .where(sql`${activeSessions.lastActivity} > ${twentyFourHoursAgo}`),
      // Jobs executed in last 24h
      db.select({ count: sql<number>`count(*)::int` })
        .from(jobs)
        .where(sql`${jobs.createdAt} > ${twentyFourHoursAgo}`),
      // Logins today (successful - count distinct IPs/users)
      db.select({ count: sql<number>`count(*)::int` })
        .from(activeSessions)
        .where(sql`${activeSessions.createdAt} > ${startOfDay}`),
    ]);

    return {
      activeUsers24h: activeUsersResult[0]?.count || 0,
      jobsExecuted24h: jobsResult[0]?.count || 0,
      loginsToday: loginsResult[0]?.count || 0,
    };
  }
}

export const telemetryService = new TelemetryService();
