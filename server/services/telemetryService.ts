import * as os from 'os';
import * as fs from 'fs';
import { execSync } from 'child_process';
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
  private lastNetSnapshot: { time: number; rx: number; tx: number } | null = null;

  /**
   * Collect all telemetry data for the heartbeat payload
   */
  async collect(applianceId: string): Promise<HeartbeatRequest> {
    const [system, performance, threatStats, usage] = await Promise.all([
      this.collectSystem(),
      this.collectPerformance(),
      this.collectThreatStats(),
      this.collectUsage(),
    ]);

    return {
      applianceId,
      version: process.env.APP_VERSION || '1.0.0',
      timestamp: new Date().toISOString(),
      system,
      performance,
      threatStats,
      usage,
    };
  }

  /**
   * System metrics: CPU, memory, disk, network, services
   */
  private async collectSystem(): Promise<HeartbeatRequest['system']> {
    const result: NonNullable<HeartbeatRequest['system']> = {};

    // CPU usage (average across cores over last idle/total)
    try {
      const cpus = os.cpus();
      let totalIdle = 0, totalTick = 0;
      for (const cpu of cpus) {
        const { user, nice, sys, idle, irq } = cpu.times;
        totalTick += user + nice + sys + idle + irq;
        totalIdle += idle;
      }
      const percent = totalTick > 0 ? Math.round(((totalTick - totalIdle) / totalTick) * 1000) / 10 : 0;
      result.cpu = { percent };
    } catch { /* omit if unavailable */ }

    // Memory
    try {
      const totalMb = Math.round(os.totalmem() / (1024 * 1024));
      const freeMb = Math.round(os.freemem() / (1024 * 1024));
      const usedMb = totalMb - freeMb;
      const percent = totalMb > 0 ? Math.round((usedMb / totalMb) * 1000) / 10 : 0;
      result.memory = { percent, usedMb, totalMb };
    } catch { /* omit if unavailable */ }

    // Disk (root partition)
    try {
      const output = execSync("df -B1 / | tail -1", { timeout: 5000 }).toString().trim();
      const parts = output.split(/\s+/);
      if (parts.length >= 4) {
        const totalBytes = parseInt(parts[1], 10);
        const usedBytes = parseInt(parts[2], 10);
        if (!isNaN(totalBytes) && !isNaN(usedBytes) && totalBytes > 0) {
          const totalGb = Math.round((totalBytes / (1024 ** 3)) * 10) / 10;
          const usedGb = Math.round((usedBytes / (1024 ** 3)) * 10) / 10;
          const percent = Math.round((usedBytes / totalBytes) * 1000) / 10;
          result.disk = { percent, usedGb, totalGb };
        }
      }
    } catch { /* omit if unavailable */ }

    // Network throughput (bytes/s between snapshots)
    try {
      const netData = this.readNetworkBytes();
      if (netData && this.lastNetSnapshot) {
        const elapsed = (netData.time - this.lastNetSnapshot.time) / 1000;
        if (elapsed > 0) {
          result.network = {
            inBps: Math.round((netData.rx - this.lastNetSnapshot.rx) / elapsed),
            outBps: Math.round((netData.tx - this.lastNetSnapshot.tx) / elapsed),
          };
        }
      }
      if (netData) {
        this.lastNetSnapshot = netData;
      }
    } catch { /* omit if unavailable */ }

    // Services status
    try {
      result.services = this.collectServices();
    } catch { /* omit if unavailable */ }

    return Object.keys(result).length > 0 ? result : undefined;
  }

  private readNetworkBytes(): { time: number; rx: number; tx: number } | null {
    try {
      const content = fs.readFileSync('/proc/net/dev', 'utf-8');
      const lines = content.split('\n').slice(2); // skip headers
      let rx = 0, tx = 0;
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (!parts[0] || parts[0] === 'lo:') continue; // skip loopback
        rx += parseInt(parts[1], 10) || 0;
        tx += parseInt(parts[9], 10) || 0;
      }
      return { time: Date.now(), rx, tx };
    } catch {
      return null;
    }
  }

  private collectServices(): { name: string; status: string; uptime: number }[] {
    const serviceNames = ['samureye-scanner', 'samureye-collector', 'postgresql', 'nginx'];
    const services: { name: string; status: string; uptime: number }[] = [];

    for (const name of serviceNames) {
      try {
        const raw = execSync(
          `systemctl show ${name} --property=ActiveState,ActiveEnterTimestamp --no-pager 2>/dev/null`,
          { timeout: 3000 },
        ).toString();
        const stateMatch = raw.match(/ActiveState=(\S+)/);
        const tsMatch = raw.match(/ActiveEnterTimestamp=(.+)/);
        const state = stateMatch?.[1];
        if (!state || state === 'inactive') continue;

        let uptime = 0;
        if (tsMatch?.[1] && tsMatch[1].trim() !== '') {
          const entered = new Date(tsMatch[1].trim()).getTime();
          if (!isNaN(entered)) {
            uptime = Math.floor((Date.now() - entered) / 1000);
          }
        }

        services.push({
          name,
          status: state === 'active' ? 'running' : state,
          uptime: Math.max(0, uptime),
        });
      } catch { /* service not found or systemctl unavailable */ }
    }

    return services.length > 0 ? services : [];
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
