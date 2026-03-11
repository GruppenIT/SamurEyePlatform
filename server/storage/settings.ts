import { db } from "../db";
import {
  settings,
  auditLog,
  users,
  assets,
  threats,
  jobs,
  type Setting,
  type AuditLogEntry,
} from "@shared/schema";
import { eq, desc, and, or, sql, count } from "drizzle-orm";
import * as os from "os";
import { getJourney } from "./journeys";
import { getAsset, getCredential } from "./assets";
import { getUser } from "./users";
import { getThreat } from "./threats";
import { getRunningJobs } from "./journeys";

// Settings operations
export async function getSetting(key: string): Promise<Setting | undefined> {
  const [setting] = await db.select().from(settings).where(eq(settings.key, key));
  return setting;
}

export async function setSetting(key: string, value: any, userId: string): Promise<Setting> {
  const [setting] = await db
    .insert(settings)
    .values({ key, value, updatedBy: userId })
    .onConflictDoUpdate({
      target: settings.key,
      set: {
        value,
        updatedBy: userId,
        updatedAt: new Date(),
      },
    })
    .returning();
  return setting;
}

export async function getAllSettings(): Promise<Setting[]> {
  return await db.select().from(settings).orderBy(settings.key);
}

// Audit operations
export async function logAudit(entry: Omit<AuditLogEntry, 'id' | 'createdAt'>): Promise<AuditLogEntry> {
  const [auditEntry] = await db.insert(auditLog).values(entry).returning();
  return auditEntry;
}

export async function getAuditLog(limit = 100): Promise<any[]> {
  // Get audit logs with user information via JOIN
  const logs = await db
    .select({
      id: auditLog.id,
      actorId: auditLog.actorId,
      action: auditLog.action,
      objectType: auditLog.objectType,
      objectId: auditLog.objectId,
      before: auditLog.before,
      after: auditLog.after,
      createdAt: auditLog.createdAt,
      actorFirstName: users.firstName,
      actorLastName: users.lastName,
      actorEmail: users.email,
    })
    .from(auditLog)
    .leftJoin(users, eq(auditLog.actorId, users.id))
    .orderBy(desc(auditLog.createdAt))
    .limit(limit);

  // Enrich with object details
  const enrichedLogs = await Promise.all(logs.map(async (log) => {
    let objectDetails = null;

    // Combine firstName and lastName for actorName
    const actorName = log.actorFirstName && log.actorLastName
      ? `${log.actorFirstName} ${log.actorLastName}`
      : null;

    try {
      switch (log.objectType) {
        case 'journey':
          if (log.objectId) {
            const journey = await getJourney(log.objectId);
            if (journey) {
              objectDetails = {
                name: journey.name,
                type: journey.type,
              };
            }
          }
          break;
        case 'asset':
          if (log.objectId) {
            const asset = await getAsset(log.objectId);
            if (asset) {
              objectDetails = {
                type: asset.type,
                value: asset.value,
              };
            }
          }
          break;
        case 'credential':
          if (log.objectId) {
            const credential = await getCredential(log.objectId);
            if (credential) {
              objectDetails = {
                name: credential.name,
                type: credential.type,
                username: credential.username,
              };
            }
          }
          break;
        case 'user':
          if (log.objectId) {
            const user = await getUser(log.objectId);
            if (user) {
              objectDetails = {
                name: `${user.firstName} ${user.lastName}`,
                email: user.email,
                role: user.role,
              };
            }
          }
          break;
        case 'threat':
          if (log.objectId) {
            const threat = await getThreat(log.objectId);
            if (threat) {
              objectDetails = {
                title: threat.title,
                severity: threat.severity,
                status: threat.status,
              };
            }
          }
          break;
      }
    } catch (error) {
      // Object may have been deleted, that's OK
      // Note: 'log' here is the .map() loop variable (audit log entry), not the pino logger
      // Using console-free approach: silently continue since object may have been deleted
    }

    return {
      id: log.id,
      actorId: log.actorId,
      action: log.action,
      objectType: log.objectType,
      objectId: log.objectId,
      before: log.before,
      after: log.after,
      createdAt: log.createdAt,
      actorName,
      actorEmail: log.actorEmail,
      objectDetails,
    };
  }));

  return enrichedLogs;
}

// Dashboard operations
export async function getDashboardMetrics(): Promise<{
  activeAssets: number;
  criticalThreats: number;
  jobsExecuted: number;
  successRate: number;
}> {
  const [assetCount] = await db.select({ count: count() }).from(assets);
  const [criticalThreatsCount] = await db
    .select({ count: count() })
    .from(threats)
    .where(and(eq(threats.severity, 'critical'), eq(threats.status, 'open')));
  const [jobsCount] = await db.select({ count: count() }).from(jobs);

  // Calculate success rate
  const [completedJobs] = await db
    .select({ count: count() })
    .from(jobs)
    .where(eq(jobs.status, 'completed'));

  const [finishedJobs] = await db
    .select({ count: count() })
    .from(jobs)
    .where(or(eq(jobs.status, 'completed'), eq(jobs.status, 'failed'), eq(jobs.status, 'timeout')));

  const successRate = Number(finishedJobs.count) > 0
    ? (Number(completedJobs.count) / Number(finishedJobs.count)) * 100
    : 100;

  return {
    activeAssets: Number(assetCount.count),
    criticalThreats: Number(criticalThreatsCount.count),
    jobsExecuted: Number(jobsCount.count),
    successRate: Math.round(successRate * 10) / 10, // Round to 1 decimal place
  };
}

export async function getSystemMetrics(): Promise<{
  cpu: number;
  memory: number;
  services: Array<{
    name: string;
    status: string;
    color: string;
  }>;
}> {
  // Get real CPU and memory usage

  // Calculate CPU usage (simple average)
  const cpus = os.cpus();
  let totalIdle = 0;
  let totalTick = 0;

  cpus.forEach((cpu: any) => {
    for (let type in cpu.times) {
      totalTick += cpu.times[type];
    }
    totalIdle += cpu.times.idle;
  });

  const idle = totalIdle / cpus.length;
  const total = totalTick / cpus.length;
  const cpuUsage = Math.round(100 - (100 * idle / total));

  // Calculate memory usage
  const totalMemory = os.totalmem();
  const freeMemory = os.freemem();
  const memoryUsage = Math.round(((totalMemory - freeMemory) / totalMemory) * 100);

  // Check database connection
  let dbStatus = "conectado";
  let dbColor = "status-success";
  try {
    await db.execute(sql`SELECT 1`);
  } catch (error) {
    dbStatus = "desconectado";
    dbColor = "status-error";
  }

  // Check running jobs for worker queue status
  const runningJobs = await getRunningJobs();
  const workerStatus = runningJobs.length > 0 ? `${runningJobs.length}/4 Workers` : "0/4 Workers";
  const workerColor = runningJobs.length > 0 ? "status-success" : "status-warning";

  return {
    cpu: cpuUsage,
    memory: memoryUsage,
    services: [
      { name: "API Backend", status: "online", color: "status-success" },
      { name: "PostgreSQL", status: dbStatus, color: dbColor },
      { name: "Redis Cache", status: "não configurado", color: "status-warning" },
      { name: "Worker Queue", status: workerStatus, color: workerColor },
    ],
  };
}
