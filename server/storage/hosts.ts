import { db } from "../db";
import {
  hosts,
  threats,
  hostRiskHistory,
  adSecurityTestResults,
  hostEnrichments,
  type Host,
  type InsertHost,
  type HostRiskHistory,
  type InsertHostRiskHistory,
  type AdSecurityTestResult,
  type InsertAdSecurityTestResult,
  type HostEnrichment,
  type InsertHostEnrichment,
} from "@shared/schema";
import { eq, desc, and, or, sql, like } from "drizzle-orm";
import { createLogger } from '../lib/logger';

const log = createLogger('storage');

export async function getHosts(filters?: { search?: string; type?: string; family?: string; sortBy?: string }): Promise<(Host & { threatCounts: { critical: number; high: number; medium: number; low: number } })[]> {
  // Build conditions
  const conditions = [];
  if (filters?.search) {
    const searchTerm = `%${filters.search.toLowerCase()}%`;
    conditions.push(
      or(
        like(hosts.name, searchTerm),
        like(hosts.description, searchTerm),
        sql`${hosts.ips}::text LIKE ${searchTerm}`,
        sql`${hosts.aliases}::text LIKE ${searchTerm}`
      )
    );
  }
  if (filters?.type && filters.type !== "all") conditions.push(eq(hosts.type, filters.type as any));
  if (filters?.family && filters.family !== "all") conditions.push(eq(hosts.family, filters.family as any));

  // Build base query
  let query = db
    .select({
      host: hosts,
      threatCritical: sql<number>`COUNT(CASE WHEN ${threats.severity} = 'critical' THEN 1 END)`,
      threatHigh: sql<number>`COUNT(CASE WHEN ${threats.severity} = 'high' THEN 1 END)`,
      threatMedium: sql<number>`COUNT(CASE WHEN ${threats.severity} = 'medium' THEN 1 END)`,
      threatLow: sql<number>`COUNT(CASE WHEN ${threats.severity} = 'low' THEN 1 END)`,
    })
    .from(hosts)
    .leftJoin(threats, eq(hosts.id, threats.hostId))
    .groupBy(hosts.id);

  // Apply filters
  if (conditions.length > 0) {
    query = query.where(and(...conditions)) as any;
  }

  // Apply sorting
  const sortBy = filters?.sortBy || 'updatedAt';
  if (sortBy === 'riskScore') {
    query = query.orderBy(desc(hosts.riskScore), desc(hosts.rawScore)) as any;
  } else if (sortBy === 'rawScore') {
    query = query.orderBy(desc(hosts.rawScore), desc(hosts.riskScore)) as any;
  } else {
    query = query.orderBy(desc(hosts.updatedAt)) as any;
  }

  const results = await query;

  return results.map(row => ({
    ...row.host,
    threatCounts: {
      critical: Number(row.threatCritical) || 0,
      high: Number(row.threatHigh) || 0,
      medium: Number(row.threatMedium) || 0,
      low: Number(row.threatLow) || 0,
    }
  }));
}

export async function getHost(id: string): Promise<Host | undefined> {
  const [host] = await db.select().from(hosts).where(eq(hosts.id, id));
  return host;
}

export async function upsertHost(host: InsertHost): Promise<Host> {
  const normalizedName = host.name.toLowerCase();

  log.info({ hostName: normalizedName, ips: host.ips }, 'attempting host upsert');

  // Try to find existing host by name first
  let existingHost = await getHostByName(normalizedName);

  // If not found by name, try by IP (critical for renamed hosts after enrichment)
  if (!existingHost && host.ips && host.ips.length > 0) {
    log.info({ ip: host.ips[0] }, 'host not found by name, searching by IP');
    existingHost = await findHostByTarget(normalizedName, host.ips[0]);
  }

  if (existingHost) {
    log.info({ hostName: existingHost.name, hostId: existingHost.id }, 'found existing host, updating');
    // Update existing host, merging IPs and aliases
    const mergedIps = Array.from(new Set([...(existingHost.ips || []), ...(host.ips || [])]));
    const mergedAliases = Array.from(new Set([...(existingHost.aliases || []), ...(host.aliases || [])]));

    const [updatedHost] = await db
      .update(hosts)
      .set({
        description: host.description || existingHost.description,
        operatingSystem: host.operatingSystem || existingHost.operatingSystem,
        type: host.type || existingHost.type,
        family: host.family || existingHost.family,
        ips: mergedIps,
        aliases: mergedAliases,
        updatedAt: new Date(),
      })
      .where(eq(hosts.id, existingHost.id))
      .returning();
    log.info({ hostName: updatedHost.name, ips: updatedHost.ips, aliases: updatedHost.aliases }, 'host updated');
    return updatedHost;
  } else {
    log.info({ hostName: normalizedName }, 'creating new host');
    // Create new host
    const hostValues = {
      ...host,
      name: normalizedName,
    } as any;

    const [newHost] = await db
      .insert(hosts)
      .values(hostValues)
      .returning();
    log.info({ hostName: newHost.name, hostId: newHost.id }, 'new host created');
    return newHost;
  }
}

export async function updateHost(id: string, host: Partial<InsertHost>): Promise<Host> {
  const updates: any = { updatedAt: new Date() };

  if (host.name !== undefined) updates.name = host.name.toLowerCase();
  if (host.description !== undefined) updates.description = host.description;
  if (host.operatingSystem !== undefined) updates.operatingSystem = host.operatingSystem;
  if (host.type !== undefined) updates.type = host.type;
  if (host.family !== undefined) updates.family = host.family;
  if (host.ips !== undefined) updates.ips = host.ips;
  if (host.aliases !== undefined) updates.aliases = host.aliases;
  if (host.riskScore !== undefined) updates.riskScore = host.riskScore;
  if (host.rawScore !== undefined) updates.rawScore = host.rawScore;
  if (host.sshHostFingerprint !== undefined) updates.sshHostFingerprint = host.sshHostFingerprint;

  const [updatedHost] = await db
    .update(hosts)
    .set(updates)
    .where(eq(hosts.id, id))
    .returning();
  return updatedHost;
}

export async function deleteHost(id: string): Promise<void> {
  await db.delete(hosts).where(eq(hosts.id, id));
}

export async function getHostByName(name: string): Promise<Host | undefined> {
  const [host] = await db.select().from(hosts).where(eq(hosts.name, name.toLowerCase()));
  return host;
}

export async function findHostByTarget(target: string, ip?: string): Promise<Host | undefined> {
  const normalizedTarget = target.toLowerCase();

  // Try to find by name first
  let host = await getHostByName(normalizedTarget);
  if (host) return host;

  // Try to find by IP or aliases (correct JSON array containment)
  if (ip) {
    const results = await db
      .select()
      .from(hosts)
      .where(
        or(
          // Correct way to check if IP exists in JSONB array
          sql`EXISTS (SELECT 1 FROM jsonb_array_elements_text(${hosts.ips}) v WHERE v = ${ip})`,
          sql`EXISTS (SELECT 1 FROM jsonb_array_elements_text(${hosts.aliases}) v WHERE v = ${normalizedTarget})`,
          sql`EXISTS (SELECT 1 FROM jsonb_array_elements_text(${hosts.aliases}) v WHERE v = ${target})`
        )
      );
    if (results.length > 0) return results[0];
  }

  // Try to find by aliases without IP (correct JSON array containment)
  const aliasResults = await db
    .select()
    .from(hosts)
    .where(
      or(
        sql`EXISTS (SELECT 1 FROM jsonb_array_elements_text(${hosts.aliases}) v WHERE v = ${normalizedTarget})`,
        sql`EXISTS (SELECT 1 FROM jsonb_array_elements_text(${hosts.aliases}) v WHERE v = ${target})`
      )
    );
  if (aliasResults.length > 0) return aliasResults[0];

  return undefined;
}

// Host enrichment operations (authenticated scan data)
export async function createHostEnrichment(enrichment: InsertHostEnrichment): Promise<HostEnrichment> {
  const [created] = await db
    .insert(hostEnrichments)
    .values(enrichment as any)
    .returning();
  return created;
}

export async function getHostEnrichments(hostId: string, jobId?: string): Promise<HostEnrichment[]> {
  const conditions = [eq(hostEnrichments.hostId, hostId)];
  if (jobId) {
    conditions.push(eq(hostEnrichments.jobId, jobId));
  }

  const results = await db
    .select()
    .from(hostEnrichments)
    .where(and(...conditions))
    .orderBy(desc(hostEnrichments.collectedAt));

  return results;
}

export async function getLatestHostEnrichment(hostId: string): Promise<HostEnrichment | undefined> {
  const [result] = await db
    .select()
    .from(hostEnrichments)
    .where(and(
      eq(hostEnrichments.hostId, hostId),
      eq(hostEnrichments.success, true)
    ))
    .orderBy(desc(hostEnrichments.collectedAt))
    .limit(1);

  return result;
}

// Host risk history operations
export async function createHostRiskHistory(history: InsertHostRiskHistory): Promise<HostRiskHistory> {
  const [newHistory] = await db
    .insert(hostRiskHistory)
    .values(history)
    .returning();
  return newHistory;
}

export async function getHostRiskHistory(hostId: string, limit?: number): Promise<HostRiskHistory[]> {
  const query = db
    .select()
    .from(hostRiskHistory)
    .where(eq(hostRiskHistory.hostId, hostId))
    .orderBy(desc(hostRiskHistory.recordedAt));

  if (limit) {
    return await query.limit(limit);
  }
  return await query;
}

// AD Security test results operations
export async function createAdSecurityTestResults(results: InsertAdSecurityTestResult[]): Promise<AdSecurityTestResult[]> {
  if (results.length === 0) return [];

  const inserted = await db
    .insert(adSecurityTestResults)
    .values(results)
    .returning();
  return inserted;
}

export async function getAdSecurityTestResults(hostId: string, jobId?: string): Promise<AdSecurityTestResult[]> {
  const conditions = [eq(adSecurityTestResults.hostId, hostId)];
  if (jobId) {
    conditions.push(eq(adSecurityTestResults.jobId, jobId));
  }

  const results = await db
    .select()
    .from(adSecurityTestResults)
    .where(and(...conditions))
    .orderBy(desc(adSecurityTestResults.executedAt));

  return results;
}

export async function getAdSecurityLatestTestResults(hostId: string): Promise<AdSecurityTestResult[]> {
  // Get the latest job ID for this host
  const latestJobResult = await db
    .select({ jobId: adSecurityTestResults.jobId })
    .from(adSecurityTestResults)
    .where(eq(adSecurityTestResults.hostId, hostId))
    .orderBy(desc(adSecurityTestResults.executedAt))
    .limit(1);

  if (latestJobResult.length === 0) return [];

  const latestJobId = latestJobResult[0].jobId;

  // Get all results from the latest job
  const results = await db
    .select()
    .from(adSecurityTestResults)
    .where(
      and(
        eq(adSecurityTestResults.hostId, hostId),
        eq(adSecurityTestResults.jobId, latestJobId)
      )
    )
    .orderBy(adSecurityTestResults.category, adSecurityTestResults.testName);

  return results;
}
