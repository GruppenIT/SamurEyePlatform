import { db } from "../db";
import {
  threats,
  hosts,
  jobs,
  users,
  threatStatusHistory,
  type Threat,
  type InsertThreat,
  type Host,
  type ThreatStatusHistory,
  type InsertThreatStatusHistory,
  type User,
} from "@shared/schema";
import { eq, desc, and, or, sql, count, like, inArray } from "drizzle-orm";
import { createLogger } from '../lib/logger';

const log = createLogger('storage');

export async function getThreats(filters?: { severity?: string; status?: string; assetId?: string; hostId?: string; jobId?: string; category?: string }): Promise<Threat[]> {
  if (filters) {
    const conditions = [];
    if (filters.severity) conditions.push(eq(threats.severity, filters.severity as any));
    if (filters.status) conditions.push(eq(threats.status, filters.status as any));
    if (filters.assetId) conditions.push(eq(threats.assetId, filters.assetId));
    if (filters.hostId) conditions.push(eq(threats.hostId, filters.hostId));
    if (filters.jobId) conditions.push(eq(threats.jobId, filters.jobId));
    if (filters.category) conditions.push(eq(threats.category, filters.category));

    if (conditions.length > 0) {
      return await db
        .select()
        .from(threats)
        .where(and(...conditions))
        .orderBy(desc(threats.createdAt));
    }
  }

  return await db.select().from(threats).orderBy(desc(threats.createdAt));
}

export async function getThreatsWithHosts(filters?: { severity?: string; status?: string; assetId?: string; hostId?: string; source?: string }): Promise<any[]> {
  let query = db
    .select({
      // Threat fields
      id: threats.id,
      title: threats.title,
      description: threats.description,
      severity: threats.severity,
      status: threats.status,
      source: threats.source,
      assetId: threats.assetId,
      hostId: threats.hostId,
      evidence: threats.evidence,
      jobId: threats.jobId,
      correlationKey: threats.correlationKey,
      category: threats.category,
      lastSeenAt: threats.lastSeenAt,
      closureReason: threats.closureReason,
      hibernatedUntil: threats.hibernatedUntil,
      statusChangedBy: threats.statusChangedBy,
      statusChangedAt: threats.statusChangedAt,
      statusJustification: threats.statusJustification,
      createdAt: threats.createdAt,
      updatedAt: threats.updatedAt,
      assignedTo: threats.assignedTo,
      parentThreatId: threats.parentThreatId,
      groupingKey: threats.groupingKey,
      contextualScore: threats.contextualScore,
      scoreBreakdown: threats.scoreBreakdown,
      projectedScoreAfterFix: threats.projectedScoreAfterFix,
      ruleId: threats.ruleId,
      // Host fields (will be null if no host)
      hostIdFromTable: hosts.id,
      hostName: hosts.name,
      hostType: hosts.type,
      hostFamily: hosts.family,
      hostIps: hosts.ips,
      hostAliases: hosts.aliases,
      hostDescription: hosts.description,
      hostOperatingSystem: hosts.operatingSystem,
      hostDiscoveredAt: hosts.discoveredAt,
      hostUpdatedAt: hosts.updatedAt,
    })
    .from(threats)
    .leftJoin(hosts, eq(threats.hostId, hosts.id));

  const conditions = [];
  if (filters) {
    if (filters.severity) conditions.push(eq(threats.severity, filters.severity as any));
    if (filters.status) conditions.push(eq(threats.status, filters.status as any));
    if (filters.assetId) conditions.push(eq(threats.assetId, filters.assetId));
    if (filters.hostId) conditions.push(eq(threats.hostId, filters.hostId));
    if (filters.source) conditions.push(eq(threats.source, filters.source as any));
  }

  const results = await (conditions.length > 0
    ? query.where(and(...conditions)).orderBy(desc(threats.createdAt))
    : query.orderBy(desc(threats.createdAt)));

  // Transform results to include host object
  return results.map(row => ({
    id: row.id,
    title: row.title,
    description: row.description,
    severity: row.severity,
    status: row.status,
    source: row.source,
    assetId: row.assetId,
    hostId: row.hostId,
    evidence: row.evidence,
    jobId: row.jobId,
    correlationKey: row.correlationKey,
    category: row.category,
    lastSeenAt: row.lastSeenAt,
    closureReason: row.closureReason,
    hibernatedUntil: row.hibernatedUntil,
    statusChangedBy: row.statusChangedBy,
    statusChangedAt: row.statusChangedAt,
    statusJustification: row.statusJustification,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    assignedTo: row.assignedTo,
    parentThreatId: row.parentThreatId,
    groupingKey: row.groupingKey,
    contextualScore: row.contextualScore,
    scoreBreakdown: row.scoreBreakdown,
    projectedScoreAfterFix: row.projectedScoreAfterFix,
    ruleId: row.ruleId,
    host: row.hostName ? {
      id: row.hostIdFromTable!,
      name: row.hostName,
      type: row.hostType || 'other',
      family: row.hostFamily || 'other',
      ips: row.hostIps || [],
      aliases: row.hostAliases || [],
      description: row.hostDescription,
      operatingSystem: row.hostOperatingSystem,
      riskScore: 0,
      rawScore: 0,
      discoveredAt: row.hostDiscoveredAt!,
      updatedAt: row.hostUpdatedAt!
    } : undefined
  }));
}

export async function getThreat(id: string): Promise<Threat | undefined> {
  const [threat] = await db.select().from(threats).where(eq(threats.id, id));
  return threat;
}

export async function createThreat(threat: InsertThreat): Promise<Threat> {
  const [newThreat] = await db.insert(threats).values(threat).returning();
  return newThreat;
}

export async function updateThreat(id: string, threat: Partial<Threat>): Promise<Threat> {
  const [updatedThreat] = await db
    .update(threats)
    .set({ ...threat, updatedAt: new Date() })
    .where(eq(threats.id, id))
    .returning();
  return updatedThreat;
}

export async function deleteThreat(id: string): Promise<void> {
  await db.delete(threats).where(eq(threats.id, id));
}

export async function getThreatStats(): Promise<{
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  open: number;
  investigating: number;
  mitigated: number;
  closed: number;
  hibernated: number;
  accepted_risk: number;
}> {
  // Get counts by severity
  const severityResult = await db
    .select({
      severity: threats.severity,
      count: count(),
    })
    .from(threats)
    .groupBy(threats.severity);

  // Get counts by status
  const statusResult = await db
    .select({
      status: threats.status,
      count: count(),
    })
    .from(threats)
    .groupBy(threats.status);

  const stats = {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    open: 0,
    investigating: 0,
    mitigated: 0,
    closed: 0,
    hibernated: 0,
    accepted_risk: 0
  };

  // Calculate severity stats
  for (const row of severityResult) {
    const severity = row.severity as 'critical' | 'high' | 'medium' | 'low';
    stats[severity] = Number(row.count);
    stats.total += Number(row.count);
  }

  // Calculate status stats
  for (const row of statusResult) {
    const status = row.status as 'open' | 'investigating' | 'mitigated' | 'closed' | 'hibernated' | 'accepted_risk';
    stats[status] = Number(row.count);
  }

  return stats;
}

// Threat lifecycle operations
export async function findThreatByCorrelationKey(correlationKey: string): Promise<Threat | undefined> {
  log.info({ correlationKey, keyLength: correlationKey.length }, 'searching threat by correlation key');

  // Get ALL threats with this correlation key, ordered by creation date
  const allThreats = await db
    .select()
    .from(threats)
    .where(eq(threats.correlationKey, correlationKey))
    .orderBy(threats.createdAt);

  log.info({ count: allThreats.length, correlationKey }, 'found threats by correlation key');

  if (allThreats.length > 1) {
    log.warn('multiple threats found with same correlationKey, using first');
    log.info({ threats: allThreats.map(t => ({ id: t.id, status: t.status, createdAt: t.createdAt })) }, 'all threats with same correlation key');
  }

  const threat = allThreats[0];

  if (threat) {
    log.info({ threatId: threat.id, status: threat.status, createdAt: threat.createdAt }, 'using existing threat');
  } else {
    log.info({ correlationKey }, 'no threat found for correlation key');
  }

  return threat;
}

export async function listOpenThreatsByJourney(journeyId: string, category?: string): Promise<Threat[]> {
  const conditions = [
    inArray(threats.status, ['open', 'investigating', 'mitigated', 'hibernated'])
  ];

  if (category) {
    conditions.push(eq(threats.category, category));
  }

  const results = await db
    .select({
      id: threats.id,
      title: threats.title,
      description: threats.description,
      severity: threats.severity,
      status: threats.status,
      source: threats.source,
      assetId: threats.assetId,
      hostId: threats.hostId,
      evidence: threats.evidence,
      jobId: threats.jobId,
      correlationKey: threats.correlationKey,
      category: threats.category,
      lastSeenAt: threats.lastSeenAt,
      closureReason: threats.closureReason,
      hibernatedUntil: threats.hibernatedUntil,
      statusChangedBy: threats.statusChangedBy,
      statusChangedAt: threats.statusChangedAt,
      statusJustification: threats.statusJustification,
      createdAt: threats.createdAt,
      updatedAt: threats.updatedAt,
      assignedTo: threats.assignedTo,
      // Phase 2 columns
      parentThreatId: threats.parentThreatId,
      groupingKey: threats.groupingKey,
      contextualScore: threats.contextualScore,
      scoreBreakdown: threats.scoreBreakdown,
      projectedScoreAfterFix: threats.projectedScoreAfterFix,
    })
    .from(threats)
    .innerJoin(jobs, eq(threats.jobId, jobs.id))
    .where(and(
      eq(jobs.journeyId, journeyId),
      ...conditions
    ));

  return results;
}

export async function closeThreatSystem(id: string, reason = 'system'): Promise<Threat> {
  const [updatedThreat] = await db
    .update(threats)
    .set({
      status: 'closed',
      closureReason: reason,
      updatedAt: new Date()
    })
    .where(eq(threats.id, id))
    .returning();
  return updatedThreat;
}

export async function upsertThreat(threat: InsertThreat & { correlationKey: string; category: string; lastSeenAt?: Date }): Promise<{ threat: Threat; isNew: boolean }> {
  log.info({ correlationKey: threat.correlationKey }, 'processing threat upsert');
  log.info({ title: threat.title, jobId: threat.jobId, status: threat.status || 'open' }, 'threat upsert input details');

  // Try to find existing threat by correlation key
  const existingThreat = await findThreatByCorrelationKey(threat.correlationKey);

  if (existingThreat) {
    log.info({ threatId: existingThreat.id, status: existingThreat.status, jobId: existingThreat.jobId }, 'found existing threat for upsert');
    log.info({ createdAt: existingThreat.createdAt, updatedAt: existingThreat.updatedAt }, 'existing threat timestamps');
  } else {
    log.info({ correlationKey: threat.correlationKey }, 'no existing threat found for upsert');
    log.info('searching for threats with similar correlation keys');

    // Debug: Check if there are any threats with similar correlation keys
    const similarThreats = await db
      .select({ id: threats.id, correlationKey: threats.correlationKey, status: threats.status })
      .from(threats)
      .where(like(threats.correlationKey, `%${threat.correlationKey.split(':')[2] || ''}%`))
      .limit(5);

    log.info({ count: similarThreats.length, similarThreats }, 'found similar threats');
  }

  if (existingThreat) {
    // Check if threat needs reactivation (mitigated, hibernated, closed, or other states)
    const shouldReactivate = ['mitigated', 'hibernated', 'closed'].includes(existingThreat.status);
    log.info({ status: existingThreat.status, shouldReactivate }, 'evaluating threat reactivation');

    // Update existing threat
    const updateSet: any = {
      evidence: threat.evidence,
      lastSeenAt: threat.lastSeenAt || new Date(),
      updatedAt: new Date(),
    };

    // Only update jobId if provided (avoid nulling existing links)
    if (threat.jobId !== undefined) {
      updateSet.jobId = threat.jobId;
    }

    // Only update hostId if provided (avoid nulling existing links)
    if (threat.hostId !== undefined) {
      updateSet.hostId = threat.hostId;
    }

    // Use transaction for atomicity
    return await db.transaction(async (tx) => {
      // Reactivate if needed (cross-journey reactivation enabled)
      if (shouldReactivate) {
        updateSet.status = 'open';
        updateSet.hibernatedUntil = null;
        updateSet.statusChangedAt = new Date();
        updateSet.statusChangedBy = 'system';
        updateSet.statusJustification = `Reaberta automaticamente: detectada novamente durante varredura`;
        log.info({ threatId: existingThreat.id, fromStatus: existingThreat.status }, 'cross-journey threat reactivation');
      }

      const [updatedThreat] = await tx
        .update(threats)
        .set(updateSet)
        .where(eq(threats.id, existingThreat.id))
        .returning();

      // Create status history entry for reactivation
      if (shouldReactivate) {
        await tx
          .insert(threatStatusHistory)
          .values({
            threatId: existingThreat.id,
            fromStatus: existingThreat.status,
            toStatus: 'open',
            justification: `Reaberta automaticamente: detectada novamente durante varredura`,
            hibernatedUntil: null,
            changedBy: 'system',
          });
        log.info({ threatId: existingThreat.id }, 'created status history for cross-journey reactivation');
      }

      return { threat: updatedThreat, isNew: false };
    });
  } else {
    // Create new threat with defensive conflict resolution
    log.info({ correlationKey: threat.correlationKey }, 'creating new threat');

    try {
      // Try using onConflictDoUpdate if unique index exists (development/updated environments)
      const [newThreat] = await db
        .insert(threats)
        .values({
          ...threat,
          lastSeenAt: threat.lastSeenAt || new Date(),
        })
        .onConflictDoUpdate({
          target: threats.correlationKey,
          set: {
            status: sql`'open'`,
            lastSeenAt: threat.lastSeenAt || new Date(),
            updatedAt: new Date(),
            jobId: threat.jobId || sql`job_id`, // Keep existing if not provided
            hostId: threat.hostId !== undefined ? threat.hostId : sql`host_id`, // Keep existing if not provided
            evidence: threat.evidence,
            hibernatedUntil: null,
            statusChangedAt: new Date(),
            statusChangedBy: sql`'system'`,
            statusJustification: sql`'Reaberta automaticamente: detectada novamente durante varredura'`,
          },
        })
        .returning();

      log.info({ threatId: newThreat.id, status: newThreat.status }, 'threat processed via onConflict');
      return { threat: newThreat, isNew: true };
    } catch (error) {
      // If onConflict fails (e.g., no unique index in on-premise), use simple insert
      if ((error as any)?.code === '42P10') {
        log.warn('onConflict not supported, falling back to simple insert');
        const [newThreat] = await db
          .insert(threats)
          .values({
            ...threat,
            lastSeenAt: threat.lastSeenAt || new Date(),
          })
          .returning();

        log.info({ threatId: newThreat.id, status: newThreat.status }, 'threat created via fallback insert');
        return { threat: newThreat, isNew: true };
      }
      // Re-throw other errors
      throw error;
    }
  }
}

// ─── Phase 2: Threat grouping storage operations ──────────────────────────────

/** Severity rank map used by deriveParentAttributes */
const SEVERITY_RANK: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };

/** Statuses that keep a parent threat "open" */
const ACTIVE_STATUSES = new Set(['open', 'investigating']);

/**
 * Upserts a parent threat record.
 * Conflict resolution is on groupingKey (via UQ_threats_grouping_key partial unique index).
 * On conflict, updates severity, status, evidence, and timestamps — preserving the original parent id.
 */
export async function upsertParentThreat(
  data: InsertThreat & { groupingKey: string; category: string },
): Promise<{ threat: Threat; isNew: boolean }> {
  log.info({ groupingKey: data.groupingKey }, 'upserting parent threat');

  try {
    const [result] = await db
      .insert(threats)
      .values({
        ...data,
        lastSeenAt: new Date(),
      })
      .onConflictDoUpdate({
        target: threats.groupingKey,
        set: {
          severity: data.severity,
          status: data.status,
          evidence: data.evidence,
          title: data.title,
          updatedAt: new Date(),
          lastSeenAt: new Date(),
        },
      })
      .returning();

    log.info({ threatId: result.id, groupingKey: data.groupingKey }, 'parent threat upserted');
    // Determine if new by checking createdAt vs updatedAt (created within last 5s means new)
    const isNew = Math.abs(result.createdAt.getTime() - result.updatedAt.getTime()) < 5000;
    return { threat: result, isNew };
  } catch (error) {
    // Fallback for environments without the unique index (42P10 = no unique index for ON CONFLICT)
    if ((error as any)?.code === '42P10') {
      log.warn('groupingKey unique index missing, falling back to lookup+insert');
      const existing = await db
        .select()
        .from(threats)
        .where(eq(threats.groupingKey, data.groupingKey))
        .limit(1);

      if (existing.length > 0) {
        const [updated] = await db
          .update(threats)
          .set({
            severity: data.severity,
            status: data.status,
            evidence: data.evidence,
            title: data.title,
            updatedAt: new Date(),
            lastSeenAt: new Date(),
          })
          .where(eq(threats.id, existing[0].id))
          .returning();
        return { threat: updated, isNew: false };
      }

      const [newThreat] = await db
        .insert(threats)
        .values({ ...data, lastSeenAt: new Date() })
        .returning();
      return { threat: newThreat, isNew: true };
    }
    throw error;
  }
}

/**
 * Links a child threat to its parent by setting parentThreatId.
 * Does NOT modify correlationKey (THRT-05 invariant).
 */
export async function linkChildToParent(
  childThreatId: string,
  parentThreatId: string,
): Promise<void> {
  await db
    .update(threats)
    .set({ parentThreatId, updatedAt: new Date() })
    .where(eq(threats.id, childThreatId));
  log.info({ childThreatId, parentThreatId }, 'child linked to parent');
}

/**
 * Returns all threat records that have the given parentThreatId.
 */
export async function getChildThreats(parentThreatId: string): Promise<Threat[]> {
  return await db
    .select()
    .from(threats)
    .where(eq(threats.parentThreatId, parentThreatId));
}

/**
 * Derives severity and status for a parent threat based on its current children.
 * severity = highest severity among children.
 * status = 'open' if any child is active (open/investigating), else 'mitigated'.
 */
export async function deriveParentAttributes(
  parentId: string,
): Promise<{ severity: 'low' | 'medium' | 'high' | 'critical'; status: 'open' | 'mitigated' }> {
  const children = await getChildThreats(parentId);

  let maxRank = 0;
  let maxSeverity: 'low' | 'medium' | 'high' | 'critical' = 'low';
  let anyActive = false;

  for (const child of children) {
    const rank = SEVERITY_RANK[child.severity] ?? 0;
    if (rank > maxRank) {
      maxRank = rank;
      maxSeverity = child.severity as 'low' | 'medium' | 'high' | 'critical';
    }
    if (ACTIVE_STATUSES.has(child.status)) {
      anyActive = true;
    }
  }

  return {
    severity: maxSeverity,
    status: anyActive ? 'open' : 'mitigated',
  };
}

// Threat status history operations
export async function createThreatStatusHistory(history: InsertThreatStatusHistory): Promise<ThreatStatusHistory> {
  const [newHistory] = await db
    .insert(threatStatusHistory)
    .values(history)
    .returning();
  return newHistory;
}

export async function getThreatStatusHistory(threatId: string): Promise<(Omit<ThreatStatusHistory, 'changedBy'> & { changedBy: Pick<User, 'id' | 'email' | 'passwordHash' | 'firstName' | 'lastName' | 'role' | 'profileImageUrl' | 'mustChangePassword' | 'createdAt' | 'updatedAt' | 'lastLogin'> })[]> {
  const results = await db
    .select({
      id: threatStatusHistory.id,
      threatId: threatStatusHistory.threatId,
      fromStatus: threatStatusHistory.fromStatus,
      toStatus: threatStatusHistory.toStatus,
      justification: threatStatusHistory.justification,
      hibernatedUntil: threatStatusHistory.hibernatedUntil,
      changedBy: {
        id: users.id,
        email: users.email,
        passwordHash: users.passwordHash,
        firstName: users.firstName,
        lastName: users.lastName,
        role: users.role,
        profileImageUrl: users.profileImageUrl,
        mustChangePassword: users.mustChangePassword,
        createdAt: users.createdAt,
        updatedAt: users.updatedAt,
        lastLogin: users.lastLogin,
      },
      changedAt: threatStatusHistory.changedAt,
    })
    .from(threatStatusHistory)
    .innerJoin(users, eq(threatStatusHistory.changedBy, users.id))
    .where(eq(threatStatusHistory.threatId, threatId))
    .orderBy(desc(threatStatusHistory.changedAt));

  return results.map(row => ({
    id: row.id,
    threatId: row.threatId,
    fromStatus: row.fromStatus,
    toStatus: row.toStatus,
    justification: row.justification,
    hibernatedUntil: row.hibernatedUntil,
    changedBy: row.changedBy,
    changedAt: row.changedAt,
  }));
}
