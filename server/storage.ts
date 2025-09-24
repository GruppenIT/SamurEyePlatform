import {
  users,
  assets,
  credentials,
  journeys,
  schedules,
  jobs,
  jobResults,
  threats,
  hosts,
  settings,
  auditLog,
  type User,
  type UpsertUser,
  type Asset,
  type InsertAsset,
  type Credential,
  type InsertCredential,
  type Journey,
  type InsertJourney,
  type Schedule,
  type InsertSchedule,
  type Job,
  type InsertJob,
  type JobResult,
  type Host,
  type InsertHost,
  type Threat,
  type InsertThreat,
  type Setting,
  type InsertSetting,
  type AuditLogEntry,
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, and, or, sql, count, like, inArray } from "drizzle-orm";
import * as os from "os";

// Interface for storage operations
export interface IStorage {
  // User operations (mandatory for Replit Auth)
  getUser(id: string): Promise<User | undefined>;
  upsertUser(user: UpsertUser): Promise<User>;
  createUser(userData: { email: string; passwordHash: string; firstName: string; lastName: string; role?: string }): Promise<User>;
  getUserByEmail(email: string): Promise<User | undefined>;
  updateUserRole(id: string, role: string): Promise<User>;
  updateUserLastLogin(id: string): Promise<User>;
  updateUserPassword(id: string, passwordHash: string): Promise<User>;
  setMustChangePassword(id: string, mustChange: boolean): Promise<User>;
  getAllUsers(): Promise<User[]>;

  // Asset operations
  getAssets(): Promise<Asset[]>;
  getAsset(id: string): Promise<Asset | undefined>;
  createAsset(asset: InsertAsset, userId: string): Promise<Asset>;
  updateAsset(id: string, asset: Partial<InsertAsset>): Promise<Asset>;
  deleteAsset(id: string): Promise<void>;

  // Credential operations
  getCredentials(): Promise<Omit<Credential, 'secretEncrypted' | 'dekEncrypted'>[]>;
  getCredential(id: string): Promise<Credential | undefined>;
  createCredential(credential: Omit<Credential, 'id' | 'createdAt'>, userId: string): Promise<Credential>;
  updateCredential(id: string, credential: Partial<Credential>): Promise<Credential>;
  deleteCredential(id: string): Promise<void>;

  // Journey operations
  getJourneys(): Promise<Journey[]>;
  getJourney(id: string): Promise<Journey | undefined>;
  createJourney(journey: InsertJourney, userId: string): Promise<Journey>;
  updateJourney(id: string, journey: Partial<InsertJourney>): Promise<Journey>;
  deleteJourney(id: string): Promise<void>;

  // Schedule operations
  getSchedules(): Promise<Schedule[]>;
  getSchedule(id: string): Promise<Schedule | undefined>;
  createSchedule(schedule: InsertSchedule, userId: string): Promise<Schedule>;
  updateSchedule(id: string, schedule: Partial<InsertSchedule>): Promise<Schedule>;
  deleteSchedule(id: string): Promise<void>;
  getActiveSchedules(): Promise<Schedule[]>;

  // Job operations
  getJobs(limit?: number): Promise<Job[]>;
  getJob(id: string): Promise<Job | undefined>;
  createJob(job: InsertJob): Promise<Job>;
  updateJob(id: string, updates: Partial<Job>): Promise<Job>;
  getJobResult(jobId: string): Promise<JobResult | undefined>;
  createJobResult(result: Omit<JobResult, 'id' | 'createdAt'>): Promise<JobResult>;
  getRunningJobs(): Promise<Job[]>;
  getRecentJobs(limit?: number): Promise<Job[]>;

  // Host operations
  getHosts(filters?: { search?: string; type?: string; family?: string }): Promise<Host[]>;
  getHost(id: string): Promise<Host | undefined>;
  upsertHost(host: InsertHost): Promise<Host>;
  updateHost(id: string, host: Partial<InsertHost>): Promise<Host>;
  deleteHost(id: string): Promise<void>;
  getHostByName(name: string): Promise<Host | undefined>;
  findHostByTarget(target: string, ip?: string): Promise<Host | undefined>;

  // Threat operations
  getThreats(filters?: { severity?: string; status?: string; assetId?: string; hostId?: string }): Promise<Threat[]>;
  getThreatsWithHosts(filters?: { severity?: string; status?: string; assetId?: string; hostId?: string }): Promise<(Threat & { host?: Host })[]>;
  getThreat(id: string): Promise<Threat | undefined>;
  createThreat(threat: InsertThreat): Promise<Threat>;
  updateThreat(id: string, threat: Partial<Threat>): Promise<Threat>;
  deleteThreat(id: string): Promise<void>;
  getThreatStats(): Promise<{ total: number; critical: number; high: number; medium: number; low: number }>;
  
  // Threat lifecycle operations
  findThreatByCorrelationKey(correlationKey: string): Promise<Threat | undefined>;
  listOpenThreatsByJourney(journeyId: string, category?: string): Promise<Threat[]>;
  closeThreatSystem(id: string, reason?: string): Promise<Threat>;
  upsertThreat(threat: InsertThreat & { correlationKey: string; category: string; lastSeenAt?: Date }): Promise<Threat>;

  // Settings operations
  getSetting(key: string): Promise<Setting | undefined>;
  setSetting(key: string, value: any, userId: string): Promise<Setting>;
  getAllSettings(): Promise<Setting[]>;

  // Audit operations
  logAudit(entry: Omit<AuditLogEntry, 'id' | 'createdAt'>): Promise<AuditLogEntry>;
  getAuditLog(limit?: number): Promise<AuditLogEntry[]>;

  // Dashboard operations
  getDashboardMetrics(): Promise<{
    activeAssets: number;
    criticalThreats: number;
    jobsExecuted: number;
    successRate: number;
  }>;

  // System metrics operations
  getSystemMetrics(): Promise<{
    cpu: number;
    memory: number;
    services: Array<{
      name: string;
      status: string;
      color: string;
    }>;
  }>;
}

export class DatabaseStorage implements IStorage {
  // User operations
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }

  async upsertUser(userData: UpsertUser): Promise<User> {
    const [user] = await db
      .insert(users)
      .values(userData)
      .onConflictDoUpdate({
        target: users.email,
        set: {
          ...userData,
          updatedAt: new Date(),
        },
      })
      .returning();
    return user;
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.email, email));
    return user;
  }

  async updateUserRole(id: string, role: string): Promise<User> {
    const [user] = await db
      .update(users)
      .set({ role: role as any, updatedAt: new Date() })
      .where(eq(users.id, id))
      .returning();
    return user;
  }

  async createUser(userData: { email: string; passwordHash: string; firstName: string; lastName: string; role?: string }): Promise<User> {
    const [user] = await db
      .insert(users)
      .values({
        email: userData.email,
        passwordHash: userData.passwordHash,
        firstName: userData.firstName,
        lastName: userData.lastName,
        role: (userData.role as any) || 'read_only',
      })
      .returning();
    return user;
  }

  async updateUserLastLogin(id: string): Promise<User> {
    const [user] = await db
      .update(users)
      .set({ lastLogin: new Date(), updatedAt: new Date() })
      .where(eq(users.id, id))
      .returning();
    return user;
  }

  async updateUserPassword(id: string, passwordHash: string): Promise<User> {
    const [user] = await db
      .update(users)
      .set({ passwordHash, updatedAt: new Date() })
      .where(eq(users.id, id))
      .returning();
    return user;
  }

  async setMustChangePassword(id: string, mustChange: boolean): Promise<User> {
    const [user] = await db
      .update(users)
      .set({ mustChangePassword: mustChange, updatedAt: new Date() })
      .where(eq(users.id, id))
      .returning();
    return user;
  }

  async getAllUsers(): Promise<User[]> {
    return await db.select().from(users).orderBy(desc(users.createdAt));
  }

  // Asset operations
  async getAssets(): Promise<Asset[]> {
    return await db.select().from(assets).orderBy(desc(assets.createdAt));
  }

  async getAsset(id: string): Promise<Asset | undefined> {
    const [asset] = await db.select().from(assets).where(eq(assets.id, id));
    return asset;
  }

  async createAsset(asset: InsertAsset, userId: string): Promise<Asset> {
    const assetValues = {
      type: asset.type,
      value: asset.value,
      tags: asset.tags || [],
      createdBy: userId,
    } as any;
    
    const [newAsset] = await db
      .insert(assets)
      .values(assetValues)
      .returning();
    return newAsset;
  }

  async updateAsset(id: string, asset: Partial<InsertAsset>): Promise<Asset> {
    const updates: any = {};
    if (asset.type !== undefined) updates.type = asset.type;
    if (asset.value !== undefined) updates.value = asset.value;
    if (asset.tags !== undefined) updates.tags = asset.tags;
    
    const [updatedAsset] = await db
      .update(assets)
      .set(updates)
      .where(eq(assets.id, id))
      .returning();
    return updatedAsset;
  }

  async deleteAsset(id: string): Promise<void> {
    await db.delete(assets).where(eq(assets.id, id));
  }

  // Credential operations
  async getCredentials(): Promise<Omit<Credential, 'secretEncrypted' | 'dekEncrypted'>[]> {
    const results = await db
      .select({
        id: credentials.id,
        name: credentials.name,
        type: credentials.type,
        hostOverride: credentials.hostOverride,
        port: credentials.port,
        domain: credentials.domain,
        username: credentials.username,
        createdAt: credentials.createdAt,
        createdBy: credentials.createdBy,
      })
      .from(credentials)
      .orderBy(desc(credentials.createdAt));
    return results;
  }

  async getCredential(id: string): Promise<Credential | undefined> {
    const [credential] = await db.select().from(credentials).where(eq(credentials.id, id));
    return credential;
  }

  async createCredential(credential: Omit<Credential, 'id' | 'createdAt'>, userId: string): Promise<Credential> {
    const [newCredential] = await db
      .insert(credentials)
      .values({ ...credential, createdBy: userId })
      .returning();
    return newCredential;
  }

  async updateCredential(id: string, credential: Partial<Credential>): Promise<Credential> {
    const [updatedCredential] = await db
      .update(credentials)
      .set(credential)
      .where(eq(credentials.id, id))
      .returning();
    return updatedCredential;
  }

  async deleteCredential(id: string): Promise<void> {
    await db.delete(credentials).where(eq(credentials.id, id));
  }

  // Journey operations
  async getJourneys(): Promise<Journey[]> {
    return await db.select().from(journeys).orderBy(desc(journeys.createdAt));
  }

  async getJourney(id: string): Promise<Journey | undefined> {
    const [journey] = await db.select().from(journeys).where(eq(journeys.id, id));
    return journey;
  }

  async createJourney(journey: InsertJourney, userId: string): Promise<Journey> {
    const [newJourney] = await db
      .insert(journeys)
      .values({ ...journey, createdBy: userId })
      .returning();
    return newJourney;
  }

  async updateJourney(id: string, journey: Partial<InsertJourney>): Promise<Journey> {
    const [updatedJourney] = await db
      .update(journeys)
      .set({ ...journey, updatedAt: new Date() })
      .where(eq(journeys.id, id))
      .returning();
    return updatedJourney;
  }

  async deleteJourney(id: string): Promise<void> {
    await db.delete(journeys).where(eq(journeys.id, id));
  }

  // Schedule operations
  async getSchedules(): Promise<Schedule[]> {
    return await db.select().from(schedules).orderBy(desc(schedules.createdAt));
  }

  async getSchedule(id: string): Promise<Schedule | undefined> {
    const [schedule] = await db.select().from(schedules).where(eq(schedules.id, id));
    return schedule;
  }

  async createSchedule(schedule: InsertSchedule, userId: string): Promise<Schedule> {
    const [newSchedule] = await db
      .insert(schedules)
      .values({ ...schedule, createdBy: userId })
      .returning();
    return newSchedule;
  }

  async updateSchedule(id: string, schedule: Partial<InsertSchedule>): Promise<Schedule> {
    const [updatedSchedule] = await db
      .update(schedules)
      .set(schedule)
      .where(eq(schedules.id, id))
      .returning();
    return updatedSchedule;
  }

  async deleteSchedule(id: string): Promise<void> {
    await db.delete(schedules).where(eq(schedules.id, id));
  }

  async getActiveSchedules(): Promise<Schedule[]> {
    return await db
      .select()
      .from(schedules)
      .where(eq(schedules.enabled, true))
      .orderBy(schedules.createdAt);
  }

  // Job operations
  async getJobs(limit = 50): Promise<Job[]> {
    return await db
      .select()
      .from(jobs)
      .orderBy(desc(jobs.createdAt))
      .limit(limit);
  }

  async getJob(id: string): Promise<Job | undefined> {
    const [job] = await db.select().from(jobs).where(eq(jobs.id, id));
    return job;
  }

  async createJob(job: InsertJob): Promise<Job> {
    const [newJob] = await db.insert(jobs).values(job).returning();
    return newJob;
  }

  async updateJob(id: string, updates: Partial<Job>): Promise<Job> {
    const [updatedJob] = await db
      .update(jobs)
      .set(updates)
      .where(eq(jobs.id, id))
      .returning();
    
    if (!updatedJob) {
      throw new Error(`Job with ID ${id} not found - cannot update non-existent job`);
    }
    
    return updatedJob;
  }

  async getJobResult(jobId: string): Promise<JobResult | undefined> {
    const [result] = await db.select().from(jobResults).where(eq(jobResults.jobId, jobId));
    return result;
  }

  async createJobResult(result: Omit<JobResult, 'id' | 'createdAt'>): Promise<JobResult> {
    const [newResult] = await db.insert(jobResults).values(result).returning();
    return newResult;
  }

  async getRunningJobs(): Promise<Job[]> {
    return await db
      .select()
      .from(jobs)
      .where(eq(jobs.status, 'running'))
      .orderBy(jobs.startedAt);
  }

  async getRecentJobs(limit = 10): Promise<Job[]> {
    return await db
      .select()
      .from(jobs)
      .where(inArray(jobs.status, ['completed', 'failed', 'timeout']))
      .orderBy(desc(jobs.finishedAt))
      .limit(limit);
  }

  // Threat operations
  async getThreats(filters?: { severity?: string; status?: string; assetId?: string; hostId?: string }): Promise<Threat[]> {
    if (filters) {
      const conditions = [];
      if (filters.severity) conditions.push(eq(threats.severity, filters.severity as any));
      if (filters.status) conditions.push(eq(threats.status, filters.status as any));
      if (filters.assetId) conditions.push(eq(threats.assetId, filters.assetId));
      if (filters.hostId) conditions.push(eq(threats.hostId, filters.hostId));
      
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

  async getThreat(id: string): Promise<Threat | undefined> {
    const [threat] = await db.select().from(threats).where(eq(threats.id, id));
    return threat;
  }

  async createThreat(threat: InsertThreat): Promise<Threat> {
    const [newThreat] = await db.insert(threats).values(threat).returning();
    return newThreat;
  }

  async updateThreat(id: string, threat: Partial<Threat>): Promise<Threat> {
    const [updatedThreat] = await db
      .update(threats)
      .set({ ...threat, updatedAt: new Date() })
      .where(eq(threats.id, id))
      .returning();
    return updatedThreat;
  }

  async deleteThreat(id: string): Promise<void> {
    await db.delete(threats).where(eq(threats.id, id));
  }

  async getThreatStats(): Promise<{ total: number; critical: number; high: number; medium: number; low: number }> {
    const result = await db
      .select({
        severity: threats.severity,
        count: count(),
      })
      .from(threats)
      .where(eq(threats.status, 'open'))
      .groupBy(threats.severity);

    const stats = { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
    
    for (const row of result) {
      stats[row.severity as keyof typeof stats] = Number(row.count);
      stats.total += Number(row.count);
    }
    
    return stats;
  }

  async getThreatsWithHosts(filters?: { severity?: string; status?: string; assetId?: string; hostId?: string }): Promise<(Threat & { host?: Host })[]> {
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
        createdAt: threats.createdAt,
        updatedAt: threats.updatedAt,
        assignedTo: threats.assignedTo,
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
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      assignedTo: row.assignedTo,
      host: row.hostName ? {
        id: row.hostIdFromTable!,
        name: row.hostName,
        type: row.hostType || 'other',
        family: row.hostFamily || 'other',
        ips: row.hostIps || [],
        aliases: row.hostAliases || [],
        description: row.hostDescription,
        operatingSystem: row.hostOperatingSystem,
        discoveredAt: row.hostDiscoveredAt!,
        updatedAt: row.hostUpdatedAt!
      } : undefined
    }));
  }

  // Threat lifecycle operations
  async findThreatByCorrelationKey(correlationKey: string): Promise<Threat | undefined> {
    const [threat] = await db
      .select()
      .from(threats)
      .where(eq(threats.correlationKey, correlationKey));
    return threat;
  }

  async listOpenThreatsByJourney(journeyId: string, category?: string): Promise<Threat[]> {
    const conditions = [
      inArray(threats.status, ['open', 'investigating', 'mitigated'])
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
        createdAt: threats.createdAt,
        updatedAt: threats.updatedAt,
        assignedTo: threats.assignedTo,
      })
      .from(threats)
      .innerJoin(jobs, eq(threats.jobId, jobs.id))
      .where(and(
        eq(jobs.journeyId, journeyId),
        ...conditions
      ));

    return results;
  }

  async closeThreatSystem(id: string, reason = 'system'): Promise<Threat> {
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

  async upsertThreat(threat: InsertThreat & { correlationKey: string; category: string; lastSeenAt?: Date }): Promise<Threat> {
    // Try to find existing threat by correlation key
    const existingThreat = await this.findThreatByCorrelationKey(threat.correlationKey);
    
    if (existingThreat && existingThreat.status !== 'closed') {
      // Update existing threat
      const updateSet: any = {
        evidence: threat.evidence,
        lastSeenAt: threat.lastSeenAt || new Date(),
        updatedAt: new Date(),
      };
      
      // Only update hostId if provided (avoid nulling existing links)
      if (threat.hostId !== undefined) {
        updateSet.hostId = threat.hostId;
      }
      
      const [updatedThreat] = await db
        .update(threats)
        .set(updateSet)
        .where(eq(threats.id, existingThreat.id))
        .returning();
      return updatedThreat;
    } else {
      // Create new threat
      const [newThreat] = await db
        .insert(threats)
        .values({
          ...threat,
          lastSeenAt: threat.lastSeenAt || new Date(),
        })
        .returning();
      return newThreat;
    }
  }

  // Host operations
  async getHosts(filters?: { search?: string; type?: string; family?: string }): Promise<Host[]> {
    if (filters) {
      const conditions = [];
      if (filters.search) {
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
      if (filters.type && filters.type !== "all") conditions.push(eq(hosts.type, filters.type as any));
      if (filters.family && filters.family !== "all") conditions.push(eq(hosts.family, filters.family as any));
      
      if (conditions.length > 0) {
        return await db
          .select()
          .from(hosts)
          .where(and(...conditions))
          .orderBy(desc(hosts.updatedAt));
      }
    }
    
    return await db.select().from(hosts).orderBy(desc(hosts.updatedAt));
  }

  async getHost(id: string): Promise<Host | undefined> {
    const [host] = await db.select().from(hosts).where(eq(hosts.id, id));
    return host;
  }

  async upsertHost(host: InsertHost): Promise<Host> {
    const normalizedName = host.name.toLowerCase();
    
    // Try to find existing host by name first
    const existingHost = await this.getHostByName(normalizedName);
    
    if (existingHost) {
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
      return updatedHost;
    } else {
      // Create new host
      const hostValues = {
        ...host,
        name: normalizedName,
      } as any;
      
      const [newHost] = await db
        .insert(hosts)
        .values(hostValues)
        .returning();
      return newHost;
    }
  }

  async updateHost(id: string, host: Partial<InsertHost>): Promise<Host> {
    const updates: any = { updatedAt: new Date() };
    
    if (host.name !== undefined) updates.name = host.name.toLowerCase();
    if (host.description !== undefined) updates.description = host.description;
    if (host.operatingSystem !== undefined) updates.operatingSystem = host.operatingSystem;
    if (host.type !== undefined) updates.type = host.type;
    if (host.family !== undefined) updates.family = host.family;
    if (host.ips !== undefined) updates.ips = host.ips;
    if (host.aliases !== undefined) updates.aliases = host.aliases;
    
    const [updatedHost] = await db
      .update(hosts)
      .set(updates)
      .where(eq(hosts.id, id))
      .returning();
    return updatedHost;
  }

  async deleteHost(id: string): Promise<void> {
    await db.delete(hosts).where(eq(hosts.id, id));
  }

  async getHostByName(name: string): Promise<Host | undefined> {
    const [host] = await db.select().from(hosts).where(eq(hosts.name, name.toLowerCase()));
    return host;
  }

  async findHostByTarget(target: string, ip?: string): Promise<Host | undefined> {
    const normalizedTarget = target.toLowerCase();
    
    // Try to find by name first
    let host = await this.getHostByName(normalizedTarget);
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

  // Settings operations
  async getSetting(key: string): Promise<Setting | undefined> {
    const [setting] = await db.select().from(settings).where(eq(settings.key, key));
    return setting;
  }

  async setSetting(key: string, value: any, userId: string): Promise<Setting> {
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

  async getAllSettings(): Promise<Setting[]> {
    return await db.select().from(settings).orderBy(settings.key);
  }

  // Audit operations
  async logAudit(entry: Omit<AuditLogEntry, 'id' | 'createdAt'>): Promise<AuditLogEntry> {
    const [auditEntry] = await db.insert(auditLog).values(entry).returning();
    return auditEntry;
  }

  async getAuditLog(limit = 100): Promise<AuditLogEntry[]> {
    return await db
      .select()
      .from(auditLog)
      .orderBy(desc(auditLog.createdAt))
      .limit(limit);
  }

  // Dashboard operations
  async getDashboardMetrics(): Promise<{
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

  async getSystemMetrics(): Promise<{
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
    const runningJobs = await this.getRunningJobs();
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
}

export const storage = new DatabaseStorage();
