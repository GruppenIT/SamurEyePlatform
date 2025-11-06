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
  hostRiskHistory,
  adSecurityTestResults,
  settings,
  auditLog,
  activeSessions,
  loginAttempts,
  threatStatusHistory,
  emailSettings,
  notificationPolicies,
  notificationLog,
  journeyCredentials,
  hostEnrichments,
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
  type HostRiskHistory,
  type InsertHostRiskHistory,
  type AdSecurityTestResult,
  type InsertAdSecurityTestResult,
  type Threat,
  type InsertThreat,
  type Setting,
  type InsertSetting,
  type ThreatStatusHistory,
  type InsertThreatStatusHistory,
  type AuditLogEntry,
  type ActiveSession,
  type InsertActiveSession,
  type LoginAttempt,
  type InsertLoginAttempt,
  type EmailSettings,
  type InsertEmailSettings,
  type NotificationPolicy,
  type InsertNotificationPolicy,
  type NotificationLog,
  type InsertNotificationLog,
  type JourneyCredential,
  type InsertJourneyCredential,
  type HostEnrichment,
  type InsertHostEnrichment,
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, and, or, sql, count, like, inArray } from "drizzle-orm";
import * as os from "os";
import * as crypto from "crypto";

// Utility function to sanitize strings for PostgreSQL
function sanitizeString(str: string): string {
  if (typeof str !== 'string') return str;
  
  // Only remove null bytes which cause PostgreSQL 22P05 errors
  // Keep other characters like \n, \r, \t which are valid and useful
  return str.replace(/\u0000/g, '');
}

// Utility function to sanitize objects recursively
function sanitizeObject(obj: any): any {
  if (obj === null || obj === undefined) return obj;
  
  if (typeof obj === 'string') {
    return sanitizeString(obj);
  }
  
  if (obj instanceof Date) {
    return obj.toISOString();
  }
  
  if (Buffer.isBuffer(obj)) {
    return sanitizeString(obj.toString('utf8'));
  }
  
  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item));
  }
  
  if (typeof obj === 'object' && obj.constructor === Object) {
    // Only sanitize plain objects, leave other objects untouched
    const sanitized: any = {};
    for (const [key, value] of Object.entries(obj)) {
      sanitized[key] = sanitizeObject(value);
    }
    return sanitized;
  }
  
  return obj;
}

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
  getAssetsByTags(tags: string[]): Promise<Asset[]>;
  getAssetsByType(type: string): Promise<Asset[]>;
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
  getJobsByJourneyId(journeyId: string): Promise<Job[]>;

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
  getThreatStats(): Promise<{ 
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
  }>;
  
  // Threat lifecycle operations
  findThreatByCorrelationKey(correlationKey: string): Promise<Threat | undefined>;
  listOpenThreatsByJourney(journeyId: string, category?: string): Promise<Threat[]>;
  closeThreatSystem(id: string, reason?: string): Promise<Threat>;
  upsertThreat(threat: InsertThreat & { correlationKey: string; category: string; lastSeenAt?: Date }): Promise<{ threat: Threat; isNew: boolean }>;
  
  // Threat status history operations
  createThreatStatusHistory(history: InsertThreatStatusHistory): Promise<ThreatStatusHistory>;
  getThreatStatusHistory(threatId: string): Promise<(Omit<ThreatStatusHistory, 'changedBy'> & { changedBy: User })[]>;

  // Settings operations
  getSetting(key: string): Promise<Setting | undefined>;
  setSetting(key: string, value: any, userId: string): Promise<Setting>;
  getAllSettings(): Promise<Setting[]>;

  // Audit operations
  logAudit(entry: Omit<AuditLogEntry, 'id' | 'createdAt'>): Promise<AuditLogEntry>;
  getAuditLog(limit?: number): Promise<AuditLogEntry[]>;

  // Active session operations
  createActiveSession(session: InsertActiveSession): Promise<ActiveSession>;
  getActiveSessionBySessionId(sessionId: string): Promise<ActiveSession | undefined>;
  getActiveSessionsByUserId(userId: string): Promise<ActiveSession[]>;
  updateActiveSessionLastActivity(sessionId: string): Promise<ActiveSession>;
  deleteActiveSession(sessionId: string): Promise<void>;
  deleteActiveSessionsByUserId(userId: string): Promise<void>;
  cleanupExpiredSessions(): Promise<void>;
  getAllActiveSessions(limit?: number): Promise<(ActiveSession & { user: User })[]>;

  // Login attempt operations (rate limiting)
  getLoginAttempt(identifier: string): Promise<LoginAttempt | undefined>;
  upsertLoginAttempt(identifier: string, increment: boolean): Promise<LoginAttempt>;
  resetLoginAttempts(identifier: string): Promise<void>;
  cleanupOldLoginAttempts(): Promise<void>;

  // Session version operations
  getCurrentSessionVersion(): Promise<number>;
  incrementSessionVersion(userId: string): Promise<number>;

  // Email settings operations
  getEmailSettings(): Promise<EmailSettings | undefined>;
  setEmailSettings(settings: Omit<EmailSettings, 'id' | 'updatedAt'>, userId: string): Promise<EmailSettings>;

  // Notification policy operations
  getNotificationPolicies(): Promise<NotificationPolicy[]>;
  getNotificationPolicy(id: string): Promise<NotificationPolicy | undefined>;
  createNotificationPolicy(policy: InsertNotificationPolicy, userId: string): Promise<NotificationPolicy>;
  updateNotificationPolicy(id: string, policy: Partial<InsertNotificationPolicy>): Promise<NotificationPolicy>;
  deleteNotificationPolicy(id: string): Promise<void>;

  // Notification log operations
  createNotificationLog(log: InsertNotificationLog): Promise<NotificationLog>;
  getNotificationLogs(limit?: number): Promise<NotificationLog[]>;

  // Host risk history operations
  createHostRiskHistory(history: InsertHostRiskHistory): Promise<HostRiskHistory>;
  getHostRiskHistory(hostId: string, limit?: number): Promise<HostRiskHistory[]>;

  // AD Security test results operations
  createAdSecurityTestResults(results: InsertAdSecurityTestResult[]): Promise<AdSecurityTestResult[]>;
  getAdSecurityTestResults(hostId: string, jobId?: string): Promise<AdSecurityTestResult[]>;
  getAdSecurityLatestTestResults(hostId: string): Promise<AdSecurityTestResult[]>;

  // Journey credentials operations (authenticated scanning)
  createJourneyCredential(journeyCredential: InsertJourneyCredential): Promise<JourneyCredential>;
  getJourneyCredentials(journeyId: string): Promise<JourneyCredential[]>;
  deleteJourneyCredentials(journeyId: string): Promise<void>;
  deleteJourneyCredential(id: string): Promise<void>;

  // Host enrichment operations (authenticated scan data)
  createHostEnrichment(enrichment: InsertHostEnrichment): Promise<HostEnrichment>;
  getHostEnrichments(hostId: string, jobId?: string): Promise<HostEnrichment[]>;
  getLatestHostEnrichment(hostId: string): Promise<HostEnrichment | undefined>;

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

  async getAssetsByTags(tags: string[]): Promise<Asset[]> {
    if (tags.length === 0) {
      return [];
    }
    
    // Busca assets que possuem QUALQUER uma das tags fornecidas
    // Usando o operador ?| do PostgreSQL para arrays JSONB
    const results = await db.select().from(assets).where(
      sql`${assets.tags}::jsonb ?| array[${sql.join(tags.map(tag => sql`${tag}`), sql`, `)}]::text[]`
    );
    return results;
  }

  async getAssetsByType(type: string): Promise<Asset[]> {
    return await db.select().from(assets).where(sql`${assets.type} = ${type}`).orderBy(desc(assets.createdAt));
  }

  async getUniqueTags(): Promise<string[]> {
    // Busca todas as TAGs únicas de todos os assets
    // Usando jsonb_array_elements_text para expandir o array JSONB em linhas
    const result = await db.execute<{ tag: string }>(
      sql`SELECT DISTINCT jsonb_array_elements_text(${assets.tags}) as tag FROM ${assets} WHERE ${assets.tags} IS NOT NULL AND jsonb_array_length(${assets.tags}) > 0 ORDER BY tag`
    );
    return result.rows.map(row => row.tag);
  }

  async createAsset(asset: InsertAsset, userId: string): Promise<Asset> {
    // Check for existing asset with same value and type
    const existing = await db
      .select()
      .from(assets)
      .where(and(
        eq(assets.value, asset.value),
        eq(assets.type, asset.type)
      ))
      .limit(1);
    
    if (existing.length > 0) {
      console.log(`ℹ️  Ativo duplicado ignorado: ${asset.value} (tipo: ${asset.type})`);
      return existing[0];
    }
    
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
    // Sanitize all string fields to prevent PostgreSQL errors with control characters
    const sanitizedResult = {
      ...result,
      stdout: result.stdout ? sanitizeString(result.stdout) : result.stdout,
      stderr: result.stderr ? sanitizeString(result.stderr) : result.stderr,
      artifacts: result.artifacts ? sanitizeObject(result.artifacts) : result.artifacts,
    };
    
    const [newResult] = await db.insert(jobResults).values(sanitizedResult).returning();
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

  async getJobsByJourneyId(journeyId: string): Promise<Job[]> {
    return await db
      .select()
      .from(jobs)
      .where(eq(jobs.journeyId, journeyId))
      .orderBy(desc(jobs.createdAt));
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

  async getThreatStats(): Promise<{ 
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
        hibernatedUntil: threats.hibernatedUntil,
        statusChangedBy: threats.statusChangedBy,
        statusChangedAt: threats.statusChangedAt,
        statusJustification: threats.statusJustification,
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
      hibernatedUntil: row.hibernatedUntil,
      statusChangedBy: row.statusChangedBy,
      statusChangedAt: row.statusChangedAt,
      statusJustification: row.statusJustification,
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
        riskScore: 0,
        rawScore: 0,
        discoveredAt: row.hostDiscoveredAt!,
        updatedAt: row.hostUpdatedAt!
      } : undefined
    }));
  }

  // Threat lifecycle operations
  async findThreatByCorrelationKey(correlationKey: string): Promise<Threat | undefined> {
    console.log(`🔍 FIND: Searching for correlationKey: "${correlationKey}" (length: ${correlationKey.length})`);
    
    // Get ALL threats with this correlation key, ordered by creation date
    const allThreats = await db
      .select()
      .from(threats)
      .where(eq(threats.correlationKey, correlationKey))
      .orderBy(threats.createdAt);
    
    console.log(`🔍 FIND: Found ${allThreats.length} threats with correlationKey: "${correlationKey}"`);
    
    if (allThreats.length > 1) {
      console.log(`⚠️ FIND: Multiple threats found with same correlationKey! Using the first one.`);
      console.log(`🔍 FIND: All threats: ${allThreats.map(t => `${t.id} (${t.status}, ${t.createdAt})`).join(', ')}`);
    }
    
    const threat = allThreats[0];
    
    if (threat) {
      console.log(`✅ FIND: Using threat ${threat.id} with status: ${threat.status} (created: ${threat.createdAt})`);
    } else {
      console.log(`❌ FIND: No threat found for key: "${correlationKey}"`);
    }
    
    return threat;
  }

  async listOpenThreatsByJourney(journeyId: string, category?: string): Promise<Threat[]> {
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

  async upsertThreat(threat: InsertThreat & { correlationKey: string; category: string; lastSeenAt?: Date }): Promise<{ threat: Threat; isNew: boolean }> {
    console.log(`📋 UPSERT: Processing threat with correlationKey: ${threat.correlationKey}`);
    console.log(`📋 UPSERT: Input threat details - title: ${threat.title}, jobId: ${threat.jobId}, status: ${threat.status || 'open'}`);
    
    // Try to find existing threat by correlation key
    const existingThreat = await this.findThreatByCorrelationKey(threat.correlationKey);
    
    if (existingThreat) {
      console.log(`🔍 UPSERT: Found existing threat ${existingThreat.id} with status: ${existingThreat.status}, jobId: ${existingThreat.jobId}`);
      console.log(`🔍 UPSERT: Existing threat created: ${existingThreat.createdAt}, updated: ${existingThreat.updatedAt}`);
    } else {
      console.log(`🆕 UPSERT: No existing threat found for correlationKey: ${threat.correlationKey}`);
      console.log(`🔍 UPSERT: Searching for threats with similar keys...`);
      
      // Debug: Check if there are any threats with similar correlation keys
      const similarThreats = await db
        .select({ id: threats.id, correlationKey: threats.correlationKey, status: threats.status })
        .from(threats)
        .where(like(threats.correlationKey, `%${threat.correlationKey.split(':')[2] || ''}%`))
        .limit(5);
      
      console.log(`🔍 UPSERT: Found ${similarThreats.length} similar threats:`, JSON.stringify(similarThreats, null, 2));
    }
    
    if (existingThreat) {
      // Check if threat needs reactivation (mitigated, hibernated, closed, or other states)
      const shouldReactivate = ['mitigated', 'hibernated', 'closed'].includes(existingThreat.status);
      console.log(`🔄 UPSERT: Existing threat status is '${existingThreat.status}', shouldReactivate: ${shouldReactivate}`);
      
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
          console.log(`🔄 Cross-journey reactivation: threat ${existingThreat.id} from ${existingThreat.status} to open`);
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
          console.log(`📋 Created status history for cross-journey threat reactivation: ${existingThreat.id}`);
        }

        return { threat: updatedThreat, isNew: false };
      });
    } else {
      // Create new threat with defensive conflict resolution
      console.log(`🆕 UPSERT: Creating new threat with correlationKey: ${threat.correlationKey}`);
      
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
          
        console.log(`✅ UPSERT: Processed threat ${newThreat.id} via onConflict - status: ${newThreat.status}`);
        return { threat: newThreat, isNew: true };
      } catch (error) {
        // If onConflict fails (e.g., no unique index in on-premise), use simple insert
        if ((error as any)?.code === '42P10') {
          console.log(`⚠️  UPSERT: onConflict not supported, falling back to simple insert`);
          const [newThreat] = await db
            .insert(threats)
            .values({
              ...threat,
              lastSeenAt: threat.lastSeenAt || new Date(),
            })
            .returning();
          
          console.log(`✅ UPSERT: Created new threat ${newThreat.id} via fallback insert - status: ${newThreat.status}`);
          return { threat: newThreat, isNew: true };
        }
        // Re-throw other errors
        throw error;
      }
    }
  }

  // Threat status history operations
  async createThreatStatusHistory(history: InsertThreatStatusHistory): Promise<ThreatStatusHistory> {
    const [newHistory] = await db
      .insert(threatStatusHistory)
      .values(history)
      .returning();
    return newHistory;
  }

  async getThreatStatusHistory(threatId: string): Promise<(Omit<ThreatStatusHistory, 'changedBy'> & { changedBy: User })[]> {
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

  // Host risk history operations
  async createHostRiskHistory(history: InsertHostRiskHistory): Promise<HostRiskHistory> {
    const [newHistory] = await db
      .insert(hostRiskHistory)
      .values(history)
      .returning();
    return newHistory;
  }

  async getHostRiskHistory(hostId: string, limit?: number): Promise<HostRiskHistory[]> {
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
  async createAdSecurityTestResults(results: InsertAdSecurityTestResult[]): Promise<AdSecurityTestResult[]> {
    if (results.length === 0) return [];
    
    const inserted = await db
      .insert(adSecurityTestResults)
      .values(results)
      .returning();
    return inserted;
  }

  async getAdSecurityTestResults(hostId: string, jobId?: string): Promise<AdSecurityTestResult[]> {
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

  async getAdSecurityLatestTestResults(hostId: string): Promise<AdSecurityTestResult[]> {
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

  // Journey credentials operations (authenticated scanning)
  async createJourneyCredential(journeyCredential: InsertJourneyCredential): Promise<JourneyCredential> {
    const [created] = await db
      .insert(journeyCredentials)
      .values(journeyCredential)
      .returning();
    return created;
  }

  async getJourneyCredentials(journeyId: string): Promise<JourneyCredential[]> {
    const results = await db
      .select()
      .from(journeyCredentials)
      .where(eq(journeyCredentials.journeyId, journeyId))
      .orderBy(journeyCredentials.priority);
    return results;
  }

  async deleteJourneyCredentials(journeyId: string): Promise<void> {
    await db
      .delete(journeyCredentials)
      .where(eq(journeyCredentials.journeyId, journeyId));
  }

  async deleteJourneyCredential(id: string): Promise<void> {
    await db
      .delete(journeyCredentials)
      .where(eq(journeyCredentials.id, id));
  }

  // Host enrichment operations (authenticated scan data)
  async createHostEnrichment(enrichment: InsertHostEnrichment): Promise<HostEnrichment> {
    const [created] = await db
      .insert(hostEnrichments)
      .values(enrichment)
      .returning();
    return created;
  }

  async getHostEnrichments(hostId: string, jobId?: string): Promise<HostEnrichment[]> {
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

  async getLatestHostEnrichment(hostId: string): Promise<HostEnrichment | undefined> {
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

  // Host operations
  async getHosts(filters?: { search?: string; type?: string; family?: string; sortBy?: string }): Promise<(Host & { threatCounts: { critical: number; high: number; medium: number; low: number } })[]> {
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
    if (host.riskScore !== undefined) updates.riskScore = host.riskScore;
    if (host.rawScore !== undefined) updates.rawScore = host.rawScore;
    
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

  async getAuditLog(limit = 100): Promise<any[]> {
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
              const journey = await this.getJourney(log.objectId);
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
              const asset = await this.getAsset(log.objectId);
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
              const credential = await this.getCredential(log.objectId);
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
              const user = await this.getUser(log.objectId);
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
              const threat = await this.getThreat(log.objectId);
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
        console.log(`Could not fetch details for ${log.objectType} ${log.objectId}`);
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

  // Email settings operations
  async getEmailSettings(): Promise<EmailSettings | undefined> {
    const [settings] = await db.select().from(emailSettings).limit(1);
    return settings;
  }

  async setEmailSettings(settingsData: Omit<EmailSettings, 'id' | 'updatedAt'>, userId: string): Promise<EmailSettings> {
    const existing = await this.getEmailSettings();
    
    if (existing) {
      const [updated] = await db
        .update(emailSettings)
        .set({
          ...settingsData,
          updatedAt: new Date(),
          updatedBy: userId,
        })
        .where(eq(emailSettings.id, existing.id))
        .returning();
      return updated;
    }
    
    const [created] = await db
      .insert(emailSettings)
      .values({
        ...settingsData,
        updatedBy: userId,
      })
      .returning();
    return created;
  }

  // Notification policy operations
  async getNotificationPolicies(): Promise<NotificationPolicy[]> {
    return await db
      .select()
      .from(notificationPolicies)
      .orderBy(notificationPolicies.createdAt);
  }

  async getNotificationPolicy(id: string): Promise<NotificationPolicy | undefined> {
    const [policy] = await db
      .select()
      .from(notificationPolicies)
      .where(eq(notificationPolicies.id, id));
    return policy;
  }

  async createNotificationPolicy(policy: InsertNotificationPolicy, userId: string): Promise<NotificationPolicy> {
    const [created] = await db
      .insert(notificationPolicies)
      .values({
        ...policy,
        createdBy: userId,
      })
      .returning();
    return created;
  }

  async updateNotificationPolicy(id: string, policy: Partial<InsertNotificationPolicy>): Promise<NotificationPolicy> {
    const [updated] = await db
      .update(notificationPolicies)
      .set({
        ...policy,
        updatedAt: new Date(),
      })
      .where(eq(notificationPolicies.id, id))
      .returning();
    return updated;
  }

  async deleteNotificationPolicy(id: string): Promise<void> {
    await db.delete(notificationPolicies).where(eq(notificationPolicies.id, id));
  }

  // Notification log operations
  async createNotificationLog(log: InsertNotificationLog): Promise<NotificationLog> {
    const [created] = await db
      .insert(notificationLog)
      .values([{
        ...log,
        emailAddresses: Array.isArray(log.emailAddresses) ? [...log.emailAddresses] : [],
      }])
      .returning();
    return created;
  }

  async getNotificationLogs(limit = 100): Promise<NotificationLog[]> {
    return await db
      .select()
      .from(notificationLog)
      .orderBy(desc(notificationLog.sentAt))
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

  // Database initialization and migration utilities
  async initializeDatabaseStructure(): Promise<void> {
    try {
      console.log('🔧 Verificando estrutura do banco de dados...');
      
      // Step 0: Ensure system user exists
      await this.ensureSystemUserExists();
      
      // Check if unique index exists
      const indexCheck = await db.execute(sql`
        SELECT indexname 
        FROM pg_indexes 
        WHERE tablename = 'threats' 
          AND indexname = 'UQ_threats_correlation_key'
      `);
      
      const hasUniqueIndex = (indexCheck.rowCount ?? 0) > 0;
      console.log(`🔍 Índice único de correlation_key: ${hasUniqueIndex ? 'EXISTE' : 'NÃO EXISTE'}`);
      
      if (!hasUniqueIndex) {
        console.log('🔧 Criando estrutura de prevenção de duplicatas...');
        
        // Step 1: Consolidate existing duplicates
        console.log('📋 Consolidando duplicatas existentes...');
        await this.consolidateDuplicateThreats();
        
        // Step 2: Create unique index
        console.log('🏗️  Criando índice único para correlation_key...');
        await db.execute(sql`
          CREATE UNIQUE INDEX "UQ_threats_correlation_key" 
          ON threats (correlation_key) 
          WHERE (
            correlation_key IS NOT NULL 
            AND (status != 'closed' OR closure_reason != 'duplicate')
          )
        `);
        
        console.log('✅ Índice único criado com sucesso!');
        console.log('🎉 Sistema de prevenção de duplicatas ativo!');
      } else {
        console.log('✅ Estrutura do banco de dados já está atualizada');
      }
      
    } catch (error) {
      console.error('❌ Erro na inicialização do banco:', error);
      // Don't throw - let the system continue with fallback mode
    }
  }

  private async ensureSystemUserExists(): Promise<void> {
    try {
      // Check if system user exists
      const existingUsers = await db
        .select()
        .from(users)
        .where(eq(users.id, 'system'))
        .limit(1);
      
      if (existingUsers.length === 0) {
        console.log('🤖 Criando usuário sistema...');
        
        // Create system user with Drizzle insert for type safety
        await db.insert(users).values({
          id: 'system',
          email: 'system@samureye.local',
          firstName: 'Sistema',
          lastName: 'Automatizado',
          role: 'global_administrator',
          passwordHash: crypto.randomBytes(32).toString('hex'), // Unusable random password
          mustChangePassword: false,
        }).onConflictDoNothing();
        
        console.log('✅ Usuário sistema criado com sucesso!');
      } else {
        console.log('✅ Usuário sistema já existe');
      }
      
      // Verify system user exists after creation attempt
      const verifyUser = await db
        .select({ id: users.id })
        .from(users)
        .where(eq(users.id, 'system'))
        .limit(1);
        
      if (verifyUser.length === 0) {
        console.error('❌ Usuário sistema não foi criado corretamente!');
        throw new Error('Failed to create system user - this will cause FK violations');
      }
      
    } catch (error) {
      console.error('❌ Erro ao verificar/criar usuário sistema:', error);
      // This is critical for on-premise compatibility - throw to surface configuration issues
      throw error;
    }
  }

  private async consolidateDuplicateThreats(): Promise<void> {
    try {
      // Find duplicates using direct query execution
      const duplicatesResult = await db.execute(sql`
        SELECT 
          correlation_key,
          COUNT(*) as total,
          ARRAY_AGG(id ORDER BY created_at ASC) as ids
        FROM threats 
        WHERE correlation_key IS NOT NULL
        GROUP BY correlation_key
        HAVING COUNT(*) > 1
      `);
      
      const duplicates = duplicatesResult.rows;
      
      if (duplicates.length === 0) {
        console.log('📋 Nenhuma duplicata encontrada');
        return;
      }
      
      console.log(`📋 Encontradas ${duplicates?.length || 0} chaves com duplicatas`);
      
      // Consolidate each group of duplicates
      let totalRemoved = 0;
      
      if (!duplicates || duplicates.length === 0) {
        console.log('📋 Nenhuma duplicata encontrada para consolidar');
        return;
      }
      
      for (const duplicate of duplicates) {
        const ids = (duplicate as any).ids as string[];
        const keepId = ids[0]; // Keep the oldest (first in the array)
        const removeIds = ids.slice(1); // Remove the rest
        
        if (removeIds.length > 0) {
          // Remove status history for duplicates
          await db.execute(sql`
            DELETE FROM threat_status_history 
            WHERE threat_id = ANY(${removeIds})
          `);
          
          // Remove duplicate threats
          await db.execute(sql`
            DELETE FROM threats 
            WHERE id = ANY(${removeIds})
          `);
          
          totalRemoved += removeIds.length;
          console.log(`🗑️  Removidas ${removeIds.length} duplicatas de ${(duplicate as any).correlation_key}`);
        }
      }
      
      console.log(`✅ Consolidação concluída: ${totalRemoved} duplicatas removidas`);
      
    } catch (error) {
      console.error('❌ Erro na consolidação de duplicatas:', error);
      throw error;
    }
  }

  // Active session operations
  async createActiveSession(session: InsertActiveSession): Promise<ActiveSession> {
    const [newSession] = await db.insert(activeSessions).values(session).returning();
    return newSession;
  }

  async getActiveSessionBySessionId(sessionId: string): Promise<ActiveSession | undefined> {
    const [session] = await db.select().from(activeSessions).where(eq(activeSessions.sessionId, sessionId));
    return session;
  }

  async getActiveSessionsByUserId(userId: string): Promise<ActiveSession[]> {
    return await db.select()
      .from(activeSessions)
      .where(eq(activeSessions.userId, userId))
      .orderBy(desc(activeSessions.lastActivity));
  }

  async updateActiveSessionLastActivity(sessionId: string): Promise<ActiveSession> {
    const [updated] = await db.update(activeSessions)
      .set({ lastActivity: new Date() })
      .where(eq(activeSessions.sessionId, sessionId))
      .returning();
    return updated;
  }

  async deleteActiveSession(sessionId: string): Promise<void> {
    await db.delete(activeSessions).where(eq(activeSessions.sessionId, sessionId));
  }

  async deleteActiveSessionsByUserId(userId: string): Promise<void> {
    await db.delete(activeSessions).where(eq(activeSessions.userId, userId));
  }

  async cleanupExpiredSessions(): Promise<void> {
    await db.delete(activeSessions).where(sql`${activeSessions.expiresAt} < NOW()`);
  }

  async getAllActiveSessions(limit: number = 100): Promise<(ActiveSession & { user: User })[]> {
    const sessions = await db.select({
      session: activeSessions,
      user: users,
    })
    .from(activeSessions)
    .innerJoin(users, eq(activeSessions.userId, users.id))
    .orderBy(desc(activeSessions.lastActivity))
    .limit(limit);

    return sessions.map(row => ({
      ...row.session,
      user: row.user,
    }));
  }

  // Login attempt operations (rate limiting)
  async getLoginAttempt(identifier: string): Promise<LoginAttempt | undefined> {
    const [attempt] = await db.select()
      .from(loginAttempts)
      .where(eq(loginAttempts.identifier, identifier));
    return attempt;
  }

  async upsertLoginAttempt(identifier: string, increment: boolean): Promise<LoginAttempt> {
    const existing = await this.getLoginAttempt(identifier);
    
    if (existing) {
      const newAttempts = increment ? existing.attempts + 1 : existing.attempts;
      const [updated] = await db.update(loginAttempts)
        .set({
          attempts: newAttempts,
          lastAttempt: new Date(),
          blockedUntil: newAttempts >= 5 ? new Date(Date.now() + 15 * 60 * 1000) : null, // Block for 15 min after 5 attempts
        })
        .where(eq(loginAttempts.identifier, identifier))
        .returning();
      return updated;
    } else {
      const [newAttempt] = await db.insert(loginAttempts).values({
        identifier,
        attempts: 1,
        lastAttempt: new Date(),
      }).returning();
      return newAttempt;
    }
  }

  async resetLoginAttempts(identifier: string): Promise<void> {
    await db.delete(loginAttempts).where(eq(loginAttempts.identifier, identifier));
  }

  async cleanupOldLoginAttempts(): Promise<void> {
    // Clean up attempts older than 24 hours
    await db.delete(loginAttempts).where(sql`${loginAttempts.lastAttempt} < NOW() - INTERVAL '24 hours'`);
  }

  // Session version operations
  async getCurrentSessionVersion(): Promise<number> {
    const setting = await this.getSetting('session_version');
    return setting ? (setting.value as number) : 1;
  }

  async incrementSessionVersion(userId: string): Promise<number> {
    const currentVersion = await this.getCurrentSessionVersion();
    const newVersion = currentVersion + 1;
    await this.setSetting('session_version', newVersion, userId);
    return newVersion;
  }
}

export const storage = new DatabaseStorage();
