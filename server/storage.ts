import {
  users,
  assets,
  credentials,
  journeys,
  schedules,
  jobs,
  jobResults,
  threats,
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
  type Threat,
  type InsertThreat,
  type Setting,
  type InsertSetting,
  type AuditLogEntry,
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, and, or, sql, count, like, inArray } from "drizzle-orm";

// Interface for storage operations
export interface IStorage {
  // User operations (mandatory for Replit Auth)
  getUser(id: string): Promise<User | undefined>;
  upsertUser(user: UpsertUser): Promise<User>;
  getUserByEmail(email: string): Promise<User | undefined>;
  updateUserRole(id: string, role: string): Promise<User>;
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

  // Threat operations
  getThreats(filters?: { severity?: string; status?: string; assetId?: string }): Promise<Threat[]>;
  getThreat(id: string): Promise<Threat | undefined>;
  createThreat(threat: InsertThreat): Promise<Threat>;
  updateThreat(id: string, threat: Partial<Threat>): Promise<Threat>;
  deleteThreat(id: string): Promise<void>;
  getThreatStats(): Promise<{ total: number; critical: number; high: number; medium: number; low: number }>;

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
    coverage: number;
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
    const [newAsset] = await db
      .insert(assets)
      .values({
        type: asset.type,
        value: asset.value,
        tags: asset.tags,
        createdBy: userId,
      })
      .returning();
    return newAsset;
  }

  async updateAsset(id: string, asset: Partial<InsertAsset>): Promise<Asset> {
    const [updatedAsset] = await db
      .update(assets)
      .set(asset)
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
  async getThreats(filters?: { severity?: string; status?: string; assetId?: string }): Promise<Threat[]> {
    let query = db.select().from(threats);
    
    if (filters) {
      const conditions = [];
      if (filters.severity) conditions.push(eq(threats.severity, filters.severity as any));
      if (filters.status) conditions.push(eq(threats.status, filters.status as any));
      if (filters.assetId) conditions.push(eq(threats.assetId, filters.assetId));
      
      if (conditions.length > 0) {
        query = query.where(and(...conditions));
      }
    }
    
    return await query.orderBy(desc(threats.createdAt));
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
    coverage: number;
  }> {
    const [assetCount] = await db.select({ count: count() }).from(assets);
    const [criticalThreatsCount] = await db
      .select({ count: count() })
      .from(threats)
      .where(and(eq(threats.severity, 'critical'), eq(threats.status, 'open')));
    const [jobsCount] = await db.select({ count: count() }).from(jobs);
    
    return {
      activeAssets: Number(assetCount.count),
      criticalThreats: Number(criticalThreatsCount.count),
      jobsExecuted: Number(jobsCount.count),
      coverage: 94.8, // This would be calculated based on actual coverage logic
    };
  }
}

export const storage = new DatabaseStorage();
