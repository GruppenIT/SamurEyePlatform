import {
  type User,
  type UpsertUser,
  type Asset,
  type InsertAsset,
  type Credential,
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
  type ThreatStatusHistory,
  type InsertThreatStatusHistory,
  type AuditLogEntry,
  type ActiveSession,
  type InsertActiveSession,
  type LoginAttempt,
  type EmailSettings,
  type NotificationPolicy,
  type InsertNotificationPolicy,
  type NotificationLog,
  type InsertNotificationLog,
  type JourneyCredential,
  type InsertJourneyCredential,
  type HostEnrichment,
  type InsertHostEnrichment,
  type ApplianceSubscription,
  type ApplianceCommand,
  type ConsoleCommand,
  type EdrDeployment,
  type InsertEdrDeployment,
  type MfaEmailChallenge,
  type InsertMfaEmailChallenge,
} from "@shared/schema";

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
  getUserMfa(id: string): Promise<Pick<User, 'id' | 'email' | 'mfaEnabled' | 'mfaSecretEncrypted' | 'mfaSecretDek' | 'mfaBackupCodes' | 'mfaInvitationDismissed' | 'mfaEnabledAt'> | undefined>;
  setUserMfa(id: string, data: { mfaEnabled: boolean; mfaSecretEncrypted: string | null; mfaSecretDek: string | null; mfaBackupCodes: string[] | null; mfaEnabledAt: Date | null }): Promise<void>;
  updateBackupCodes(id: string, codes: string[]): Promise<void>;
  dismissMfaInvitation(id: string): Promise<void>;

  // Asset operations
  getAssets(): Promise<Asset[]>;
  getAsset(id: string): Promise<Asset | undefined>;
  getAssetsByTags(tags: string[]): Promise<Asset[]>;
  getAssetsByType(type: string): Promise<Asset[]>;
  getUniqueTags(): Promise<string[]>;
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
  touchEmailSettingsTest(id: string, at: Date): Promise<void>;

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

  // Appliance subscription operations
  getSubscription(): Promise<ApplianceSubscription | undefined>;
  upsertSubscription(data: Partial<Omit<ApplianceSubscription, 'id'>>, userId?: string): Promise<ApplianceSubscription>;
  updateHeartbeatSuccess(consoleResponse: {
    active: boolean;
    plan: string;
    expiresAt: string | null;
    features: string[];
    tenantId?: string;
    tenantName?: string;
    planSlug?: string;
    maxAppliances?: number;
    isTrial?: boolean;
    durationDays?: number | null;
    message?: string | null;
  }): Promise<ApplianceSubscription>;
  updateHeartbeatFailure(error: string): Promise<ApplianceSubscription>;
  saveReceivedCommands(commands: ConsoleCommand[]): Promise<void>;
  getPendingCommands(): Promise<ApplianceCommand[]>;
  updateCommandStatus(
    id: string,
    status: 'running' | 'completed' | 'failed',
    extra?: { result?: Record<string, any>; error?: string },
  ): Promise<void>;
  getUnreportedCommandResults(): Promise<ApplianceCommand[]>;
  markCommandsReported(ids: string[]): Promise<void>;

  // EDR deployment operations
  insertEdrDeployment(data: InsertEdrDeployment): Promise<EdrDeployment>;
  getEdrDeploymentsByJourney(journeyId: string): Promise<EdrDeployment[]>;
  getEdrDeploymentsByJourneyWithHost(journeyId: string): Promise<Array<EdrDeployment & { hostName: string | null; hostIps: string[]; hostOperatingSystem: string | null }>>;

  // MFA email challenges
  createMfaEmailChallenge(data: InsertMfaEmailChallenge): Promise<MfaEmailChallenge>;
  getActiveChallenges(userId: string): Promise<MfaEmailChallenge[]>;
  consumeChallenge(id: string): Promise<void>;
  countRecentChallenges(userId: string, sinceMs: number): Promise<number>;
  cleanupOldChallenges(userId: string): Promise<void>;

  // Database initialization
  initializeDatabaseStructure(): Promise<void>;
}
