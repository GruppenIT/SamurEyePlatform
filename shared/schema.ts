import { sql } from 'drizzle-orm';
import { relations } from 'drizzle-orm';
import {
  index,
  uniqueIndex,
  jsonb,
  pgTable,
  timestamp,
  varchar,
  text,
  integer,
  boolean,
  pgEnum,
  real,
  check,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Session storage table for Replit Auth
export const sessions = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull(),
  },
  (table) => [index("IDX_session_expire").on(table.expire)],
);

// User roles enum
export const userRoleEnum = pgEnum('user_role', ['global_administrator', 'operator', 'read_only']);

// Asset types enum
export const assetTypeEnum = pgEnum('asset_type', ['host', 'range', 'web_application']);

// Credential types enum
export const credentialTypeEnum = pgEnum('credential_type', ['ssh', 'wmi', 'omi', 'ad']);

// Journey types enum
export const journeyTypeEnum = pgEnum('journey_type', ['attack_surface', 'ad_security', 'edr_av', 'web_application']);

// Schedule kinds enum
export const scheduleKindEnum = pgEnum('schedule_kind', ['on_demand', 'once', 'recurring']);

// Recurrence types enum for recurring schedules
export const recurrenceTypeEnum = pgEnum('recurrence_type', ['daily', 'weekly', 'monthly']);

// Job status enum
export const jobStatusEnum = pgEnum('job_status', ['pending', 'running', 'completed', 'failed', 'timeout']);

// Threat severity enum
export const threatSeverityEnum = pgEnum('threat_severity', ['low', 'medium', 'high', 'critical']);

// Action plan status enum
export const actionPlanStatusEnum = pgEnum('action_plan_status', ['pending', 'in_progress', 'blocked', 'done', 'cancelled']);

// Action plan priority enum
export const actionPlanPriorityEnum = pgEnum('action_plan_priority', ['low', 'medium', 'high', 'critical']);

// Threat status enum
export const threatStatusEnum = pgEnum('threat_status', ['open', 'investigating', 'mitigated', 'closed', 'hibernated', 'accepted_risk']);

// Email auth type enum
export const emailAuthTypeEnum = pgEnum('email_auth_type', ['password', 'oauth2_gmail', 'oauth2_microsoft']);

// Subscription status enum
export const subscriptionStatusEnum = pgEnum('subscription_status', ['not_configured', 'active', 'expired', 'grace_period', 'unreachable']);

// Notification status enum
export const notificationStatusEnum = pgEnum('notification_status', ['sent', 'failed']);

// Host types enum
export const hostTypeEnum = pgEnum('host_type', ['server', 'desktop', 'firewall', 'switch', 'router', 'domain', 'other']);

// Host families enum  
export const hostFamilyEnum = pgEnum('host_family', ['linux', 'windows_server', 'windows_desktop', 'fortios', 'network_os', 'other']);

// AD Security test status enum
export const adSecurityTestStatusEnum = pgEnum('ad_security_test_status', ['pass', 'fail', 'error', 'skipped']);

// Host enrichment protocol enum
export const enrichmentProtocolEnum = pgEnum('enrichment_protocol', ['wmi', 'ssh', 'snmp']);

// Phase 9: API Discovery enums ---

// API type — ROADMAP Phase 9 HIER-01
export const apiTypeEnum = pgEnum('api_type_enum', ['rest', 'graphql', 'soap']);

// OWASP API Top 10 2023 — ROADMAP Phase 9 FIND-01
// NEVER mutate this enum (Postgres enum mutation requires ALTER TYPE).
// For OWASP 2027, create a new enum `owasp_api_category_2027`.
// Keys MUST match shared/owaspApiCategories.ts OWASP_API_CATEGORY_LABELS keys.
export const owaspApiCategoryEnum = pgEnum('owasp_api_category', [
  'api1_bola_2023',
  'api2_broken_auth_2023',
  'api3_bopla_2023',
  'api4_rate_limit_2023',
  'api5_bfla_2023',
  'api6_business_flow_2023',
  'api7_ssrf_2023',
  'api8_misconfiguration_2023',
  'api9_inventory_2023',
  'api10_unsafe_consumption_2023',
]);

// api_findings lifecycle status — ROADMAP Phase 9 FIND-01, UI Phase 16 UI-05
export const apiFindingStatusEnum = pgEnum('api_finding_status',
  ['open', 'triaged', 'false_positive', 'closed']);

// Phase 10 — API Credentials (CRED-01)
// Ordem fixa — qualquer adição futura cria nova enum em vez de ALTER TYPE.
export const apiAuthTypeEnum = pgEnum('api_auth_type', [
  'api_key_header',
  'api_key_query',
  'bearer_jwt',
  'basic',
  'oauth2_client_credentials',
  'hmac',
  'mtls',
]);

// Users table
export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: varchar("email").unique().notNull(),
  passwordHash: varchar("password_hash"), // For local authentication
  firstName: varchar("first_name").notNull(),
  lastName: varchar("last_name").notNull(),
  profileImageUrl: varchar("profile_image_url"),
  role: userRoleEnum("role").default('read_only').notNull(),
  mustChangePassword: boolean("must_change_password").default(false).notNull(),
  // MFA (TOTP) fields
  mfaEnabled: boolean("mfa_enabled").default(false).notNull(),
  mfaSecretEncrypted: text("mfa_secret_encrypted"),
  mfaSecretDek: text("mfa_secret_dek"),
  mfaBackupCodes: text("mfa_backup_codes").array(),
  mfaEnabledAt: timestamp("mfa_enabled_at"),
  mfaInvitationDismissed: boolean("mfa_invitation_dismissed").default(false).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
  lastLogin: timestamp("last_login"),
});

// Assets table
export const assets = pgTable("assets", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  type: assetTypeEnum("type").notNull(),
  value: text("value").notNull(), // FQDN, IP, or CIDR range
  tags: jsonb("tags").$type<string[]>().default([]).notNull(),
  parentAssetId: varchar("parent_asset_id").references((): any => assets.id, { onDelete: 'cascade' }),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  createdBy: varchar("created_by").references(() => users.id).notNull(),
}, (table) => [
  index("IDX_assets_parent").on(table.parentAssetId),
]);

// Credentials table
export const credentials = pgTable("credentials", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: varchar("name").notNull(),
  type: credentialTypeEnum("type").notNull(),
  hostOverride: text("host_override"), // Optional specific host
  port: integer("port"),
  domain: text("domain"), // Domain for AD/LDAP credentials
  username: text("username").notNull(),
  secretEncrypted: text("secret_encrypted").notNull(), // AES-256-GCM encrypted
  dekEncrypted: text("dek_encrypted").notNull(), // Data Encryption Key encrypted with KEK
  createdAt: timestamp("created_at").defaultNow().notNull(),
  createdBy: varchar("created_by").references(() => users.id).notNull(),
});

// Target selection mode enum
export const targetSelectionModeEnum = pgEnum('target_selection_mode', ['individual', 'by_tag']);

// Journeys table
export const journeys = pgTable("journeys", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: varchar("name").notNull(),
  type: journeyTypeEnum("type").notNull(),
  description: text("description"),
  params: jsonb("params").$type<Record<string, any>>().default({}).notNull(),
  targetSelectionMode: targetSelectionModeEnum("target_selection_mode").default('individual').notNull(),
  selectedTags: jsonb("selected_tags").$type<string[]>().default([]).notNull(),
  enableCveDetection: boolean("enable_cve_detection").default(true).notNull(), // For attack_surface journey
  createdAt: timestamp("created_at").defaultNow().notNull(),
  createdBy: varchar("created_by").references(() => users.id).notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// Journey credentials junction table - links credentials to journeys for authenticated scanning
export const journeyCredentials = pgTable("journey_credentials", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  journeyId: varchar("journey_id").references(() => journeys.id).notNull(),
  credentialId: varchar("credential_id").references(() => credentials.id).notNull(),
  protocol: enrichmentProtocolEnum("protocol").notNull(),
  priority: integer("priority").default(1).notNull(), // Order of attempt (1 = highest priority)
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => [
  index("IDX_journey_credentials_journey_id").on(table.journeyId),
  index("IDX_journey_credentials_credential_id").on(table.credentialId),
]);

// Repeat unit enum for flexible intervals
export const repeatUnitEnum = pgEnum('repeat_unit', ['hours', 'days']);

// Schedules table
export const schedules = pgTable("schedules", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  journeyId: varchar("journey_id").references(() => journeys.id).notNull(),
  name: varchar("name").notNull(),
  kind: scheduleKindEnum("kind").notNull(),
  // Legacy CRON support (mantido para compatibilidade)
  cronExpression: text("cron_expression"), // For recurring schedules
  // New simple recurrence fields
  recurrenceType: recurrenceTypeEnum("recurrence_type"), // daily, weekly, monthly
  hour: integer("hour"), // 0-23 for execution hour
  minute: integer("minute").default(0), // 0-59 for execution minute
  dayOfWeek: integer("day_of_week"), // 0-6 (Sunday=0) for weekly schedules
  dayOfMonth: integer("day_of_month"), // 1-31 for monthly schedules
  // Repeat interval fields (Repetir a cada X unidades)
  repeatInterval: integer("repeat_interval"), // Number of units between executions
  repeatUnit: repeatUnitEnum("repeat_unit"), // hours or days
  // For one-time schedules
  onceAt: timestamp("once_at"), // For one-time schedules
  // Execution tracking
  lastExecutedAt: timestamp("last_executed_at"), // Last time this schedule was executed
  enabled: boolean("enabled").default(true).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  createdBy: varchar("created_by").references(() => users.id).notNull(),
});

// Jobs table
export const jobs = pgTable("jobs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  journeyId: varchar("journey_id").references(() => journeys.id).notNull(),
  scheduleId: varchar("schedule_id").references(() => schedules.id), // Optional, null for on-demand
  status: jobStatusEnum("status").default('pending').notNull(),
  progress: integer("progress").default(0).notNull(), // 0-100
  currentTask: text("current_task"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  startedAt: timestamp("started_at"),
  finishedAt: timestamp("finished_at"),
  error: text("error"),
});

// Job results table
export const jobResults = pgTable("job_results", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  jobId: varchar("job_id").references(() => jobs.id).notNull(),
  stdout: text("stdout"),
  stderr: text("stderr"),
  artifacts: jsonb("artifacts").$type<Record<string, any>>().default({}).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Hosts table
export const hosts = pgTable("hosts", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(), // Always lowercase, initially NetBIOS or reverse DNS
  description: text("description"), // User-editable description
  operatingSystem: text("operating_system"), // Detected from scans
  type: hostTypeEnum("type").default('other').notNull(),
  family: hostFamilyEnum("family").default('other').notNull(),
  ips: jsonb("ips").$type<string[]>().default([]).notNull(), // Array of IPs
  aliases: jsonb("aliases").$type<string[]>().default([]).notNull(), // FQDNs and alternative names
  riskScore: integer("risk_score").default(0).notNull(), // 0-100 based on CVSS intervals
  rawScore: integer("raw_score").default(0).notNull(), // Sum of weighted threat scores
  sshHostFingerprint: text("ssh_host_fingerprint"), // SHA-256 fingerprint of SSH host key (FND-009 TOFU)
  discoveredAt: timestamp("discovered_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
}, (table) => [
  index("IDX_hosts_name").on(table.name),
  index("IDX_hosts_type").on(table.type),
  index("IDX_hosts_risk_score").on(table.riskScore),
]);

// Phase 5: EDR deployment metadata table (PARS-10) — one row per host test
export const edrDeployments = pgTable("edr_deployments", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  hostId: varchar("host_id").references(() => hosts.id).notNull(),
  journeyId: varchar("journey_id").references(() => journeys.id).notNull(),
  jobId: varchar("job_id").references(() => jobs.id).notNull(),
  deploymentTimestamp: timestamp("deployment_timestamp"),
  detectionTimestamp: timestamp("detection_timestamp"),
  deploymentMethod: text("deployment_method").notNull(),
  detected: boolean("detected"),
  testDuration: integer("test_duration").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => [
  index("IDX_edr_deployments_journey_id").on(table.journeyId),
  index("IDX_edr_deployments_host_id").on(table.hostId),
]);

export type EdrDeployment = typeof edrDeployments.$inferSelect;
export type InsertEdrDeployment = typeof edrDeployments.$inferInsert;

// Host enrichments table - stores authenticated scan data collected from hosts
export const hostEnrichments = pgTable("host_enrichments", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  hostId: varchar("host_id").references(() => hosts.id).notNull(),
  jobId: varchar("job_id").references(() => jobs.id).notNull(),
  protocol: enrichmentProtocolEnum("protocol").notNull(),
  credentialId: varchar("credential_id").references(() => credentials.id),
  success: boolean("success").notNull(),
  collectedAt: timestamp("collected_at").defaultNow().notNull(),
  
  // Normalized collected data
  osVersion: text("os_version"), // Exact OS version (e.g., "Windows Server 2019 Build 17763.5820")
  osBuild: text("os_build"), // OS build number for precise matching
  installedApps: jsonb("installed_apps").$type<Array<{name: string; version: string; vendor?: string}>>(), // Applications detected
  patches: jsonb("patches").$type<string[]>(), // Installed patches/KBs (Windows: KB numbers, Linux: package versions)
  services: jsonb("services").$type<Array<{name: string; displayName?: string; startType?: string; status?: string; description?: string}>>(), // Detected services with startup config and status
  
  // Audit trail - commands executed
  commandsExecuted: jsonb("commands_executed").$type<Array<{
    command: string;
    stdout: string;
    stderr: string;
    exitCode: number;
  }>>(),
  errorMessage: text("error_message"), // Error if collection failed
}, (table) => [
  index("IDX_host_enrichments_host_id").on(table.hostId),
  index("IDX_host_enrichments_job_id").on(table.jobId),
  index("IDX_host_enrichments_collected_at").on(table.collectedAt),
]);

// Phase 2: Score breakdown structure for contextual threat scoring
export interface ScoreBreakdownRecord {
  baseSeverityWeight: number;
  criticalityMultiplier: number;
  exposureFactor: number;
  controlsReductionFactor: number;
  exploitabilityMultiplier: number;
  rawScore: number;
  normalizedScore: number;
}

// Threats table
export const threats = pgTable("threats", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  title: text("title").notNull(),
  description: text("description"),
  severity: threatSeverityEnum("severity").notNull(),
  status: threatStatusEnum("status").default('open').notNull(),
  source: text("source").notNull(), // e.g., 'journey', 'manual'
  assetId: varchar("asset_id").references(() => assets.id),
  hostId: varchar("host_id").references(() => hosts.id), // Link to discovered host
  evidence: jsonb("evidence").$type<Record<string, any>>().default({}).notNull(),
  jobId: varchar("job_id").references(() => jobs.id),
  // Lifecycle management fields
  correlationKey: text("correlation_key"), // Unique identifier for threat correlation
  category: text("category"), // Journey type semantics (attack_surface, ad_hygiene, edr_av)
  ruleId: text("rule_id"), // Phase 3: Threat rule ID for recommendation template lookup (e.g. 'exposed-service', 'cve-detected')
  lastSeenAt: timestamp("last_seen_at"), // Last time threat was observed
  closureReason: text("closure_reason"), // Reason for closure ('system', 'manual', etc.)
  // Status management fields
  hibernatedUntil: timestamp("hibernated_until"), // Date when hibernation expires
  statusChangedBy: varchar("status_changed_by").references(() => users.id), // Last user who changed status
  statusChangedAt: timestamp("status_changed_at"), // Last status change time
  statusJustification: text("status_justification"), // Justification for last status change
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
  assignedTo: varchar("assigned_to").references(() => users.id),
  // Phase 2: Threat grouping and contextual scoring columns (all nullable — additive only)
  parentThreatId: varchar("parent_threat_id").references((): any => threats.id), // Self-referential FK for threat grouping
  groupingKey: text("grouping_key"), // Set only on parent threats, null on children
  contextualScore: real("contextual_score"), // 0-100 scale, null until scoring runs
  scoreBreakdown: jsonb("score_breakdown").$type<ScoreBreakdownRecord>(), // Typed JSONB, null until scoring runs
  projectedScoreAfterFix: real("projected_score_after_fix"), // Posture delta, null until scoring runs
}, (table) => [
  index("IDX_threats_correlation_key").on(table.correlationKey),
  uniqueIndex("UQ_threats_correlation_key").on(table.correlationKey).where(sql`correlation_key IS NOT NULL AND (status != 'closed' OR closure_reason != 'duplicate')`),
  index("IDX_threats_host_id").on(table.hostId),
  index("IDX_threats_status").on(table.status),
  // Phase 2 indexes
  uniqueIndex("UQ_threats_grouping_key").on(table.groupingKey).where(sql`grouping_key IS NOT NULL`),
  index("IDX_threats_parent_threat_id").on(table.parentThreatId),
]);

// Threat status history table
export const threatStatusHistory = pgTable("threat_status_history", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  threatId: varchar("threat_id").references(() => threats.id).notNull(),
  fromStatus: threatStatusEnum("from_status"),
  toStatus: threatStatusEnum("to_status").notNull(),
  justification: text("justification").notNull(),
  hibernatedUntil: timestamp("hibernated_until"), // Only for hibernated status
  changedBy: varchar("changed_by").references(() => users.id).notNull(),
  changedAt: timestamp("changed_at").defaultNow().notNull(),
}, (table) => [
  index("IDX_threat_status_history_threat_id").on(table.threatId),
  index("IDX_threat_status_history_changed_at").on(table.changedAt),
]);

// Phase 2: Posture snapshots table — captures score at end of each job
export const postureSnapshots = pgTable("posture_snapshots", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  jobId: varchar("job_id").references(() => jobs.id).notNull(),
  journeyId: varchar("journey_id").references(() => journeys.id).notNull(),
  score: real("score").notNull(),
  openThreatCount: integer("open_threat_count").notNull(),
  criticalCount: integer("critical_count").notNull().default(0),
  highCount: integer("high_count").notNull().default(0),
  mediumCount: integer("medium_count").notNull().default(0),
  lowCount: integer("low_count").notNull().default(0),
  scoredAt: timestamp("scored_at").defaultNow().notNull(),
}, (table) => [
  index("IDX_posture_snapshots_job_id").on(table.jobId),
  index("IDX_posture_snapshots_journey_id").on(table.journeyId),
  index("IDX_posture_snapshots_scored_at").on(table.scoredAt),
]);

// Phase 2: Recommendations table — populated by Phase 3, defined here to avoid second migration
export const recommendations = pgTable("recommendations", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  threatId: varchar("threat_id").references(() => threats.id).notNull(),
  templateId: text("template_id").notNull(),
  title: text("title").notNull(),
  whatIsWrong: text("what_is_wrong").notNull(),
  businessImpact: text("business_impact").notNull(),
  fixSteps: jsonb("fix_steps").$type<string[]>().default([]).notNull(),
  verificationStep: text("verification_step"),
  references: jsonb("references").$type<string[]>().default([]),
  effortTag: text("effort_tag"),
  roleRequired: text("role_required"),
  hostSpecificData: jsonb("host_specific_data").$type<Record<string, any>>().default({}),
  status: text("status").default('pending').notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
}, (table) => [
  index("IDX_recommendations_threat_id").on(table.threatId),
  uniqueIndex("UQ_recommendations_threat_id").on(table.threatId),
]);

// Settings table
export const settings = pgTable("settings", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  key: text("key").unique().notNull(),
  value: jsonb("value").$type<any>().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
  updatedBy: varchar("updated_by").references(() => users.id).notNull(),
});

// Audit log table
export const auditLog = pgTable("audit_log", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  actorId: varchar("actor_id").references(() => users.id).notNull(),
  action: text("action").notNull(),
  objectType: text("object_type").notNull(),
  objectId: varchar("object_id"),
  before: jsonb("before").$type<Record<string, any>>(),
  after: jsonb("after").$type<Record<string, any>>(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Active sessions table - tracks all active user sessions for security
export const activeSessions = pgTable("active_sessions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  sessionId: text("session_id").notNull().unique(), // connect.sid value
  userId: varchar("user_id").references(() => users.id).notNull(),
  sessionVersion: integer("session_version").notNull(), // Global version for invalidation
  ipAddress: text("ip_address").notNull(),
  userAgent: text("user_agent").notNull(),
  deviceInfo: text("device_info"), // Parsed device/browser info
  createdAt: timestamp("created_at").defaultNow().notNull(),
  lastActivity: timestamp("last_activity").defaultNow().notNull(),
  expiresAt: timestamp("expires_at").notNull(),
}, (table) => [
  index("IDX_active_sessions_user_id").on(table.userId),
  index("IDX_active_sessions_session_id").on(table.sessionId),
  index("IDX_active_sessions_expires_at").on(table.expiresAt),
]);

// Login attempts table - persistent rate limiting to prevent brute force
export const loginAttempts = pgTable("login_attempts", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  identifier: text("identifier").notNull().unique(), // email:ip combination
  attempts: integer("attempts").notNull().default(0),
  lastAttempt: timestamp("last_attempt").defaultNow().notNull(),
  blockedUntil: timestamp("blocked_until"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => [
  index("IDX_login_attempts_identifier").on(table.identifier),
  index("IDX_login_attempts_blocked_until").on(table.blockedUntil),
]);

// Host risk score history table - tracks risk score changes over time
export const hostRiskHistory = pgTable("host_risk_history", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  hostId: varchar("host_id").references(() => hosts.id).notNull(),
  riskScore: integer("risk_score").notNull().default(0),
  rawScore: real("raw_score").notNull().default(0),
  criticalCount: integer("critical_count").notNull().default(0),
  highCount: integer("high_count").notNull().default(0),
  mediumCount: integer("medium_count").notNull().default(0),
  lowCount: integer("low_count").notNull().default(0),
  recordedAt: timestamp("recorded_at").defaultNow().notNull(),
}, (table) => [
  index("IDX_host_risk_history_host_id").on(table.hostId),
  index("IDX_host_risk_history_recorded_at").on(table.recordedAt),
]);

// AD Security test results table - stores all test executions (pass/fail) for audit
export const adSecurityTestResults = pgTable("ad_security_test_results", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  jobId: varchar("job_id").references(() => jobs.id).notNull(), // Which job execution
  hostId: varchar("host_id").references(() => hosts.id).notNull(), // Which domain/host
  testId: text("test_id").notNull(), // Unique test identifier (e.g., "test_001_admin_count")
  testName: text("test_name").notNull(), // Display name in Portuguese
  category: text("category").notNull(), // Test category (configuracoes_criticas, etc.)
  severityHint: threatSeverityEnum("severity_hint").notNull(), // Potential severity if fails
  status: adSecurityTestStatusEnum("status").notNull(), // pass/fail/error/skipped
  evidence: jsonb("evidence").$type<Record<string, any>>().default({}).notNull(), // Raw data captured
  executedAt: timestamp("executed_at").defaultNow().notNull(),
}, (table) => [
  index("IDX_ad_test_results_job_id").on(table.jobId),
  index("IDX_ad_test_results_host_id").on(table.hostId),
  index("IDX_ad_test_results_executed_at").on(table.executedAt),
]);

// Email settings table
export const emailSettings = pgTable("email_settings", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  smtpHost: text("smtp_host").notNull(),
  smtpPort: integer("smtp_port").notNull(),
  smtpSecure: boolean("smtp_secure").default(true).notNull(),
  authType: emailAuthTypeEnum("auth_type").notNull().default('password'),
  // Basic auth (password) fields
  authUser: text("auth_user"),
  authPassword: text("auth_password"), // Encrypted password (for basic auth)
  dekEncrypted: text("dek_encrypted"), // Data Encryption Key encrypted with KEK (for basic auth)
  // OAuth2 fields (for gmail/microsoft)
  oauth2ClientId: text("oauth2_client_id"),
  oauth2ClientSecret: text("oauth2_client_secret"), // Encrypted
  oauth2ClientSecretDek: text("oauth2_client_secret_dek"), // DEK for client secret
  oauth2RefreshToken: text("oauth2_refresh_token"), // Encrypted
  oauth2RefreshTokenDek: text("oauth2_refresh_token_dek"), // DEK for refresh token
  oauth2TenantId: text("oauth2_tenant_id"), // For Microsoft 365 only
  fromEmail: text("from_email").notNull(),
  fromName: text("from_name").notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
  updatedBy: varchar("updated_by").references(() => users.id).notNull(),
  lastTestSuccessAt: timestamp("last_test_success_at"),
});

// Notification policies table
export const notificationPolicies = pgTable("notification_policies", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  enabled: boolean("enabled").default(true).notNull(),
  emailAddresses: jsonb("email_addresses").$type<string[]>().default([]).notNull(),
  severities: jsonb("severities").$type<string[]>().default([]).notNull(), // ['low', 'medium', 'high', 'critical']
  statuses: jsonb("statuses").$type<string[]>().default([]).notNull(), // ['open', 'mitigated', etc]
  createdAt: timestamp("created_at").defaultNow().notNull(),
  createdBy: varchar("created_by").references(() => users.id).notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// Notification log table
export const notificationLog = pgTable("notification_log", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  policyId: varchar("policy_id").references(() => notificationPolicies.id),
  threatId: varchar("threat_id").references(() => threats.id),
  emailAddresses: jsonb("email_addresses").$type<string[]>().default([]).notNull(),
  subject: text("subject").notNull(),
  body: text("body").notNull(),
  status: notificationStatusEnum("status").notNull(),
  error: text("error"),
  sentAt: timestamp("sent_at").defaultNow().notNull(),
}, (table) => [
  index("IDX_notification_log_policy_id").on(table.policyId),
  index("IDX_notification_log_threat_id").on(table.threatId),
  index("IDX_notification_log_sent_at").on(table.sentAt),
]);

// Appliance subscription table - manages connection to SamurEye central console
export const applianceSubscription = pgTable("appliance_subscription", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  applianceId: varchar("appliance_id").notNull().unique(), // UUID generated on first activation, immutable
  apiKey: text("api_key"),                                 // Encrypted API key provided by console
  apiKeyDek: text("api_key_dek"),                          // DEK for API key decryption
  // Cached subscription data from console
  status: subscriptionStatusEnum("status").default('not_configured').notNull(),
  tenantId: varchar("tenant_id"),
  tenantName: text("tenant_name"),
  plan: text("plan"),
  expiresAt: timestamp("expires_at"),
  features: jsonb("features").$type<string[]>().default([]),
  planSlug: text("plan_slug"),                               // e.g. "professional", "trial"
  maxAppliances: integer("max_appliances"),                   // -1 = unlimited
  isTrial: boolean("is_trial").default(false),
  durationDays: integer("duration_days"),                     // Original plan duration
  consoleMessage: text("console_message"),                    // Message from console (e.g. expiration warning)
  // Communication state
  lastHeartbeatAt: timestamp("last_heartbeat_at"),          // Last successful heartbeat
  lastHeartbeatError: text("last_heartbeat_error"),         // Last error message
  consecutiveFailures: integer("consecutive_failures").default(0).notNull(),
  graceDeadline: timestamp("grace_deadline"),               // When grace period expires (72h after first failure)
  consoleBaseUrl: text("console_base_url").default('https://api.samureye.com.br'),
  // Metadata
  activatedAt: timestamp("activated_at"),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
  updatedBy: varchar("updated_by").references(() => users.id),
});

// Action Plans tables
export const actionPlans = pgTable('action_plans', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  code: varchar('code', { length: 20 }).notNull().unique(),
  title: varchar('title', { length: 255 }).notNull(),
  description: text('description'),
  status: actionPlanStatusEnum('status').notNull().default('pending'),
  priority: actionPlanPriorityEnum('priority').notNull().default('medium'),
  createdBy: varchar('created_by').notNull().references(() => users.id, { onDelete: 'restrict' }),
  assigneeId: varchar('assignee_id').references(() => users.id, { onDelete: 'set null' }),
  blockReason: text('block_reason'),
  cancelReason: text('cancel_reason'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  codeIdx: uniqueIndex('action_plans_code_idx').on(t.code),
  statusIdx: index('action_plans_status_idx').on(t.status),
  assigneeIdx: index('action_plans_assignee_idx').on(t.assigneeId),
}));

export type ActionPlan = typeof actionPlans.$inferSelect;
export type NewActionPlan = typeof actionPlans.$inferInsert;
export const insertActionPlanSchema = createInsertSchema(actionPlans);

export const actionPlanThreats = pgTable('action_plan_threats', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  actionPlanId: varchar('action_plan_id').notNull().references(() => actionPlans.id, { onDelete: 'cascade' }),
  threatId: varchar('threat_id').notNull().references(() => threats.id, { onDelete: 'cascade' }),
  addedAt: timestamp('added_at', { withTimezone: true }).defaultNow().notNull(),
  addedBy: varchar('added_by').notNull().references(() => users.id, { onDelete: 'restrict' }),
}, (t) => ({
  uniqPlanThreat: uniqueIndex('action_plan_threats_plan_threat_idx').on(t.actionPlanId, t.threatId),
  threatIdx: index('action_plan_threats_threat_idx').on(t.threatId),
}));

export type ActionPlanThreat = typeof actionPlanThreats.$inferSelect;

export const actionPlanComments = pgTable('action_plan_comments', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  actionPlanId: varchar('action_plan_id').notNull().references(() => actionPlans.id, { onDelete: 'cascade' }),
  authorId: varchar('author_id').notNull().references(() => users.id, { onDelete: 'restrict' }),
  content: text('content').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }),
}, (t) => ({
  planIdx: index('action_plan_comments_plan_idx').on(t.actionPlanId, t.createdAt),
}));

export type ActionPlanComment = typeof actionPlanComments.$inferSelect;

export const actionPlanCommentThreats = pgTable('action_plan_comment_threats', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  commentId: varchar('comment_id').notNull().references(() => actionPlanComments.id, { onDelete: 'cascade' }),
  threatId: varchar('threat_id').notNull().references(() => threats.id, { onDelete: 'cascade' }),
}, (t) => ({
  uniqCommentThreat: uniqueIndex('ap_comment_threats_unique_idx').on(t.commentId, t.threatId),
  threatIdx: index('ap_comment_threats_threat_idx').on(t.threatId),
}));

export const actionPlanHistory = pgTable('action_plan_history', {
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  actionPlanId: varchar('action_plan_id').notNull().references(() => actionPlans.id, { onDelete: 'cascade' }),
  actorId: varchar('actor_id').notNull().references(() => users.id, { onDelete: 'restrict' }),
  action: varchar('action', { length: 64 }).notNull(),
  detailsJson: jsonb('details_json'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  planIdx: index('action_plan_history_plan_idx').on(t.actionPlanId, t.createdAt),
}));

export type ActionPlanHistory = typeof actionPlanHistory.$inferSelect;

export const ACTION_PLAN_HISTORY_ACTIONS = [
  'created',
  'status_changed',
  'assignee_changed',
  'title_changed',
  'description_changed',
  'priority_changed',
  'threat_added',
  'threat_removed',
  'comment_added',
  'comment_edited',
] as const;
export type ActionPlanHistoryAction = typeof ACTION_PLAN_HISTORY_ACTIONS[number];

// Relations
export const usersRelations = relations(users, ({ many }) => ({
  assets: many(assets),
  credentials: many(credentials),
  journeys: many(journeys),
  schedules: many(schedules),
  assignedThreats: many(threats),
  auditEntries: many(auditLog),
}));

export const assetsRelations = relations(assets, ({ one, many }) => ({
  createdBy: one(users, { fields: [assets.createdBy], references: [users.id] }),
  parent: one(assets, { fields: [assets.parentAssetId], references: [assets.id], relationName: "assetParent" }),
  children: many(assets, { relationName: "assetParent" }),
  threats: many(threats),
}));

export const credentialsRelations = relations(credentials, ({ one }) => ({
  createdBy: one(users, {
    fields: [credentials.createdBy],
    references: [users.id],
  }),
}));

export const journeysRelations = relations(journeys, ({ one, many }) => ({
  createdBy: one(users, {
    fields: [journeys.createdBy],
    references: [users.id],
  }),
  schedules: many(schedules),
  jobs: many(jobs),
}));

export const schedulesRelations = relations(schedules, ({ one, many }) => ({
  journey: one(journeys, {
    fields: [schedules.journeyId],
    references: [journeys.id],
  }),
  createdBy: one(users, {
    fields: [schedules.createdBy],
    references: [users.id],
  }),
  jobs: many(jobs),
}));

export const jobsRelations = relations(jobs, ({ one, many }) => ({
  journey: one(journeys, {
    fields: [jobs.journeyId],
    references: [journeys.id],
  }),
  schedule: one(schedules, {
    fields: [jobs.scheduleId],
    references: [schedules.id],
  }),
  results: many(jobResults),
  threats: many(threats),
}));

export const jobResultsRelations = relations(jobResults, ({ one }) => ({
  job: one(jobs, {
    fields: [jobResults.jobId],
    references: [jobs.id],
  }),
}));

export const hostsRelations = relations(hosts, ({ many }) => ({
  threats: many(threats),
}));

export const threatsRelations = relations(threats, ({ one, many }) => ({
  asset: one(assets, {
    fields: [threats.assetId],
    references: [assets.id],
  }),
  host: one(hosts, {
    fields: [threats.hostId],
    references: [hosts.id],
  }),
  job: one(jobs, {
    fields: [threats.jobId],
    references: [jobs.id],
  }),
  assignedTo: one(users, {
    fields: [threats.assignedTo],
    references: [users.id],
  }),
  statusChangedBy: one(users, {
    fields: [threats.statusChangedBy],
    references: [users.id],
  }),
  statusHistory: many(threatStatusHistory),
}));

export const threatStatusHistoryRelations = relations(threatStatusHistory, ({ one }) => ({
  threat: one(threats, {
    fields: [threatStatusHistory.threatId],
    references: [threats.id],
  }),
  changedBy: one(users, {
    fields: [threatStatusHistory.changedBy],
    references: [users.id],
  }),
}));

export const auditLogRelations = relations(auditLog, ({ one }) => ({
  actor: one(users, {
    fields: [auditLog.actorId],
    references: [users.id],
  }),
}));

export const emailSettingsRelations = relations(emailSettings, ({ one }) => ({
  updatedBy: one(users, {
    fields: [emailSettings.updatedBy],
    references: [users.id],
  }),
}));

export const notificationPoliciesRelations = relations(notificationPolicies, ({ one, many }) => ({
  createdBy: one(users, {
    fields: [notificationPolicies.createdBy],
    references: [users.id],
  }),
  logs: many(notificationLog),
}));

export const notificationLogRelations = relations(notificationLog, ({ one }) => ({
  policy: one(notificationPolicies, {
    fields: [notificationLog.policyId],
    references: [notificationPolicies.id],
  }),
  threat: one(threats, {
    fields: [notificationLog.threatId],
    references: [threats.id],
  }),
}));

// Insert schemas
export const insertUserSchema = createInsertSchema(users).omit({
  id: true,
  passwordHash: true,
  mustChangePassword: true, // Security: não expor via API pública
  mfaSecretEncrypted: true,
  mfaSecretDek: true,
  mfaBackupCodes: true,
  createdAt: true,
  updatedAt: true,
  lastLogin: true,
});

// Authentication schemas
export const registerUserSchema = z.object({
  email: z.string().email("Email inválido"),
  password: z.string().min(8, "Senha deve ter pelo menos 8 caracteres")
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, "Senha deve conter ao menos uma letra minúscula, uma maiúscula e um número"),
  firstName: z.string().min(1, "Nome é obrigatório"),
  lastName: z.string().min(1, "Sobrenome é obrigatório"),
  role: z.enum(['global_administrator', 'operator', 'read_only']).optional(),
});

export const loginUserSchema = z.object({
  email: z.string().email("Email inválido"),
  password: z.string().min(1, "Senha é obrigatória"),
});

// Shared password policy (min 12 chars + upper + lower + digit + special)
export const passwordComplexitySchema = z.string()
  .min(12, "Senha deve ter pelo menos 12 caracteres")
  .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])/,
    "Senha deve conter ao menos: 1 minúscula, 1 maiúscula, 1 número e 1 símbolo especial");

// Schema para troca de senha
export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, "Senha atual é obrigatória"),
  newPassword: passwordComplexitySchema,
  confirmPassword: z.string().min(1, "Confirmação de senha é obrigatória"),
}).refine(data => data.newPassword === data.confirmPassword, {
  message: "As senhas não conferem",
  path: ["confirmPassword"], // Campo onde o erro será exibido
});

export const confirmPasswordResetSchema = z.object({
  token: z.string().min(1, "Token obrigatório"),
  newPassword: passwordComplexitySchema,
});

export type ConfirmPasswordReset = z.infer<typeof confirmPasswordResetSchema>;

export const insertAssetSchema = createInsertSchema(assets).omit({
  id: true,
  createdAt: true,
  createdBy: true,
});

export const insertCredentialSchema = createInsertSchema(credentials).omit({
  id: true,
  createdAt: true,
  createdBy: true,
  secretEncrypted: true,
  dekEncrypted: true,
}).extend({
  secret: z.string().min(1, "Senha/chave é obrigatória"),
});

// Schema de validação para parâmetros de jornada Attack Surface
export const attackSurfaceParamsSchema = z.object({
  targets: z.array(z.string()).min(1, "Pelo menos um alvo é obrigatório"),
  credentials: z.array(z.string()).optional(),
  nmapProfile: z.enum(['leve', 'profundo', 'fast', 'comprehensive', 'stealth']).optional(), // fast/comprehensive/stealth são legados
  webScanEnabled: z.boolean().default(false), // Varredura web com Nuclei nas URLs HTTP/HTTPS descobertas
  vulnScriptTimeout: z.number().min(5).max(180).default(60), // Timeout por processo em minutos (5-180min)
});

// Schema de validação para parâmetros de jornada AD Security
export const adSecurityParamsSchema = z.object({
  domain: z.string().min(1, "Domínio é obrigatório"),
  credentialId: z.string().min(1, "Credencial é obrigatória"),
  primaryDC: z.string().ip("IP do DC primário inválido").optional(),
  secondaryDC: z.string().ip("IP do DC secundário inválido").optional(),
  enabledCategories: z.object({
    configuracoes_criticas: z.boolean().default(true),
    gerenciamento_contas: z.boolean().default(true),
    kerberos_delegacao: z.boolean().default(true),
    compartilhamentos_gpos: z.boolean().default(true),
    politicas_configuracao: z.boolean().default(true),
    contas_inativas: z.boolean().default(true),
  }).default({
    configuracoes_criticas: true,
    gerenciamento_contas: true,
    kerberos_delegacao: true,
    compartilhamentos_gpos: true,
    politicas_configuracao: true,
    contas_inativas: true,
  }),
});

export const insertJourneySchema = createInsertSchema(journeys).omit({
  id: true,
  createdAt: true,
  createdBy: true,
  updatedAt: true,
});

export const insertScheduleSchema = createInsertSchema(schedules).omit({
  id: true,
  createdAt: true,
  createdBy: true,
});

// Schema customizado para criação de agendamentos com validação condicional
export const createScheduleSchema = z.object({
  journeyId: z.string().min(1, "Jornada é obrigatória"),
  name: z.string().min(1, "Nome é obrigatório"),
  kind: z.enum(['on_demand', 'once', 'recurring'], {
    required_error: "Tipo de agendamento é obrigatório",
  }),
  // Campos para execução única
  onceAt: z.date().optional(),
  // Campos para execução recorrente
  recurrenceType: z.enum(['daily', 'weekly', 'monthly']).optional(),
  hour: z.number().min(0).max(23).optional(),
  minute: z.number().min(0).max(59).default(0),
  dayOfWeek: z.number().min(0).max(6).optional(), // 0=Sunday, 6=Saturday
  dayOfMonth: z.number().min(1).max(31).optional(),
  // Campos de intervalo customizado (Repetir a cada X)
  repeatInterval: z.number().min(1).optional(), // Número de unidades
  repeatUnit: z.enum(['hours', 'days']).optional(), // Unidade de tempo
  // Campos legados (mantidos para compatibilidade)
  cronExpression: z.string().optional(),
  lastExecutedAt: z.date().optional(),
  enabled: z.boolean().default(true),
}).refine(data => {
  // Validação para execução única
  if (data.kind === 'once') {
    return data.onceAt != null;
  }
  // Validação para execução recorrente
  if (data.kind === 'recurring') {
    if (!data.recurrenceType) return false;
    if (data.hour == null) return false;
    
    // Validação específica por tipo de recorrência
    if (data.recurrenceType === 'weekly' && data.dayOfWeek == null) return false;
    if (data.recurrenceType === 'monthly' && data.dayOfMonth == null) return false;
    
    // Se repeatInterval for fornecido, repeatUnit também deve ser
    if (data.repeatInterval != null && !data.repeatUnit) return false;
    if (data.repeatUnit != null && data.repeatInterval == null) return false;
  }
  return true;
}, {
  message: "Configuração de agendamento inválida",
  path: ["recurrenceType"],
});

export const insertJobSchema = createInsertSchema(jobs).omit({
  id: true,
  createdAt: true,
  startedAt: true,
  finishedAt: true,
});

export const insertHostSchema = createInsertSchema(hosts).omit({
  id: true,
  discoveredAt: true,
  updatedAt: true,
});

export const insertHostRiskHistorySchema = createInsertSchema(hostRiskHistory).omit({
  id: true,
  recordedAt: true,
});

export const insertAdSecurityTestResultSchema = createInsertSchema(adSecurityTestResults).omit({
  id: true,
  executedAt: true,
});

export const insertThreatSchema = createInsertSchema(threats).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertSettingSchema = createInsertSchema(settings).omit({
  id: true,
  updatedAt: true,
  updatedBy: true,
});

export const insertThreatStatusHistorySchema = createInsertSchema(threatStatusHistory).omit({
  id: true,
  changedAt: true,
});

// Schema for status change with justification
export const changeThreatStatusSchema = z.object({
  status: z.enum(['open', 'investigating', 'mitigated', 'hibernated', 'accepted_risk']),
  justification: z.string().min(10, "Justificativa deve ter pelo menos 10 caracteres"),
  hibernatedUntil: z.string().datetime().optional(), // ISO string for hibernated status
}).refine(data => {
  if (data.status === 'hibernated' && !data.hibernatedUntil) {
    return false;
  }
  return true;
}, {
  message: "Data limite é obrigatória para status hibernado",
  path: ["hibernatedUntil"],
});

// Email settings schemas
export const insertEmailSettingsSchema = createInsertSchema(emailSettings).omit({
  id: true,
  updatedAt: true,
  updatedBy: true,
  authPassword: true,
  dekEncrypted: true,
  oauth2ClientSecret: true,
  oauth2ClientSecretDek: true,
  oauth2RefreshToken: true,
  oauth2RefreshTokenDek: true,
}).extend({
  // Plain text fields for encryption (optional on updates)
  authPasswordPlain: z.string().optional(), // For password auth
  oauth2ClientSecretPlain: z.string().optional(), // For OAuth2
  oauth2RefreshTokenPlain: z.string().optional(), // For OAuth2
});

// Notification policy schemas
export const insertNotificationPolicySchema = createInsertSchema(notificationPolicies).omit({
  id: true,
  createdAt: true,
  createdBy: true,
  updatedAt: true,
}).extend({
  emailAddresses: z.array(z.string().email("Email inválido")).min(1, "Adicione pelo menos um email"),
  severities: z.array(z.enum(['low', 'medium', 'high', 'critical'])).min(1, "Selecione pelo menos uma severidade"),
  statuses: z.array(z.enum(['open', 'investigating', 'mitigated', 'hibernated', 'accepted_risk'])).min(1, "Selecione pelo menos um status"),
});

// Notification log schema
export const insertNotificationLogSchema = createInsertSchema(notificationLog).omit({
  id: true,
  sentAt: true,
});

// Active session schema
export const insertActiveSessionSchema = createInsertSchema(activeSessions).omit({
  id: true,
  createdAt: true,
  lastActivity: true,
});

// Login attempt schema
export const insertLoginAttemptSchema = createInsertSchema(loginAttempts).omit({
  id: true,
  createdAt: true,
});

// Journey credentials schema
export const insertJourneyCredentialSchema = createInsertSchema(journeyCredentials).omit({
  id: true,
  createdAt: true,
});

// Host enrichment schema
export const insertHostEnrichmentSchema = createInsertSchema(hostEnrichments).omit({
  id: true,
  collectedAt: true,
});

// Phase 2: Posture snapshot and recommendation schemas
export const insertPostureSnapshotSchema = createInsertSchema(postureSnapshots);
export const insertRecommendationSchema = createInsertSchema(recommendations);

// Types
export type UpsertUser = z.infer<typeof insertUserSchema>;
export type RegisterUser = z.infer<typeof registerUserSchema>;
export type LoginUser = z.infer<typeof loginUserSchema>;
export type ChangePassword = z.infer<typeof changePasswordSchema>;
export type User = typeof users.$inferSelect;
export type Asset = typeof assets.$inferSelect;
export type InsertAsset = z.infer<typeof insertAssetSchema>;
export type Credential = typeof credentials.$inferSelect;
export type InsertCredential = z.infer<typeof insertCredentialSchema>;
export type Journey = typeof journeys.$inferSelect;
export type InsertJourney = z.infer<typeof insertJourneySchema>;
export type Schedule = typeof schedules.$inferSelect;
export type InsertSchedule = z.infer<typeof insertScheduleSchema>;
export type CreateSchedule = z.infer<typeof createScheduleSchema>;
export type Job = typeof jobs.$inferSelect;
export type InsertJob = z.infer<typeof insertJobSchema>;
export type JobResult = typeof jobResults.$inferSelect;
export type Host = typeof hosts.$inferSelect;
export type InsertHost = z.infer<typeof insertHostSchema>;
export type HostRiskHistory = typeof hostRiskHistory.$inferSelect;
export type InsertHostRiskHistory = z.infer<typeof insertHostRiskHistorySchema>;
export type Threat = typeof threats.$inferSelect;
export type InsertThreat = z.infer<typeof insertThreatSchema>;
export type Setting = typeof settings.$inferSelect;
export type InsertSetting = z.infer<typeof insertSettingSchema>;
export type ThreatStatusHistory = typeof threatStatusHistory.$inferSelect;
export type InsertThreatStatusHistory = z.infer<typeof insertThreatStatusHistorySchema>;
export type ChangeThreatStatus = z.infer<typeof changeThreatStatusSchema>;
export type AuditLogEntry = typeof auditLog.$inferSelect;
export type EmailSettings = typeof emailSettings.$inferSelect;
export type InsertEmailSettings = z.infer<typeof insertEmailSettingsSchema>;
export type ActiveSession = typeof activeSessions.$inferSelect;
export type InsertActiveSession = z.infer<typeof insertActiveSessionSchema>;
export type LoginAttempt = typeof loginAttempts.$inferSelect;
export type InsertLoginAttempt = z.infer<typeof insertLoginAttemptSchema>;
export type NotificationPolicy = typeof notificationPolicies.$inferSelect;
export type InsertNotificationPolicy = z.infer<typeof insertNotificationPolicySchema>;
export type NotificationLog = typeof notificationLog.$inferSelect;
export type InsertNotificationLog = z.infer<typeof insertNotificationLogSchema>;
export type AdSecurityTestResult = typeof adSecurityTestResults.$inferSelect;
export type InsertAdSecurityTestResult = z.infer<typeof insertAdSecurityTestResultSchema>;
export type JourneyCredential = typeof journeyCredentials.$inferSelect;
export type InsertJourneyCredential = z.infer<typeof insertJourneyCredentialSchema>;
export type HostEnrichment = typeof hostEnrichments.$inferSelect;
export type InsertHostEnrichment = z.infer<typeof insertHostEnrichmentSchema>;
export type ApplianceSubscription = typeof applianceSubscription.$inferSelect;
// Phase 2: Posture snapshot and recommendation types
export type PostureSnapshot = typeof postureSnapshots.$inferSelect;
export type InsertPostureSnapshot = typeof postureSnapshots.$inferInsert;
export type Recommendation = typeof recommendations.$inferSelect;
export type InsertRecommendation = typeof recommendations.$inferInsert;

// Appliance commands — tracks commands received from console via heartbeat
export const commandStatusEnum = pgEnum("command_status", [
  "pending",     // Received from console, not yet started
  "running",     // Currently executing
  "completed",   // Successfully finished
  "failed",      // Execution failed
]);

export const applianceCommands = pgTable("appliance_commands", {
  id: varchar("id").primaryKey(),                          // UUID from console (dedup key)
  type: varchar("type").notNull(),                         // e.g. "system_update", "restart_service"
  params: jsonb("params").$type<Record<string, any>>().default({}),
  status: commandStatusEnum("status").default('pending').notNull(),
  receivedAt: timestamp("received_at").defaultNow().notNull(),
  startedAt: timestamp("started_at"),
  finishedAt: timestamp("finished_at"),
  result: jsonb("result").$type<Record<string, any>>(),    // Output data (version, logs, etc.)
  error: text("error"),
  reportedToConsole: boolean("reported_to_console").default(false).notNull(),
}, (table) => [
  index("idx_appliance_commands_status").on(table.status),
  index("idx_appliance_commands_reported").on(table.reportedToConsole),
]);

export type ApplianceCommand = typeof applianceCommands.$inferSelect;

export const mfaEmailChallenges = pgTable("mfa_email_challenges", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").references(() => users.id, { onDelete: 'cascade' }).notNull(),
  codeHash: text("code_hash").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  consumedAt: timestamp("consumed_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => [
  index("idx_mfa_email_challenges_user_active").on(table.userId, table.expiresAt),
]);

export type MfaEmailChallenge = typeof mfaEmailChallenges.$inferSelect;
export type InsertMfaEmailChallenge = typeof mfaEmailChallenges.$inferInsert;

export const passwordResetTokens = pgTable("password_reset_tokens", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").references(() => users.id, { onDelete: 'cascade' }).notNull(),
  tokenHash: text("token_hash").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  consumedAt: timestamp("consumed_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => [
  index("idx_password_reset_tokens_user_active").on(table.userId, table.expiresAt),
]);

export type PasswordResetToken = typeof passwordResetTokens.$inferSelect;
export type InsertPasswordResetToken = typeof passwordResetTokens.$inferInsert;

// ============================================================================
// Phase 9: API Discovery & Security Assessment — HIER-01, HIER-02, FIND-01
// ============================================================================

// Shape validated by apiFindingEvidenceSchema below — JSONB shape is:
//   { request: {method, url, headers?, bodySnippet?},
//     response: {status, headers?, bodySnippet?},
//     extractedValues?, context? }
// bodySnippet (not body) is defensive naming — Phase 14 will truncate to 8KB.
export interface ApiFindingEvidence {
  request: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    bodySnippet?: string;
  };
  response: {
    status: number;
    headers?: Record<string, string>;
    bodySnippet?: string;
  };
  extractedValues?: Record<string, unknown>;
  context?: string;
}

// apis table — HIER-01, HIER-03. Parent is always type='web_application' (validated at route layer).
export const apis = pgTable("apis", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  parentAssetId: varchar("parent_asset_id")
    .references(() => assets.id, { onDelete: 'cascade' }).notNull(),
  baseUrl: text("base_url").notNull(),
  apiType: apiTypeEnum("api_type").notNull(),
  name: text("name"),
  description: text("description"),
  specUrl: text("spec_url"),
  specHash: text("spec_hash"),                // populated Phase 11 (DISC-06)
  specVersion: text("spec_version"),          // populated Phase 11
  specLastFetchedAt: timestamp("spec_last_fetched_at"), // populated Phase 11
  createdAt: timestamp("created_at").defaultNow().notNull(),
  createdBy: varchar("created_by").references(() => users.id).notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
}, (table) => [
  uniqueIndex("UQ_apis_parent_base_url").on(table.parentAssetId, table.baseUrl),
  index("IDX_apis_parent_asset_id").on(table.parentAssetId),
]);

export type Api = typeof apis.$inferSelect;
export type InsertApi = typeof apis.$inferInsert;

// api_endpoints table — HIER-02. CHECK on method; tri-valor requiresAuth; text[] discoverySources.
export const apiEndpoints = pgTable("api_endpoints", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  apiId: varchar("api_id").references(() => apis.id, { onDelete: 'cascade' }).notNull(),
  method: text("method").notNull(),
  path: text("path").notNull(),
  pathParams: jsonb("path_params")
    .$type<Array<{ name: string; type?: string; required?: boolean; example?: unknown }>>()
    .default([]).notNull(),
  queryParams: jsonb("query_params")
    .$type<Array<{ name: string; type?: string; required?: boolean; example?: unknown }>>()
    .default([]).notNull(),
  headerParams: jsonb("header_params")
    .$type<Array<{ name: string; type?: string; required?: boolean; example?: unknown }>>()
    .default([]).notNull(),
  requestSchema: jsonb("request_schema").$type<Record<string, unknown>>(),   // populated Phase 11
  responseSchema: jsonb("response_schema").$type<Record<string, unknown>>(), // populated Phase 11
  // tri-valor: NULL=not probed, true=401/403, false=open (ENRH-02 populates in Phase 11).
  requiresAuth: boolean("requires_auth"),
  // Allowed values: 'spec' | 'crawler' | 'kiterunner' | 'manual' (see shared/owaspApiCategories.ts DISCOVERY_SOURCES).
  discoverySources: text("discovery_sources").array()
    .$type<Array<'spec' | 'crawler' | 'kiterunner' | 'manual'>>()
    .notNull().default(sql`ARRAY[]::text[]`),
  // Phase 11 ENRH-01 — httpx enrichment columns (additive, all nullable).
  // Populated by httpx.ts scanner on every discovery run; NULL means unprobed.
  httpxStatus: integer("httpx_status"),
  httpxContentType: text("httpx_content_type"),
  httpxTech: text("httpx_tech").array().$type<string[]>(),
  httpxTls: jsonb("httpx_tls").$type<{
    host?: string;
    port?: number;
    tls_version?: string;
    cipher?: string;
    not_after?: string;
    not_before?: string;
    subject_cn?: string;
    subject_san?: string[];
    issuer_cn?: string;
  }>(),
  httpxLastProbedAt: timestamp("httpx_last_probed_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
}, (table) => [
  uniqueIndex("UQ_api_endpoints_api_method_path").on(table.apiId, table.method, table.path),
  index("IDX_api_endpoints_api_id").on(table.apiId),
  check(
    "CK_api_endpoints_method",
    sql`${table.method} IN ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS')`,
  ),
]);

export type ApiEndpoint = typeof apiEndpoints.$inferSelect;
export type InsertApiEndpoint = typeof apiEndpoints.$inferInsert;

// api_findings table — FIND-01. Reuses threatSeverityEnum; promotedThreatId populated by Phase 14 FIND-03.
export const apiFindings = pgTable("api_findings", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  apiEndpointId: varchar("api_endpoint_id")
    .references(() => apiEndpoints.id, { onDelete: 'cascade' }).notNull(),
  jobId: varchar("job_id").references(() => jobs.id), // nullable: manual findings have no job
  owaspCategory: owaspApiCategoryEnum("owasp_category").notNull(),
  severity: threatSeverityEnum("severity").notNull(),
  status: apiFindingStatusEnum("status").default('open').notNull(),
  title: text("title").notNull(),
  description: text("description"),
  remediation: text("remediation"),
  riskScore: real("risk_score"), // 0-100, null until Phase 12+ scoringEngine runs
  evidence: jsonb("evidence").$type<ApiFindingEvidence>().default(sql`'{}'::jsonb`).notNull(),
  // Phase 14 FIND-03 will populate; created now to avoid double migration.
  promotedThreatId: varchar("promoted_threat_id")
    .references(() => threats.id, { onDelete: 'set null' }),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
}, (table) => [
  index("IDX_api_findings_endpoint_id").on(table.apiEndpointId),
  index("IDX_api_findings_job_id").on(table.jobId),
  index("IDX_api_findings_owasp_category").on(table.owaspCategory),
  index("IDX_api_findings_severity").on(table.severity),
  index("IDX_api_findings_status").on(table.status),
]);

export type ApiFinding = typeof apiFindings.$inferSelect;
export type InsertApiFinding = typeof apiFindings.$inferInsert;

// Phase 10 — API Credentials (CRED-01..05)
// Tabela isolada — NÃO estende `credentials` legada (ssh/wmi/omi/ad).
// Secrets cifrados via encryptionService (KEK/DEK existente, AES-256-GCM).
export const apiCredentials = pgTable("api_credentials", {
  // --- identidade ---
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  description: text("description"),
  authType: apiAuthTypeEnum("auth_type").notNull(),

  // --- mapeamento (CRED-03, CRED-04) ---
  urlPattern: text("url_pattern").notNull().default("*"),
  priority: integer("priority").notNull().default(100),
  apiId: varchar("api_id").references(() => apis.id, { onDelete: "set null" }),

  // --- crypto (CRED-02) ---
  secretEncrypted: text("secret_encrypted").notNull(),
  dekEncrypted: text("dek_encrypted").notNull(),

  // --- por auth type (nullable, validados via Zod discriminated union) ---
  apiKeyHeaderName: text("api_key_header_name"),
  apiKeyQueryParam: text("api_key_query_param"),
  basicUsername: text("basic_username"),
  bearerExpiresAt: timestamp("bearer_expires_at"),
  oauth2ClientId: text("oauth2_client_id"),
  oauth2TokenUrl: text("oauth2_token_url"),
  oauth2Scope: text("oauth2_scope"),
  oauth2Audience: text("oauth2_audience"),
  hmacKeyId: text("hmac_key_id"),
  hmacAlgorithm: text("hmac_algorithm"), // HMAC-SHA1 | HMAC-SHA256 | HMAC-SHA512
  hmacSignatureHeader: text("hmac_signature_header"),
  hmacSignedHeaders: text("hmac_signed_headers").array(),
  hmacCanonicalTemplate: text("hmac_canonical_template"),

  // --- auditoria ---
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
  createdBy: varchar("created_by").references(() => users.id).notNull(),
  updatedBy: varchar("updated_by").references(() => users.id),
}, (table) => [
  index("IDX_api_credentials_api_id").on(table.apiId),
  index("IDX_api_credentials_priority").on(table.priority),
  uniqueIndex("UQ_api_credentials_name_created_by").on(table.name, table.createdBy),
]);

export const apiCredentialsRelations = relations(apiCredentials, ({ one }) => ({
  api: one(apis, {
    fields: [apiCredentials.apiId],
    references: [apis.id],
  }),
  creator: one(users, {
    fields: [apiCredentials.createdBy],
    references: [users.id],
    relationName: "apiCredentialCreator",
  }),
  updater: one(users, {
    fields: [apiCredentials.updatedBy],
    references: [users.id],
    relationName: "apiCredentialUpdater",
  }),
}));

// Phase 10 — Discriminated union para insert de api_credentials (CRED-01)
// Armadilha 2 do RESEARCH: TODOS os campos por-tipo são omitidos do baseInsert
// para que cada variante REJEITE campos de outros tipos.
const baseInsertApiCredential = createInsertSchema(apiCredentials).omit({
  id: true,
  secretEncrypted: true,
  dekEncrypted: true,
  createdAt: true,
  updatedAt: true,
  createdBy: true,
  updatedBy: true,
  bearerExpiresAt: true, // derivado no backend a partir do JWT exp
  // Campos por-tipo — omitir do base, adicionar SO na variante correta:
  apiKeyHeaderName: true,
  apiKeyQueryParam: true,
  basicUsername: true,
  oauth2ClientId: true,
  oauth2TokenUrl: true,
  oauth2Scope: true,
  oauth2Audience: true,
  hmacKeyId: true,
  hmacAlgorithm: true,
  hmacSignatureHeader: true,
  hmacSignedHeaders: true,
  hmacCanonicalTemplate: true,
}).strict();

// Regex PEM compartilhado (mTLS)
const PEM_REGEX = /-----BEGIN [A-Z ]+-----[\s\S]+-----END [A-Z ]+-----/;

export const insertApiCredentialSchema = z.discriminatedUnion("authType", [
  baseInsertApiCredential.extend({
    authType: z.literal("api_key_header"),
    apiKeyHeaderName: z.string().min(1, "Nome do header é obrigatório"),
    secret: z.string().min(1, "API key é obrigatória"),
  }),
  baseInsertApiCredential.extend({
    authType: z.literal("api_key_query"),
    apiKeyQueryParam: z.string().min(1, "Parâmetro de query é obrigatório"),
    secret: z.string().min(1, "API key é obrigatória"),
  }),
  baseInsertApiCredential.extend({
    authType: z.literal("bearer_jwt"),
    secret: z.string().min(1, "JWT é obrigatório"),
  }),
  baseInsertApiCredential.extend({
    authType: z.literal("basic"),
    basicUsername: z.string().min(1, "Username é obrigatório"),
    secret: z.string().min(1, "Senha é obrigatória"),
  }),
  baseInsertApiCredential.extend({
    authType: z.literal("oauth2_client_credentials"),
    oauth2ClientId: z.string().min(1, "Client ID é obrigatório"),
    oauth2TokenUrl: z.string().url("Token URL inválida"),
    oauth2Scope: z.string().optional(),
    oauth2Audience: z.string().optional(),
    secret: z.string().min(1, "Client secret é obrigatório"),
  }),
  baseInsertApiCredential.extend({
    authType: z.literal("hmac"),
    hmacKeyId: z.string().min(1, "Key ID é obrigatório"),
    hmacAlgorithm: z.enum(["HMAC-SHA1", "HMAC-SHA256", "HMAC-SHA512"]),
    hmacSignatureHeader: z.string().default("Authorization"),
    hmacSignedHeaders: z.array(z.string()).default([]),
    hmacCanonicalTemplate: z.string().nullable().optional(),
    secret: z.string().min(1, "HMAC secret key é obrigatória"),
  }),
  baseInsertApiCredential.extend({
    authType: z.literal("mtls"),
    mtlsCert: z.string().regex(PEM_REGEX, "Certificado PEM inválido"),
    mtlsKey: z.string().regex(PEM_REGEX, "Chave PEM inválida"),
    mtlsCa: z.string().regex(PEM_REGEX, "CA PEM inválida").nullable().optional(),
  }),
]);

// Schema de PATCH — flat com todos campos opcionais, exceto authType (imutável).
// Ver Pergunta em Aberto #3 do RESEARCH: discriminated union .partial() não é nativo.
export const patchApiCredentialSchema = z.object({
  name: z.string().min(1).optional(),
  description: z.string().nullable().optional(),
  urlPattern: z.string().min(1).optional(),
  priority: z.number().int().optional(),
  apiId: z.string().nullable().optional(),
  // Campos por-tipo — todos opcionais; rota valida que não cruzam authType
  apiKeyHeaderName: z.string().min(1).optional(),
  apiKeyQueryParam: z.string().min(1).optional(),
  basicUsername: z.string().min(1).optional(),
  oauth2ClientId: z.string().min(1).optional(),
  oauth2TokenUrl: z.string().url().optional(),
  oauth2Scope: z.string().optional(),
  oauth2Audience: z.string().optional(),
  hmacKeyId: z.string().min(1).optional(),
  hmacAlgorithm: z.enum(["HMAC-SHA1", "HMAC-SHA256", "HMAC-SHA512"]).optional(),
  hmacSignatureHeader: z.string().optional(),
  hmacSignedHeaders: z.array(z.string()).optional(),
  hmacCanonicalTemplate: z.string().nullable().optional(),
  // Re-encrypt do secret se passado
  secret: z.string().min(1).optional(),
  mtlsCert: z.string().regex(PEM_REGEX).optional(),
  mtlsKey: z.string().regex(PEM_REGEX).optional(),
  mtlsCa: z.string().regex(PEM_REGEX).nullable().optional(),
});

// Phase 10 — Tipos derivados de api_credentials
export type ApiCredential = typeof apiCredentials.$inferSelect;
export type InsertApiCredential = z.infer<typeof insertApiCredentialSchema>;
export type PatchApiCredential = z.infer<typeof patchApiCredentialSchema>;
export type ApiAuthType = ApiCredential["authType"];

// Shape sanitizado retornado por listApiCredentials/getApiCredential (sem secret*/dek*)
export type ApiCredentialSafe = Omit<ApiCredential, "secretEncrypted" | "dekEncrypted">;

// Shape interno usado SO pelo executor (Phase 11+) via getApiCredentialWithSecret
export type ApiCredentialWithSecret = ApiCredential;

// API contract types for appliance ↔ console communication
export const activateApplianceSchema = z.object({
  apiKey: z.string().min(1, "Chave de API é obrigatória"),
  consoleUrl: z.string().url("URL da console inválida").min(1, "URL da console é obrigatória"),
});

// Schema for command results reported by appliance back to console
export const commandResultSchema = z.object({
  id: z.string(),
  status: z.enum(['acknowledged', 'completed', 'failed']),
  result: z.record(z.string(), z.any()).optional(),
  error: z.string().optional(),
  startedAt: z.string().datetime().optional(),
  finishedAt: z.string().datetime().optional(),
});

// Phase 9 Zod schemas --- HIER-03 + FIND-01

// Evidence JSONB shape — Zod-validated, strict (rejects unknown keys).
// Phase 14 FIND-02 will further sanitize (redact auth headers, PII, truncate to 8KB).
export const apiFindingEvidenceSchema = z.object({
  request: z.object({
    method: z.string().min(1),
    url: z.string().url(),
    headers: z.record(z.string()).optional(),
    bodySnippet: z.string().max(8192).optional(),
  }),
  response: z.object({
    status: z.number().int().min(100).max(599),
    headers: z.record(z.string()).optional(),
    bodySnippet: z.string().max(8192).optional(),
  }),
  extractedValues: z.record(z.unknown()).optional(),
  context: z.string().optional(),
}).strict();

export type ApiFindingEvidenceInput = z.infer<typeof apiFindingEvidenceSchema>;

// POST /api/v1/apis body — HIER-03. parentAssetId/baseUrl shape validated here;
// parent.type='web_application' check is in the route (Zod cannot cross-DB validate).
export const insertApiSchema = createInsertSchema(apis).omit({
  id: true, createdAt: true, createdBy: true, updatedAt: true,
  specHash: true, specVersion: true, specLastFetchedAt: true,
}).extend({
  parentAssetId: z.string().uuid("ID de ativo pai inválido"),
  baseUrl: z.string().url("URL base inválida"),
  apiType: z.enum(['rest', 'graphql', 'soap']),
});

// Endpoint creation — used by Phase 11 discovery writers.
export const insertApiEndpointSchema = createInsertSchema(apiEndpoints).omit({
  id: true, createdAt: true, updatedAt: true,
});

// Finding creation — evidence is strictly Zod-validated.
export const insertApiFindingSchema = createInsertSchema(apiFindings, {
  evidence: apiFindingEvidenceSchema,
}).omit({
  id: true, createdAt: true, updatedAt: true,
  promotedThreatId: true, riskScore: true,
});

export const heartbeatRequestSchema = z.object({
  applianceId: z.string(),
  version: z.string(),
  timestamp: z.string().datetime(),
  system: z.object({
    cpu: z.object({
      percent: z.number(),
    }).optional(),
    memory: z.object({
      percent: z.number(),
      usedMb: z.number().int(),
      totalMb: z.number().int(),
    }).optional(),
    disk: z.object({
      percent: z.number(),
      usedGb: z.number(),
      totalGb: z.number(),
    }).optional(),
    network: z.object({
      inBps: z.number().int(),
      outBps: z.number().int(),
    }).optional(),
    services: z.array(z.object({
      name: z.string(),
      status: z.string(),
      uptime: z.number().int(),
    })).optional(),
  }).optional(),
  performance: z.object({
    uptimeSeconds: z.number(),
    hostCount: z.number(),
    assetCount: z.number(),
  }),
  threatStats: z.object({
    total: z.number(),
    bySeverity: z.object({
      critical: z.number(),
      high: z.number(),
      medium: z.number(),
      low: z.number(),
    }),
    byCategory: z.record(z.string(), z.number()),
    byStatus: z.record(z.string(), z.number()),
  }),
  usage: z.object({
    activeUsers24h: z.number(),
    jobsExecuted24h: z.number(),
    loginsToday: z.number(),
  }),
  identity: z.object({
    applianceName: z.string().max(100),
    locationType: z.string().max(50),
    locationDetail: z.string().max(200),
  }).optional(),
  commandResults: z.array(commandResultSchema).optional(),
});

// Schema for commands sent by console to appliance via heartbeat response
export const consoleCommandSchema = z.object({
  id: z.string(),
  type: z.string(),
  params: z.record(z.string(), z.any()).optional(),
});

export const heartbeatResponseSchema = z.object({
  subscription: z.object({
    active: z.boolean(),
    plan: z.string(),
    expiresAt: z.string().datetime().nullable(),
    features: z.array(z.string()),
    tenantId: z.string().optional(),
    tenantName: z.string().optional(),
    message: z.string().nullable().optional(),
  }),
  commands: z.array(consoleCommandSchema).optional(),
});

export type ActivateAppliance = z.infer<typeof activateApplianceSchema>;
export type HeartbeatRequest = z.infer<typeof heartbeatRequestSchema>;
export type HeartbeatResponse = z.infer<typeof heartbeatResponseSchema>;
export type ConsoleCommand = z.infer<typeof consoleCommandSchema>;

// ─────────────────────────────────────────────────────────────────────────────
// NormalizedFinding discriminated union — Phase 1: Parser Foundation
// These schemas are NOT Drizzle tables; they represent parsed scanner output.
// ─────────────────────────────────────────────────────────────────────────────

export const BaseFindingSchema = z.object({
  type: z.string(),
  target: z.string(),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  timestamp: z.string().datetime().optional(),
});

export const NseScriptSchema = z.object({
  id: z.string(),
  output: z.string(),
  cves: z.array(z.string()).optional(),
  exploitState: z.string().optional(),
  tables: z.record(z.unknown()).optional(),
});

export const NmapFindingSchema = BaseFindingSchema.extend({
  type: z.literal('port'),
  ip: z.string().optional(),
  port: z.string(),
  state: z.enum(['open', 'closed', 'filtered']),
  service: z.string(),
  product: z.string().optional(),
  version: z.string().optional(),
  extrainfo: z.string().optional(),
  serviceCpe: z.string().optional(),
  osName: z.string().optional(),
  osAccuracy: z.number().optional(),
  osCpe: z.array(z.string()).optional(),
  nseScripts: z.array(NseScriptSchema).optional(),
  banner: z.string().optional(),
  osInfo: z.string().optional(),
}).strip();

/**
 * NmapVulnFindingSchema — same shape as NmapFindingSchema but with
 * type literal 'nmap_vuln'. Preserves compatibility with threatEngine
 * rule 'cve-detected' which matches on finding.type === 'nmap_vuln'.
 */
export const NmapVulnFindingSchema = BaseFindingSchema.extend({
  type: z.literal('nmap_vuln'),
  ip: z.string().optional(),
  port: z.string(),
  state: z.enum(['open', 'closed', 'filtered']),
  service: z.string(),
  product: z.string().optional(),
  version: z.string().optional(),
  extrainfo: z.string().optional(),
  serviceCpe: z.string().optional(),
  osName: z.string().optional(),
  osAccuracy: z.number().optional(),
  osCpe: z.array(z.string()).optional(),
  nseScripts: z.array(NseScriptSchema).optional(),
  banner: z.string().optional(),
  osInfo: z.string().optional(),
}).strip();

export type BaseFinding = z.infer<typeof BaseFindingSchema>;
export type NseScript = z.infer<typeof NseScriptSchema>;
export type NmapFinding = z.infer<typeof NmapFindingSchema>;
export type NmapVulnFinding = z.infer<typeof NmapVulnFindingSchema>;

/**
 * NucleiFindingSchema — Zod-validated nuclei JSONL output shape.
 * PARS-05: every line goes through safeParse; bad lines are logged and skipped.
 * PARS-06: matcher-name, extracted-results, curl-command, and template tags captured.
 */
export const NucleiFindingSchema = BaseFindingSchema.extend({
  type: z.literal('nuclei'),
  templateId: z.string(),
  matchedAt: z.string(),
  matcherName: z.string().optional(),        // PARS-06: matcher-name
  extractedResults: z.array(z.string()).optional(), // PARS-06: extracted-results
  curlCommand: z.string().optional(),        // PARS-06: curl-command
  info: z.object({
    name: z.string(),
    severity: z.string(),
    description: z.string().optional(),
    tags: z.array(z.string()).optional(),
    classification: z.object({
      cveId: z.array(z.string()).optional(),
      cweId: z.array(z.string()).optional(),
    }).optional(),
    references: z.array(z.string()).optional(),
    remediation: z.string().optional(),
  }),
  host: z.string().optional(),
  port: z.string().optional(),
}).strip();

export type NucleiFinding = z.infer<typeof NucleiFindingSchema>;
export type CommandResult = z.infer<typeof commandResultSchema>;

// ─────────────────────────────────────────────────────────────────────────────
// EdrTimelineEventSchema — per-host timeline event for EDR/AV test (PARS-09)
// ─────────────────────────────────────────────────────────────────────────────
export const EdrTimelineEventSchema = z.object({
  timestamp: z.string(), // ISO-8601
  action: z.enum([
    'deploy_attempt',
    'deploy_success',
    'detected',
    'not_detected',
    'timeout',
    'cleanup',
  ]),
  detail: z.string(),
  share: z.string().optional(),
});

export type EdrTimelineEvent = z.infer<typeof EdrTimelineEventSchema>;

// ─────────────────────────────────────────────────────────────────────────────
// EdrFindingSchema — EDR/AV test result with timeline (PARS-09, PARS-10)
// ─────────────────────────────────────────────────────────────────────────────
export const EdrFindingSchema = BaseFindingSchema.extend({
  type: z.literal('edr_test'),
  hostname: z.string(),
  eicarRemoved: z.boolean().nullable(),
  testDuration: z.number(),
  deploymentMethod: z.string(),
  filePath: z.string().optional(),
  share: z.string().optional(),
  error: z.string().optional(),
  timeline: z.array(EdrTimelineEventSchema),
  sampleRate: z.number().optional(),
  detected: z.boolean().nullable(),
  // PARS-09: explicit per-host timestamps
  deploymentTimestamp: z.string().optional(),  // ISO-8601, from first deploy_success event
  detectionTimestamp: z.string().optional(),   // ISO-8601, from detected event; null when not detected
}).strip();

export type EdrFinding = z.infer<typeof EdrFindingSchema>;

// ─────────────────────────────────────────────────────────────────────────────
// AdFindingSchema — typed AD security finding output (PARS-07, PARS-08, PARS-10)
// ─────────────────────────────────────────────────────────────────────────────
export const AdFindingSchema = BaseFindingSchema.extend({
  type: z.literal('ad_finding'),
  checkId: z.string(),
  checkName: z.string(),
  details: z.string().optional(),
  groupMembership: z.array(z.string()).optional(), // PARS-08: ordered chain
  gpoLinks: z.array(
    z.object({
      name: z.string(),
      path: z.string(),
      enabled: z.boolean().optional(),
    })
  ).optional(), // PARS-08: structured GPO links
  trustAttributes: z.object({
    direction: z.string(),
    type: z.string(),
    transitivity: z.string().optional(),
  }).optional(), // PARS-08: typed trust attributes
  uacFlags: z.array(
    z.object({
      flag: z.string(),
      risk: z.string(),
    })
  ).optional(),
  rawData: z.record(z.unknown()).optional(), // fallback for full PS output
}).strip();

export type AdFinding = z.infer<typeof AdFindingSchema>;

// ─────────────────────────────────────────────────────────────────────────────
// NormalizedFinding — discriminated union of all 4 parser types (PARS-10)
// ─────────────────────────────────────────────────────────────────────────────
export const NormalizedFindingSchema = z.discriminatedUnion('type', [
  NmapFindingSchema,
  NmapVulnFindingSchema,
  NucleiFindingSchema,
  AdFindingSchema,
  EdrFindingSchema,
]);

export type NormalizedFinding = z.infer<typeof NormalizedFindingSchema>;

// ─────────────────────────────────────────────────────────────────────────────
// Phase 11 DISC/ENRH — discoverApiOptsSchema
// opts for discoverApi(apiId, opts, jobId?) + POST /api/v1/apis/:id/discover.
// Zod schema; .strict() rejects unknown top-level fields. Defaults applied here
// so the orchestrator never observes undefined stages.
// ─────────────────────────────────────────────────────────────────────────────
export const discoverApiOptsSchema = z.object({
  stages: z.object({
    spec: z.boolean().default(true),
    crawler: z.boolean().default(true),
    kiterunner: z.boolean().default(false),  // opt-in per DISC-05
    httpx: z.boolean().default(true),
    arjun: z.boolean().default(false),        // opt-in per ENRH-03
  }).strict().default({}),
  arjunEndpointIds: z.array(z.string().uuid()).min(1).optional(),
  credentialIdOverride: z.string().uuid().optional(),
  dryRun: z.boolean().default(false),
  katana: z.object({
    headless: z.boolean().optional(),
    depth: z.number().int().min(1).max(10).optional(),
  }).strict().optional(),
  kiterunner: z.object({
    rateLimit: z.number().int().min(1).max(50).optional(),
  }).strict().optional(),
}).strict().superRefine((data, ctx) => {
  // Arjun stage requires arjunEndpointIds — enforced here because the field is
  // optional at the schema level (undefined is valid when stages.arjun=false).
  if (data.stages?.arjun === true && (!data.arjunEndpointIds || data.arjunEndpointIds.length === 0)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'arjunEndpointIds é obrigatório quando stages.arjun=true',
      path: ['arjunEndpointIds'],
    });
  }
});

export type DiscoverApiOpts = z.infer<typeof discoverApiOptsSchema>;
