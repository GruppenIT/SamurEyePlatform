import { sql } from 'drizzle-orm';
import { relations } from 'drizzle-orm';
import {
  index,
  jsonb,
  pgTable,
  timestamp,
  varchar,
  text,
  integer,
  boolean,
  pgEnum,
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
export const assetTypeEnum = pgEnum('asset_type', ['host', 'range']);

// Credential types enum
export const credentialTypeEnum = pgEnum('credential_type', ['ssh', 'wmi', 'omi', 'ad']);

// Journey types enum
export const journeyTypeEnum = pgEnum('journey_type', ['attack_surface', 'ad_hygiene', 'edr_av']);

// Schedule kinds enum
export const scheduleKindEnum = pgEnum('schedule_kind', ['on_demand', 'once', 'recurring']);

// Job status enum
export const jobStatusEnum = pgEnum('job_status', ['pending', 'running', 'completed', 'failed', 'timeout']);

// Threat severity enum
export const threatSeverityEnum = pgEnum('threat_severity', ['low', 'medium', 'high', 'critical']);

// Threat status enum
export const threatStatusEnum = pgEnum('threat_status', ['open', 'investigating', 'mitigated', 'closed', 'hibernated']);

// Host types enum
export const hostTypeEnum = pgEnum('host_type', ['server', 'desktop', 'firewall', 'switch', 'router', 'domain', 'other']);

// Host families enum  
export const hostFamilyEnum = pgEnum('host_family', ['linux', 'windows_server', 'windows_desktop', 'fortios', 'network_os', 'other']);

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
  createdAt: timestamp("created_at").defaultNow().notNull(),
  createdBy: varchar("created_by").references(() => users.id).notNull(),
});

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

// Journeys table
export const journeys = pgTable("journeys", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: varchar("name").notNull(),
  type: journeyTypeEnum("type").notNull(),
  description: text("description"),
  params: jsonb("params").$type<Record<string, any>>().default({}).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  createdBy: varchar("created_by").references(() => users.id).notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// Schedules table
export const schedules = pgTable("schedules", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  journeyId: varchar("journey_id").references(() => journeys.id).notNull(),
  name: varchar("name").notNull(),
  kind: scheduleKindEnum("kind").notNull(),
  cronExpression: text("cron_expression"), // For recurring schedules
  onceAt: timestamp("once_at"), // For one-time schedules
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
  discoveredAt: timestamp("discovered_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
}, (table) => [
  index("IDX_hosts_name").on(table.name),
  index("IDX_hosts_type").on(table.type),
]);

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
}, (table) => [
  index("IDX_threats_correlation_key").on(table.correlationKey),
  index("IDX_threats_host_id").on(table.hostId),
  index("IDX_threats_status").on(table.status),
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
  createdBy: one(users, {
    fields: [assets.createdBy],
    references: [users.id],
  }),
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

// Insert schemas
export const insertUserSchema = createInsertSchema(users).omit({
  id: true,
  passwordHash: true,
  mustChangePassword: true, // Security: não expor via API pública
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

// Schema para troca de senha
export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, "Senha atual é obrigatória"),
  newPassword: z.string().min(12, "Nova senha deve ter pelo menos 12 caracteres")
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])/, 
      "Nova senha deve conter ao menos: 1 minúscula, 1 maiúscula, 1 número e 1 símbolo especial"),
  confirmPassword: z.string().min(1, "Confirmação de senha é obrigatória"),
}).refine(data => data.newPassword === data.confirmPassword, {
  message: "As senhas não conferem",
  path: ["confirmPassword"], // Campo onde o erro será exibido
});

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
  status: z.enum(['open', 'investigating', 'mitigated', 'closed', 'hibernated']),
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
export type Job = typeof jobs.$inferSelect;
export type InsertJob = z.infer<typeof insertJobSchema>;
export type JobResult = typeof jobResults.$inferSelect;
export type Host = typeof hosts.$inferSelect;
export type InsertHost = z.infer<typeof insertHostSchema>;
export type Threat = typeof threats.$inferSelect;
export type InsertThreat = z.infer<typeof insertThreatSchema>;
export type Setting = typeof settings.$inferSelect;
export type InsertSetting = z.infer<typeof insertSettingSchema>;
export type ThreatStatusHistory = typeof threatStatusHistory.$inferSelect;
export type InsertThreatStatusHistory = z.infer<typeof insertThreatStatusHistorySchema>;
export type ChangeThreatStatus = z.infer<typeof changeThreatStatusSchema>;
export type AuditLogEntry = typeof auditLog.$inferSelect;
