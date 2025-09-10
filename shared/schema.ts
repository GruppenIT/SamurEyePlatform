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
export const threatStatusEnum = pgEnum('threat_status', ['open', 'investigating', 'mitigated', 'closed']);

// Users table
export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: varchar("email").unique(),
  firstName: varchar("first_name"),
  lastName: varchar("last_name"),
  profileImageUrl: varchar("profile_image_url"),
  role: userRoleEnum("role").default('read_only').notNull(),
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

// Threats table
export const threats = pgTable("threats", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  title: text("title").notNull(),
  description: text("description"),
  severity: threatSeverityEnum("severity").notNull(),
  status: threatStatusEnum("status").default('open').notNull(),
  source: text("source").notNull(), // e.g., 'journey', 'manual'
  assetId: varchar("asset_id").references(() => assets.id),
  evidence: jsonb("evidence").$type<Record<string, any>>().default({}).notNull(),
  jobId: varchar("job_id").references(() => jobs.id),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
  assignedTo: varchar("assigned_to").references(() => users.id),
});

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

export const threatsRelations = relations(threats, ({ one }) => ({
  asset: one(assets, {
    fields: [threats.assetId],
    references: [assets.id],
  }),
  job: one(jobs, {
    fields: [threats.jobId],
    references: [jobs.id],
  }),
  assignedTo: one(users, {
    fields: [threats.assignedTo],
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
  createdAt: true,
  updatedAt: true,
  lastLogin: true,
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

// Types
export type UpsertUser = z.infer<typeof insertUserSchema>;
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
export type Threat = typeof threats.$inferSelect;
export type InsertThreat = z.infer<typeof insertThreatSchema>;
export type Setting = typeof settings.$inferSelect;
export type InsertSetting = z.infer<typeof insertSettingSchema>;
export type AuditLogEntry = typeof auditLog.$inferSelect;
