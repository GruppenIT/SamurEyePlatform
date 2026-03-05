// REDIGIDO PARA DEPOSITO INPI (sem segredos)
// Schema do banco de dados PostgreSQL - Drizzle ORM (shared/schema.ts)
// Define todas as tabelas, enums, relacoes e schemas de validacao Zod

import { sql } from 'drizzle-orm';
import { relations } from 'drizzle-orm';
import {
  index, uniqueIndex, jsonb, pgTable, timestamp, varchar,
  text, integer, boolean, pgEnum, real,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// === ENUMS ===
export const userRoleEnum = pgEnum('user_role', ['global_administrator', 'operator', 'read_only']);
export const assetTypeEnum = pgEnum('asset_type', ['host', 'range', 'web_application']);
export const credentialTypeEnum = pgEnum('credential_type', ['ssh', 'wmi', 'omi', 'ad']);
export const journeyTypeEnum = pgEnum('journey_type', ['attack_surface', 'ad_security', 'edr_av', 'web_application']);
export const scheduleKindEnum = pgEnum('schedule_kind', ['on_demand', 'once', 'recurring']);
export const recurrenceTypeEnum = pgEnum('recurrence_type', ['daily', 'weekly', 'monthly']);
export const jobStatusEnum = pgEnum('job_status', ['pending', 'running', 'completed', 'failed', 'timeout']);
export const threatSeverityEnum = pgEnum('threat_severity', ['low', 'medium', 'high', 'critical']);
export const threatStatusEnum = pgEnum('threat_status', ['open', 'investigating', 'mitigated', 'closed', 'hibernated', 'accepted_risk']);
export const emailAuthTypeEnum = pgEnum('email_auth_type', ['password', 'oauth2_gmail', 'oauth2_microsoft']);
export const subscriptionStatusEnum = pgEnum('subscription_status', ['not_configured', 'active', 'expired', 'grace_period', 'unreachable']);
export const hostTypeEnum = pgEnum('host_type', ['server', 'desktop', 'firewall', 'switch', 'router', 'domain', 'other']);
export const hostFamilyEnum = pgEnum('host_family', ['linux', 'windows_server', 'windows_desktop', 'fortios', 'network_os', 'other']);
export const adSecurityTestStatusEnum = pgEnum('ad_security_test_status', ['pass', 'fail', 'error', 'skipped']);
export const enrichmentProtocolEnum = pgEnum('enrichment_protocol', ['wmi', 'ssh', 'snmp']);
export const targetSelectionModeEnum = pgEnum('target_selection_mode', ['individual', 'by_tag']);

// === TABELAS PRINCIPAIS ===

// Sessoes (connect-pg-simple)
export const sessions = pgTable("sessions", {
  sid: varchar("sid").primaryKey(),
  sess: jsonb("sess").notNull(),
  expire: timestamp("expire").notNull(),
}, (table) => [index("IDX_session_expire").on(table.expire)]);

// Usuarios
export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: varchar("email").unique().notNull(),
  passwordHash: varchar("password_hash"),
  firstName: varchar("first_name").notNull(),
  lastName: varchar("last_name").notNull(),
  role: userRoleEnum("role").default('read_only').notNull(),
  mustChangePassword: boolean("must_change_password").default(false).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
  lastLogin: timestamp("last_login"),
});

// Ativos (Assets) - hosts, ranges e web applications
export const assets = pgTable("assets", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  type: assetTypeEnum("type").notNull(),
  value: text("value").notNull(),
  tags: jsonb("tags").$type<string[]>().default([]).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  createdBy: varchar("created_by").references(() => users.id).notNull(),
});

// Credenciais (criptografadas com AES-256-GCM, modelo DEK/KEK)
export const credentials = pgTable("credentials", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: varchar("name").notNull(),
  type: credentialTypeEnum("type").notNull(),
  hostOverride: text("host_override"),
  port: integer("port"),
  domain: text("domain"),
  username: text("username").notNull(),
  secretEncrypted: text("secret_encrypted").notNull(),
  dekEncrypted: text("dek_encrypted").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  createdBy: varchar("created_by").references(() => users.id).notNull(),
});

// Jornadas de verificacao
export const journeys = pgTable("journeys", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: varchar("name").notNull(),
  type: journeyTypeEnum("type").notNull(),
  description: text("description"),
  params: jsonb("params").$type<Record<string, any>>().default({}).notNull(),
  targetSelectionMode: targetSelectionModeEnum("target_selection_mode").default('individual').notNull(),
  selectedTags: jsonb("selected_tags").$type<string[]>().default([]).notNull(),
  enableCveDetection: boolean("enable_cve_detection").default(true).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  createdBy: varchar("created_by").references(() => users.id).notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// Agendamentos (on_demand, once, recurring)
export const schedules = pgTable("schedules", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  journeyId: varchar("journey_id").references(() => journeys.id).notNull(),
  name: varchar("name").notNull(),
  kind: scheduleKindEnum("kind").notNull(),
  recurrenceType: recurrenceTypeEnum("recurrence_type"),
  hour: integer("hour"),
  minute: integer("minute").default(0),
  dayOfWeek: integer("day_of_week"),
  dayOfMonth: integer("day_of_month"),
  onceAt: timestamp("once_at"),
  lastExecutedAt: timestamp("last_executed_at"),
  enabled: boolean("enabled").default(true).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  createdBy: varchar("created_by").references(() => users.id).notNull(),
});

// Jobs (execucoes de jornadas)
export const jobs = pgTable("jobs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  journeyId: varchar("journey_id").references(() => journeys.id).notNull(),
  scheduleId: varchar("schedule_id").references(() => schedules.id),
  status: jobStatusEnum("status").default('pending').notNull(),
  progress: integer("progress").default(0).notNull(),
  currentTask: text("current_task"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  startedAt: timestamp("started_at"),
  finishedAt: timestamp("finished_at"),
  error: text("error"),
});

// Ameacas (Threats) - com correlacao, ciclo de vida e hibernacao
export const threats = pgTable("threats", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  title: text("title").notNull(),
  description: text("description"),
  severity: threatSeverityEnum("severity").notNull(),
  status: threatStatusEnum("status").default('open').notNull(),
  source: text("source").notNull(),
  assetId: varchar("asset_id").references(() => assets.id),
  hostId: varchar("host_id").references(() => hosts.id),
  evidence: jsonb("evidence").$type<Record<string, any>>().default({}).notNull(),
  jobId: varchar("job_id").references(() => jobs.id),
  correlationKey: text("correlation_key"),
  category: text("category"),
  lastSeenAt: timestamp("last_seen_at"),
  closureReason: text("closure_reason"),
  hibernatedUntil: timestamp("hibernated_until"),
  statusChangedBy: varchar("status_changed_by").references(() => users.id),
  statusChangedAt: timestamp("status_changed_at"),
  statusJustification: text("status_justification"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
  assignedTo: varchar("assigned_to").references(() => users.id),
}, (table) => [
  index("IDX_threats_correlation_key").on(table.correlationKey),
  index("IDX_threats_host_id").on(table.hostId),
  index("IDX_threats_status").on(table.status),
]);

// Hosts descobertos (com risk score e enrichment)
export const hosts = pgTable("hosts", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  description: text("description"),
  operatingSystem: text("operating_system"),
  type: hostTypeEnum("type").default('other').notNull(),
  family: hostFamilyEnum("family").default('other').notNull(),
  ips: jsonb("ips").$type<string[]>().default([]).notNull(),
  aliases: jsonb("aliases").$type<string[]>().default([]).notNull(),
  riskScore: integer("risk_score").default(0).notNull(),
  rawScore: integer("raw_score").default(0).notNull(),
  discoveredAt: timestamp("discovered_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// Auditoria
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

// [Tabelas adicionais omitidas por brevidade:]
// - activeSessions: rastreamento de sessoes ativas
// - loginAttempts: rate limiting persistente
// - hostRiskHistory: historico de risk score
// - adSecurityTestResults: resultados de testes AD
// - emailSettings: configuracao de email/SMTP
// - notificationPolicies: politicas de alerta
// - notificationLog: log de notificacoes enviadas
// - journeyCredentials: associacao jornada-credencial
// - hostEnrichments: dados coletados via WMI/SSH

// === SCHEMAS DE VALIDACAO ZOD ===
// [gerados via createInsertSchema + refinamentos customizados]
// Exemplos: insertAssetSchema, insertCredentialSchema, insertJourneySchema,
//           createScheduleSchema, registerUserSchema, changeThreatStatusSchema, etc.
