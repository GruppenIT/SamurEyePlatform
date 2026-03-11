// REDIGIDO PARA DEPOSITO INPI (sem segredos)
// Camada de armazenamento (Storage Layer) - acesso ao banco de dados via Drizzle ORM
// Trecho representativo das importacoes e interface

import {
  users, assets, credentials, journeys, schedules, jobs, jobResults,
  threats, hosts, hostRiskHistory, adSecurityTestResults, settings,
  auditLog, activeSessions, loginAttempts, threatStatusHistory,
  emailSettings, notificationPolicies, notificationLog,
  journeyCredentials, hostEnrichments,
  type User, type UpsertUser,
  type Asset, type InsertAsset,
  type Credential, type InsertCredential,
  type Journey, type InsertJourney,
  type Schedule, type InsertSchedule,
  type Job, type InsertJob,
  type JobResult,
  type Host, type InsertHost,
  type Threat, type InsertThreat,
  type Setting, type InsertSetting,
  type AuditLogEntry,
  type ActiveSession, type InsertActiveSession,
  type LoginAttempt,
  type EmailSettings, type InsertEmailSettings,
  type NotificationPolicy, type InsertNotificationPolicy,
} from '@shared/schema';

// O arquivo completo (~2000 linhas) implementa metodos CRUD para todas as entidades:
//
// - Usuarios: getUser, getUserByEmail, createUser, updateUserPassword, updateUserRole, ...
// - Ativos (Assets): getAssets, createAsset, updateAsset, deleteAsset, getUniqueTags, getAssetsByTags, ...
// - Credenciais: getCredentials, createCredential, deleteCredential, ... (com criptografia DEK/KEK)
// - Jornadas (Journeys): getJourneys, createJourney, updateJourney, deleteJourney, ...
// - Agendamentos: getSchedules, createSchedule, updateSchedule, ...
// - Jobs: getJobs, createJob, updateJob, getRunningJobs, ...
// - Ameacas (Threats): getThreats, createThreat, changeThreatStatus, getThreatStats, ...
// - Hosts: getHosts, createHost, updateHost, getHostByAddress, ...
// - Sessoes: createActiveSession, deleteActiveSession, getActiveSessions, ...
// - Auditoria: logAudit, getAuditLog, ...
// - Configuracoes: getSetting, setSetting, ...
// - Notificacoes: createNotificationPolicy, getNotificationPolicies, ...
// - Metricas do sistema: getSystemMetrics (CPU, memoria, status de servicos)
// - Inicializacao: initializeDatabaseStructure (indices, dedup, migracao)
