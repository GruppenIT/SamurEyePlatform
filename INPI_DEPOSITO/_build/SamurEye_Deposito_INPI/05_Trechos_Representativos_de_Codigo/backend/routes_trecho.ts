// REDIGIDO PARA DEPOSITO INPI (sem segredos)
// Trecho representativo das rotas da API REST (server/routes.ts)
// O arquivo completo contem ~2000 linhas com todas as rotas CRUD e WebSocket

import type { Express } from "express";
import { createServer, type Server } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { storage } from "./storage";
import { db } from "./db";
import { sql } from "drizzle-orm";
import { setupAuth, isAuthenticatedWithPasswordCheck } from "./localAuth";
import { jobQueue } from "./services/jobQueue";
import { threatEngine } from "./services/threatEngine";
import { encryptionService } from "./services/encryption";
import { processTracker } from "./services/processTracker";
import { emailService } from "./services/emailService";
import { notificationService } from "./services/notificationService";
import { subscriptionService } from "./services/subscriptionService";
import { APP_VERSION } from "./version";
import {
  insertAssetSchema,
  insertCredentialSchema,
  insertJourneySchema,
  insertScheduleSchema,
  createScheduleSchema,
  registerUserSchema,
  insertHostSchema,
  changeThreatStatusSchema,
  insertEmailSettingsSchema,
  insertNotificationPolicySchema,
  userRoleEnum,
  insertJourneyCredentialSchema,
} from "@shared/schema";
import { z } from "zod";

// Middleware de verificacao de role Admin
function requireAdmin(req: any, res: any, next: any) {
  if (req.user?.role !== 'global_administrator') {
    return res.status(403).json({ message: "Acesso negado. Apenas administradores." });
  }
  next();
}

// Middleware de verificacao de role Operator+
function requireOperator(req: any, res: any, next: any) {
  const role = req.user?.role;
  if (role !== 'global_administrator' && role !== 'operator') {
    return res.status(403).json({ message: "Acesso negado. Usuarios somente-leitura nao podem realizar esta operacao." });
  }
  next();
}

// Middleware de subscricao ativa (bloqueia escrita quando expirada)
function requireActiveSubscription(req: any, res: any, next: any) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (req.path.startsWith('/api/login') || req.path.startsWith('/api/logout')) return next();
  if (req.path.startsWith('/api/subscription')) return next();
  if (subscriptionService.isReadOnly()) {
    return res.status(403).json({
      message: "Subscricao expirada. Modo somente-leitura.",
      code: "SUBSCRIPTION_EXPIRED",
    });
  }
  next();
}

// Schemas de validacao para PATCH
const patchAssetSchema = z.object({
  type: z.enum(['host', 'range', 'web_application']).optional(),
  value: z.string().min(1).optional(),
  tags: z.array(z.string()).optional(),
}).strict();

const patchJourneySchema = z.object({
  name: z.string().min(1).optional(),
  type: z.enum(['attack_surface', 'ad_security', 'edr_av', 'web_application']).optional(),
  description: z.string().optional(),
  params: z.record(z.any()).optional(),
  targetSelectionMode: z.enum(['individual', 'by_tag']).optional(),
  selectedTags: z.array(z.string()).optional(),
}).strict();

// [... restante das rotas omitido por brevidade ...]
// O arquivo completo define rotas para:
// - Assets (CRUD, tags)
// - Credentials (CRUD, criptografia)
// - Journeys (CRUD, execucao)
// - Schedules (CRUD, agendamento)
// - Jobs (execucao, monitoramento, WebSocket)
// - Threats (gestao, status, estatisticas)
// - Users (CRUD, roles)
// - Settings (configuracoes do sistema)
// - Audit (log de auditoria)
// - Notifications (politicas de alerta)
// - Subscription (licenciamento)
// - System (metricas, versao)
