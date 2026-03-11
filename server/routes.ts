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
import { activateApplianceSchema } from "@shared/schema";
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
import { createLogger } from './lib/logger';

const log = createLogger('routes');
// Simple cookie parser (avoids extra dependency)
function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  cookieHeader.split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx > 0) {
      const key = pair.substring(0, idx).trim();
      const val = decodeURIComponent(pair.substring(idx + 1).trim());
      cookies[key] = val;
    }
  });
  return cookies;
}

// Admin role check middleware
function requireAdmin(req: any, res: any, next: any) {
  if (req.user?.role !== 'global_administrator') {
    return res.status(403).json({ message: "Acesso negado. Apenas administradores podem acessar este recurso." });
  }
  next();
}

// Operator or Admin role check middleware (blocks read_only from write operations)
function requireOperator(req: any, res: any, next: any) {
  const role = req.user?.role;
  if (role !== 'global_administrator' && role !== 'operator') {
    return res.status(403).json({ message: "Acesso negado. Usuários somente-leitura não podem realizar esta operação." });
  }
  next();
}

// Subscription read-only middleware: blocks write operations when subscription is expired
// Allows: GET requests, login/logout, subscription management, settings reads
function requireActiveSubscription(req: any, res: any, next: any) {
  // Always allow GET/HEAD/OPTIONS (read operations)
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

  // Always allow auth routes (login, logout, password change)
  if (req.path.startsWith('/api/login') || req.path.startsWith('/api/logout') || req.path.startsWith('/api/change-password')) return next();

  // Always allow subscription management (so admin can fix it)
  if (req.path.startsWith('/api/subscription')) return next();

  // Check if read-only mode is active
  if (subscriptionService.isReadOnly()) {
    return res.status(403).json({
      message: "Subscrição expirada. O SamurEye está em modo somente-leitura. Atualize sua subscrição para continuar.",
      code: "SUBSCRIPTION_EXPIRED",
    });
  }

  next();
}

// Validation schemas for PATCH operations
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
  credentials: z.array(z.object({
    credentialId: z.string().uuid(),
    protocol: z.enum(['ssh', 'wmi', 'snmp']),
    priority: z.number().int().min(0).default(0),
  })).optional(),
}).strict();

const patchCredentialSchema = z.object({
  name: z.string().min(1).optional(),
  type: z.enum(['ssh', 'wmi', 'omi', 'ad']).optional(),
  username: z.string().min(1).optional(),
  secret: z.string().optional(),
  hostOverride: z.string().nullable().optional(),
  port: z.number().int().positive().nullable().optional(),
  domain: z.string().nullable().optional(),
}).strict();

const patchThreatSchema = z.object({
  title: z.string().min(1).optional(),
  description: z.string().optional(),
  severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  assignedTo: z.string().nullable().optional(),
}).strict();

// Validate role against enum values
const validRoles = userRoleEnum.enumValues;

// HTML sanitization for email content
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Journey credential validation schema
const journeyCredentialInputSchema = z.object({
  credentialId: z.string().uuid("ID de credencial inválido"),
  protocol: z.enum(['ssh', 'wmi', 'snmp'] as const, { errorMap: () => ({ message: "Protocolo inválido" }) }),
  priority: z.number().int().min(0).default(0),
});

export async function registerRoutes(app: Express): Promise<Server> {
  // Auth middleware
  await setupAuth(app);

  // Subscription read-only enforcement (global, before all API routes)
  app.use('/api', requireActiveSubscription);

  // WebSocket connections for real-time updates
  const connectedClients = new Set<WebSocket>();

  // Broadcast to all connected clients
  function broadcast(data: any) {
    const message = JSON.stringify(data);
    connectedClients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  }

  // Listen for job updates
  jobQueue.on('jobUpdate', (update) => {
    broadcast({ type: 'jobUpdate', data: update });
  });

  // Auth routes are now handled in localAuth.ts

  // Dashboard routes (legacy - kept for backward compat)
  app.get('/api/dashboard/metrics', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const metrics = await storage.getDashboardMetrics();
      res.json(metrics);
    } catch (error) {
      log.error("Erro ao buscar métricas:", error);
      res.status(500).json({ message: "Falha ao buscar métricas" });
    }
  });

  app.get('/api/dashboard/running-jobs', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const jobs = await storage.getRunningJobs();
      res.json(jobs);
    } catch (error) {
      log.error("Erro ao buscar jobs em execução:", error);
      res.status(500).json({ message: "Falha ao buscar jobs" });
    }
  });

  app.get('/api/dashboard/recent-threats', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const threats = await storage.getThreats();
      const recentThreats = threats.slice(0, 10); // Last 10 threats
      res.json(recentThreats);
    } catch (error) {
      log.error("Erro ao buscar ameaças recentes:", error);
      res.status(500).json({ message: "Falha ao buscar ameaças" });
    }
  });

  // ===================== POSTURE & REPORTS APIs =====================

  // Posture score: consolidated risk score + 30-day history
  app.get('/api/posture/score', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const hosts = await storage.getHosts();
      const hostsWithRisk = hosts.filter(h => h.riskScore != null && h.riskScore > 0);
      const avgRisk = hostsWithRisk.length > 0
        ? hostsWithRisk.reduce((sum, h) => sum + (h.riskScore || 0), 0) / hostsWithRisk.length
        : 0;
      const postureScore = Math.round(100 - avgRisk);

      // 30-day history from host_risk_history
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const historyRows = await db.execute(sql`
        SELECT DATE(recorded_at) as day, AVG(risk_score) as avg_risk
        FROM host_risk_history
        WHERE recorded_at >= ${thirtyDaysAgo}
        GROUP BY DATE(recorded_at)
        ORDER BY day ASC
      `);

      const history = (historyRows.rows || []).map((r: any) => ({
        day: r.day,
        score: Math.round(100 - Number(r.avg_risk || 0)),
      }));

      res.json({
        score: postureScore,
        totalHosts: hosts.length,
        hostsAtRisk: hostsWithRisk.length,
        history,
      });
    } catch (error) {
      log.error("Erro ao calcular postura:", error);
      res.status(500).json({ message: "Falha ao calcular postura" });
    }
  });

  // Threat stats grouped by category + severity
  app.get('/api/threats/stats-by-category', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const rows = await db.execute(sql`
        SELECT
          COALESCE(category, 'uncategorized') as category,
          severity,
          status,
          COUNT(*)::int as count
        FROM threats
        GROUP BY category, severity, status
      `);
      // Organize into { category: { severity: { status: count } } }
      const result: Record<string, any> = {};
      for (const r of (rows.rows || []) as any[]) {
        if (!result[r.category]) result[r.category] = { open: 0, total: 0, critical: 0, high: 0 };
        const cat = result[r.category];
        cat.total += r.count;
        if (r.status === 'open') cat.open += r.count;
        if (r.severity === 'critical') cat.critical += r.count;
        if (r.severity === 'high') cat.high += r.count;
      }
      res.json(result);
    } catch (error) {
      log.error("Erro ao buscar stats por categoria:", error);
      res.status(500).json({ message: "Falha ao buscar stats" });
    }
  });

  // Activity feed: unified recent activity
  app.get('/api/activity/feed', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 15;

      // Recent threats (critical/high)
      const recentThreats = await db.execute(sql`
        SELECT id, title, severity, status, created_at as "createdAt", 'threat' as type
        FROM threats
        WHERE severity IN ('critical', 'high')
        ORDER BY created_at DESC
        LIMIT ${Math.ceil(limit / 2)}
      `);

      // Recent jobs
      const recentJobs = await db.execute(sql`
        SELECT id, status, current_task as "currentTask", journey_id as "journeyId",
               started_at as "startedAt", finished_at as "finishedAt", 'job' as type
        FROM jobs
        ORDER BY created_at DESC
        LIMIT ${Math.ceil(limit / 2)}
      `);

      // Merge and sort by date
      const feed = [
        ...(recentThreats.rows || []).map((r: any) => ({
          type: 'threat' as const,
          id: r.id,
          title: r.title,
          severity: r.severity,
          status: r.status,
          timestamp: r.createdAt,
        })),
        ...(recentJobs.rows || []).map((r: any) => ({
          type: 'job' as const,
          id: r.id,
          status: r.status,
          task: r.currentTask,
          journeyId: r.journeyId,
          timestamp: r.finishedAt || r.startedAt,
        })),
      ]
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(0, limit);

      res.json(feed);
    } catch (error) {
      log.error("Erro ao buscar feed:", error);
      res.status(500).json({ message: "Falha ao buscar feed" });
    }
  });

  // Threat trend: count by day/week grouped by severity
  app.get('/api/reports/threat-trend', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const periodDays = parseInt(req.query.period as string) || 30;
      const since = new Date(Date.now() - periodDays * 24 * 60 * 60 * 1000);

      const rows = await db.execute(sql`
        SELECT DATE(created_at) as day, severity, COUNT(*)::int as count
        FROM threats
        WHERE created_at >= ${since}
        GROUP BY DATE(created_at), severity
        ORDER BY day ASC
      `);

      // Group by day
      const byDay: Record<string, Record<string, number>> = {};
      for (const r of (rows.rows || []) as any[]) {
        const dayStr = String(r.day).slice(0, 10);
        if (!byDay[dayStr]) byDay[dayStr] = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        byDay[dayStr][r.severity] = r.count;
      }

      const trend = Object.entries(byDay).map(([day, counts]) => ({ day, ...counts }));
      res.json(trend);
    } catch (error) {
      log.error("Erro ao buscar trend:", error);
      res.status(500).json({ message: "Falha ao buscar trend" });
    }
  });

  // Summary by journey type with MTTR
  app.get('/api/reports/summary-by-journey', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const periodDays = parseInt(req.query.period as string) || 30;
      const since = new Date(Date.now() - periodDays * 24 * 60 * 60 * 1000);

      const rows = await db.execute(sql`
        SELECT
          COALESCE(category, 'uncategorized') as category,
          COUNT(*)::int as total,
          COUNT(*) FILTER (WHERE status = 'open')::int as open,
          COUNT(*) FILTER (WHERE severity = 'critical')::int as critical,
          COUNT(*) FILTER (WHERE severity = 'high')::int as high,
          COUNT(*) FILTER (WHERE status IN ('closed', 'mitigated') AND created_at >= ${since})::int as resolved,
          AVG(EXTRACT(EPOCH FROM (status_changed_at - created_at)) / 86400)
            FILTER (WHERE status IN ('closed', 'mitigated') AND created_at >= ${since}) as mttr_days
        FROM threats
        GROUP BY category
      `);

      const summary = (rows.rows || []).map((r: any) => ({
        category: r.category,
        total: r.total,
        open: r.open,
        critical: r.critical,
        high: r.high,
        resolved: r.resolved,
        mttrDays: r.mttr_days ? Math.round(Number(r.mttr_days) * 10) / 10 : null,
      }));

      res.json(summary);
    } catch (error) {
      log.error("Erro ao buscar summary:", error);
      res.status(500).json({ message: "Falha ao buscar summary" });
    }
  });

  // AD Security history: score evolution per execution
  app.get('/api/reports/ad-security/history', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const rows = await db.execute(sql`
        SELECT
          r.job_id as "jobId",
          j.started_at as "executedAt",
          COUNT(*)::int as total_tests,
          COUNT(*) FILTER (WHERE r.status = 'pass')::int as passed,
          COUNT(*) FILTER (WHERE r.status = 'fail')::int as failed,
          COUNT(*) FILTER (WHERE r.severity = 'critical' AND r.status = 'fail')::int as critical_failures
        FROM ad_security_test_results r
        JOIN jobs j ON j.id = r.job_id
        GROUP BY r.job_id, j.started_at
        ORDER BY j.started_at DESC
        LIMIT 20
      `);

      const history = (rows.rows || []).map((r: any) => ({
        jobId: r.jobId,
        executedAt: r.executedAt,
        totalTests: r.total_tests,
        passed: r.passed,
        failed: r.failed,
        criticalFailures: r.critical_failures,
        score: r.total_tests > 0 ? Math.round((r.passed / r.total_tests) * 100) : 0,
      }));

      res.json(history);
    } catch (error) {
      log.error("Erro ao buscar histórico AD:", error);
      res.status(500).json({ message: "Falha ao buscar histórico AD" });
    }
  });

  // EDR/AV coverage: detection rates per execution
  app.get('/api/reports/edr-coverage', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      // Get edr_av jobs with their results
      const rows = await db.execute(sql`
        SELECT
          j.id as "jobId",
          j.started_at as "executedAt",
          jr.artifacts
        FROM jobs j
        JOIN journeys jy ON jy.id = j.journey_id
        LEFT JOIN job_results jr ON jr.job_id = j.id
        WHERE jy.type = 'edr_av' AND j.status = 'completed'
        ORDER BY j.started_at DESC
        LIMIT 20
      `);

      const history = (rows.rows || []).map((r: any) => {
        const stats = r.artifacts?.statistics || {};
        return {
          jobId: r.jobId,
          executedAt: r.executedAt,
          totalDiscovered: stats.totalDiscovered || 0,
          tested: stats.successfulDeployments || 0,
          protected: stats.eicarRemovedCount || 0,
          unprotected: stats.eicarPersistedCount || 0,
          rate: stats.successfulDeployments > 0
            ? Math.round((stats.eicarRemovedCount || 0) / stats.successfulDeployments * 100)
            : 0,
        };
      });

      res.json(history);
    } catch (error) {
      log.error("Erro ao buscar cobertura EDR:", error);
      res.status(500).json({ message: "Falha ao buscar cobertura EDR" });
    }
  });

  // System metrics endpoint
  app.get('/api/system/metrics', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const metrics = await storage.getSystemMetrics();
      res.json(metrics);
    } catch (error) {
      log.error("Erro ao buscar métricas do sistema:", error);
      res.status(500).json({ message: "Falha ao buscar métricas do sistema" });
    }
  });

  // Email settings routes
  app.get('/api/email-settings', isAuthenticatedWithPasswordCheck, requireAdmin, async (req, res) => {
    try {
      const settings = await storage.getEmailSettings();
      if (!settings) {
        return res.json(null);
      }
      
      // Redact all sensitive fields
      const sanitized = {
        ...settings,
        authPassword: settings.authPassword ? '[ENCRYPTED]' : undefined,
        dekEncrypted: settings.dekEncrypted ? '[ENCRYPTED]' : undefined,
        oauth2ClientSecret: settings.oauth2ClientSecret ? '[ENCRYPTED]' : undefined,
        oauth2ClientSecretDek: settings.oauth2ClientSecretDek ? '[ENCRYPTED]' : undefined,
        oauth2RefreshToken: settings.oauth2RefreshToken ? '[ENCRYPTED]' : undefined,
        oauth2RefreshTokenDek: settings.oauth2RefreshTokenDek ? '[ENCRYPTED]' : undefined,
      };
      res.json(sanitized);
    } catch (error) {
      log.error("Erro ao buscar configurações de e-mail:", error);
      res.status(500).json({ message: "Falha ao buscar configurações de e-mail" });
    }
  });

  app.post('/api/email-settings', isAuthenticatedWithPasswordCheck, requireAdmin, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const settingsData = insertEmailSettingsSchema.parse(req.body);
      
      // Get existing settings for audit log
      const before = await storage.getEmailSettings();
      
      const authType = settingsData.authType || 'password';
      
      // Handle basic password authentication
      let authPassword, authPasswordDek, authUser;
      if (authType === 'password') {
        if (settingsData.authPasswordPlain && settingsData.authPasswordPlain.trim()) {
          const encrypted = encryptionService.encryptCredential(settingsData.authPasswordPlain);
          authPassword = encrypted.secretEncrypted;
          authPasswordDek = encrypted.dekEncrypted;
        } else if (before && before.authPassword && before.dekEncrypted) {
          // Keep existing password if not provided
          authPassword = before.authPassword;
          authPasswordDek = before.dekEncrypted;
        } else {
          return res.status(400).json({ message: "Senha SMTP é obrigatória para configuração inicial" });
        }
        authUser = settingsData.authUser;
      }
      
      // Handle OAuth2 credentials
      let oauth2ClientId, oauth2ClientSecret, oauth2ClientSecretDek, oauth2RefreshToken, oauth2RefreshTokenDek, oauth2TenantId;
      if (authType === 'oauth2_gmail' || authType === 'oauth2_microsoft') {
        oauth2ClientId = settingsData.oauth2ClientId;
        oauth2TenantId = settingsData.oauth2TenantId; // Only for Microsoft
        
        // Encrypt client secret if provided
        if (settingsData.oauth2ClientSecretPlain && settingsData.oauth2ClientSecretPlain.trim()) {
          const encrypted = encryptionService.encryptCredential(settingsData.oauth2ClientSecretPlain);
          oauth2ClientSecret = encrypted.secretEncrypted;
          oauth2ClientSecretDek = encrypted.dekEncrypted;
        } else if (before && before.oauth2ClientSecret && before.oauth2ClientSecretDek) {
          oauth2ClientSecret = before.oauth2ClientSecret;
          oauth2ClientSecretDek = before.oauth2ClientSecretDek;
        }
        
        // Encrypt refresh token if provided
        if (settingsData.oauth2RefreshTokenPlain && settingsData.oauth2RefreshTokenPlain.trim()) {
          const encrypted = encryptionService.encryptCredential(settingsData.oauth2RefreshTokenPlain);
          oauth2RefreshToken = encrypted.secretEncrypted;
          oauth2RefreshTokenDek = encrypted.dekEncrypted;
        } else if (before && before.oauth2RefreshToken && before.oauth2RefreshTokenDek) {
          oauth2RefreshToken = before.oauth2RefreshToken;
          oauth2RefreshTokenDek = before.oauth2RefreshTokenDek;
        }
        
        // Validate OAuth2 required fields for initial setup
        if (!before && (!oauth2ClientId || !oauth2ClientSecret || !oauth2RefreshToken)) {
          return res.status(400).json({ message: "Client ID, Client Secret e Refresh Token são obrigatórios para OAuth2" });
        }
        
        if (authType === 'oauth2_microsoft' && !before && !oauth2TenantId) {
          return res.status(400).json({ message: "Tenant ID é obrigatório para Microsoft 365" });
        }
      }
      
      const settings = await storage.setEmailSettings({
        smtpHost: settingsData.smtpHost,
        smtpPort: settingsData.smtpPort,
        smtpSecure: settingsData.smtpSecure || false,
        authType,
        // Basic auth fields
        authUser: authUser || null,
        authPassword: authPassword || null,
        dekEncrypted: authPasswordDek || null,
        // OAuth2 fields
        oauth2ClientId: oauth2ClientId || null,
        oauth2ClientSecret: oauth2ClientSecret || null,
        oauth2ClientSecretDek: oauth2ClientSecretDek || null,
        oauth2RefreshToken: oauth2RefreshToken || null,
        oauth2RefreshTokenDek: oauth2RefreshTokenDek || null,
        oauth2TenantId: oauth2TenantId || null,
        // Common fields
        fromEmail: settingsData.fromEmail,
        fromName: settingsData.fromName,
        updatedBy: userId,
      }, userId);
      
      // Log audit with redacted sensitive fields
      const redactedBefore = before ? {
        ...before,
        authPassword: before.authPassword ? '[ENCRYPTED]' : undefined,
        dekEncrypted: before.dekEncrypted ? '[ENCRYPTED]' : undefined,
        oauth2ClientSecret: before.oauth2ClientSecret ? '[ENCRYPTED]' : undefined,
        oauth2ClientSecretDek: before.oauth2ClientSecretDek ? '[ENCRYPTED]' : undefined,
        oauth2RefreshToken: before.oauth2RefreshToken ? '[ENCRYPTED]' : undefined,
        oauth2RefreshTokenDek: before.oauth2RefreshTokenDek ? '[ENCRYPTED]' : undefined,
      } : null;
      
      const redactedAfter = {
        ...settings,
        authPassword: settings.authPassword ? '[ENCRYPTED]' : undefined,
        dekEncrypted: settings.dekEncrypted ? '[ENCRYPTED]' : undefined,
        oauth2ClientSecret: settings.oauth2ClientSecret ? '[ENCRYPTED]' : undefined,
        oauth2ClientSecretDek: settings.oauth2ClientSecretDek ? '[ENCRYPTED]' : undefined,
        oauth2RefreshToken: settings.oauth2RefreshToken ? '[ENCRYPTED]' : undefined,
        oauth2RefreshTokenDek: settings.oauth2RefreshTokenDek ? '[ENCRYPTED]' : undefined,
      };
      
      await storage.logAudit({
        actorId: userId,
        action: before ? 'update' : 'create',
        objectType: 'email_settings',
        objectId: settings.id,
        before: redactedBefore,
        after: redactedAfter,
      });
      
      res.status(201).json(redactedAfter);
    } catch (error) {
      log.error("Erro ao salvar configurações de e-mail:", error);
      res.status(400).json({ message: "Falha ao salvar configurações de e-mail" });
    }
  });

  app.post('/api/email-settings/test', isAuthenticatedWithPasswordCheck, requireAdmin, async (req, res) => {
    try {
      // Validate test email
      const testEmail = req.body.email;
      if (!testEmail || typeof testEmail !== 'string' || !testEmail.includes('@')) {
        return res.status(400).json({ message: "E-mail de teste inválido" });
      }
      
      const settings = await storage.getEmailSettings();
      if (!settings) {
        return res.status(400).json({ message: "Configurações de e-mail não encontradas" });
      }

      // Test connection first
      const isValid = await emailService.testConnection(settings);
      if (!isValid) {
        throw new Error('Falha ao conectar ao servidor SMTP');
      }

      // Send test email
      await emailService.sendEmail(settings, {
        to: testEmail,
        subject: 'Teste de Configuração de E-mail',
        html: `
          <h2>Teste de Configuração de E-mail</h2>
          <p>Se você recebeu este e-mail, significa que suas configurações de e-mail estão funcionando corretamente!</p>
          <p><strong>Servidor SMTP:</strong> ${settings.smtpHost}:${settings.smtpPort}</p>
          <p><strong>De:</strong> ${settings.fromName} &lt;${settings.fromEmail}&gt;</p>
        `,
      });
      
      res.json({ message: "E-mail de teste enviado com sucesso" });
    } catch (error: any) {
      log.error("Erro ao testar configurações de e-mail:", error);
      res.status(400).json({ message: error.message || "Falha ao testar configurações de e-mail" });
    }
  });

  // ═══════════════════════════════════════════════════════════
  // Subscription management routes
  // ═══════════════════════════════════════════════════════════

  // Get subscription status (available to all authenticated users for banner display)
  app.get('/api/subscription/status', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const status = await subscriptionService.getStatus();
      res.json(status);
    } catch (error) {
      log.error("Erro ao buscar status da subscrição:", error);
      res.status(500).json({ message: "Falha ao buscar status da subscrição" });
    }
  });

  // Activate subscription with API key (admin only)
  app.post('/api/subscription/activate', isAuthenticatedWithPasswordCheck, requireAdmin, async (req: any, res) => {
    try {
      const { apiKey, consoleUrl } = activateApplianceSchema.parse(req.body);
      const userId = req.user.id;

      const result = await subscriptionService.activate(apiKey, consoleUrl, userId);

      if (!result.success) {
        return res.status(400).json({ message: result.error });
      }

      // Audit log
      await storage.logAudit({
        actorId: userId,
        action: 'subscription.activate',
        objectType: 'subscription',
        objectId: result.subscription?.applianceId || 'unknown',
        before: null,
        after: {
          tenantName: result.subscription?.tenantName,
          plan: result.subscription?.plan,
        },
      });

      res.json({
        message: "Subscrição ativada com sucesso",
        subscription: await subscriptionService.getStatus(),
      });
    } catch (error: any) {
      log.error("Erro ao ativar subscrição:", error);
      res.status(400).json({ message: error.message || "Falha ao ativar subscrição" });
    }
  });

  // Deactivate subscription (admin only)
  app.post('/api/subscription/deactivate', isAuthenticatedWithPasswordCheck, requireAdmin, async (req: any, res) => {
    try {
      const userId = req.user.id;

      await subscriptionService.deactivate(userId);

      // Audit log
      await storage.logAudit({
        actorId: userId,
        action: 'subscription.deactivate',
        objectType: 'subscription',
        objectId: 'appliance',
        before: null,
        after: null,
      });

      res.json({
        message: "Subscrição desativada",
        subscription: await subscriptionService.getStatus(),
      });
    } catch (error: any) {
      log.error("Erro ao desativar subscrição:", error);
      res.status(400).json({ message: error.message || "Falha ao desativar subscrição" });
    }
  });

  // Force heartbeat (admin only, for testing)
  app.post('/api/subscription/heartbeat', isAuthenticatedWithPasswordCheck, requireAdmin, async (req: any, res) => {
    try {
      await subscriptionService.sendHeartbeat();
      const status = await subscriptionService.getStatus();
      res.json({ message: "Heartbeat enviado", subscription: status });
    } catch (error: any) {
      log.error("Erro ao enviar heartbeat:", error);
      res.status(500).json({ message: error.message || "Falha ao enviar heartbeat" });
    }
  });

  // Notification policies routes
  app.get('/api/notification-policies', isAuthenticatedWithPasswordCheck, requireAdmin, async (req, res) => {
    try {
      const policies = await storage.getNotificationPolicies();
      res.json(policies);
    } catch (error) {
      log.error("Erro ao buscar políticas de notificação:", error);
      res.status(500).json({ message: "Falha ao buscar políticas de notificação" });
    }
  });

  app.get('/api/notification-policies/:id', isAuthenticatedWithPasswordCheck, requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const policy = await storage.getNotificationPolicy(id);
      if (!policy) {
        return res.status(404).json({ message: "Política de notificação não encontrada" });
      }
      res.json(policy);
    } catch (error) {
      log.error("Erro ao buscar política de notificação:", error);
      res.status(500).json({ message: "Falha ao buscar política de notificação" });
    }
  });

  app.post('/api/notification-policies', isAuthenticatedWithPasswordCheck, requireAdmin, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const policyData = insertNotificationPolicySchema.parse(req.body);
      const policy = await storage.createNotificationPolicy(policyData, userId);
      
      // Log audit
      await storage.logAudit({
        actorId: userId,
        action: 'create',
        objectType: 'notification_policy',
        objectId: policy.id,
        before: null,
        after: policy,
      });
      
      res.status(201).json(policy);
    } catch (error) {
      log.error("Erro ao criar política de notificação:", error);
      res.status(400).json({ message: "Falha ao criar política de notificação" });
    }
  });

  app.patch('/api/notification-policies/:id', isAuthenticatedWithPasswordCheck, requireAdmin, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;
      const before = await storage.getNotificationPolicy(id);
      
      if (!before) {
        return res.status(404).json({ message: "Política de notificação não encontrada" });
      }
      
      const policyData = insertNotificationPolicySchema.partial().parse(req.body);
      const policy = await storage.updateNotificationPolicy(id, policyData);
      
      // Log audit
      await storage.logAudit({
        actorId: userId,
        action: 'update',
        objectType: 'notification_policy',
        objectId: id,
        before,
        after: policy,
      });
      
      res.json(policy);
    } catch (error) {
      log.error("Erro ao atualizar política de notificação:", error);
      res.status(400).json({ message: "Falha ao atualizar política de notificação" });
    }
  });

  app.delete('/api/notification-policies/:id', isAuthenticatedWithPasswordCheck, requireAdmin, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;
      const before = await storage.getNotificationPolicy(id);
      
      if (!before) {
        return res.status(404).json({ message: "Política de notificação não encontrada" });
      }
      
      await storage.deleteNotificationPolicy(id);
      
      // Log audit
      await storage.logAudit({
        actorId: userId,
        action: 'delete',
        objectType: 'notification_policy',
        objectId: id,
        before,
        after: null,
      });
      
      res.status(204).send();
    } catch (error) {
      log.error("Erro ao deletar política de notificação:", error);
      res.status(400).json({ message: "Falha ao deletar política de notificação" });
    }
  });

  // Asset routes
  app.get('/api/assets', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const assets = await storage.getAssets();
      res.json(assets);
    } catch (error) {
      log.error("Erro ao buscar ativos:", error);
      res.status(500).json({ message: "Falha ao buscar ativos" });
    }
  });

  app.get('/api/assets/tags/unique', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const tags = await storage.getUniqueTags();
      res.json(tags);
    } catch (error) {
      log.error("Erro ao buscar TAGs únicas:", error);
      res.status(500).json({ message: "Falha ao buscar TAGs únicas" });
    }
  });

  app.get('/api/assets/by-type/:type', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { type } = req.params;
      const assets = await storage.getAssetsByType(type);
      res.json(assets);
    } catch (error) {
      log.error(`Erro ao buscar ativos do tipo ${req.params.type}:`, error);
      res.status(500).json({ message: "Falha ao buscar ativos por tipo" });
    }
  });

  app.post('/api/assets', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const assetData = insertAssetSchema.parse(req.body);
      const asset = await storage.createAsset(assetData, userId);
      
      // Log audit
      await storage.logAudit({
        actorId: userId,
        action: 'create',
        objectType: 'asset',
        objectId: asset.id,
        before: null,
        after: asset,
      });
      
      res.status(201).json(asset);
    } catch (error) {
      log.error("Erro ao criar ativo:", error);
      res.status(400).json({ message: "Falha ao criar ativo" });
    }
  });

  app.patch('/api/assets/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      // Validate allowed fields only
      const updates = patchAssetSchema.parse(req.body);

      const beforeAsset = await storage.getAsset(id);
      if (!beforeAsset) {
        return res.status(404).json({ message: "Ativo não encontrado" });
      }
      const asset = await storage.updateAsset(id, updates);
      
      await storage.logAudit({
        actorId: userId,
        action: 'update',
        objectType: 'asset',
        objectId: id,
        before: beforeAsset || null,
        after: asset,
      });
      
      res.json(asset);
    } catch (error) {
      log.error("Erro ao atualizar ativo:", error);
      res.status(400).json({ message: "Falha ao atualizar ativo" });
    }
  });

  app.delete('/api/assets/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;
      
      const beforeAsset = await storage.getAsset(id);
      await storage.deleteAsset(id);
      
      await storage.logAudit({
        actorId: userId,
        action: 'delete',
        objectType: 'asset',
        objectId: id,
        before: beforeAsset || null,
        after: null,
      });
      
      res.status(204).send();
    } catch (error) {
      log.error("Erro ao excluir ativo:", error);
      res.status(400).json({ message: "Falha ao excluir ativo" });
    }
  });

  // Host routes
  app.get('/api/hosts', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      // Extract query parameters for filtering and sorting
      const { type, family, search, sortBy } = req.query;
      
      const filters: any = {};
      if (type) filters.type = type as string;
      if (family) filters.family = family as string;
      if (search) filters.search = search as string;
      if (sortBy) filters.sortBy = sortBy as string;
      
      const hosts = await storage.getHosts(filters);
      res.json(hosts);
    } catch (error) {
      log.error("Erro ao buscar hosts:", error);
      res.status(500).json({ message: "Falha ao buscar hosts" });
    }
  });

  app.get('/api/hosts/:id', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { id } = req.params;
      const host = await storage.getHost(id);
      
      if (!host) {
        return res.status(404).json({ message: "Host não encontrado" });
      }
      
      res.json(host);
    } catch (error) {
      log.error("Erro ao buscar host:", error);
      res.status(500).json({ message: "Falha ao buscar host" });
    }
  });

  app.get('/api/hosts/:id/risk-history', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { id } = req.params;
      const { limit } = req.query;
      
      const history = await storage.getHostRiskHistory(id, limit ? parseInt(limit as string) : undefined);
      res.json(history);
    } catch (error) {
      log.error("Erro ao buscar histórico de risk score:", error);
      res.status(500).json({ message: "Falha ao buscar histórico de risk score" });
    }
  });

  app.get('/api/hosts/:id/ad-tests', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { id } = req.params;
      
      // Check if host exists
      const host = await storage.getHost(id);
      if (!host) {
        return res.status(404).json({ message: "Host não encontrado" });
      }
      
      // Get AD Security test results for this host (latest results)
      const testResults = await storage.getAdSecurityLatestTestResults(id);
      res.json(testResults);
    } catch (error) {
      log.error("Erro ao buscar resultados dos testes AD Security:", error);
      res.status(500).json({ message: "Falha ao buscar resultados dos testes AD Security" });
    }
  });

  // AD Security Scorecard - aggregated security metrics from latest test results
  app.get('/api/hosts/:id/ad-scorecard', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { id } = req.params;

      const host = await storage.getHost(id);
      if (!host) {
        return res.status(404).json({ message: "Host não encontrado" });
      }

      const testResults = await storage.getAdSecurityLatestTestResults(id);
      if (testResults.length === 0) {
        return res.json(null);
      }

      // Severity weights for score calculation
      const severityWeight: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

      // Aggregate per category
      const categories: Record<string, { total: number; passed: number; failed: number; error: number; skipped: number; maxWeight: number; failedWeight: number }> = {};
      let totalWeighted = 0;
      let failedWeighted = 0;
      let totalPassed = 0;
      let totalFailed = 0;
      let totalError = 0;
      let totalSkipped = 0;

      for (const test of testResults) {
        const cat = test.category;
        if (!categories[cat]) {
          categories[cat] = { total: 0, passed: 0, failed: 0, error: 0, skipped: 0, maxWeight: 0, failedWeight: 0 };
        }
        const w = severityWeight[test.severityHint] || 1;
        categories[cat].total++;
        categories[cat].maxWeight += w;
        totalWeighted += w;

        if (test.status === 'pass') {
          categories[cat].passed++;
          totalPassed++;
        } else if (test.status === 'fail') {
          categories[cat].failed++;
          categories[cat].failedWeight += w;
          failedWeighted += w;
          totalFailed++;
        } else if (test.status === 'error') {
          categories[cat].error++;
          totalError++;
        } else {
          categories[cat].skipped++;
          totalSkipped++;
        }
      }

      // Overall score: 0-100, higher is better
      const overallScore = totalWeighted > 0
        ? Math.round(((totalWeighted - failedWeighted) / totalWeighted) * 100)
        : 0;

      // Per-category scores
      const categoryScores = Object.entries(categories).map(([name, data]) => ({
        name,
        total: data.total,
        passed: data.passed,
        failed: data.failed,
        error: data.error,
        skipped: data.skipped,
        score: data.maxWeight > 0
          ? Math.round(((data.maxWeight - data.failedWeight) / data.maxWeight) * 100)
          : 0,
      }));

      // Severity distribution of failures
      const failedBySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const test of testResults) {
        if (test.status === 'fail') {
          failedBySeverity[test.severityHint] = (failedBySeverity[test.severityHint] || 0) + 1;
        }
      }

      res.json({
        overallScore,
        totalTests: testResults.length,
        totalPassed,
        totalFailed,
        totalError,
        totalSkipped,
        failedBySeverity,
        categories: categoryScores,
        executedAt: testResults[0]?.executedAt,
        jobId: testResults[0]?.jobId,
      });
    } catch (error) {
      log.error("Erro ao calcular scorecard AD:", error);
      res.status(500).json({ message: "Falha ao calcular scorecard de segurança AD" });
    }
  });

  app.get('/api/hosts/:id/enrichments', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { id } = req.params;

      // Check if host exists
      const host = await storage.getHost(id);
      if (!host) {
        return res.status(404).json({ message: "Host não encontrado" });
      }
      
      // Get latest successful enrichment data for this host
      const enrichment = await storage.getLatestHostEnrichment(id);
      res.json(enrichment || null);
    } catch (error) {
      log.error("Erro ao buscar dados de enriquecimento:", error);
      res.status(500).json({ message: "Falha ao buscar dados de enriquecimento" });
    }
  });

  app.patch('/api/hosts/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;
      
      // Validate updates using partial host schema (only allow certain fields)
      const allowedUpdates = insertHostSchema.partial().pick({
        name: true,
        description: true,
        aliases: true,
      });
      const updates = allowedUpdates.parse(req.body);
      
      const beforeHost = await storage.getHost(id);
      if (!beforeHost) {
        return res.status(404).json({ message: "Host não encontrado" });
      }
      
      const host = await storage.updateHost(id, updates);
      
      await storage.logAudit({
        actorId: userId,
        action: 'update',
        objectType: 'host',
        objectId: id,
        before: beforeHost || null,
        after: host,
      });
      
      res.json(host);
    } catch (error) {
      log.error("Erro ao atualizar host:", error);
      res.status(400).json({ message: "Falha ao atualizar host" });
    }
  });

  // Credential routes
  app.get('/api/credentials', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const credentials = await storage.getCredentials();
      // Note: storage.getCredentials() already omits secretEncrypted/dekEncrypted
      res.json(credentials);
    } catch (error) {
      log.error("Erro ao buscar credenciais:", error);
      res.status(500).json({ message: "Falha ao buscar credenciais" });
    }
  });

  app.post('/api/credentials', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const credentialData = insertCredentialSchema.parse(req.body);
      
      // Encrypt the secret
      const { secretEncrypted, dekEncrypted } = encryptionService.encryptCredential(credentialData.secret);
      
      const credential = await storage.createCredential({
        name: credentialData.name,
        type: credentialData.type,
        hostOverride: credentialData.hostOverride ?? null,
        port: credentialData.port ?? null,
        domain: credentialData.domain ?? null,
        username: credentialData.username,
        secretEncrypted,
        dekEncrypted,
        createdBy: userId,
      }, userId);
      
      await storage.logAudit({
        actorId: userId,
        action: 'create',
        objectType: 'credential',
        objectId: credential.id,
        before: null,
        after: { ...credential, secretEncrypted: '[ENCRYPTED]', dekEncrypted: '[ENCRYPTED]' },
      });
      
      res.status(201).json({
        ...credential,
        secretEncrypted: '[ENCRYPTED]',
        dekEncrypted: '[ENCRYPTED]',
      });
    } catch (error) {
      log.error("Erro ao criar credencial:", error);
      res.status(400).json({ message: "Falha ao criar credencial" });
    }
  });

  app.patch('/api/credentials/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      // Validate allowed fields
      const updateData = patchCredentialSchema.parse(req.body);
      
      const existingCredential = await storage.getCredential(id);
      if (!existingCredential) {
        return res.status(404).json({ message: "Credencial não encontrada" });
      }
      
      const beforeState = {
        ...existingCredential,
        secretEncrypted: '[ENCRYPTED]',
        dekEncrypted: '[ENCRYPTED]',
      };
      
      const updatePayload: any = {
        name: updateData.name,
        type: updateData.type,
        hostOverride: updateData.hostOverride ?? null,
        port: updateData.port ?? null,
        domain: updateData.domain ?? null,
        username: updateData.username,
      };
      
      if (updateData.secret && updateData.secret.trim() !== '') {
        const { secretEncrypted, dekEncrypted } = encryptionService.encryptCredential(updateData.secret);
        updatePayload.secretEncrypted = secretEncrypted;
        updatePayload.dekEncrypted = dekEncrypted;
      }
      
      const updatedCredential = await storage.updateCredential(id, updatePayload);
      
      await storage.logAudit({
        actorId: userId,
        action: 'update',
        objectType: 'credential',
        objectId: id,
        before: beforeState,
        after: { ...updatedCredential, secretEncrypted: '[ENCRYPTED]', dekEncrypted: '[ENCRYPTED]' },
      });
      
      res.json({
        ...updatedCredential,
        secretEncrypted: '[ENCRYPTED]',
        dekEncrypted: '[ENCRYPTED]',
      });
    } catch (error) {
      log.error("Erro ao atualizar credencial:", error);
      res.status(400).json({ message: "Falha ao atualizar credencial" });
    }
  });

  app.delete('/api/credentials/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      // Capture before state for audit (with redacted secrets)
      const existingCredential = await storage.getCredential(id);
      if (!existingCredential) {
        return res.status(404).json({ message: "Credencial não encontrada" });
      }
      const beforeState = {
        ...existingCredential,
        secretEncrypted: '[ENCRYPTED]',
        dekEncrypted: '[ENCRYPTED]',
      };

      await storage.deleteCredential(id);

      await storage.logAudit({
        actorId: userId,
        action: 'delete',
        objectType: 'credential',
        objectId: id,
        before: beforeState,
        after: null,
      });
      
      res.status(204).send();
    } catch (error) {
      log.error("Erro ao excluir credencial:", error);
      res.status(400).json({ message: "Falha ao excluir credencial" });
    }
  });

  // Journey routes
  app.get('/api/journeys', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const journeys = await storage.getJourneys();
      res.json(journeys);
    } catch (error) {
      log.error("Erro ao buscar jornadas:", error);
      res.status(500).json({ message: "Falha ao buscar jornadas" });
    }
  });

  app.post('/api/journeys', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const journeyData = insertJourneySchema.parse(req.body);
      
      // Server-side validation: ensure at least one target or TAG is selected
      if (journeyData.type === 'attack_surface' || 
          (journeyData.type === 'edr_av' && (journeyData.params as any)?.edrAvType === 'network_based')) {
        const mode = journeyData.targetSelectionMode || 'individual';
        const hasAssets = Array.isArray(journeyData.params?.assetIds) && journeyData.params.assetIds.length > 0;
        const hasTags = Array.isArray(journeyData.selectedTags) && journeyData.selectedTags.length > 0;
        
        if (mode === 'individual' && !hasAssets) {
          return res.status(400).json({ 
            message: "Pelo menos um alvo deve ser selecionado no modo Individual" 
          });
        }
        if (mode === 'by_tag' && !hasTags) {
          return res.status(400).json({ 
            message: "Pelo menos uma TAG deve ser selecionada no modo Tag-Based" 
          });
        }
      }
      
      const journey = await storage.createJourney(journeyData, userId);
      
      // Handle journey credentials (if provided)
      const credentials = req.body.credentials;

      if (Array.isArray(credentials) && credentials.length > 0) {
        for (const cred of credentials) {
          // Validate each credential entry
          const validCred = journeyCredentialInputSchema.parse(cred);
          await storage.createJourneyCredential({
            journeyId: journey.id,
            credentialId: validCred.credentialId,
            protocol: validCred.protocol,
            priority: validCred.priority,
          });
        }
      }
      
      await storage.logAudit({
        actorId: userId,
        action: 'create',
        objectType: 'journey',
        objectId: journey.id,
        before: null,
        after: journey,
      });
      
      res.status(201).json(journey);
    } catch (error) {
      log.error("Erro ao criar jornada:", error);
      res.status(400).json({ message: "Falha ao criar jornada" });
    }
  });

  app.patch('/api/journeys/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      // Validate allowed fields
      const updates = patchJourneySchema.parse(req.body);

      const beforeJourney = await storage.getJourney(id);
      if (!beforeJourney) {
        return res.status(404).json({ message: "Jornada não encontrada" });
      }
      const { credentials, ...journeyUpdates } = updates;
      const journey = await storage.updateJourney(id, journeyUpdates as any);
      
      // Handle journey credentials update (if provided in validated data)
      if (Array.isArray(credentials)) {
        // Delete all existing credentials for this journey
        await storage.deleteJourneyCredentials(id);

        // Create new credentials with validation
        if (credentials.length > 0) {
          for (const cred of credentials) {
            const validCred = journeyCredentialInputSchema.parse(cred);
            await storage.createJourneyCredential({
              journeyId: id,
              credentialId: validCred.credentialId,
              protocol: validCred.protocol,
              priority: validCred.priority,
            });
          }
        }
      }
      
      await storage.logAudit({
        actorId: userId,
        action: 'update',
        objectType: 'journey',
        objectId: id,
        before: beforeJourney || null,
        after: journey,
      });
      
      res.json(journey);
    } catch (error) {
      log.error("Erro ao atualizar jornada:", error);
      res.status(400).json({ message: "Falha ao atualizar jornada" });
    }
  });

  app.delete('/api/journeys/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;
      
      const beforeJourney = await storage.getJourney(id);
      await storage.deleteJourney(id);
      
      await storage.logAudit({
        actorId: userId,
        action: 'delete',
        objectType: 'journey',
        objectId: id,
        before: beforeJourney || null,
        after: null,
      });
      
      res.status(204).send();
    } catch (error) {
      log.error("Erro ao excluir jornada:", error);
      res.status(400).json({ message: "Falha ao excluir jornada" });
    }
  });

  // Get credentials for a specific journey
  app.get('/api/journeys/:id/credentials', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { id } = req.params;
      const credentials = await storage.getJourneyCredentials(id);
      res.json(credentials);
    } catch (error) {
      log.error("Erro ao buscar credenciais da jornada:", error);
      res.status(500).json({ message: "Falha ao buscar credenciais da jornada" });
    }
  });

  // Schedule routes
  app.get('/api/schedules', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const schedules = await storage.getSchedules();
      res.json(schedules);
    } catch (error) {
      log.error("Erro ao buscar agendamentos:", error);
      res.status(500).json({ message: "Falha ao buscar agendamentos" });
    }
  });

  app.post('/api/schedules', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const scheduleData = createScheduleSchema.parse(req.body);
      const schedule = await storage.createSchedule(scheduleData, userId);
      
      await storage.logAudit({
        actorId: userId,
        action: 'create',
        objectType: 'schedule',
        objectId: schedule.id,
        before: null,
        after: schedule,
      });
      
      res.status(201).json(schedule);
    } catch (error) {
      log.error("Erro ao criar agendamento:", error);
      res.status(400).json({ message: "Falha ao criar agendamento" });
    }
  });

  app.patch('/api/schedules/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;
      
      const beforeSchedule = await storage.getSchedule(id);
      if (!beforeSchedule) {
        return res.status(404).json({ message: "Agendamento não encontrado" });
      }
      
      const updateData = insertScheduleSchema.parse(req.body);
      const schedule = await storage.updateSchedule(id, updateData);
      
      await storage.logAudit({
        actorId: userId,
        action: 'update',
        objectType: 'schedule',
        objectId: id,
        before: beforeSchedule,
        after: schedule,
      });
      
      res.json(schedule);
    } catch (error) {
      log.error("Erro ao atualizar agendamento:", error);
      res.status(400).json({ message: "Falha ao atualizar agendamento" });
    }
  });

  app.delete('/api/schedules/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;
      
      const beforeSchedule = await storage.getSchedule(id);
      
      await storage.deleteSchedule(id);
      
      await storage.logAudit({
        actorId: userId,
        action: 'delete',
        objectType: 'schedule',
        objectId: id,
        before: beforeSchedule || null,
        after: null,
      });
      
      res.status(204).send();
    } catch (error) {
      log.error("Erro ao excluir agendamento:", error);
      res.status(400).json({ message: "Falha ao excluir agendamento" });
    }
  });

  // Job routes
  app.get('/api/jobs', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const limit = req.query.limit ? parseInt(req.query.limit as string) : undefined;
      const jobs = await storage.getJobs(limit);
      res.json(jobs);
    } catch (error) {
      log.error("Erro ao buscar jobs:", error);
      res.status(500).json({ message: "Falha ao buscar jobs" });
    }
  });

  app.post('/api/jobs/execute', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { journeyId } = req.body;
      
      if (!journeyId) {
        return res.status(400).json({ message: "ID da jornada é obrigatório" });
      }
      
      const job = await jobQueue.executeJobNow(journeyId);
      
      await storage.logAudit({
        actorId: userId,
        action: 'execute',
        objectType: 'job',
        objectId: job.id,
        before: null,
        after: job,
      });
      
      res.status(201).json(job);
    } catch (error) {
      log.error("Erro ao executar job:", error);
      res.status(400).json({ message: "Falha ao executar job" });
    }
  });

  app.get('/api/jobs/:id/result', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { id } = req.params;
      const result = await storage.getJobResult(id);
      
      if (!result) {
        return res.status(404).json({ message: "Resultado não encontrado" });
      }
      
      res.json(result);
    } catch (error) {
      log.error("Erro ao buscar resultado do job:", error);
      res.status(500).json({ message: "Falha ao buscar resultado" });
    }
  });

  app.post('/api/jobs/:id/cancel-process', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;
      
      // Verificar se o job existe
      const job = await storage.getJob(id);
      if (!job) {
        return res.status(404).json({ message: "Job não encontrado" });
      }
      
      // Verificar se o job está em execução
      if (job.status !== 'running') {
        return res.status(400).json({ message: "Job não está em execução" });
      }
      
      // Marcar job como cancelado para cooperative cancellation
      jobQueue.markJobAsCancelled(id);

      // Matar todos os processos do job (pode ser 0 entre fases)
      const killedCount = processTracker.killAll(id);

      // Marcar job como cancelado no DB
      await storage.updateJob(id, {
        status: 'failed',
        error: 'Job cancelado pelo usuário',
        finishedAt: new Date()
      });

      // Emitir update WebSocket para atualizar UI imediatamente
      jobQueue.emit('jobUpdate', {
        jobId: id,
        status: 'failed',
        progress: job.progress,
        currentTask: 'Job cancelado pelo usuário',
        error: 'Job cancelado pelo usuário',
      });

      // Log de auditoria
      await storage.logAudit({
        actorId: userId,
        action: 'cancel',
        objectType: 'job',
        objectId: id,
        before: null,
        after: { status: 'failed', error: 'Job cancelado pelo usuário' },
      });

      log.info(`🔪 Job ${id} cancelado pelo usuário ${userId} - ${killedCount} processos terminados`);

      res.json({
        message: `Job cancelado com sucesso.${killedCount > 0 ? ` ${killedCount} processo(s) terminado(s).` : ' Cancelamento cooperativo ativado.'}`,
        killedProcesses: killedCount
      });
      
    } catch (error) {
      log.error("Erro ao cancelar job:", error);
      res.status(500).json({ message: "Falha ao cancelar job" });
    }
  });

  // Threat routes
  app.get('/api/threats', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { severity, status, assetId, hostId } = req.query;
      const filters: any = {};
      
      if (severity) filters.severity = severity as string;
      if (status) filters.status = status as string;
      if (assetId) filters.assetId = assetId as string;
      if (hostId) filters.hostId = hostId as string;
      
      const threats = await storage.getThreatsWithHosts(filters);
      res.json(threats);
    } catch (error) {
      log.error("Erro ao buscar ameaças:", error);
      res.status(500).json({ message: "Falha ao buscar ameaças" });
    }
  });

  app.patch('/api/threats/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      // Validate allowed fields only (no status change here - use /status endpoint)
      const updates = patchThreatSchema.parse(req.body);

      const beforeThreat = await storage.getThreat(id);
      if (!beforeThreat) {
        return res.status(404).json({ message: "Ameaça não encontrada" });
      }
      const threat = await storage.updateThreat(id, updates);
      
      await storage.logAudit({
        actorId: userId,
        action: 'update',
        objectType: 'threat',
        objectId: id,
        before: beforeThreat || null,
        after: threat,
      });
      
      res.json(threat);
    } catch (error) {
      log.error("Erro ao atualizar ameaça:", error);
      res.status(400).json({ message: "Falha ao atualizar ameaça" });
    }
  });

  // Change threat status with justification
  app.patch('/api/threats/:id/status', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;
      
      // Validate input using Zod schema
      const validationResult = changeThreatStatusSchema.safeParse(req.body);
      if (!validationResult.success) {
        log.info(`⚠️ Validation failed for status change:`, validationResult.error.issues);
        return res.status(400).json({ 
          message: validationResult.error.issues.map(i => i.message).join(', ') 
        });
      }
      
      const { status, justification, hibernatedUntil } = validationResult.data;
      
      const beforeThreat = await storage.getThreat(id);
      if (!beforeThreat) {
        return res.status(404).json({ message: "Ameaça não encontrada" });
      }
      
      // Update threat with new status
      const updates: any = {
        status,
        statusChangedBy: userId,
        statusChangedAt: new Date(),
        statusJustification: justification,
        updatedAt: new Date(),
      };
      
      if (status === 'hibernated' && hibernatedUntil) {
        updates.hibernatedUntil = new Date(hibernatedUntil);
      } else {
        updates.hibernatedUntil = null;
      }
      
      const threat = await storage.updateThreat(id, updates);
      
      // Create status history entry
      await storage.createThreatStatusHistory({
        threatId: id,
        fromStatus: beforeThreat.status,
        toStatus: status,
        justification,
        hibernatedUntil: status === 'hibernated' && hibernatedUntil ? new Date(hibernatedUntil) : null,
        changedBy: userId,
      });
      
      // Log audit
      await storage.logAudit({
        actorId: userId,
        action: 'change_status',
        objectType: 'threat',
        objectId: id,
        before: { status: beforeThreat.status },
        after: { status, justification },
      });
      
      // Send notifications for status change
      try {
        const user = await storage.getUser(userId);
        if (user) {
          await notificationService.notifyThreatStatusChanged(
            threat,
            beforeThreat.status,
            status,
            user,
            justification
          );
        }
      } catch (notifError) {
        log.error(`⚠️ Erro ao enviar notificações de mudança de status para ameaça ${id}:`, notifError);
        // Don't fail status change if notification fails
      }
      
      // Recalculate host risk score after status change
      if (threat.hostId) {
        try {
          await threatEngine.recalculateHostRiskScore(threat.hostId);
          log.info(`✅ Risk score recalculado para host ${threat.hostId} após mudança de status`);
        } catch (riskError) {
          log.error(`⚠️ Erro ao recalcular risk score para host ${threat.hostId}:`, riskError);
          // Don't fail status change if risk recalculation fails
        }
      }
      
      res.json(threat);
    } catch (error) {
      log.error("Erro ao alterar status da ameaça:", error);
      res.status(400).json({ message: "Falha ao alterar status da ameaça" });
    }
  });

  // Get threat status history
  app.get('/api/threats/:id/history', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { id } = req.params;
      const history = await storage.getThreatStatusHistory(id);
      res.json(history);
    } catch (error) {
      log.error("Erro ao buscar histórico da ameaça:", error);
      res.status(500).json({ message: "Falha ao buscar histórico" });
    }
  });

  app.get('/api/threats/stats', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const stats = await storage.getThreatStats();
      res.json(stats);
    } catch (error) {
      log.error("Erro ao buscar estatísticas de ameaças:", error);
      res.status(500).json({ message: "Falha ao buscar estatísticas" });
    }
  });

  // User management routes (admin only)
  app.get('/api/users', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
    try {
      const userRole = req.user.role || 'read_only';
      if (userRole !== 'global_administrator') {
        return res.status(403).json({ message: "Acesso negado" });
      }
      
      const users = await storage.getAllUsers();
      // Strip sensitive data before sending to client
      const sanitizedUsers = users.map(({ passwordHash, ...user }) => user);
      res.json(sanitizedUsers);
    } catch (error) {
      log.error("Erro ao buscar usuários:", error);
      res.status(500).json({ message: "Falha ao buscar usuários" });
    }
  });

  app.post('/api/users', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
    try {
      const actorRole = req.user.role || 'read_only';
      if (actorRole !== 'global_administrator') {
        return res.status(403).json({ message: "Acesso negado - apenas administradores podem criar usuários" });
      }

      // Validate request body
      const validatedData = registerUserSchema.parse(req.body);
      const { email, firstName, lastName, password, role } = validatedData;
      const actorId = req.user.id;

      // Check if user already exists
      const existingUser = await storage.getUserByEmail(email);
      if (existingUser) {
        return res.status(400).json({ message: 'Email já está em uso' });
      }

      // Hash password
      const bcrypt = await import('bcryptjs');
      const passwordHash = await bcrypt.default.hash(password, 12);

      // Create user
      const newUser = await storage.createUser({
        email,
        passwordHash,
        firstName,
        lastName,
        role: role || 'read_only',
      });

      // Log audit
      await storage.logAudit({
        actorId,
        action: 'create',
        objectType: 'user',
        objectId: newUser.id,
        before: null,
        after: newUser,
      });

      res.json({ 
        message: 'Usuário criado com sucesso',
        user: {
          id: newUser.id,
          email: newUser.email,
          firstName: newUser.firstName,
          lastName: newUser.lastName,
          role: newUser.role
        }
      });
    } catch (error: any) {
      log.error("Erro ao criar usuário:", error);
      if (error.name === 'ZodError') {
        return res.status(400).json({ 
          message: 'Dados inválidos',
          errors: error.errors 
        });
      }
      res.status(500).json({ message: 'Erro interno do servidor' });
    }
  });

  app.patch('/api/users/:id/role', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
    try {
      const actorRole = req.user.role || 'read_only';
      if (actorRole !== 'global_administrator') {
        return res.status(403).json({ message: "Acesso negado" });
      }
      
      const { id } = req.params;
      const { role } = req.body;
      const actorId = req.user.id;

      // Validate role against enum
      if (!role || !validRoles.includes(role)) {
        return res.status(400).json({
          message: `Role inválido. Valores permitidos: ${validRoles.join(', ')}`
        });
      }

      // Prevent self-demotion
      if (id === actorId && role !== 'global_administrator') {
        return res.status(400).json({ message: "Não é possível alterar seu próprio papel" });
      }

      const beforeUser = await storage.getUser(id);
      if (!beforeUser) {
        return res.status(404).json({ message: "Usuário não encontrado" });
      }
      const user = await storage.updateUserRole(id, role);
      
      await storage.logAudit({
        actorId,
        action: 'update_role',
        objectType: 'user',
        objectId: id,
        before: beforeUser || null,
        after: user,
      });
      
      res.json(user);
    } catch (error) {
      log.error("Erro ao atualizar papel do usuário:", error);
      res.status(400).json({ message: "Falha ao atualizar papel" });
    }
  });

  // Audit log routes
  app.get('/api/audit', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
    try {
      const userRole = req.user.role || 'read_only';
      if (userRole !== 'global_administrator') {
        return res.status(403).json({ message: "Acesso negado" });
      }
      
      const limit = req.query.limit ? parseInt(req.query.limit as string) : undefined;
      const auditLog = await storage.getAuditLog(limit);
      res.json(auditLog);
    } catch (error) {
      log.error("Erro ao buscar log de auditoria:", error);
      res.status(500).json({ message: "Falha ao buscar auditoria" });
    }
  });

  // Admin maintenance routes
  app.post('/api/admin/recalculate-risk-scores', isAuthenticatedWithPasswordCheck, requireAdmin, async (req: any, res) => {
    try {
      const userId = req.user.id;
      
      log.info(`🔄 Iniciando recálculo de risk scores (solicitado por ${userId})...`);
      await threatEngine.recalculateAllHostRiskScores();
      
      await storage.logAudit({
        actorId: userId,
        action: 'recalculate_risk_scores',
        objectType: 'host',
        objectId: 'all',
        before: null,
        after: { message: 'Recálculo de todos os risk scores concluído' },
      });
      
      res.json({ 
        message: 'Risk scores recalculados com sucesso para todos os hosts',
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      log.error("Erro ao recalcular risk scores:", error);
      res.status(500).json({ message: "Falha ao recalcular risk scores" });
    }
  });

  // Session management routes
  app.get('/api/sessions', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const currentSessionId = req.sessionID;
      const sessions = await storage.getActiveSessionsByUserId(userId);
      
      // Marcar a sessão atual para o frontend
      const sessionsWithCurrent = sessions.map(session => ({
        ...session,
        isCurrent: session.sessionId === currentSessionId
      }));
      
      res.json(sessionsWithCurrent);
    } catch (error) {
      log.error("Erro ao buscar sessões ativas:", error);
      res.status(500).json({ message: "Falha ao buscar sessões ativas" });
    }
  });

  app.delete('/api/sessions/:sessionId', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { sessionId } = req.params;
      
      // Verificar se a sessão pertence ao usuário
      const session = await storage.getActiveSessionBySessionId(sessionId);
      if (!session) {
        return res.status(404).json({ message: "Sessão não encontrada" });
      }
      
      if (session.userId !== userId) {
        return res.status(403).json({ message: "Você não pode revogar sessões de outros usuários" });
      }
      
      // Remover sessão ativa do tracking
      await storage.deleteActiveSession(sessionId);
      
      // CRITICAL: Destruir a sessão do Express store (forçar remoção do cache em memória)
      // connect-pg-simple armazena o sessionId SEM o prefixo "s:", então usamos direto
      
      // Usar sessionStore.destroy para remover do cache em memória do Express
      if (req.sessionStore && req.sessionStore.destroy) {
        await new Promise<void>((resolve, reject) => {
          req.sessionStore.destroy(sessionId, (err: any) => {
            if (err) {
              log.error('Erro ao destruir sessão do store:', err);
              reject(err);
            } else {
              log.info(`✅ Sessão ${sessionId} revogada com sucesso`);
              resolve();
            }
          });
        });
      } else {
        // Fallback: deletar direto do banco se sessionStore não estiver disponível
        await db.execute(sql`DELETE FROM sessions WHERE sid = ${sessionId}`);
        log.info(`✅ Sessão ${sessionId} deletada do banco (fallback)`);
      }
      
      // Registrar auditoria
      await storage.logAudit({
        actorId: userId,
        action: 'session.revoke',
        objectType: 'session',
        objectId: sessionId,
        before: session,
        after: null,
      });
      
      res.json({ message: 'Sessão revogada com sucesso' });
    } catch (error) {
      log.error("Erro ao revogar sessão:", error);
      res.status(500).json({ message: "Falha ao revogar sessão" });
    }
  });

  app.delete('/api/sessions', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
    try {
      const userId = req.user.id;
      
      // Buscar todas as sessões do usuário antes de deletar
      const userSessions = await storage.getActiveSessionsByUserId(userId);
      
      // CRITICAL: Destruir todas as sessões do Express store (forçar remoção do cache)
      // connect-pg-simple armazena o sessionId SEM o prefixo "s:", então usamos direto
      for (const session of userSessions) {
        // Usar sessionStore.destroy para remover do cache em memória
        if (req.sessionStore && req.sessionStore.destroy) {
          await new Promise<void>((resolve, reject) => {
            req.sessionStore.destroy(session.sessionId, (err: any) => {
              if (err) {
                log.error(`Erro ao destruir sessão ${session.sessionId} do store:`, err);
                reject(err);
              } else {
                log.info(`✅ Sessão ${session.sessionId} revogada`);
                resolve();
              }
            });
          });
        } else {
          // Fallback: deletar direto do banco
          await db.execute(sql`DELETE FROM sessions WHERE sid = ${session.sessionId}`);
          log.info(`✅ Sessão ${session.sessionId} deletada (fallback)`);
        }
      }
      
      // Remover todas as sessões do tracking
      await storage.deleteActiveSessionsByUserId(userId);
      
      // Registrar auditoria
      await storage.logAudit({
        actorId: userId,
        action: 'session.revoke_all',
        objectType: 'session',
        objectId: userId,
        before: null,
        after: { message: 'Todas as sessões foram revogadas' },
      });
      
      res.json({ message: 'Todas as sessões foram revogadas com sucesso' });
    } catch (error) {
      log.error("Erro ao revogar todas as sessões:", error);
      res.status(500).json({ message: "Falha ao revogar todas as sessões" });
    }
  });

  app.get('/api/admin/sessions', isAuthenticatedWithPasswordCheck, requireAdmin, async (req: any, res) => {
    try {
      const limit = req.query.limit ? parseInt(req.query.limit as string) : 100;
      const sessions = await storage.getAllActiveSessions(limit);
      res.json(sessions);
    } catch (error) {
      log.error("Erro ao buscar todas as sessões ativas:", error);
      res.status(500).json({ message: "Falha ao buscar todas as sessões ativas" });
    }
  });

  // Health check
  app.get('/api/health', (req, res) => {
    res.json({ 
      status: 'ok', 
      timestamp: new Date().toISOString(),
      version: APP_VERSION
    });
  });

  const httpServer = createServer(app);

  // WebSocket server for real-time updates
  const wss = new WebSocketServer({
    server: httpServer,
    path: '/ws',
    verifyClient: async (info, callback) => {
      try {
        // Extract session cookie from upgrade request
        const cookieHeader = info.req.headers.cookie;
        if (!cookieHeader) {
          log.info('🔒 WebSocket rejeitado: sem cookie de sessão');
          callback(false, 401, 'Não autorizado');
          return;
        }

        const cookies = parseCookies(cookieHeader);
        const sessionId = cookies['connect.sid'];
        if (!sessionId) {
          log.info('🔒 WebSocket rejeitado: cookie connect.sid ausente');
          callback(false, 401, 'Não autorizado');
          return;
        }

        // Decode the signed session ID (format: s:<id>.<signature>)
        const rawSid = sessionId.startsWith('s:')
          ? sessionId.slice(2).split('.')[0]
          : sessionId;

        // Verify session exists in active_sessions
        const activeSession = await storage.getActiveSessionBySessionId(rawSid);
        if (!activeSession) {
          log.info('🔒 WebSocket rejeitado: sessão não encontrada ou revogada');
          callback(false, 401, 'Sessão inválida');
          return;
        }

        callback(true);
      } catch (error) {
        log.error('❌ Erro ao verificar WebSocket:', error);
        callback(false, 500, 'Erro interno');
      }
    }
  });

  wss.on('connection', (ws) => {
    log.info('Cliente WebSocket conectado (autenticado)');
    connectedClients.add(ws);

    ws.on('close', () => {
      log.info('Cliente WebSocket desconectado');
      connectedClients.delete(ws);
    });

    ws.on('error', (error) => {
      log.error('Erro WebSocket:', error);
      connectedClients.delete(ws);
    });

    // Send initial connection confirmation
    ws.send(JSON.stringify({ 
      type: 'connected', 
      message: 'Conectado ao SamurEye' 
    }));
  });

  // Export cleanup function for graceful shutdown
  (httpServer as any).closeWebSocket = () => {
    return new Promise<void>((resolve) => {
      // Close all client connections
      wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          client.close();
        }
      });
      
      // Close the WebSocket server
      wss.close(() => {
        resolve();
      });
    });
  };

  return httpServer;
}
