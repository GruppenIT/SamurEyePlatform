import type { Express } from "express";
import { storage } from "../storage";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { requireAdmin } from "./middleware";
import { encryptionService } from "../services/encryption";
import { emailService } from "../services/emailService";
import { subscriptionService } from "../services/subscriptionService";
import { threatEngine } from "../services/threatEngine";
import { activateApplianceSchema } from "@shared/schema";
import {
  insertEmailSettingsSchema,
  insertNotificationPolicySchema,
} from "@shared/schema";
import { createLogger } from '../lib/logger';

const log = createLogger('routes:admin');

export function registerAdminRoutes(app: Express) {
  // System metrics endpoint
  app.get('/api/system/metrics', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const metrics = await storage.getSystemMetrics();
      res.json(metrics);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch system metrics');
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
      log.error({ err: error }, 'failed to fetch email settings');
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
      log.error({ err: error }, 'failed to save email settings');
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
      log.error({ err: error }, 'failed to test email settings');
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
      log.error({ err: error }, 'failed to fetch subscription status');
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
      log.error({ err: error }, 'failed to activate subscription');
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
      log.error({ err: error }, 'failed to deactivate subscription');
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
      log.error({ err: error }, 'failed to send heartbeat');
      res.status(500).json({ message: error.message || "Falha ao enviar heartbeat" });
    }
  });

  // Notification policies routes
  app.get('/api/notification-policies', isAuthenticatedWithPasswordCheck, requireAdmin, async (req, res) => {
    try {
      const policies = await storage.getNotificationPolicies();
      res.json(policies);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch notification policies');
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
      log.error({ err: error }, 'failed to fetch notification policy');
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
      log.error({ err: error }, 'failed to create notification policy');
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
      log.error({ err: error }, 'failed to update notification policy');
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
      log.error({ err: error }, 'failed to delete notification policy');
      res.status(400).json({ message: "Falha ao deletar política de notificação" });
    }
  });

  // Admin maintenance routes
  app.post('/api/admin/recalculate-risk-scores', isAuthenticatedWithPasswordCheck, requireAdmin, async (req: any, res) => {
    try {
      const userId = req.user.id;

      log.info({ userId }, 'starting risk score recalculation');
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
      log.error({ err: error }, 'failed to recalculate risk scores');
      res.status(500).json({ message: "Falha ao recalcular risk scores" });
    }
  });

  // Admin sessions
  app.get('/api/admin/sessions', isAuthenticatedWithPasswordCheck, requireAdmin, async (req: any, res) => {
    try {
      const limit = req.query.limit ? parseInt(req.query.limit as string) : 100;
      const sessions = await storage.getAllActiveSessions(limit);
      res.json(sessions);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch all active sessions');
      res.status(500).json({ message: "Falha ao buscar todas as sessões ativas" });
    }
  });
}
