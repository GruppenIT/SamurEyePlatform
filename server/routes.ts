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
  insertNotificationPolicySchema
} from "@shared/schema";

// Admin role check middleware
function requireAdmin(req: any, res: any, next: any) {
  if (req.user?.role !== 'global_administrator') {
    return res.status(403).json({ message: "Acesso negado. Apenas administradores podem acessar este recurso." });
  }
  next();
}

export async function registerRoutes(app: Express): Promise<Server> {
  // Auth middleware
  await setupAuth(app);

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

  // Dashboard routes
  app.get('/api/dashboard/metrics', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const metrics = await storage.getDashboardMetrics();
      res.json(metrics);
    } catch (error) {
      console.error("Erro ao buscar métricas:", error);
      res.status(500).json({ message: "Falha ao buscar métricas" });
    }
  });

  app.get('/api/dashboard/running-jobs', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const jobs = await storage.getRunningJobs();
      res.json(jobs);
    } catch (error) {
      console.error("Erro ao buscar jobs em execução:", error);
      res.status(500).json({ message: "Falha ao buscar jobs" });
    }
  });

  app.get('/api/dashboard/recent-threats', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const threats = await storage.getThreats();
      const recentThreats = threats.slice(0, 10); // Last 10 threats
      res.json(recentThreats);
    } catch (error) {
      console.error("Erro ao buscar ameaças recentes:", error);
      res.status(500).json({ message: "Falha ao buscar ameaças" });
    }
  });

  // System metrics endpoint
  app.get('/api/system/metrics', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const metrics = await storage.getSystemMetrics();
      res.json(metrics);
    } catch (error) {
      console.error("Erro ao buscar métricas do sistema:", error);
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
      console.error("Erro ao buscar configurações de e-mail:", error);
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
      console.error("Erro ao salvar configurações de e-mail:", error);
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
      console.error("Erro ao testar configurações de e-mail:", error);
      res.status(400).json({ message: error.message || "Falha ao testar configurações de e-mail" });
    }
  });

  // Notification policies routes
  app.get('/api/notification-policies', isAuthenticatedWithPasswordCheck, requireAdmin, async (req, res) => {
    try {
      const policies = await storage.getNotificationPolicies();
      res.json(policies);
    } catch (error) {
      console.error("Erro ao buscar políticas de notificação:", error);
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
      console.error("Erro ao buscar política de notificação:", error);
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
      console.error("Erro ao criar política de notificação:", error);
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
      console.error("Erro ao atualizar política de notificação:", error);
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
      console.error("Erro ao deletar política de notificação:", error);
      res.status(400).json({ message: "Falha ao deletar política de notificação" });
    }
  });

  // Asset routes
  app.get('/api/assets', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const assets = await storage.getAssets();
      res.json(assets);
    } catch (error) {
      console.error("Erro ao buscar ativos:", error);
      res.status(500).json({ message: "Falha ao buscar ativos" });
    }
  });

  app.get('/api/assets/tags/unique', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const tags = await storage.getUniqueTags();
      res.json(tags);
    } catch (error) {
      console.error("Erro ao buscar TAGs únicas:", error);
      res.status(500).json({ message: "Falha ao buscar TAGs únicas" });
    }
  });

  app.get('/api/assets/by-type/:type', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { type } = req.params;
      const assets = await storage.getAssetsByType(type);
      res.json(assets);
    } catch (error) {
      console.error(`Erro ao buscar ativos do tipo ${req.params.type}:`, error);
      res.status(500).json({ message: "Falha ao buscar ativos por tipo" });
    }
  });

  app.post('/api/assets', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
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
      console.error("Erro ao criar ativo:", error);
      res.status(400).json({ message: "Falha ao criar ativo" });
    }
  });

  app.patch('/api/assets/:id', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;
      const updates = req.body;
      
      const beforeAsset = await storage.getAsset(id);
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
      console.error("Erro ao atualizar ativo:", error);
      res.status(400).json({ message: "Falha ao atualizar ativo" });
    }
  });

  app.delete('/api/assets/:id', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
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
      console.error("Erro ao excluir ativo:", error);
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
      console.error("Erro ao buscar hosts:", error);
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
      console.error("Erro ao buscar host:", error);
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
      console.error("Erro ao buscar histórico de risk score:", error);
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
      console.error("Erro ao buscar resultados dos testes AD Security:", error);
      res.status(500).json({ message: "Falha ao buscar resultados dos testes AD Security" });
    }
  });

  app.patch('/api/hosts/:id', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
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
      console.error("Erro ao atualizar host:", error);
      res.status(400).json({ message: "Falha ao atualizar host" });
    }
  });

  // Credential routes
  app.get('/api/credentials', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const credentials = await storage.getCredentials();
      res.json(credentials);
    } catch (error) {
      console.error("Erro ao buscar credenciais:", error);
      res.status(500).json({ message: "Falha ao buscar credenciais" });
    }
  });

  app.post('/api/credentials', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
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
      console.error("Erro ao criar credencial:", error);
      res.status(400).json({ message: "Falha ao criar credencial" });
    }
  });

  app.delete('/api/credentials/:id', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;
      
      await storage.deleteCredential(id);
      
      await storage.logAudit({
        actorId: userId,
        action: 'delete',
        objectType: 'credential',
        objectId: id,
        before: null,
        after: null,
      });
      
      res.status(204).send();
    } catch (error) {
      console.error("Erro ao excluir credencial:", error);
      res.status(400).json({ message: "Falha ao excluir credencial" });
    }
  });

  // Journey routes
  app.get('/api/journeys', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const journeys = await storage.getJourneys();
      res.json(journeys);
    } catch (error) {
      console.error("Erro ao buscar jornadas:", error);
      res.status(500).json({ message: "Falha ao buscar jornadas" });
    }
  });

  app.post('/api/journeys', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const journeyData = insertJourneySchema.parse(req.body);
      
      // Server-side validation: ensure at least one target or TAG is selected
      if (journeyData.type === 'attack_surface' || 
          (journeyData.type === 'edr_av' && journeyData.params?.edrAvType === 'network_based')) {
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
          await storage.createJourneyCredential({
            journeyId: journey.id,
            credentialId: cred.credentialId,
            protocol: cred.protocol,
            priority: cred.priority || 0,
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
      console.error("Erro ao criar jornada:", error);
      res.status(400).json({ message: "Falha ao criar jornada" });
    }
  });

  app.patch('/api/journeys/:id', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;
      const updates = req.body;
      
      const beforeJourney = await storage.getJourney(id);
      const journey = await storage.updateJourney(id, updates);
      
      // Handle journey credentials update (if provided)
      const credentials = req.body.credentials;
      if (Array.isArray(credentials)) {
        // Delete all existing credentials for this journey
        await storage.deleteJourneyCredentials(id);
        
        // Create new credentials
        for (const cred of credentials) {
          await storage.createJourneyCredential({
            journeyId: id,
            credentialId: cred.credentialId,
            protocol: cred.protocol,
            priority: cred.priority || 0,
          });
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
      console.error("Erro ao atualizar jornada:", error);
      res.status(400).json({ message: "Falha ao atualizar jornada" });
    }
  });

  app.delete('/api/journeys/:id', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
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
      console.error("Erro ao excluir jornada:", error);
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
      console.error("Erro ao buscar credenciais da jornada:", error);
      res.status(500).json({ message: "Falha ao buscar credenciais da jornada" });
    }
  });

  // Schedule routes
  app.get('/api/schedules', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const schedules = await storage.getSchedules();
      res.json(schedules);
    } catch (error) {
      console.error("Erro ao buscar agendamentos:", error);
      res.status(500).json({ message: "Falha ao buscar agendamentos" });
    }
  });

  app.post('/api/schedules', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
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
      console.error("Erro ao criar agendamento:", error);
      res.status(400).json({ message: "Falha ao criar agendamento" });
    }
  });

  app.patch('/api/schedules/:id', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
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
      console.error("Erro ao atualizar agendamento:", error);
      res.status(400).json({ message: "Falha ao atualizar agendamento" });
    }
  });

  app.delete('/api/schedules/:id', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
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
      console.error("Erro ao excluir agendamento:", error);
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
      console.error("Erro ao buscar jobs:", error);
      res.status(500).json({ message: "Falha ao buscar jobs" });
    }
  });

  app.post('/api/jobs/execute', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
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
      console.error("Erro ao executar job:", error);
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
      console.error("Erro ao buscar resultado do job:", error);
      res.status(500).json({ message: "Falha ao buscar resultado" });
    }
  });

  app.post('/api/jobs/:id/cancel-process', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
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
      
      // Cancelar todos os processos do job
      const killedCount = processTracker.killAll(id);
      
      if (killedCount === 0) {
        return res.status(404).json({ 
          message: "Nenhum processo ativo encontrado para este job" 
        });
      }
      
      // Marcar job como cancelado
      await storage.updateJob(id, { 
        status: 'failed',
        error: 'Job cancelado pelo usuário',
        finishedAt: new Date()
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
      
      console.log(`🔪 Job ${id} cancelado pelo usuário ${userId} - ${killedCount} processos terminados`);
      
      res.json({ 
        message: `Job cancelado com sucesso. ${killedCount} processo(s) terminado(s).`,
        killedProcesses: killedCount
      });
      
    } catch (error) {
      console.error("Erro ao cancelar job:", error);
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
      console.error("Erro ao buscar ameaças:", error);
      res.status(500).json({ message: "Falha ao buscar ameaças" });
    }
  });

  app.patch('/api/threats/:id', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;
      const updates = req.body;
      
      const beforeThreat = await storage.getThreat(id);
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
      console.error("Erro ao atualizar ameaça:", error);
      res.status(400).json({ message: "Falha ao atualizar ameaça" });
    }
  });

  // Change threat status with justification
  app.patch('/api/threats/:id/status', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;
      
      // Validate input using Zod schema
      const validationResult = changeThreatStatusSchema.safeParse(req.body);
      if (!validationResult.success) {
        console.log(`⚠️ Validation failed for status change:`, validationResult.error.issues);
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
        console.error(`⚠️ Erro ao enviar notificações de mudança de status para ameaça ${id}:`, notifError);
        // Don't fail status change if notification fails
      }
      
      res.json(threat);
    } catch (error) {
      console.error("Erro ao alterar status da ameaça:", error);
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
      console.error("Erro ao buscar histórico da ameaça:", error);
      res.status(500).json({ message: "Falha ao buscar histórico" });
    }
  });

  app.get('/api/threats/stats', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const stats = await storage.getThreatStats();
      res.json(stats);
    } catch (error) {
      console.error("Erro ao buscar estatísticas de ameaças:", error);
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
      res.json(users);
    } catch (error) {
      console.error("Erro ao buscar usuários:", error);
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
      console.error("Erro ao criar usuário:", error);
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
      
      const beforeUser = await storage.getUser(id);
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
      console.error("Erro ao atualizar papel do usuário:", error);
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
      console.error("Erro ao buscar log de auditoria:", error);
      res.status(500).json({ message: "Falha ao buscar auditoria" });
    }
  });

  // Admin maintenance routes
  app.post('/api/admin/recalculate-risk-scores', isAuthenticatedWithPasswordCheck, requireAdmin, async (req: any, res) => {
    try {
      const userId = req.user.id;
      
      console.log(`🔄 Iniciando recálculo de risk scores (solicitado por ${userId})...`);
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
      console.error("Erro ao recalcular risk scores:", error);
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
      console.error("Erro ao buscar sessões ativas:", error);
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
              console.error('Erro ao destruir sessão do store:', err);
              reject(err);
            } else {
              console.log(`✅ Sessão ${sessionId} revogada com sucesso`);
              resolve();
            }
          });
        });
      } else {
        // Fallback: deletar direto do banco se sessionStore não estiver disponível
        await db.execute(sql`DELETE FROM sessions WHERE sid = ${sessionId}`);
        console.log(`✅ Sessão ${sessionId} deletada do banco (fallback)`);
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
      console.error("Erro ao revogar sessão:", error);
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
                console.error(`Erro ao destruir sessão ${session.sessionId} do store:`, err);
                reject(err);
              } else {
                console.log(`✅ Sessão ${session.sessionId} revogada`);
                resolve();
              }
            });
          });
        } else {
          // Fallback: deletar direto do banco
          await db.execute(sql`DELETE FROM sessions WHERE sid = ${session.sessionId}`);
          console.log(`✅ Sessão ${session.sessionId} deletada (fallback)`);
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
      console.error("Erro ao revogar todas as sessões:", error);
      res.status(500).json({ message: "Falha ao revogar todas as sessões" });
    }
  });

  app.get('/api/admin/sessions', isAuthenticatedWithPasswordCheck, requireAdmin, async (req: any, res) => {
    try {
      const limit = req.query.limit ? parseInt(req.query.limit as string) : 100;
      const sessions = await storage.getAllActiveSessions(limit);
      res.json(sessions);
    } catch (error) {
      console.error("Erro ao buscar todas as sessões ativas:", error);
      res.status(500).json({ message: "Falha ao buscar todas as sessões ativas" });
    }
  });

  // Health check
  app.get('/api/health', (req, res) => {
    res.json({ 
      status: 'ok', 
      timestamp: new Date().toISOString(),
      version: '1.0.0'
    });
  });

  const httpServer = createServer(app);

  // WebSocket server for real-time updates
  const wss = new WebSocketServer({ 
    server: httpServer, 
    path: '/ws' 
  });

  wss.on('connection', (ws) => {
    console.log('Cliente WebSocket conectado');
    connectedClients.add(ws);

    ws.on('close', () => {
      console.log('Cliente WebSocket desconectado');
      connectedClients.delete(ws);
    });

    ws.on('error', (error) => {
      console.error('Erro WebSocket:', error);
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
