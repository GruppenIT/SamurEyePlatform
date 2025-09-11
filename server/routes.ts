import type { Express } from "express";
import { createServer, type Server } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { storage } from "./storage";
import { setupAuth, isAuthenticated } from "./localAuth";
import { jobQueue } from "./services/jobQueue";
import { threatEngine } from "./services/threatEngine";
import { encryptionService } from "./services/encryption";
import { 
  insertAssetSchema, 
  insertCredentialSchema, 
  insertJourneySchema, 
  insertScheduleSchema 
} from "@shared/schema";

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
  app.get('/api/dashboard/metrics', isAuthenticated, async (req, res) => {
    try {
      const metrics = await storage.getDashboardMetrics();
      res.json(metrics);
    } catch (error) {
      console.error("Erro ao buscar métricas:", error);
      res.status(500).json({ message: "Falha ao buscar métricas" });
    }
  });

  app.get('/api/dashboard/running-jobs', isAuthenticated, async (req, res) => {
    try {
      const jobs = await storage.getRunningJobs();
      res.json(jobs);
    } catch (error) {
      console.error("Erro ao buscar jobs em execução:", error);
      res.status(500).json({ message: "Falha ao buscar jobs" });
    }
  });

  app.get('/api/dashboard/recent-threats', isAuthenticated, async (req, res) => {
    try {
      const threats = await storage.getThreats();
      const recentThreats = threats.slice(0, 10); // Last 10 threats
      res.json(recentThreats);
    } catch (error) {
      console.error("Erro ao buscar ameaças recentes:", error);
      res.status(500).json({ message: "Falha ao buscar ameaças" });
    }
  });

  // Asset routes
  app.get('/api/assets', isAuthenticated, async (req, res) => {
    try {
      const assets = await storage.getAssets();
      res.json(assets);
    } catch (error) {
      console.error("Erro ao buscar ativos:", error);
      res.status(500).json({ message: "Falha ao buscar ativos" });
    }
  });

  app.post('/api/assets', isAuthenticated, async (req: any, res) => {
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

  app.patch('/api/assets/:id', isAuthenticated, async (req: any, res) => {
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
        before: beforeAsset,
        after: asset,
      });
      
      res.json(asset);
    } catch (error) {
      console.error("Erro ao atualizar ativo:", error);
      res.status(400).json({ message: "Falha ao atualizar ativo" });
    }
  });

  app.delete('/api/assets/:id', isAuthenticated, async (req: any, res) => {
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
        before: beforeAsset,
        after: null,
      });
      
      res.status(204).send();
    } catch (error) {
      console.error("Erro ao excluir ativo:", error);
      res.status(400).json({ message: "Falha ao excluir ativo" });
    }
  });

  // Credential routes
  app.get('/api/credentials', isAuthenticated, async (req, res) => {
    try {
      const credentials = await storage.getCredentials();
      res.json(credentials);
    } catch (error) {
      console.error("Erro ao buscar credenciais:", error);
      res.status(500).json({ message: "Falha ao buscar credenciais" });
    }
  });

  app.post('/api/credentials', isAuthenticated, async (req: any, res) => {
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
        username: credentialData.username,
        secretEncrypted,
        dekEncrypted,
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

  app.delete('/api/credentials/:id', isAuthenticated, async (req: any, res) => {
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
  app.get('/api/journeys', isAuthenticated, async (req, res) => {
    try {
      const journeys = await storage.getJourneys();
      res.json(journeys);
    } catch (error) {
      console.error("Erro ao buscar jornadas:", error);
      res.status(500).json({ message: "Falha ao buscar jornadas" });
    }
  });

  app.post('/api/journeys', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const journeyData = insertJourneySchema.parse(req.body);
      const journey = await storage.createJourney(journeyData, userId);
      
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

  app.patch('/api/journeys/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;
      const updates = req.body;
      
      const beforeJourney = await storage.getJourney(id);
      const journey = await storage.updateJourney(id, updates);
      
      await storage.logAudit({
        actorId: userId,
        action: 'update',
        objectType: 'journey',
        objectId: id,
        before: beforeJourney,
        after: journey,
      });
      
      res.json(journey);
    } catch (error) {
      console.error("Erro ao atualizar jornada:", error);
      res.status(400).json({ message: "Falha ao atualizar jornada" });
    }
  });

  app.delete('/api/journeys/:id', isAuthenticated, async (req: any, res) => {
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
        before: beforeJourney,
      });
      
      res.status(204).send();
    } catch (error) {
      console.error("Erro ao excluir jornada:", error);
      res.status(400).json({ message: "Falha ao excluir jornada" });
    }
  });

  // Schedule routes
  app.get('/api/schedules', isAuthenticated, async (req, res) => {
    try {
      const schedules = await storage.getSchedules();
      res.json(schedules);
    } catch (error) {
      console.error("Erro ao buscar agendamentos:", error);
      res.status(500).json({ message: "Falha ao buscar agendamentos" });
    }
  });

  app.post('/api/schedules', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const scheduleData = insertScheduleSchema.parse(req.body);
      const schedule = await storage.createSchedule(scheduleData, userId);
      
      await storage.logAudit({
        actorId: userId,
        action: 'create',
        objectType: 'schedule',
        objectId: schedule.id,
        after: schedule,
      });
      
      res.status(201).json(schedule);
    } catch (error) {
      console.error("Erro ao criar agendamento:", error);
      res.status(400).json({ message: "Falha ao criar agendamento" });
    }
  });

  // Job routes
  app.get('/api/jobs', isAuthenticated, async (req, res) => {
    try {
      const limit = req.query.limit ? parseInt(req.query.limit as string) : undefined;
      const jobs = await storage.getJobs(limit);
      res.json(jobs);
    } catch (error) {
      console.error("Erro ao buscar jobs:", error);
      res.status(500).json({ message: "Falha ao buscar jobs" });
    }
  });

  app.post('/api/jobs/execute', isAuthenticated, async (req: any, res) => {
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
        after: job,
      });
      
      res.status(201).json(job);
    } catch (error) {
      console.error("Erro ao executar job:", error);
      res.status(400).json({ message: "Falha ao executar job" });
    }
  });

  app.get('/api/jobs/:id/result', isAuthenticated, async (req, res) => {
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

  // Threat routes
  app.get('/api/threats', isAuthenticated, async (req, res) => {
    try {
      const { severity, status, assetId } = req.query;
      const filters: any = {};
      
      if (severity) filters.severity = severity as string;
      if (status) filters.status = status as string;
      if (assetId) filters.assetId = assetId as string;
      
      const threats = await storage.getThreats(filters);
      res.json(threats);
    } catch (error) {
      console.error("Erro ao buscar ameaças:", error);
      res.status(500).json({ message: "Falha ao buscar ameaças" });
    }
  });

  app.patch('/api/threats/:id', isAuthenticated, async (req: any, res) => {
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
        before: beforeThreat,
        after: threat,
      });
      
      res.json(threat);
    } catch (error) {
      console.error("Erro ao atualizar ameaça:", error);
      res.status(400).json({ message: "Falha ao atualizar ameaça" });
    }
  });

  app.get('/api/threats/stats', isAuthenticated, async (req, res) => {
    try {
      const stats = await storage.getThreatStats();
      res.json(stats);
    } catch (error) {
      console.error("Erro ao buscar estatísticas de ameaças:", error);
      res.status(500).json({ message: "Falha ao buscar estatísticas" });
    }
  });

  // User management routes (admin only)
  app.get('/api/users', isAuthenticated, async (req: any, res) => {
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

  app.post('/api/users', isAuthenticated, async (req: any, res) => {
    try {
      const actorRole = req.user.role || 'read_only';
      if (actorRole !== 'global_administrator') {
        return res.status(403).json({ message: "Acesso negado - apenas administradores podem criar usuários" });
      }

      const { email, firstName, lastName, password, role } = req.body;
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

  app.patch('/api/users/:id/role', isAuthenticated, async (req: any, res) => {
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
        before: beforeUser,
        after: user,
      });
      
      res.json(user);
    } catch (error) {
      console.error("Erro ao atualizar papel do usuário:", error);
      res.status(400).json({ message: "Falha ao atualizar papel" });
    }
  });

  // Audit log routes
  app.get('/api/audit', isAuthenticated, async (req: any, res) => {
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

  return httpServer;
}
