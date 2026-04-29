import type { Express } from "express";
import { storage } from "../storage";
import { db } from "../db";
import { sql } from "drizzle-orm";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { requireAdmin, validRoles } from "./middleware";
import { registerUserSchema } from "@shared/schema";
import { createLogger } from '../lib/logger';

const log = createLogger('routes:users');

export function registerUserRoutes(app: Express) {
  // User management routes (admin only)
  app.get('/api/users', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
    try {
      const userRole = req.user.role || 'read_only';
      if (userRole !== 'global_administrator') {
        return res.status(403).json({ message: "Acesso negado" });
      }

      const allUsers = await storage.getAllUsers();
      // In demo mode, only admin@samureye.local sees demo leads
      const visibleUsers = (process.env.DEMO_MODE === 'true' && req.user?.email !== 'admin@samureye.local')
        ? allUsers.filter(u => !u.isDemoLead)
        : allUsers;
      const sanitizedUsers = visibleUsers.map(({ passwordHash, ...user }) => user);
      res.json(sanitizedUsers);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch users');
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
      log.error({ err: error }, 'failed to create user');
      if (error.name === 'ZodError') {
        return res.status(400).json({
          message: 'Dados inválidos',
          errors: error.errors
        });
      }
      res.status(500).json({ message: 'Erro interno do servidor' });
    }
  });

  app.delete('/api/users/:id', isAuthenticatedWithPasswordCheck, requireAdmin, async (req: any, res) => {
    const { id } = req.params;
    if (id === req.user?.id) {
      return res.status(400).json({ message: 'Não é possível excluir sua própria conta.' });
    }
    try {
      const target = await storage.getUser(id);
      if (!target) return res.status(404).json({ message: 'Usuário não encontrado.' });
      await storage.deleteActiveSessionsByUserId(id);
      await storage.deleteUser(id);
      log.info({ actorId: req.user.id, deletedUserId: id, deletedEmail: target.email }, 'user deleted');
      res.status(204).end();
    } catch (err) {
      log.error({ err }, 'failed to delete user');
      res.status(500).json({ message: 'Erro ao excluir usuário.' });
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
      log.error({ err: error }, 'failed to update user role');
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
      log.error({ err: error }, 'failed to fetch audit log');
      res.status(500).json({ message: "Falha ao buscar auditoria" });
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
      log.error({ err: error }, 'failed to fetch active sessions');
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
              log.error({ err: err }, 'failed to destroy session from store');
              reject(err);
            } else {
              log.info({ sessionId }, 'session revoked successfully');
              resolve();
            }
          });
        });
      } else {
        // Fallback: deletar direto do banco se sessionStore não estiver disponível
        await db.execute(sql`DELETE FROM sessions WHERE sid = ${sessionId}`);
        log.info({ sessionId }, 'session deleted from db (fallback)');
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
      log.error({ err: error }, 'failed to revoke session');
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
                log.error({ err, sessionId: session.sessionId }, 'failed to destroy session from store');
                reject(err);
              } else {
                log.info({ sessionId: session.sessionId }, 'session revoked');
                resolve();
              }
            });
          });
        } else {
          // Fallback: deletar direto do banco
          await db.execute(sql`DELETE FROM sessions WHERE sid = ${session.sessionId}`);
          log.info({ sessionId: session.sessionId }, 'session deleted (fallback)');
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
      log.error({ err: error }, 'failed to revoke all sessions');
      res.status(500).json({ message: "Falha ao revogar todas as sessões" });
    }
  });

  // UI preferences — any authenticated user, scoped to own account
  app.get('/api/user/preferences', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
    try {
      const prefs = await storage.getUserPreferences(req.user.id);
      res.json(prefs ?? {});
    } catch (error) {
      log.error({ err: error }, 'failed to get user preferences');
      res.status(500).json({ message: 'Falha ao buscar preferências' });
    }
  });

  app.patch('/api/user/preferences', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
    try {
      const { theme, sidebarCollapsed } = req.body;
      const allowed = ['light', 'dark', 'system'];
      const prefs: { theme?: 'light' | 'dark' | 'system'; sidebarCollapsed?: boolean } = {};
      if (theme !== undefined) {
        if (!allowed.includes(theme)) return res.status(400).json({ message: 'Tema inválido' });
        prefs.theme = theme;
      }
      if (sidebarCollapsed !== undefined) {
        prefs.sidebarCollapsed = Boolean(sidebarCollapsed);
      }
      await storage.updateUserPreferences(req.user.id, prefs);
      res.json({ ok: true });
    } catch (error) {
      log.error({ err: error }, 'failed to update user preferences');
      res.status(500).json({ message: 'Falha ao salvar preferências' });
    }
  });
}
