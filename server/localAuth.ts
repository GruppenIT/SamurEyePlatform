import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session from "express-session";
import type { Express, RequestHandler } from "express";
import bcrypt from "bcryptjs";
import connectPg from "connect-pg-simple";
import { storage } from "./storage";
import { loginUserSchema, changePasswordSchema, type LoginUser, type ChangePassword } from "@shared/schema";
import { sql } from "drizzle-orm";
import { db } from "./db";
import { createLogger } from './lib/logger';

const log = createLogger('auth');

// Hash password utility function
async function hashPassword(password: string): Promise<string> {
  return await bcrypt.hash(password, 12);
}

/**
 * Bootstrap admin user for development testing
 */
async function bootstrapDevAdmin() {
  try {
    // Check if admin user exists
    const existingAdmin = await storage.getUserByEmail('admin@example.com');
    if (existingAdmin && existingAdmin.passwordHash) {
      return; // Admin already exists with password
    }

    log.info('🔧 Criando usuário admin para desenvolvimento...');
    
    // Create or update admin user
    const adminPassword = 'admin';
    const hashedPassword = await hashPassword(adminPassword);
    
    if (existingAdmin) {
      // Update existing user with password and role
      await storage.updateUserPassword(existingAdmin.id, hashedPassword);
      await storage.updateUserRole(existingAdmin.id, 'global_administrator');
      await storage.setMustChangePassword(existingAdmin.id, false);
      log.info('✅ Usuário admin atualizado: admin@example.com / admin');
    } else {
      // Create new admin user
      const newUser = await storage.createUser({
        email: 'admin@example.com',
        passwordHash: hashedPassword,
        firstName: 'Admin',
        lastName: 'User',
        role: 'global_administrator'
      });
      await storage.setMustChangePassword(newUser.id, false);
      log.info('✅ Usuário admin criado: admin@example.com / admin');
    }
  } catch (error) {
    log.error('❌ Erro ao criar usuário admin:', error);
  }
}

// Persistent rate limiting using PostgreSQL
async function isRateLimited(identifier: string): Promise<boolean> {
  const attempt = await storage.getLoginAttempt(identifier);
  if (!attempt) return false;

  const now = new Date();
  
  // Check if still blocked
  if (attempt.blockedUntil && now < attempt.blockedUntil) {
    return true;
  }

  return false;
}

async function recordLoginAttempt(identifier: string, success: boolean) {
  if (success) {
    // Clear on successful login
    await storage.resetLoginAttempts(identifier);
    return;
  }

  // Increment attempts
  await storage.upsertLoginAttempt(identifier, true);
}

/**
 * Limpa sessões expiradas do banco de dados
 */
async function cleanupExpiredSessions(): Promise<void> {
  try {
    // Limpar sessões connect-pg-simple
    await db.execute(sql`
      DELETE FROM sessions 
      WHERE expire < NOW()
    `);
    
    // Limpar active_sessions expiradas
    await storage.cleanupExpiredSessions();
    
    // Limpar login attempts antigos
    await storage.cleanupOldLoginAttempts();
    
    log.info(`🧹 Limpeza de sessões expiradas executada`);
  } catch (error) {
    log.error('❌ Erro ao limpar sessões expiradas:', error);
  }
}

/**
 * Incrementa a versão global de sessão para invalidar todas as sessões ativas
 * Executado ao iniciar o servidor
 */
async function invalidateAllSessionsOnStartup(): Promise<void> {
  try {
    // Buscar o primeiro admin para usar como userId
    const users = await storage.getAllUsers();
    const adminUser = users.find(u => u.role === 'global_administrator') || users[0];
    
    if (!adminUser) {
      log.warn('⚠️  Nenhum usuário encontrado para incrementar versão de sessão');
      return;
    }
    
    const newVersion = await storage.incrementSessionVersion(adminUser.id);
    log.info(`🔐 Versão de sessão incrementada para ${newVersion} - todas as sessões anteriores invalidadas`);
    
    // Limpar todas as sessões ativas do banco (connect-pg-simple)
    await db.execute(sql`DELETE FROM sessions`);
    
    // Limpar todas as sessões ativas rastreadas
    await db.execute(sql`DELETE FROM active_sessions`);
    
    log.info(`🔒 Todas as sessões anteriores foram removidas`);
  } catch (error) {
    log.error('❌ Erro ao invalidar sessões na inicialização:', error);
  }
}

/**
 * Obtém informações sobre o device do user agent
 */
function parseDeviceInfo(userAgent: string): string {
  if (!userAgent) return 'Unknown Device';
  
  // Detectar navegador
  let browser = 'Unknown Browser';
  if (userAgent.includes('Chrome')) browser = 'Chrome';
  else if (userAgent.includes('Firefox')) browser = 'Firefox';
  else if (userAgent.includes('Safari')) browser = 'Safari';
  else if (userAgent.includes('Edge')) browser = 'Edge';
  
  // Detectar OS
  let os = 'Unknown OS';
  if (userAgent.includes('Windows')) os = 'Windows';
  else if (userAgent.includes('Mac')) os = 'macOS';
  else if (userAgent.includes('Linux')) os = 'Linux';
  else if (userAgent.includes('Android')) os = 'Android';
  else if (userAgent.includes('iOS')) os = 'iOS';
  
  return `${browser} on ${os}`;
}

export function getSession() {
  // Require SESSION_SECRET in production
  if (!process.env.SESSION_SECRET) {
    throw new Error("SESSION_SECRET environment variable is required");
  }

  // Use 8 hours for security applications  
  // TTL for cookies (in milliseconds) and store (in seconds)
  const sessionTtlMs = 8 * 60 * 60 * 1000; // 8 hours in milliseconds 
  const sessionTtlSec = 8 * 60 * 60; // 8 hours in seconds
  
  const pgStore = connectPg(session);
  const sessionStore = new pgStore({
    conString: process.env.DATABASE_URL,
    createTableIfMissing: false,
    ttl: sessionTtlSec, // connect-pg-simple expects seconds, not milliseconds!
    tableName: "sessions"
  });

  // Configurar limpeza automática de sessões expiradas
  setInterval(() => {
    cleanupExpiredSessions();
  }, 10 * 60 * 1000); // Limpar a cada 10 minutos

  // Use express-session's built-in HTTPS detection with trust proxy
  return session({
    secret: process.env.SESSION_SECRET,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: 'auto', // Automatically detects HTTPS based on trust proxy + X-Forwarded-Proto
      sameSite: 'lax', // CSRF protection
      maxAge: sessionTtlMs, // Cookie maxAge expects milliseconds
    },
  });
}

/**
 * Middleware para verificar se a sessão ainda é válida
 * Valida tanto a expiração quanto a versão da sessão
 */
export function validateSession(): RequestHandler {
  return async (req: any, res, next) => {
    // Se não há usuário logado, prosseguir normalmente
    if (!req.user) {
      return next();
    }

    // Verificar se a sessão expirou usando o método nativo
    const cookieExpires = req.session.cookie.expires;
    if (cookieExpires && cookieExpires <= new Date()) {
      log.info(`🔒 Sessão expirada para usuário ${req.user.id}, forçando logout`);
      
      // Remover sessão ativa
      if (req.sessionID) {
        await storage.deleteActiveSession(req.sessionID).catch(err => {
          log.error('Erro ao remover sessão ativa:', err);
        });
      }
      
      // Destruir sessão
      req.session.destroy((err: any) => {
        if (err) {
          log.error('Erro ao destruir sessão expirada:', err);
        }
      });
      
      // Limpar cookie
      res.clearCookie('connect.sid', {
        path: '/',
        httpOnly: true,
        secure: req.secure || req.get('X-Forwarded-Proto') === 'https',
        sameSite: 'lax'
      });
      
      // Retornar 401 se for request API, redirect se for página
      if (req.path.startsWith('/api/')) {
        return res.status(401).json({ message: 'Sessão expirada', expired: true });
      } else {
        return res.redirect('/login');
      }
    }

    // CRITICAL: Validar se a sessão está rastreada em active_sessions
    try {
      const activeSession = await storage.getActiveSessionBySessionId(req.sessionID);
      
      // Bloquear sessões que não estão rastreadas (revogadas ou inválidas)
      if (!activeSession) {
        log.info(`🔒 Sessão não rastreada para usuário ${req.user.id} - provavelmente revogada`);
        
        // Destruir sessão
        req.session.destroy((err: any) => {
          if (err) {
            log.error('Erro ao destruir sessão não rastreada:', err);
          }
        });
        
        // Limpar cookie
        res.clearCookie('connect.sid', {
          path: '/',
          httpOnly: true,
          secure: req.secure || req.get('X-Forwarded-Proto') === 'https',
          sameSite: 'lax'
        });
        
        // Retornar 401 se for request API, redirect se for página
        if (req.path.startsWith('/api/')) {
          return res.status(401).json({ message: 'Sessão revogada', expired: true });
        } else {
          return res.redirect('/login');
        }
      }
      
      const currentVersion = await storage.getCurrentSessionVersion();
      
      // Bloquear sessões com versão desatualizada
      if (activeSession.sessionVersion !== currentVersion) {
        log.info(`🔒 Sessão invalidada para usuário ${req.user.id} (versão ${activeSession.sessionVersion} vs atual ${currentVersion})`);
        
        // Remover sessão ativa
        await storage.deleteActiveSession(req.sessionID).catch(err => {
          log.error('Erro ao remover sessão ativa:', err);
        });
        
        // Destruir sessão
        req.session.destroy((err: any) => {
          if (err) {
            log.error('Erro ao destruir sessão invalidada:', err);
          }
        });
        
        // Limpar cookie
        res.clearCookie('connect.sid', {
          path: '/',
          httpOnly: true,
          secure: req.secure || req.get('X-Forwarded-Proto') === 'https',
          sameSite: 'lax'
        });
        
        // Retornar 401 se for request API, redirect se for página
        if (req.path.startsWith('/api/')) {
          return res.status(401).json({ message: 'Sessão invalidada', expired: true });
        } else {
          return res.redirect('/login');
        }
      }
      
      // Atualizar última atividade
      await storage.updateActiveSessionLastActivity(req.sessionID).catch(err => {
        log.error('Erro ao atualizar última atividade da sessão:', err);
      });
    } catch (error) {
      log.error('Erro ao validar sessão:', error);
      // Em caso de erro, forçar logout por segurança
      req.session.destroy((err: any) => {
        if (err) {
          log.error('Erro ao destruir sessão após erro de validação:', err);
        }
      });
      res.clearCookie('connect.sid', {
        path: '/',
        httpOnly: true,
        secure: req.secure || req.get('X-Forwarded-Proto') === 'https',
        sameSite: 'lax'
      });
      if (req.path.startsWith('/api/')) {
        return res.status(401).json({ message: 'Erro ao validar sessão', expired: true });
      } else {
        return res.redirect('/login');
      }
    }
    
    next();
  };
}

export async function setupAuth(app: Express) {
  app.set("trust proxy", 1);
  app.use(getSession());
  app.use(passport.initialize());
  app.use(passport.session());
  
  // Express-session já controla expiração, mas adicionamos validação extra para APIs
  app.use(validateSession());

  // Bootstrap admin user for development testing
  if (process.env.NODE_ENV === 'development') {
    await bootstrapDevAdmin();
  }

  // Invalidar todas as sessões ao iniciar o servidor
  await invalidateAllSessionsOnStartup();

  // Local strategy for email/password authentication
  passport.use(new LocalStrategy(
    {
      usernameField: 'email',
      passwordField: 'password'
    },
    async (email: string, password: string, done: any) => {
      try {
        const user = await storage.getUserByEmail(email);
        if (!user || !user.passwordHash) {
          return done(null, false, { message: 'Email ou senha inválidos' });
        }

        const isValidPassword = await bcrypt.compare(password, user.passwordHash);
        if (!isValidPassword) {
          return done(null, false, { message: 'Email ou senha inválidos' });
        }

        // Update last login
        await storage.updateUserLastLogin(user.id);

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  ));

  passport.serializeUser((user: any, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id: string, done) => {
    try {
      const user = await storage.getUser(id);
      done(null, user);
    } catch (error) {
      done(error);
    }
  });


  // Login route
  app.post('/api/auth/login', async (req, res, next) => {
    try {
      loginUserSchema.parse(req.body);
    } catch (error: any) {
      return res.status(400).json({ 
        message: 'Dados inválidos',
        errors: error.errors 
      });
    }

    const { email } = req.body;
    const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
    const rateLimitKey = `${email}:${clientIP}`;

    // Check rate limiting
    if (await isRateLimited(rateLimitKey)) {
      return res.status(429).json({ 
        message: 'Muitas tentativas de login. Tente novamente em 15 minutos.' 
      });
    }

    passport.authenticate('local', async (err: any, user: any, info: any) => {
      const success = !!user;
      await recordLoginAttempt(rateLimitKey, success);

      if (err) {
        log.error("Erro de autenticação:", err);
        return res.status(500).json({ message: 'Erro interno do servidor' });
      }
      
      if (!user) {
        return res.status(401).json({ message: info?.message || 'Credenciais inválidas' });
      }

      // Regenerate session ID to prevent session fixation
      req.session.regenerate(async (err) => {
        if (err) {
          log.error("Erro ao regenerar sessão:", err);
          return res.status(500).json({ message: 'Erro interno do servidor' });
        }

        req.logIn(user, async (err) => {
          if (err) {
            log.error("Erro ao fazer login:", err);
            return res.status(500).json({ message: 'Erro interno do servidor' });
          }
          
          try {
            // Criar sessão ativa rastreada
            const userAgent = req.get('user-agent') || 'Unknown';
            const deviceInfo = parseDeviceInfo(userAgent);
            const currentVersion = await storage.getCurrentSessionVersion();
            const sessionTtlMs = 8 * 60 * 60 * 1000; // 8 hours
            
            await storage.createActiveSession({
              sessionId: req.sessionID,
              userId: user.id,
              sessionVersion: currentVersion,
              ipAddress: clientIP,
              userAgent: userAgent,
              deviceInfo: deviceInfo,
              expiresAt: new Date(Date.now() + sessionTtlMs),
            });
            
            // Registrar auditoria de login
            await storage.logAudit({
              actorId: user.id,
              action: 'user.login',
              objectType: 'session',
              objectId: req.sessionID,
              before: null,
              after: {
                ip: clientIP,
                userAgent: userAgent,
                device: deviceInfo,
              }
            });
            
            log.info(`✅ Login bem-sucedido: ${user.email} de ${clientIP} (${deviceInfo})`);
          } catch (error) {
            log.error('Erro ao criar sessão ativa:', error);
            // Não falhar o login se houver erro ao criar sessão ativa
          }
          
          res.json({ 
            message: 'Login realizado com sucesso',
            user: {
              id: user.id,
              email: user.email,
              firstName: user.firstName,
              lastName: user.lastName,
              role: user.role,
              mustChangePassword: user.mustChangePassword
            }
          });
        });
      });
    })(req, res, next);
  });

  // Logout route
  app.post('/api/auth/logout', async (req: any, res) => {
    const userId = req.user?.id;
    const sessionId = req.sessionID;
    const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
    
    req.logout(async (err: any) => {
      if (err) {
        log.error("Erro ao fazer logout:", err);
        return res.status(500).json({ message: 'Erro interno do servidor' });
      }

      // Remover sessão ativa rastreada
      if (sessionId) {
        try {
          await storage.deleteActiveSession(sessionId);
        } catch (error) {
          log.error('Erro ao remover sessão ativa:', error);
        }
      }

      // Registrar auditoria de logout
      if (userId) {
        try {
          await storage.logAudit({
            actorId: userId,
            action: 'user.logout',
            objectType: 'session',
            objectId: sessionId,
            before: null,
            after: {
              ip: clientIP,
              reason: 'voluntary',
            }
          });
        } catch (error) {
          log.error('Erro ao registrar auditoria de logout:', error);
        }
      }

      // Destroy the session and clear cookie
      req.session.destroy((err: any) => {
        if (err) {
          log.error("Erro ao destruir sessão:", err);
          return res.status(500).json({ message: 'Erro interno do servidor' });
        }

        // Clear the session cookie with same settings as session
        res.clearCookie('connect.sid', {
          path: '/',
          httpOnly: true,
          secure: req.secure || req.get('X-Forwarded-Proto') === 'https', // Match session cookie security
          sameSite: 'lax'
        });

        res.json({ message: 'Logout realizado com sucesso' });
      });
    });
  });

  // Get current user route
  app.get('/api/auth/user', isAuthenticated, async (req: any, res) => {
    try {
      const user = req.user;
      res.json({
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        mustChangePassword: user.mustChangePassword,
        lastLogin: user.lastLogin
      });
    } catch (error) {
      log.error("Erro ao buscar usuário:", error);
      res.status(500).json({ message: "Falha ao buscar usuário" });
    }
  });

  // Change password route (allowed even when mustChangePassword is true)
  app.post('/api/auth/change-password', isAuthenticated, async (req: any, res) => {
    try {
      // Validate input
      const validatedData = changePasswordSchema.parse(req.body);
      const { currentPassword, newPassword } = validatedData;
      
      const user = req.user;
      
      // Verify current password
      const isCurrentPasswordValid = await verifyPassword(currentPassword, user.passwordHash);
      if (!isCurrentPasswordValid) {
        return res.status(400).json({ message: 'Senha atual incorreta' });
      }
      
      // Hash new password
      const newPasswordHash = await hashPassword(newPassword);
      
      // Update password and clear must change flag
      await storage.updateUserPassword(user.id, newPasswordHash);
      await storage.setMustChangePassword(user.id, false);

      // Audit log for password change
      const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
      await storage.logAudit({
        actorId: user.id,
        action: 'user.change_password',
        objectType: 'user',
        objectId: user.id,
        before: null,
        after: { ip: clientIP },
      });

      // Regenerate session to prevent session fixation
      const oldSessionId = req.sessionID;
      req.session.regenerate(async (err: any) => {
        if (err) {
          log.error("Erro ao regenerar sessão:", err);
          return res.status(500).json({ message: 'Erro interno do servidor' });
        }

        // Re-login user with updated information
        const updatedUser = await storage.getUser(user.id);
        if (!updatedUser) {
          return res.status(500).json({ message: 'Erro interno do servidor' });
        }

        req.logIn(updatedUser, async (err: any) => {
          if (err) {
            log.error("Erro ao fazer login:", err);
            return res.status(500).json({ message: 'Erro interno do servidor' });
          }

          try {
            // Remove old session from tracking
            await storage.deleteActiveSession(oldSessionId);

            // Create new active session entry for the regenerated session
            const userAgent = req.get('user-agent') || 'Unknown';
            const deviceInfo = parseDeviceInfo(userAgent);
            const currentVersion = await storage.getCurrentSessionVersion();
            const sessionTtlMs = 8 * 60 * 60 * 1000;

            await storage.createActiveSession({
              sessionId: req.sessionID,
              userId: updatedUser.id,
              sessionVersion: currentVersion,
              ipAddress: clientIP,
              userAgent: userAgent,
              deviceInfo: deviceInfo,
              expiresAt: new Date(Date.now() + sessionTtlMs),
            });
          } catch (sessionError) {
            log.error('Erro ao rastrear sessão pós-troca de senha:', sessionError);
          }

          res.json({
            message: 'Senha alterada com sucesso',
            user: {
              id: updatedUser.id,
              email: updatedUser.email,
              firstName: updatedUser.firstName,
              lastName: updatedUser.lastName,
              role: updatedUser.role,
              mustChangePassword: updatedUser.mustChangePassword,
              lastLogin: updatedUser.lastLogin
            }
          });
        });
      });
    } catch (error: any) {
      if (error.name === 'ZodError') {
        return res.status(400).json({ 
          message: 'Dados inválidos',
          errors: error.errors 
        });
      }
      log.error("Erro ao alterar senha:", error);
      res.status(500).json({ message: 'Erro interno do servidor' });
    }
  });
}

export const isAuthenticated: RequestHandler = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: "Não autorizado" });
};

// Middleware to enforce password change when required
export const enforcePasswordChange: RequestHandler = (req, res, next) => {
  const user = (req as any).user;
  
  // Skip check if user is not authenticated
  if (!req.isAuthenticated() || !user) {
    return next();
  }
  
  // Allow certain routes even when password change is required
  const allowedRoutes = [
    '/api/auth/change-password',
    '/api/auth/logout',
    '/api/auth/user'
  ];
  
  if (allowedRoutes.includes(req.path)) {
    return next();
  }
  
  // Check if user must change password
  if (user.mustChangePassword) {
    return res.status(403).json({ 
      message: "Troca de senha obrigatória",
      reason: "password_change_required"
    });
  }
  
  next();
};

// Combined middleware for authentication with password change enforcement
export const isAuthenticatedWithPasswordCheck: RequestHandler = (req, res, next) => {
  isAuthenticated(req, res, (err?: any) => {
    if (err) return next(err);
    enforcePasswordChange(req, res, next);
  });
};

// Verify password utility function
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return await bcrypt.compare(password, hash);
}

// Export hash password utility function
export { hashPassword };