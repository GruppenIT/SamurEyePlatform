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

    console.log('🔧 Criando usuário admin para desenvolvimento...');
    
    // Create or update admin user
    const adminPassword = 'admin';
    const hashedPassword = await hashPassword(adminPassword);
    
    if (existingAdmin) {
      // Update existing user with password and role
      await storage.updateUserPassword(existingAdmin.id, hashedPassword);
      await storage.updateUserRole(existingAdmin.id, 'global_administrator');
      await storage.setMustChangePassword(existingAdmin.id, false);
      console.log('✅ Usuário admin atualizado: admin@example.com / admin');
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
      console.log('✅ Usuário admin criado: admin@example.com / admin');
    }
  } catch (error) {
    console.error('❌ Erro ao criar usuário admin:', error);
  }
}

// Simple in-memory rate limiting for login attempts
interface RateLimitEntry {
  attempts: number;
  lastAttempt: Date;
  blockedUntil?: Date;
}

const loginAttempts = new Map<string, RateLimitEntry>();
const MAX_ATTEMPTS = 5;
const BLOCK_DURATION = 15 * 60 * 1000; // 15 minutes
const ATTEMPT_WINDOW = 60 * 1000; // 1 minute window

function isRateLimited(identifier: string): boolean {
  const entry = loginAttempts.get(identifier);
  if (!entry) return false;

  const now = new Date();
  
  // Check if still blocked
  if (entry.blockedUntil && now < entry.blockedUntil) {
    return true;
  }

  // Reset if attempt window has passed
  if (now.getTime() - entry.lastAttempt.getTime() > ATTEMPT_WINDOW) {
    loginAttempts.delete(identifier);
    return false;
  }

  return entry.attempts >= MAX_ATTEMPTS;
}

function recordLoginAttempt(identifier: string, success: boolean) {
  const now = new Date();
  const entry = loginAttempts.get(identifier);

  if (success) {
    // Clear on successful login
    loginAttempts.delete(identifier);
    return;
  }

  if (!entry) {
    loginAttempts.set(identifier, {
      attempts: 1,
      lastAttempt: now
    });
    return;
  }

  entry.attempts += 1;
  entry.lastAttempt = now;

  if (entry.attempts >= MAX_ATTEMPTS) {
    entry.blockedUntil = new Date(now.getTime() + BLOCK_DURATION);
  }

  loginAttempts.set(identifier, entry);
}

/**
 * Limpa sessões expiradas do banco de dados
 */
async function cleanupExpiredSessions(): Promise<void> {
  try {
    await db.execute(sql`
      DELETE FROM sessions 
      WHERE expire < NOW()
    `);
    
    console.log(`🧹 Limpeza de sessões expiradas executada`);
  } catch (error) {
    console.error('❌ Erro ao limpar sessões expiradas:', error);
  }
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
 * Middleware para verificar se a sessão ainda é válida (simplificado)
 * Usa a funcionalidade nativa do express-session ao invés de cálculos manuais
 */
export function validateSession(): RequestHandler {
  return (req: any, res, next) => {
    // Se não há usuário logado, prosseguir normalmente
    if (!req.user) {
      return next();
    }

    // Verificar se a sessão expirou usando o método nativo
    const cookieExpires = req.session.cookie.expires;
    if (cookieExpires && cookieExpires <= new Date()) {
      console.log(`🔒 Sessão expirada para usuário ${req.user.id}, forçando logout`);
      
      // Destruir sessão
      req.session.destroy((err: any) => {
        if (err) {
          console.error('Erro ao destruir sessão expirada:', err);
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
  app.post('/api/auth/login', (req, res, next) => {
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
    if (isRateLimited(rateLimitKey)) {
      return res.status(429).json({ 
        message: 'Muitas tentativas de login. Tente novamente em 15 minutos.' 
      });
    }

    passport.authenticate('local', (err: any, user: any, info: any) => {
      const success = !!user;
      recordLoginAttempt(rateLimitKey, success);

      if (err) {
        console.error("Erro de autenticação:", err);
        return res.status(500).json({ message: 'Erro interno do servidor' });
      }
      
      if (!user) {
        return res.status(401).json({ message: info?.message || 'Credenciais inválidas' });
      }

      // Regenerate session ID to prevent session fixation
      req.session.regenerate((err) => {
        if (err) {
          console.error("Erro ao regenerar sessão:", err);
          return res.status(500).json({ message: 'Erro interno do servidor' });
        }

        req.logIn(user, (err) => {
          if (err) {
            console.error("Erro ao fazer login:", err);
            return res.status(500).json({ message: 'Erro interno do servidor' });
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
  app.post('/api/auth/logout', (req, res) => {
    req.logout((err) => {
      if (err) {
        console.error("Erro ao fazer logout:", err);
        return res.status(500).json({ message: 'Erro interno do servidor' });
      }

      // Destroy the session and clear cookie
      req.session.destroy((err) => {
        if (err) {
          console.error("Erro ao destruir sessão:", err);
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
      console.error("Erro ao buscar usuário:", error);
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
      
      // Regenerate session to prevent session fixation
      req.session.regenerate(async (err: any) => {
        if (err) {
          console.error("Erro ao regenerar sessão:", err);
          return res.status(500).json({ message: 'Erro interno do servidor' });
        }
        
        // Re-login user with updated information
        const updatedUser = await storage.getUser(user.id);
        if (!updatedUser) {
          return res.status(500).json({ message: 'Erro interno do servidor' });
        }
        
        req.logIn(updatedUser, (err: any) => {
          if (err) {
            console.error("Erro ao fazer login:", err);
            return res.status(500).json({ message: 'Erro interno do servidor' });
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
      console.error("Erro ao alterar senha:", error);
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