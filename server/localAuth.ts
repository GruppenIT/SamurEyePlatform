import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session from "express-session";
import type { Express, RequestHandler } from "express";
import bcrypt from "bcryptjs";
import connectPg from "connect-pg-simple";
import { storage } from "./storage";
import { loginUserSchema, changePasswordSchema, type LoginUser, type ChangePassword } from "@shared/schema";

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

export function getSession() {
  // Require SESSION_SECRET in production
  if (!process.env.SESSION_SECRET) {
    throw new Error("SESSION_SECRET environment variable is required");
  }

  const sessionTtl = 7 * 24 * 60 * 60 * 1000; // 1 week
  const pgStore = connectPg(session);
  const sessionStore = new pgStore({
    conString: process.env.DATABASE_URL,
    createTableIfMissing: false,
    ttl: sessionTtl,
    tableName: "sessions",
  });

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
      maxAge: sessionTtl,
    },
  });
}

export async function setupAuth(app: Express) {
  app.set("trust proxy", 1);
  app.use(getSession());
  app.use(passport.initialize());
  app.use(passport.session());

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
        // Log failed login attempt (but only occasionally to avoid spam)
        if (Math.random() < 0.1) { // Log 10% of failed attempts to avoid spam
          storage.logAudit({
            actorId: 'system',
            action: 'login_failed',
            objectType: 'user',
            objectId: null,
            before: null,
            after: {
              email: req.body.email,
              reason: info?.message || 'Credenciais inválidas',
              timestamp: new Date().toISOString(),
              clientIP: req.ip || req.connection.remoteAddress || 'unknown'
            },
          }).catch(err => console.error("Erro ao logar tentativa de login falhada:", err));
        }
        return res.status(401).json({ message: info?.message || 'Credenciais inválidas' });
      }

      // Regenerate session ID to prevent session fixation
      req.session.regenerate((err: any) => {
        if (err) {
          console.error("Erro ao regenerar sessão:", err);
          return res.status(500).json({ message: 'Erro interno do servidor' });
        }

        req.logIn(user, async (err: any) => {
          if (err) {
            console.error("Erro ao fazer login:", err);
            return res.status(500).json({ message: 'Erro interno do servidor' });
          }
          
          // Log successful login
          await storage.logAudit({
            actorId: user.id,
            action: 'login',
            objectType: 'user',
            objectId: user.id,
            before: null,
            after: {
              email: user.email,
              timestamp: new Date().toISOString(),
              clientIP: req.ip || req.connection.remoteAddress || 'unknown'
            },
          });

          res.json({ 
            message: 'Login realizado com sucesso',
            user: {
              id: user.id,
              email: user.email,
              firstName: user.firstName,
              lastName: user.lastName,
              role: user.role
            }
          });
        });
      });
    })(req, res, next);
  });

  // Logout route
  app.post('/api/auth/logout', async (req: any, res) => {
    const user = req.user;
    
    req.logout((err) => {
      if (err) {
        console.error("Erro ao fazer logout:", err);
        return res.status(500).json({ message: 'Erro interno do servidor' });
      }

      // Log logout if user was authenticated
      if (user) {
        storage.logAudit({
          actorId: user.id,
          action: 'logout',
          objectType: 'user',
          objectId: user.id,
          before: null,
          after: {
            email: user.email,
            timestamp: new Date().toISOString(),
            clientIP: req.ip || req.connection.remoteAddress || 'unknown'
          },
        }).catch((err: any) => console.error("Erro ao logar audit de logout:", err));
      }

      // Destroy the session and clear cookie
      req.session.destroy((err: any) => {
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
        lastLogin: user.lastLogin,
        mustChangePassword: user.mustChangePassword
      });
    } catch (error) {
      console.error("Erro ao buscar usuário:", error);
      res.status(500).json({ message: "Falha ao buscar usuário" });
    }
  });

  // Change password route
  app.post('/api/auth/change-password', isAuthenticated, async (req: any, res) => {
    try {
      const validation = changePasswordSchema.safeParse(req.body);
      if (!validation.success) {
        return res.status(400).json({ 
          message: 'Dados inválidos',
          errors: validation.error.errors 
        });
      }

      const { currentPassword, newPassword }: ChangePassword = validation.data;
      const user = req.user;

      // Verify current password
      const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.passwordHash);
      if (!isCurrentPasswordValid) {
        return res.status(400).json({ message: 'Senha atual incorreta' });
      }

      // Hash new password
      const newPasswordHash = await bcrypt.hash(newPassword, 12);

      // Update password and clear mustChangePassword flag
      await storage.updateUserPassword(user.id, newPasswordHash);

      // Log password change
      await storage.logAudit({
        actorId: user.id,
        action: 'change_password',
        objectType: 'user',
        objectId: user.id,
        before: null,
        after: {
          email: user.email,
          timestamp: new Date().toISOString(),
          clientIP: req.ip || req.connection.remoteAddress || 'unknown'
        },
      });

      res.json({ message: 'Senha alterada com sucesso' });
    } catch (error) {
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

// Hash password utility function
export async function hashPassword(password: string): Promise<string> {
  return await bcrypt.hash(password, 12);
}

// Verify password utility function
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return await bcrypt.compare(password, hash);
}