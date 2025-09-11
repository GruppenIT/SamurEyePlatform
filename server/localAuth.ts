import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session from "express-session";
import type { Express, RequestHandler } from "express";
import bcrypt from "bcryptjs";
import connectPg from "connect-pg-simple";
import { storage } from "./storage";
import { registerUserSchema, loginUserSchema, type RegisterUser, type LoginUser } from "@shared/schema";

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

  const isProduction = process.env.NODE_ENV === 'production';
  
  return session({
    secret: process.env.SESSION_SECRET,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: isProduction, // Only secure cookies over HTTPS in production
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
              role: user.role
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

        // Clear the session cookie
        res.clearCookie('connect.sid', {
          path: '/',
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
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
        lastLogin: user.lastLogin
      });
    } catch (error) {
      console.error("Erro ao buscar usuário:", error);
      res.status(500).json({ message: "Falha ao buscar usuário" });
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