// REDIGIDO PARA DEPOSITO INPI (sem segredos)
// Modulo de autenticacao local - Passport.js com estrategia email/senha
// Inclui: rate limiting persistente, gestao de sessoes, auditoria

import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session from "express-session";
import type { Express, RequestHandler } from "express";
import bcrypt from "bcryptjs";
import connectPg from "connect-pg-simple";
import { storage } from "./storage";
import { loginUserSchema, changePasswordSchema } from "@shared/schema";
import { sql } from "drizzle-orm";
import { db } from "./db";

async function hashPassword(password: string): Promise<string> {
  return await bcrypt.hash(password, 12);
}

// Rate limiting persistente em PostgreSQL
async function isRateLimited(identifier: string): Promise<boolean> {
  const attempt = await storage.getLoginAttempt(identifier);
  if (!attempt) return false;
  const now = new Date();
  if (attempt.blockedUntil && now < attempt.blockedUntil) return true;
  return false;
}

async function recordLoginAttempt(identifier: string, success: boolean) {
  if (success) {
    await storage.resetLoginAttempts(identifier);
    return;
  }
  await storage.upsertLoginAttempt(identifier, true);
}

// Limpeza periodica de sessoes expiradas
async function cleanupExpiredSessions(): Promise<void> {
  try {
    await db.execute(sql`DELETE FROM sessions WHERE expire < NOW()`);
    await storage.cleanupExpiredSessions();
    await storage.cleanupOldLoginAttempts();
  } catch (error) {
    console.error('Erro ao limpar sessoes expiradas:', error);
  }
}

// Invalidacao de sessoes ao iniciar o servidor
async function invalidateAllSessionsOnStartup(): Promise<void> {
  try {
    const users = await storage.getAllUsers();
    const adminUser = users.find(u => u.role === 'global_administrator') || users[0];
    if (!adminUser) return;
    const newVersion = await storage.incrementSessionVersion(adminUser.id);
    await db.execute(sql`DELETE FROM sessions`);
    await db.execute(sql`DELETE FROM active_sessions`);
  } catch (error) {
    console.error('Erro ao invalidar sessoes:', error);
  }
}

export function getSession() {
  if (!process.env.SESSION_SECRET) {
    throw new Error("SESSION_SECRET environment variable is required");
  }
  const sessionTtlMs = 8 * 60 * 60 * 1000; // 8 horas
  const sessionTtlSec = 8 * 60 * 60;
  const pgStore = connectPg(session);
  const sessionStore = new pgStore({
    conString: process.env.DATABASE_URL,
    createTableIfMissing: false,
    ttl: sessionTtlSec,
    tableName: "sessions"
  });
  setInterval(() => { cleanupExpiredSessions(); }, 10 * 60 * 1000);
  return session({
    secret: process.env.SESSION_SECRET,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: 'auto',
      sameSite: 'lax',
      maxAge: sessionTtlMs,
    },
  });
}

// Middleware de validacao de sessao (verifica expiracao e versao)
export function validateSession(): RequestHandler {
  return async (req: any, res, next) => {
    if (!req.user) return next();
    // Valida expiracao, rastreamento em active_sessions e versao de sessao
    // [implementacao completa omitida - ver codigo-fonte]
    next();
  };
}

export async function setupAuth(app: Express) {
  app.set("trust proxy", 1);
  app.use(getSession());
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(validateSession());
  await invalidateAllSessionsOnStartup();

  passport.use(new LocalStrategy(
    { usernameField: 'email', passwordField: 'password' },
    async (email: string, password: string, done: any) => {
      try {
        const user = await storage.getUserByEmail(email);
        if (!user || !user.passwordHash) {
          return done(null, false, { message: 'Email ou senha invalidos' });
        }
        const isValidPassword = await bcrypt.compare(password, user.passwordHash);
        if (!isValidPassword) {
          return done(null, false, { message: 'Email ou senha invalidos' });
        }
        await storage.updateUserLastLogin(user.id);
        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  ));

  passport.serializeUser((user: any, done) => { done(null, user.id); });
  passport.deserializeUser(async (id: string, done) => {
    try {
      const user = await storage.getUser(id);
      done(null, user);
    } catch (error) { done(error); }
  });

  // Rota de login com rate limiting e auditoria
  // Rota de logout com rastreamento de sessao
  // Rota de troca de senha com regeneracao de sessao
  // [rotas completas omitidas - ver codigo-fonte]
}

export const isAuthenticated: RequestHandler = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.status(401).json({ message: "Nao autorizado" });
};

export const enforcePasswordChange: RequestHandler = (req, res, next) => {
  const user = (req as any).user;
  if (!req.isAuthenticated() || !user) return next();
  const allowedRoutes = ['/api/auth/change-password', '/api/auth/logout', '/api/auth/user'];
  if (allowedRoutes.includes(req.path)) return next();
  if (user.mustChangePassword) {
    return res.status(403).json({
      message: "Troca de senha obrigatoria",
      reason: "password_change_required"
    });
  }
  next();
};

export const isAuthenticatedWithPasswordCheck: RequestHandler = (req, res, next) => {
  isAuthenticated(req, res, (err?: any) => {
    if (err) return next(err);
    enforcePasswordChange(req, res, next);
  });
};

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return await bcrypt.compare(password, hash);
}
export { hashPassword };
