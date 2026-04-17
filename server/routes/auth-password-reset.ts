import type { Express } from "express";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import { storage } from "../storage";
import { passwordResetService } from "../services/passwordResetService";
import { confirmPasswordResetSchema } from "@shared/schema";
import { createLogger } from "../lib/logger";

const log = createLogger('routes:password-reset');

const IP_HASH = (ip: string) => crypto.createHash('sha256').update(ip).digest('hex').slice(0, 16);
const EMAIL_HASH = (email: string) => crypto.createHash('sha256').update(email.trim().toLowerCase()).digest('hex').slice(0, 16);

async function isBlocked(key: string): Promise<boolean> {
  const attempt = await storage.getLoginAttempt(key);
  if (!attempt?.blockedUntil) return false;
  return new Date() < attempt.blockedUntil;
}

export function registerAuthPasswordResetRoutes(app: Express) {
  // GET /api/auth/features — public
  app.get('/api/auth/features', async (_req, res) => {
    try {
      const passwordRecoveryAvailable = await passwordResetService.isDeliveryAvailable();
      res.json({ passwordRecoveryAvailable });
    } catch (error) {
      log.error({ err: error }, 'features check failed');
      res.json({ passwordRecoveryAvailable: false });
    }
  });

  // POST /api/auth/password-reset/request — always 202
  app.post('/api/auth/password-reset/request', async (req, res) => {
    const rawEmail = String(req.body?.email ?? '').trim().toLowerCase();
    const clientIp = req.ip || 'unknown';
    const ipKey = `pwreset:ip:${IP_HASH(clientIp)}`;
    const emailKey = rawEmail ? `pwreset:email:${EMAIL_HASH(rawEmail)}` : null;

    const always202 = () =>
      res.status(202).json({ message: "Se o e-mail existir em nossa base, enviaremos um link em instantes." });

    try {
      if (!rawEmail || !rawEmail.includes('@')) return always202();
      if (await isBlocked(ipKey)) return always202();
      if (emailKey && await isBlocked(emailKey)) return always202();
      if (!(await passwordResetService.isDeliveryAvailable())) {
        log.warn('password reset requested but messaging not ready');
        return always202();
      }
      const user = await storage.getUserByEmail(rawEmail);
      if (!user) return always202();

      await storage.cleanupOldPasswordResetTokens(user.id);
      const raw = passwordResetService.generateToken();
      const tokenHash = await passwordResetService.hashToken(raw);
      await storage.createPasswordResetToken({
        userId: user.id,
        tokenHash,
        expiresAt: passwordResetService.computeExpiresAt(),
      });

      const proto = req.headers['x-forwarded-proto'] ?? req.protocol ?? 'https';
      const host = req.headers['x-forwarded-host'] ?? req.get('host');
      const link = `${proto}://${host}/reset-password?token=${encodeURIComponent(raw)}`;

      try {
        await passwordResetService.sendResetEmail(user.email, link);
        await storage.logAudit({
          actorId: user.id,
          action: 'user.password_reset.request',
          objectType: 'user',
          objectId: user.id,
          before: null,
          after: { ip: clientIp },
        });
      } catch (mailErr) {
        log.error({ err: mailErr, userId: user.id }, 'failed to send reset email');
      }

      await storage.upsertLoginAttempt(ipKey, true);
      if (emailKey) await storage.upsertLoginAttempt(emailKey, true);
      return always202();
    } catch (error) {
      log.error({ err: error }, 'password reset request failed');
      return always202();
    }
  });

  // GET /api/auth/password-reset/verify
  app.get('/api/auth/password-reset/verify', async (req, res) => {
    try {
      const token = String(req.query?.token ?? '');
      if (!token) return res.status(410).json({ valid: false });
      const match = await passwordResetService.findTokenMatch(token);
      if (!match) return res.status(410).json({ valid: false });
      res.json({ valid: true });
    } catch (error) {
      log.error({ err: error }, 'password reset verify failed');
      res.status(500).json({ valid: false });
    }
  });

  // POST /api/auth/password-reset/confirm
  app.post('/api/auth/password-reset/confirm', async (req, res) => {
    const clientIp = req.ip || 'unknown';
    const ipKey = `pwreset:confirm:ip:${IP_HASH(clientIp)}`;
    try {
      if (await isBlocked(ipKey)) {
        return res.status(429).json({ message: "Muitas tentativas. Aguarde 15 minutos." });
      }
      const parsed = confirmPasswordResetSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({
          message: "Dados inválidos",
          errors: parsed.error.flatten(),
        });
      }
      const { token, newPassword } = parsed.data;

      const match = await passwordResetService.findTokenMatch(token);
      if (!match) {
        await storage.upsertLoginAttempt(ipKey, true);
        return res.status(401).json({ message: "Link inválido ou expirado" });
      }

      const userId = match.token.userId;
      const newHash = await bcrypt.hash(newPassword, 12);

      await storage.updateUserPassword(userId, newHash);
      await storage.setMustChangePassword(userId, false);
      await storage.consumePasswordResetToken(match.token.id);
      await storage.consumeAllPasswordResetTokensForUser(userId);
      await storage.deleteActiveSessionsByUserId(userId);
      await storage.resetLoginAttempts(ipKey);

      await storage.logAudit({
        actorId: userId,
        action: 'user.password_reset.success',
        objectType: 'user',
        objectId: userId,
        before: null,
        after: { ip: clientIp },
      });

      res.json({ message: "Senha atualizada. Faça login novamente." });
    } catch (error) {
      log.error({ err: error }, 'password reset confirm failed');
      res.status(500).json({ message: "Falha ao redefinir a senha" });
    }
  });
}
