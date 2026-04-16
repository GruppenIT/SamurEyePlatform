import type { Express } from "express";
import { storage } from "../storage";
import { isAuthenticated, verifyPassword } from "../localAuth";
import { mfaService } from "../services/mfaService";
import { emailService } from "../services/emailService";
import { createLogger } from "../lib/logger";

const log = createLogger('routes:auth-mfa');

async function isMfaBlocked(userId: string): Promise<boolean> {
  const attempt = await storage.getLoginAttempt(`mfa:${userId}`);
  if (!attempt) return false;
  return !!attempt.blockedUntil && new Date() < attempt.blockedUntil;
}

export function registerAuthMfaRoutes(app: Express) {
  // POST /api/auth/mfa/setup
  app.post('/api/auth/mfa/setup', isAuthenticated, async (req: any, res) => {
    try {
      const user = req.user;
      if (user.mfaEnabled) {
        return res.status(400).json({ message: "MFA já está ativado" });
      }
      const setup = await mfaService.generateSetup(user.email);
      (req.session as any).pendingMfaSecret = setup.secret;
      (req.session as any).pendingMfaBackupHashes = setup.backupCodeHashes;
      req.session.save(() => {
        res.json({
          otpauthUrl: setup.otpauthUrl,
          qrCodeSvg: setup.qrCodeSvg,
          backupCodes: setup.backupCodes,
        });
      });
    } catch (error) {
      log.error({ err: error }, 'mfa setup failed');
      res.status(500).json({ message: "Falha ao preparar MFA" });
    }
  });

  // POST /api/auth/mfa/enable
  app.post('/api/auth/mfa/enable', isAuthenticated, async (req: any, res) => {
    try {
      const user = req.user;
      const token = String(req.body?.token ?? '').trim();
      const pendingSecret = (req.session as any).pendingMfaSecret;
      const pendingHashes = (req.session as any).pendingMfaBackupHashes;
      if (!pendingSecret || !Array.isArray(pendingHashes) || pendingHashes.length !== 8) {
        return res.status(400).json({ message: "Setup de MFA não iniciado. Recarregue a página." });
      }
      if (!mfaService.verifyTotp(token, pendingSecret)) {
        return res.status(400).json({ message: "Código TOTP inválido" });
      }
      const { encrypted, dek } = mfaService.encryptSecret(pendingSecret);
      await storage.setUserMfa(user.id, {
        mfaEnabled: true,
        mfaSecretEncrypted: encrypted,
        mfaSecretDek: dek,
        mfaBackupCodes: pendingHashes,
        mfaEnabledAt: new Date(),
      });
      delete (req.session as any).pendingMfaSecret;
      delete (req.session as any).pendingMfaBackupHashes;
      await storage.logAudit({
        actorId: user.id,
        action: 'user.mfa.enable',
        objectType: 'user',
        objectId: user.id,
        before: null,
        after: { mfaEnabled: true },
      });
      req.session.save(() => res.json({ success: true }));
    } catch (error) {
      log.error({ err: error }, 'mfa enable failed');
      res.status(500).json({ message: "Falha ao ativar MFA" });
    }
  });

  // POST /api/auth/mfa/verify — promote pendingMfa session (or re-verify)
  app.post('/api/auth/mfa/verify', async (req: any, res) => {
    try {
      const userId = (req.session as any).mfaUserId || req.user?.id;
      if (!userId) return res.status(401).json({ message: "Sessão inválida" });
      if (await isMfaBlocked(userId)) {
        return res.status(423).json({ message: "Muitas tentativas. Aguarde 15 minutos." });
      }
      const token = String(req.body?.token ?? '').trim();
      if (!token) return res.status(400).json({ message: "Código obrigatório" });

      const mfa = await storage.getUserMfa(userId);
      if (!mfa || !mfa.mfaEnabled || !mfa.mfaSecretEncrypted || !mfa.mfaSecretDek) {
        return res.status(400).json({ message: "MFA não configurado" });
      }

      // 1) email challenge
      if (await mfaService.verifyEmailChallenge(userId, token)) {
        await storage.resetLoginAttempts(`mfa:${userId}`);
        (req.session as any).pendingMfa = false;
        delete (req.session as any).mfaUserId;
        return req.session.save(() => res.json({ success: true }));
      }

      // 2) TOTP
      const secret = mfaService.decryptSecret(mfa.mfaSecretEncrypted, mfa.mfaSecretDek);
      if (mfaService.verifyTotp(token, secret)) {
        await storage.resetLoginAttempts(`mfa:${userId}`);
        (req.session as any).pendingMfa = false;
        delete (req.session as any).mfaUserId;
        return req.session.save(() => res.json({ success: true }));
      }

      // 3) backup code
      const hashes = mfa.mfaBackupCodes ?? [];
      const { matchIndex } = await mfaService.verifyBackupCode(token, hashes);
      if (matchIndex >= 0) {
        const remaining = hashes.filter((_, i) => i !== matchIndex);
        await storage.updateBackupCodes(userId, remaining);
        await storage.resetLoginAttempts(`mfa:${userId}`);
        (req.session as any).pendingMfa = false;
        delete (req.session as any).mfaUserId;
        return req.session.save(() => res.json({ success: true, backupCodeUsed: true, remaining: remaining.length }));
      }

      await storage.upsertLoginAttempt(`mfa:${userId}`, true);
      res.status(401).json({ message: "Código inválido" });
    } catch (error) {
      log.error({ err: error }, 'mfa verify failed');
      res.status(500).json({ message: "Falha ao validar código" });
    }
  });

  // POST /api/auth/mfa/email — send 6-digit code via email
  app.post('/api/auth/mfa/email', async (req: any, res) => {
    try {
      const userId = (req.session as any).mfaUserId || req.user?.id;
      if (!userId) return res.status(401).json({ message: "Sessão inválida" });
      const mfa = await storage.getUserMfa(userId);
      if (!mfa || !mfa.mfaEnabled) {
        return res.status(400).json({ message: "MFA não ativado" });
      }
      const emailSettings = await storage.getEmailSettings();
      const windowCutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      if (!emailSettings?.lastTestSuccessAt || emailSettings.lastTestSuccessAt < windowCutoff) {
        return res.status(400).json({ message: "Mensageria não foi testada recentemente" });
      }
      const { code } = await mfaService.createEmailChallenge(userId);
      await emailService.sendEmail(emailSettings, {
        to: mfa.email,
        subject: 'Código de verificação SamurEye',
        html: `
          <p>Seu código de verificação é:</p>
          <p style="font-size:24px;font-weight:bold;letter-spacing:4px">${code}</p>
          <p>Válido por 5 minutos. Se você não solicitou, ignore este e-mail.</p>
        `,
      });
      res.status(202).json({ message: "Código enviado" });
    } catch (error: any) {
      log.error({ err: error }, 'mfa email send failed');
      res.status(error?.message?.includes('Limite') ? 429 : 500).json({
        message: error?.message || "Falha ao enviar código",
      });
    }
  });

  // POST /api/auth/mfa/disable — password + current TOTP
  app.post('/api/auth/mfa/disable', isAuthenticated, async (req: any, res) => {
    try {
      const user = req.user;
      if (!user.mfaEnabled) return res.status(400).json({ message: "MFA não está ativado" });
      const { currentPassword, token } = req.body ?? {};
      if (!(await verifyPassword(String(currentPassword ?? ''), user.passwordHash))) {
        return res.status(401).json({ message: "Senha incorreta" });
      }
      const mfa = await storage.getUserMfa(user.id);
      if (!mfa?.mfaSecretEncrypted || !mfa?.mfaSecretDek) {
        return res.status(400).json({ message: "MFA em estado inválido" });
      }
      const secret = mfaService.decryptSecret(mfa.mfaSecretEncrypted, mfa.mfaSecretDek);
      if (!mfaService.verifyTotp(String(token ?? ''), secret)) {
        return res.status(401).json({ message: "TOTP inválido" });
      }
      await storage.setUserMfa(user.id, {
        mfaEnabled: false,
        mfaSecretEncrypted: null,
        mfaSecretDek: null,
        mfaBackupCodes: null,
        mfaEnabledAt: null,
      });
      await storage.logAudit({
        actorId: user.id,
        action: 'user.mfa.disable',
        objectType: 'user',
        objectId: user.id,
        before: { mfaEnabled: true },
        after: { mfaEnabled: false },
      });
      res.json({ success: true });
    } catch (error) {
      log.error({ err: error }, 'mfa disable failed');
      res.status(500).json({ message: "Falha ao desativar MFA" });
    }
  });

  // POST /api/auth/mfa/recovery-codes/regenerate — password + regen
  app.post('/api/auth/mfa/recovery-codes/regenerate', isAuthenticated, async (req: any, res) => {
    try {
      const user = req.user;
      if (!user.mfaEnabled) return res.status(400).json({ message: "MFA não está ativado" });
      const currentPassword = String(req.body?.currentPassword ?? '');
      if (!(await verifyPassword(currentPassword, user.passwordHash))) {
        return res.status(401).json({ message: "Senha incorreta" });
      }
      const setup = await mfaService.generateSetup(user.email);
      await storage.updateBackupCodes(user.id, setup.backupCodeHashes);
      await storage.logAudit({
        actorId: user.id,
        action: 'user.mfa.backupcodes.regenerate',
        objectType: 'user',
        objectId: user.id,
        before: null,
        after: { count: setup.backupCodes.length },
      });
      res.json({ backupCodes: setup.backupCodes });
    } catch (error) {
      log.error({ err: error }, 'mfa regenerate failed');
      res.status(500).json({ message: "Falha ao regenerar códigos" });
    }
  });

  // PUT /api/auth/me/mfa-invitation-dismissed
  app.put('/api/auth/me/mfa-invitation-dismissed', isAuthenticated, async (req: any, res) => {
    try {
      await storage.dismissMfaInvitation(req.user.id);
      res.json({ success: true });
    } catch (error) {
      log.error({ err: error }, 'dismiss mfa invitation failed');
      res.status(500).json({ message: "Falha ao salvar preferência" });
    }
  });
}
