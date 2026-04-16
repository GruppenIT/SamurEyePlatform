import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { storage } from '../storage';
import { emailService } from './emailService';
import { createLogger } from '../lib/logger';
import type { PasswordResetToken } from '@shared/schema';

const log = createLogger('password-reset');

const TOKEN_BYTES = 32;
const TOKEN_TTL_MS = 30 * 60 * 1000;
const BCRYPT_COST = 10;
const EMAIL_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

export class PasswordResetService {
  async isDeliveryAvailable(): Promise<boolean> {
    const settings = await storage.getEmailSettings();
    if (!settings?.lastTestSuccessAt) return false;
    return settings.lastTestSuccessAt.getTime() > Date.now() - EMAIL_WINDOW_MS;
  }

  generateToken(): string {
    return crypto.randomBytes(TOKEN_BYTES).toString('base64url');
  }

  async hashToken(token: string): Promise<string> {
    return bcrypt.hash(token, BCRYPT_COST);
  }

  computeExpiresAt(): Date {
    return new Date(Date.now() + TOKEN_TTL_MS);
  }

  async sendResetEmail(email: string, link: string): Promise<void> {
    const settings = await storage.getEmailSettings();
    if (!settings) throw new Error('mensageria não configurada');
    await emailService.sendEmail(settings, {
      to: email,
      subject: 'Recuperação de senha SamurEye',
      html: `
        <p>Você solicitou a redefinição de senha para sua conta SamurEye.</p>
        <p>Clique no link abaixo (válido por 30 minutos):</p>
        <p><a href="${link}">${link}</a></p>
        <p>Se você não fez essa solicitação, ignore este e-mail — sua senha permanece inalterada.</p>
      `,
    });
  }

  async findTokenMatch(rawToken: string): Promise<{ token: PasswordResetToken } | null> {
    const tokens = await storage.getActivePasswordResetTokens();
    for (const t of tokens) {
      if (await bcrypt.compare(rawToken, t.tokenHash)) return { token: t };
    }
    return null;
  }
}

export const passwordResetService = new PasswordResetService();
