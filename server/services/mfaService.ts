import { generateSecret, generateURI, verify } from 'otplib';
import bcrypt from 'bcryptjs';
import QRCode from 'qrcode';
import crypto from 'crypto';
import { encryptionService } from './encryption';
import { storage } from '../storage';
import { createLogger } from '../lib/logger';

const log = createLogger('mfa');

// One period tolerance on each side (30 s before / 30 s after)
const TOTP_EPOCH_TOLERANCE = 30;
const BACKUP_CODE_COUNT = 8;
const BACKUP_CODE_BYTES = 8;
const EMAIL_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const EMAIL_CHALLENGE_RATE_LIMIT_MS = 5 * 60 * 1000;
const EMAIL_CHALLENGE_RATE_LIMIT_MAX = 3;
const BCRYPT_COST = 10;

export interface SetupPayload {
  secret: string;
  otpauthUrl: string;
  qrCodeSvg: string;
  backupCodes: string[];
  backupCodeHashes: string[];
}

export class MfaService {
  async generateSetup(userEmail: string): Promise<SetupPayload> {
    const secret = generateSecret();
    const otpauthUrl = generateURI({ issuer: 'SamurEye', label: userEmail, secret });
    const qrCodeSvg = await QRCode.toString(otpauthUrl, { type: 'svg', margin: 1, width: 240 });
    const backupCodes = Array.from({ length: BACKUP_CODE_COUNT }, () => this.generateBackupCode());
    const backupCodeHashes = await Promise.all(
      backupCodes.map((code) => bcrypt.hash(code, BCRYPT_COST)),
    );
    return { secret, otpauthUrl, qrCodeSvg, backupCodes, backupCodeHashes };
  }

  private generateBackupCode(): string {
    return crypto.randomBytes(BACKUP_CODE_BYTES).toString('hex').slice(0, 10);
  }

  async verifyTotp(token: string, secret: string): Promise<boolean> {
    if (!/^\d{6}$/.test(token)) return false;
    try {
      const result = await verify({ token, secret, epochTolerance: TOTP_EPOCH_TOLERANCE });
      return result.valid;
    } catch {
      return false;
    }
  }

  async verifyBackupCode(token: string, hashes: string[]): Promise<{ matchIndex: number }> {
    for (let i = 0; i < hashes.length; i++) {
      if (await bcrypt.compare(token, hashes[i])) {
        return { matchIndex: i };
      }
    }
    return { matchIndex: -1 };
  }

  encryptSecret(secret: string): { encrypted: string; dek: string } {
    const { secretEncrypted, dekEncrypted } = encryptionService.encryptCredential(secret);
    return { encrypted: secretEncrypted, dek: dekEncrypted };
  }

  decryptSecret(encrypted: string, dek: string): string {
    return encryptionService.decryptCredential(encrypted, dek);
  }

  async createEmailChallenge(userId: string): Promise<{ code: string }> {
    const recent = await storage.countRecentChallenges(userId, EMAIL_CHALLENGE_RATE_LIMIT_MS);
    if (recent >= EMAIL_CHALLENGE_RATE_LIMIT_MAX) {
      throw new Error('Limite de envios por e-mail atingido. Aguarde 5 minutos.');
    }
    await storage.cleanupOldChallenges(userId);
    const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
    const codeHash = await bcrypt.hash(code, BCRYPT_COST);
    const expiresAt = new Date(Date.now() + EMAIL_CHALLENGE_TTL_MS);
    await storage.createMfaEmailChallenge({ userId, codeHash, expiresAt });
    return { code };
  }

  async verifyEmailChallenge(userId: string, token: string): Promise<boolean> {
    const active = await storage.getActiveChallenges(userId);
    for (const ch of active) {
      if (await bcrypt.compare(token, ch.codeHash)) {
        await storage.consumeChallenge(ch.id);
        return true;
      }
    }
    return false;
  }
}

export const mfaService = new MfaService();
