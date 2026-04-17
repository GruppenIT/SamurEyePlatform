/**
 * Unit tests: MfaService core paths
 *
 * Covers: generateSetup, verifyTotp, verifyBackupCode, encryptSecret/decryptSecret.
 */
import { describe, it, expect, beforeAll, vi } from 'vitest';
import crypto from 'crypto';

// Mock the database connection so the module can be imported without DATABASE_URL.
vi.mock('../db', () => ({ db: {}, pool: {} }));

// Mock storage — none of the tested methods use it (only email-challenge methods do).
vi.mock('../storage', () => ({
  storage: {
    countRecentChallenges: vi.fn(),
    cleanupOldChallenges: vi.fn(),
    createMfaEmailChallenge: vi.fn(),
    getActiveChallenges: vi.fn(),
    consumeChallenge: vi.fn(),
  },
}));
import { MfaService } from '../services/mfaService';
import { generateSync } from 'otplib';
import bcrypt from 'bcryptjs';

// Set a deterministic KEK so encryptionService does not fall back to the
// ephemeral dev key (which is fine) and never throws in production mode.
const TEST_KEK = crypto.randomBytes(32).toString('hex');

beforeAll(() => {
  process.env.ENCRYPTION_KEK = TEST_KEK;
});

describe('MfaService', () => {
  const svc = new MfaService();

  describe('generateSetup', () => {
    it('produces a secret, otpauth URL, SVG QR and 8 backup codes', async () => {
      const out = await svc.generateSetup('user@example.com');

      expect(out.secret.length).toBeGreaterThan(0);

      expect(out.otpauthUrl).toContain('otpauth://totp/');
      expect(out.otpauthUrl).toContain('SamurEye');
      expect(out.otpauthUrl.toLowerCase()).toContain('user');

      expect(out.qrCodeSvg).toContain('<svg');

      expect(out.backupCodes).toHaveLength(8);
      expect(out.backupCodeHashes).toHaveLength(8);

      for (const c of out.backupCodes) {
        expect(c).toMatch(/^[a-f0-9]{10}$/);
      }
    });
  });

  describe('verifyTotp', () => {
    it('accepts a valid live token and rejects invalid ones', async () => {
      const { secret } = await svc.generateSetup('u@e.com');

      // Generate a valid token using the same library the service uses
      const validToken = generateSync({ secret });
      expect(svc.verifyTotp(validToken, secret)).toBe(true);

      // Wrong digits — statistically never matches
      expect(svc.verifyTotp('000000', secret)).toBe(false);

      // Non-digit string — rejected by regex guard before verifySync
      expect(svc.verifyTotp('notadigit', secret)).toBe(false);

      // Too short — rejected by regex guard
      expect(svc.verifyTotp('12345', secret)).toBe(false);
    });
  });

  describe('verifyBackupCode', () => {
    it('returns the matching index for a known code', async () => {
      const codes = ['aaaaaaaaaa', 'bbbbbbbbbb', 'cccccccccc'];
      const hashes = await Promise.all(codes.map((c) => bcrypt.hash(c, 10)));

      const ok = await svc.verifyBackupCode('bbbbbbbbbb', hashes);
      expect(ok.matchIndex).toBe(1);
    });

    it('returns -1 when no code matches', async () => {
      const codes = ['aaaaaaaaaa', 'bbbbbbbbbb'];
      const hashes = await Promise.all(codes.map((c) => bcrypt.hash(c, 10)));

      const miss = await svc.verifyBackupCode('zzzzzzzzzz', hashes);
      expect(miss.matchIndex).toBe(-1);
    });
  });

  describe('encryptSecret / decryptSecret round-trip', () => {
    it('restores the original secret after encrypt→decrypt', () => {
      const secret = 'JBSWY3DPEHPK3PXP';

      const { encrypted, dek } = svc.encryptSecret(secret);

      expect(encrypted).not.toBe(secret);
      expect(dek).toBeTruthy();

      expect(svc.decryptSecret(encrypted, dek)).toBe(secret);
    });
  });
});
