/**
 * Security Tests: Encryption service (DEK/KEK pattern)
 *
 * These tests verify that the AES-256-GCM encryption with DEK/KEK
 * pattern works correctly — data encrypted can be decrypted, tampered
 * data is rejected, and the service handles edge cases properly.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import crypto from 'crypto';
import { EncryptionService } from '../services/encryption';

// Use a fixed KEK for test reproducibility
const TEST_KEK = crypto.randomBytes(32).toString('hex');

let service: EncryptionService;

beforeAll(() => {
  process.env.ENCRYPTION_KEK = TEST_KEK;
  service = new EncryptionService();
});

// ---------------------------------------------------------------------------
// Roundtrip: encrypt → decrypt
// ---------------------------------------------------------------------------
describe('encrypt/decrypt roundtrip', () => {
  it('decrypts back to original plaintext', () => {
    const secret = 'my-super-secret-password';
    const { secretEncrypted, dekEncrypted } = service.encryptCredential(secret);
    const decrypted = service.decryptCredential(secretEncrypted, dekEncrypted);
    expect(decrypted).toBe(secret);
  });

  it('handles empty string', () => {
    const { secretEncrypted, dekEncrypted } = service.encryptCredential('');
    expect(service.decryptCredential(secretEncrypted, dekEncrypted)).toBe('');
  });

  it('handles unicode content', () => {
    const secret = 'Senhaçã0 com ñ e 日本語';
    const { secretEncrypted, dekEncrypted } = service.encryptCredential(secret);
    expect(service.decryptCredential(secretEncrypted, dekEncrypted)).toBe(secret);
  });

  it('handles long passwords (4KB)', () => {
    const secret = crypto.randomBytes(2048).toString('base64');
    const { secretEncrypted, dekEncrypted } = service.encryptCredential(secret);
    expect(service.decryptCredential(secretEncrypted, dekEncrypted)).toBe(secret);
  });

  it('handles special characters commonly found in passwords', () => {
    const secret = "p@$$w0rd!#%^&*(){}[]|\\:\";<>,.?/~`'";
    const { secretEncrypted, dekEncrypted } = service.encryptCredential(secret);
    expect(service.decryptCredential(secretEncrypted, dekEncrypted)).toBe(secret);
  });
});

// ---------------------------------------------------------------------------
// Uniqueness: each encryption produces different ciphertext (random IV + DEK)
// ---------------------------------------------------------------------------
describe('ciphertext uniqueness', () => {
  it('produces different ciphertext for same plaintext (random IV)', () => {
    const secret = 'same-password';
    const a = service.encryptCredential(secret);
    const b = service.encryptCredential(secret);
    expect(a.secretEncrypted).not.toBe(b.secretEncrypted);
    expect(a.dekEncrypted).not.toBe(b.dekEncrypted);
  });
});

// ---------------------------------------------------------------------------
// Tamper detection (AES-GCM authentication)
// ---------------------------------------------------------------------------
describe('tamper detection', () => {
  it('rejects tampered ciphertext', () => {
    const { secretEncrypted, dekEncrypted } = service.encryptCredential('original');
    const tampered = Buffer.from(secretEncrypted, 'base64');
    // Flip a byte in the ciphertext portion (past IV + authTag)
    tampered[tampered.length - 1] ^= 0xff;
    expect(() => {
      service.decryptCredential(tampered.toString('base64'), dekEncrypted);
    }).toThrow();
  });

  it('rejects tampered DEK', () => {
    const { secretEncrypted, dekEncrypted } = service.encryptCredential('original');
    const tampered = Buffer.from(dekEncrypted, 'base64');
    tampered[tampered.length - 1] ^= 0xff;
    expect(() => {
      service.decryptCredential(secretEncrypted, tampered.toString('base64'));
    }).toThrow();
  });

  it('rejects truncated ciphertext', () => {
    const { secretEncrypted, dekEncrypted } = service.encryptCredential('original');
    const truncated = Buffer.from(secretEncrypted, 'base64').subarray(0, 10).toString('base64');
    expect(() => {
      service.decryptCredential(truncated, dekEncrypted);
    }).toThrow();
  });

  it('rejects completely invalid base64', () => {
    expect(() => {
      service.decryptCredential('not-valid!!!', 'also-invalid!!!');
    }).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Cross-KEK isolation (different KEK cannot decrypt)
// ---------------------------------------------------------------------------
describe('KEK isolation', () => {
  it('cannot decrypt with a different KEK', () => {
    const { secretEncrypted, dekEncrypted } = service.encryptCredential('secret');

    // Create a second service with a different KEK
    const otherKek = crypto.randomBytes(32).toString('hex');
    process.env.ENCRYPTION_KEK = otherKek;
    const otherService = new EncryptionService();

    expect(() => {
      otherService.decryptCredential(secretEncrypted, dekEncrypted);
    }).toThrow();

    // Restore original KEK
    process.env.ENCRYPTION_KEK = TEST_KEK;
  });
});

// ---------------------------------------------------------------------------
// validateCredential helper
// ---------------------------------------------------------------------------
describe('validateCredential', () => {
  it('returns true for valid encrypted credential', () => {
    const { secretEncrypted, dekEncrypted } = service.encryptCredential('valid');
    expect(service.validateCredential(secretEncrypted, dekEncrypted)).toBe(true);
  });

  it('returns false for tampered credential', () => {
    const { secretEncrypted, dekEncrypted } = service.encryptCredential('valid');
    expect(service.validateCredential('garbage', dekEncrypted)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Static utilities
// ---------------------------------------------------------------------------
describe('static utilities', () => {
  it('generateKEK produces valid 64-hex-char key', () => {
    const kek = EncryptionService.generateKEK();
    expect(kek).toMatch(/^[a-f0-9]{64}$/);
    expect(EncryptionService.validateKEK(kek)).toBe(true);
  });

  it('validateKEK rejects short keys', () => {
    expect(EncryptionService.validateKEK('abcdef')).toBe(false);
  });

  it('validateKEK rejects non-hex strings', () => {
    expect(EncryptionService.validateKEK('z'.repeat(64))).toBe(false);
  });
});
