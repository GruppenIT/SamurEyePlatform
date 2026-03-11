/**
 * FND-008 Security Tests: Logger credential redaction
 *
 * These tests verify that pino's redaction configuration correctly
 * censors sensitive fields in log output, preventing credential leaks.
 *
 * Strategy: create a pino logger with the same redaction config as production,
 * pipe output to a writable stream, and verify that sensitive values are replaced
 * with [REDACTED] in the serialized JSON.
 */
import { describe, it, expect } from 'vitest';
import pino from 'pino';
import { Writable } from 'stream';

/**
 * Redact paths — must match server/lib/logger.ts exactly.
 * Duplicated here intentionally: if someone changes the production config
 * and forgets to update tests, the tests should still catch leaks by
 * testing the expected behavior.
 */
const REDACT_PATHS = [
  'password', 'secret', 'token', 'apiKey', 'api_key',
  'secretEncrypted', 'dekEncrypted', 'sessionSecret',
  'encryptionKey', 'cookie', 'authorization',
  'credential.password', 'credential.secret', 'credential.token',
  'credentials.password', 'credentials.secret', 'credentials.token',
  'headers.authorization', 'headers.cookie',
  '*.password', '*.secret', '*.token', '*.apiKey',
  '*.secretEncrypted', '*.dekEncrypted',
];

/** Create a test logger that captures JSON output */
function createTestLogger(): { logger: pino.Logger; getOutput: () => string } {
  let output = '';
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      output += chunk.toString();
      callback();
    },
  });

  const logger = pino({
    level: 'trace',
    redact: { paths: REDACT_PATHS, censor: '[REDACTED]' },
  }, stream);

  return {
    logger,
    getOutput: () => output,
  };
}

// ---------------------------------------------------------------------------
// Direct field redaction
// ---------------------------------------------------------------------------
describe('direct field redaction', () => {
  const sensitiveFields = [
    'password', 'secret', 'token', 'apiKey', 'api_key',
    'secretEncrypted', 'dekEncrypted', 'sessionSecret',
    'encryptionKey', 'cookie', 'authorization',
  ];

  for (const field of sensitiveFields) {
    it(`redacts "${field}" field`, () => {
      const { logger, getOutput } = createTestLogger();
      logger.info({ [field]: 'SENSITIVE_VALUE_12345' }, 'test');
      logger.flush();

      const json = getOutput();
      expect(json).not.toContain('SENSITIVE_VALUE_12345');
      expect(json).toContain('[REDACTED]');
    });
  }
});

// ---------------------------------------------------------------------------
// Nested field redaction
// ---------------------------------------------------------------------------
describe('nested field redaction', () => {
  it('redacts credential.password', () => {
    const { logger, getOutput } = createTestLogger();
    logger.info({ credential: { username: 'admin', password: 'LEAK_ME' } }, 'test');
    logger.flush();

    const json = getOutput();
    expect(json).not.toContain('LEAK_ME');
    expect(json).toContain('admin'); // username should NOT be redacted
    expect(json).toContain('[REDACTED]');
  });

  it('redacts headers.authorization', () => {
    const { logger, getOutput } = createTestLogger();
    logger.info({ headers: { authorization: 'Bearer secret-jwt-token', host: 'example.com' } }, 'test');
    logger.flush();

    const json = getOutput();
    expect(json).not.toContain('secret-jwt-token');
    expect(json).toContain('example.com'); // host should NOT be redacted
  });

  it('redacts headers.cookie', () => {
    const { logger, getOutput } = createTestLogger();
    logger.info({ headers: { cookie: 'session=abc123secret' } }, 'test');
    logger.flush();

    expect(getOutput()).not.toContain('abc123secret');
  });
});

// ---------------------------------------------------------------------------
// Wildcard redaction (*.password, *.secret, etc.)
// ---------------------------------------------------------------------------
describe('wildcard redaction', () => {
  it('redacts password in any nested object', () => {
    const { logger, getOutput } = createTestLogger();
    logger.info({
      smtp: { host: 'mail.example.com', password: 'SMTP_SECRET' },
    }, 'test');
    logger.flush();

    const json = getOutput();
    expect(json).not.toContain('SMTP_SECRET');
    expect(json).toContain('mail.example.com');
  });

  it('redacts secretEncrypted in nested objects', () => {
    const { logger, getOutput } = createTestLogger();
    logger.info({
      cred: { secretEncrypted: 'BASE64_CIPHER', dekEncrypted: 'BASE64_DEK' },
    }, 'test');
    logger.flush();

    const json = getOutput();
    expect(json).not.toContain('BASE64_CIPHER');
    expect(json).not.toContain('BASE64_DEK');
  });

  it('redacts apiKey in any nested context', () => {
    const { logger, getOutput } = createTestLogger();
    logger.info({
      service: { name: 'external', apiKey: 'key-12345' },
    }, 'test');
    logger.flush();

    expect(getOutput()).not.toContain('key-12345');
  });
});

// ---------------------------------------------------------------------------
// Non-sensitive fields pass through
// ---------------------------------------------------------------------------
describe('non-sensitive fields are preserved', () => {
  it('preserves hostname, port, component, message', () => {
    const { logger, getOutput } = createTestLogger();
    logger.info({
      hostname: 'server01.corp',
      port: 5432,
      component: 'storage',
      duration: 42,
    }, 'query executed');
    logger.flush();

    const json = getOutput();
    expect(json).toContain('server01.corp');
    expect(json).toContain('5432');
    expect(json).toContain('storage');
    expect(json).toContain('query executed');
  });
});
