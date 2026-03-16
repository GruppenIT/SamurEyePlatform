# Testing Patterns

**Analysis Date:** 2026-03-16

## Test Framework

**Runner:**
- Vitest 4.0.18
- Config: `vitest.config.ts`
- Global mode enabled (no explicit imports of `describe`, `it`, `expect`)
- Environment: Node.js (not JSDOM)

**Assertion Library:**
- Vitest built-in assertions (expects ES6 standards)

**Run Commands:**
```bash
npm test                # Run all tests in server/__tests__/
npm run test:watch     # Watch mode, re-run on file changes
```

**Test Timeout:**
- Global: `testTimeout: 10_000` (10 seconds per test)
- Increase per-test with: `it('name', () => { ... }, { timeout: 20_000 })`

## Test File Organization

**Location:**
- Server tests: `server/__tests__/` (co-located alongside source)
- Client tests: not yet implemented (no files in `client/` test directories)
- Pattern: dedicated `__tests__/` directory in same folder as code being tested

**Naming:**
- File format: `{module}.test.ts`
- Examples: `encryption.test.ts`, `logger.test.ts`, `cors.test.ts`, `emailService.test.ts`

**Structure:**
```
server/
├── __tests__/
│   ├── cors.test.ts
│   ├── encryption.test.ts
│   ├── logger.test.ts
│   ├── sshCollector.test.ts
│   ├── subscriptionService.test.ts
│   ├── systemUpdateService.test.ts
│   └── edrAvScanner.test.ts
├── services/
│   ├── encryption.ts
│   ├── emailService.ts
│   └── ...
└── ...
```

## Test Structure

**Suite Organization:**
```typescript
/**
 * Test description block (JSDoc style)
 */
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';

describe('Feature or module name', () => {
  // Setup
  beforeAll(() => {
    // Run once before all tests
  });

  beforeEach(() => {
    // Run before each test
  });

  // Tests
  it('should do X', () => {
    expect(...).toBe(...);
  });

  it('should handle edge case Y', () => {
    // ...
  });
});
```

**Real Example from logger.test.ts:**
```typescript
describe('direct field redaction', () => {
  const sensitiveFields = [
    'password', 'secret', 'token', 'apiKey', 'api_key',
    // ... more fields
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
```

**Patterns:**
- **Setup:** Use `beforeAll()` for one-time initialization (e.g., creating a service with a test KEK)
- **Hooks:** Use `beforeEach()` to reset state before each test
- **Descriptive names:** Test names start with "should" or use domain language. Examples:
  - "redacts password field"
  - "produces different ciphertext for same plaintext"
  - "rejects tampered DEK"
  - "allows listed origin"

## Mocking

**Framework:** Vitest's built-in `vi` (similar to Jest)

**Patterns:**
- Mocking is NOT used in production tests (tests use real dependencies where possible)
- Test isolation through fixtures (e.g., test KEK generated fresh per test)
- Example from `encryption.test.ts`:
  ```typescript
  const TEST_KEK = crypto.randomBytes(32).toString('hex');

  beforeAll(() => {
    process.env.ENCRYPTION_KEK = TEST_KEK;
    service = new EncryptionService();
  });
  ```

**What to Mock:**
- External HTTP calls (not yet demonstrated in test suite)
- Time-dependent operations (dates, clocks) via `vi.useFakeTimers()`
- Environment variables for testing (done explicitly in `beforeAll`)

**What NOT to Mock:**
- Real encryption/decryption operations (test the actual algorithm)
- Real logger output (capture and verify actual output)
- Real database/storage operations (use in-memory or test database fixtures)
- Core domain logic (always test real behavior)

## Fixtures and Factories

**Test Data:**
- Helper functions create test instances inline
- Example from `logger.test.ts`:
  ```typescript
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
  ```

**Location:**
- Fixtures live in the test file itself (no separate `fixtures/` directory)
- Utility functions (like `createTestLogger()`) defined at top of test file
- Pattern: if test helper is used across multiple test files, move to shared utility

## Coverage

**Requirements:** No enforced coverage targets detected (no coverage config in `package.json`)

**View Coverage:**
```bash
# Not configured in current setup
# To add: npm install --save-dev @vitest/coverage-v8
# Then add to package.json: "test:coverage": "vitest run --coverage"
```

**Current Coverage:**
- Focus on critical security paths:
  - Encryption roundtrip and tamper detection
  - Logger redaction (sensitive data protection)
  - CORS origin validation
  - Email service initialization
  - SSH collector operations
  - Subscription service state management
  - System update service retry logic

## Test Types

**Unit Tests:**
- Scope: Single function or class method
- Approach: Test with real dependencies, isolated through fixtures
- Examples:
  - `encryptCredential()` roundtrip: encrypt → decrypt → verify plaintext matches
  - `corsOriginCheck()`: test all origin validation rules in isolation
  - Logger redaction: verify sensitive paths are replaced in JSON output

**Integration Tests:**
- Scope: Multiple components working together
- Approach: Not yet heavily used in test suite; focus is on unit testing critical paths
- Example: email service initialization test combines pino logger + SMTP configuration

**E2E Tests:**
- Framework: Not used
- Approach: Deployment testing done manually or via staging environment

## Common Patterns

**Async Testing:**
- Vitest auto-awaits async test functions
- No special syntax needed:
  ```typescript
  it('async operation', async () => {
    const result = await someAsyncFunction();
    expect(result).toBe(expected);
  });
  ```

**Error Testing:**
- Use `expect(...).toThrow()` for error throwing
- Verify error type or message:
  ```typescript
  it('rejects tampered ciphertext', () => {
    const { secretEncrypted, dekEncrypted } = service.encryptCredential('original');
    const tampered = Buffer.from(secretEncrypted, 'base64');
    tampered[tampered.length - 1] ^= 0xff;

    expect(() => {
      service.decryptCredential(tampered.toString('base64'), dekEncrypted);
    }).toThrow();
  });
  ```

**Testing Edge Cases:**
- Empty strings: `encryptCredential('')` → decrypt → expect `''`
- Long payloads: 4KB password roundtrip
- Unicode: "Senhaçã0 com ñ e 日本語"
- Special characters: `"p@$$w0rd!#%^&*(){}[]|\\:\";<>,.?/~\`'"`

**Testing Data Uniqueness:**
- Verify randomness (IV, DEK) produces different outputs:
  ```typescript
  it('produces different ciphertext for same plaintext', () => {
    const a = service.encryptCredential(secret);
    const b = service.encryptCredential(secret);
    expect(a.secretEncrypted).not.toBe(b.secretEncrypted);
    expect(a.dekEncrypted).not.toBe(b.dekEncrypted);
  });
  ```

## Test Files Summary

**Existing Test Files:**
- `server/__tests__/cors.test.ts` (123 lines) — CORS origin validation logic
- `server/__tests__/encryption.test.ts` (161 lines) — AES-256-GCM encrypt/decrypt/tamper
- `server/__tests__/logger.test.ts` (169 lines) — Pino redaction of sensitive fields
- `server/__tests__/sshCollector.test.ts` (161 lines) — SSH collection and parsing
- `server/__tests__/edrAvScanner.test.ts` (136 lines) — EDR/AV scanner detection
- `server/__tests__/subscriptionService.test.ts` (218 lines) — Subscription state, heartbeat, grace period
- `server/__tests__/systemUpdateService.test.ts` (171 lines) — System update retry logic and reporting

**Total:** ~1,139 lines of test code

**Testing Philosophy:**
- Tests document expected behavior
- Security-critical paths (encryption, auth, CORS) have comprehensive coverage
- Tests use real implementations where possible, fixtures for isolation
- Test names read like requirements ("should redact password field", "should allow listed origin")

---

*Testing analysis: 2026-03-16*
