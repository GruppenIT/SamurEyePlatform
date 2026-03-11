/**
 * FND-003 Security Tests: CORS origin validation
 *
 * These tests verify the CORS logic implemented in server/index.ts.
 * Since the CORS callback is inline, we replicate the exact logic here
 * and test it in isolation. If the logic in index.ts changes, these tests
 * must be updated to match — this is intentional: a divergence indicates
 * the CORS policy was modified and needs review.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

/**
 * Replicated CORS origin logic from server/index.ts.
 * This is the function under test.
 */
function corsOriginCheck(
  origin: string | undefined,
  allowedOrigins: string[],
  nodeEnv: string,
): { allowed: boolean } {
  // Requests with no Origin header: same-origin, curl, mobile apps
  if (!origin) return { allowed: true };

  // Development: allow any localhost origin
  if (nodeEnv !== 'production' && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
    return { allowed: true };
  }

  // Explicitly allowed origins from ALLOWED_ORIGINS env var
  if (allowedOrigins.length > 0 && allowedOrigins.includes(origin)) {
    return { allowed: true };
  }

  // Appliance: no ALLOWED_ORIGINS set = single-host deployment, allow all
  if (allowedOrigins.length === 0) {
    return { allowed: true };
  }

  // Reject
  return { allowed: false };
}

// ---------------------------------------------------------------------------
// No ALLOWED_ORIGINS (appliance default)
// ---------------------------------------------------------------------------
describe('CORS: no ALLOWED_ORIGINS configured (appliance default)', () => {
  const origins: string[] = [];

  it('allows any origin (single-host appliance)', () => {
    expect(corsOriginCheck('https://anything.com', origins, 'production').allowed).toBe(true);
  });

  it('allows requests with no origin', () => {
    expect(corsOriginCheck(undefined, origins, 'production').allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// ALLOWED_ORIGINS configured (managed deployment)
// ---------------------------------------------------------------------------
describe('CORS: ALLOWED_ORIGINS configured', () => {
  const origins = ['https://console.samureye.com.br', 'https://192.168.1.100:5000'];

  it('allows listed origin', () => {
    expect(corsOriginCheck('https://console.samureye.com.br', origins, 'production').allowed).toBe(true);
  });

  it('allows second listed origin', () => {
    expect(corsOriginCheck('https://192.168.1.100:5000', origins, 'production').allowed).toBe(true);
  });

  it('rejects unlisted origin', () => {
    expect(corsOriginCheck('https://evil.com', origins, 'production').allowed).toBe(false);
  });

  it('rejects similar but not exact origin', () => {
    expect(corsOriginCheck('https://console.samureye.com.br:443', origins, 'production').allowed).toBe(false);
  });

  it('rejects HTTP variant of HTTPS-listed origin', () => {
    expect(corsOriginCheck('http://console.samureye.com.br', origins, 'production').allowed).toBe(false);
  });

  it('allows no-origin requests (curl, same-origin)', () => {
    expect(corsOriginCheck(undefined, origins, 'production').allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Development mode (localhost exception)
// ---------------------------------------------------------------------------
describe('CORS: development mode', () => {
  const origins = ['https://console.samureye.com.br'];

  it('allows localhost in development', () => {
    expect(corsOriginCheck('http://localhost:5173', origins, 'development').allowed).toBe(true);
  });

  it('allows 127.0.0.1 in development', () => {
    expect(corsOriginCheck('http://127.0.0.1:3000', origins, 'development').allowed).toBe(true);
  });

  it('allows localhost without port', () => {
    expect(corsOriginCheck('http://localhost', origins, 'development').allowed).toBe(true);
  });

  it('allows https localhost', () => {
    expect(corsOriginCheck('https://localhost:5000', origins, 'development').allowed).toBe(true);
  });

  it('does NOT allow localhost in production', () => {
    expect(corsOriginCheck('http://localhost:5173', origins, 'production').allowed).toBe(false);
  });

  it('rejects localhost-like bypasses', () => {
    // localhost.evil.com should NOT match the regex
    expect(corsOriginCheck('http://localhost.evil.com', origins, 'development').allowed).toBe(false);
  });

  it('rejects localhost with path injection', () => {
    expect(corsOriginCheck('http://localhost:5173/evil', origins, 'development').allowed).toBe(false);
  });
});
