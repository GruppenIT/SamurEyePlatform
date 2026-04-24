/**
 * Phase 13 Wave 0 — Nyquist stub for rate-limit absence scanner (TEST-06 / API4).
 * Implementation comes in Wave 1 (13-02-PLAN — scanners/api/rateLimit.ts).
 * Requirement: TEST-06
 */
import { describe, it } from 'vitest';

describe('scanners/api/rateLimit: opt-in gate', () => {
  it.todo('entire stage skipped when opts.stages.rateLimit !== true (default false)');
  it.todo('stage proceeds when opts.stages.rateLimit === true');
});

describe('scanners/api/rateLimit: buildBurst parallelism', () => {
  it.todo('issues exactly burstSize parallel fetch calls via Promise.all (not sequential)');
  it.todo('respects burstSize=20 default, max 50 (Zod ceiling)');
  it.todo('uses method=GET with auth headers from resolveApiCredential');
});

describe('scanners/api/rateLimit: target endpoint selection', () => {
  it.todo('default: exactly 1 endpoint per API (first GET with httpxStatus=200 alphabetically)');
  it.todo('override via opts.rateLimit.endpointIds array (up to 5)');
  it.todo('filters endpoints to method=GET AND requiresAuth=true AND httpxStatus=200');
});

describe('scanners/api/rateLimit: detectThrottling (ALL-3-signals check)', () => {
  it.todo('emits RateLimitHit severity=medium when: no 429 + no Retry-After + no X-RateLimit-* + >=90% status<400');
  it.todo('suppresses finding when ANY response has status=429');
  it.todo('suppresses finding when ANY response has Retry-After header');
  it.todo('suppresses finding when ANY response has header matching /^x-ratelimit-/i');
  it.todo('suppresses finding when <90% responses have status<400 (endpoint unhealthy, not meaningful)');
  it.todo('evidence.extractedValues includes burstSize, successCount, throttledCount, hasRetryAfter, hasXRateLimitHeaders, windowMs, endpointPath');
});
