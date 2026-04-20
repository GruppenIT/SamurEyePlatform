/**
 * Phase 15 — SAFE-01/SAFE-02 Nyquist stubs.
 * Implementação chega no Plano 15-03.
 */
import { describe, it } from 'vitest';

describe('SAFE-01 — TokenBucketRateLimiter ceiling + default', () => {
  it.todo('MAX_API_RATE_LIMIT constant exported from rateLimiter.ts equals 50');
  it.todo('new TokenBucketRateLimiter() com arg undefined usa ratePerSecond=10 (default)');
  it.todo('new TokenBucketRateLimiter(100) clampa silenciosamente para 50 (sem throw)');
  it.todo('new TokenBucketRateLimiter(25) respeita 25 req/s (dentro do ceiling)');
  it.todo('acquire() bloqueia até token disponível quando bucket vazio');
  it.todo('acquire() retorna imediatamente quando tokens >= 1 (bucket tem capacity)');
});

describe('SAFE-02 — Retry-After + exponential backoff', () => {
  it.todo('handleRetryAfter(headers) com Retry-After: "2" aguarda 2000ms');
  it.todo('handleRetryAfter(headers) sem header Retry-After aguarda 1000ms (default)');
  it.todo('exponentialBackoff(0) aguarda ~1000ms (base 1s)');
  it.todo('exponentialBackoff(3) aguarda ~8000ms (base 1s * 2^3)');
  it.todo('exponentialBackoff(10) clampa em 30_000ms (max jitter-adjusted)');
  it.todo('exponentialBackoff aplica jitter ±20% do base delay');
});
