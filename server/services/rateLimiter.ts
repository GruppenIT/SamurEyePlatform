/**
 * Phase 15 — TokenBucketRateLimiter (SAFE-01, SAFE-02).
 *
 * Per-endpoint HTTP rate limiter used by api_security journey scanners.
 * Default 10 req/s; ceiling MAX_API_RATE_LIMIT=50 req/s is NOT user-configurable.
 * Values exceeding the ceiling are clamped SILENTLY (no throw) per CONTEXT.md
 * decision — user-facing Zod schemas already reject >50 at API boundary.
 *
 * Algorithm: token bucket (vs leaky bucket). Tokens refill continuously at
 * ratePerSecond per second; acquire() waits when bucket is empty. Allows short
 * bursts up to capacity while respecting long-run rate.
 *
 * Retry-After + exponential backoff are caller-invoked helpers, not automatic.
 * The orchestrator (Plan 04) calls them after observing 429/503 response codes.
 *
 * dryRun semantics: This class is NOT dryRun-aware. The orchestrator must
 * skip rate-limiting entirely when opts.dryRun=true (no scanner HTTP happens).
 */
import { createLogger } from '../lib/logger';

const log = createLogger('rateLimiter');

/** Absolute ceiling per SAFE-01 — NOT user-configurable. */
export const MAX_API_RATE_LIMIT = 50;

/** Default rate when caller passes no args to constructor. */
export const DEFAULT_API_RATE_LIMIT = 10;

export class TokenBucketRateLimiter {
  private tokens: number;
  private readonly ratePerSecond: number;
  private lastRefill: number;

  constructor(ratePerSecond: number = DEFAULT_API_RATE_LIMIT) {
    // SAFE-01 ceiling — silent clamp, never throw
    const clamped = Math.min(Math.max(1, ratePerSecond), MAX_API_RATE_LIMIT);
    if (clamped !== ratePerSecond) {
      log.info({ requested: ratePerSecond, clamped }, 'rate limit clamped to SAFE-01 ceiling');
    }
    this.ratePerSecond = clamped;
    this.tokens = clamped; // start full
    this.lastRefill = Date.now();
  }

  /**
   * Acquires 1 token. Blocks via setTimeout if bucket empty.
   * Never rejects — always resolves eventually (bounded wait = 1/ratePerSecond seconds).
   */
  async acquire(): Promise<void> {
    this.refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return;
    }
    // Wait for exactly 1 token's worth of time
    const waitMs = Math.ceil((1 - this.tokens) / this.ratePerSecond * 1000);
    await new Promise(resolve => setTimeout(resolve, waitMs));
    this.refill();
    this.tokens = Math.max(0, this.tokens - 1);
  }

  /**
   * Refills tokens based on elapsed time since last refill.
   * Capped at ratePerSecond (bucket capacity).
   */
  private refill(): void {
    const now = Date.now();
    const elapsedSec = (now - this.lastRefill) / 1000;
    this.tokens = Math.min(this.ratePerSecond, this.tokens + elapsedSec * this.ratePerSecond);
    this.lastRefill = now;
  }

  /**
   * SAFE-02 — Honors Retry-After HTTP header (seconds format).
   * Falls back to 1000ms when header absent or unparseable.
   * Called by the orchestrator after a 429/503 response.
   */
  async handleRetryAfter(headers: Headers): Promise<void> {
    const raw = headers.get('retry-after');
    let waitMs = 1000;
    if (raw) {
      const seconds = parseInt(raw, 10);
      if (Number.isFinite(seconds) && seconds > 0) {
        waitMs = seconds * 1000;
      }
    }
    log.info({ retryAfter: raw, waitMs }, 'Retry-After honored');
    await new Promise(resolve => setTimeout(resolve, waitMs));
  }

  /**
   * SAFE-02 — Exponential backoff with jitter.
   * base 1s, max 30s, jitter ±20%. Caller manages attempt counter (max 3 per CONTEXT.md).
   */
  async exponentialBackoff(attempt: number): Promise<void> {
    const base = Math.min(1000 * Math.pow(2, attempt), 30_000);
    const jitter = base * 0.2 * (Math.random() * 2 - 1); // ±20%
    const waitMs = Math.max(0, base + jitter);
    log.info({ attempt, baseMs: base, waitMs: Math.round(waitMs) }, 'exponential backoff');
    await new Promise(resolve => setTimeout(resolve, waitMs));
  }
}
