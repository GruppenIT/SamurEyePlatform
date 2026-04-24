import type { WebSocket } from 'ws';
import { jobEventSchema, type JobEvent } from '../../shared/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('jobEventBroadcaster');

// ============================================================================
// Constants — per 14-CONTEXT.md §"Rate limiting WebSocket events"
// ============================================================================

const RATE_LIMIT_EVENTS_PER_SEC = 10;
const RATE_LIMIT_WINDOW_MS = 1000;

// ============================================================================
// JobEventBroadcaster
// ============================================================================

/**
 * Real-time event broadcaster for Phase 14 FIND-04.
 *
 * Manages per-jobId WebSocket subscriber sets and enforces:
 *   - Zod schema validation before send (invalid events dropped with warning)
 *   - Rate limit: 10 events/sec per jobId (excess dropped with warning)
 *   - Auto-unsubscribe on ws.send failure (client disconnect resilience)
 *
 * Fail-open design: emit() NEVER throws — journey execution is never broken
 * by event delivery failures. All error paths log warnings and continue.
 *
 * Consumed by:
 *   - Wave 3 (14-04): route handlers emit findings_batch after upsertApiFindingByKey
 *   - Phase 15 journeyExecutor: emits stage_progress + journey_complete
 */
export class JobEventBroadcaster {
  private subscribers = new Map<string, Set<WebSocket>>();
  private rateTracker = new Map<string, { count: number; windowStart: number }>();

  /**
   * Subscribe a WebSocket to events for a given jobId.
   * Idempotent — re-subscribing the same ws is a no-op.
   */
  subscribe(jobId: string, ws: WebSocket): void {
    let set = this.subscribers.get(jobId);
    if (!set) {
      set = new Set<WebSocket>();
      this.subscribers.set(jobId, set);
    }
    set.add(ws);
  }

  /**
   * Unsubscribe a WebSocket from a given jobId.
   * Cleans up empty subscriber sets and rate-tracking windows.
   */
  unsubscribe(jobId: string, ws: WebSocket): void {
    const set = this.subscribers.get(jobId);
    if (!set) return;
    set.delete(ws);
    if (set.size === 0) {
      this.subscribers.delete(jobId);
      this.rateTracker.delete(jobId);
    }
  }

  /**
   * Returns current subscriber count for a jobId.
   * Useful for testing and telemetry — never exposes the raw Set.
   */
  subscriberCount(jobId: string): number {
    return this.subscribers.get(jobId)?.size ?? 0;
  }

  /**
   * Emit a validated, rate-limited event to all subscribers of a jobId.
   *
   * Execution layers:
   *   1. Zod parse — invalid payload: drop + warn (never throw)
   *   2. Rate limit 10/sec — exceeded: drop + warn
   *   3. Broadcast — ws.send failure: auto-unsubscribe dead client + warn
   */
  emit(jobId: string, event: JobEvent): void {
    // Layer 1: Validate payload (Zod parse)
    const parsed = jobEventSchema.safeParse(event);
    if (!parsed.success) {
      log.warn({
        jobId,
        errors: parsed.error.issues,
      }, '[jobEventBroadcaster] invalid event dropped');
      return;
    }

    // Layer 2: Rate limit (10 events/sec per jobId)
    if (!this.checkRateLimit(jobId)) {
      log.warn({
        jobId,
        limit: RATE_LIMIT_EVENTS_PER_SEC,
      }, '[jobEventBroadcaster] rate limit exceeded, event dropped');
      return;
    }

    // Layer 3: Broadcast
    const subscribers = this.subscribers.get(jobId);
    if (!subscribers || subscribers.size === 0) return;

    const payload = JSON.stringify(parsed.data);
    const deadSockets: WebSocket[] = [];

    subscribers.forEach((ws) => {
      try {
        ws.send(payload);
      } catch (err) {
        // Client disconnected or send error — schedule unsubscribe after iteration
        deadSockets.push(ws);
        log.warn({
          jobId,
          error: err instanceof Error ? err.message : String(err),
        }, '[jobEventBroadcaster] ws.send failed, auto-unsubscribing');
      }
    });

    // Cleanup dead sockets outside the iteration loop
    deadSockets.forEach((ws) => {
      this.unsubscribe(jobId, ws);
    });
  }

  // --------------------------------------------------------------------------
  // Private helpers
  // --------------------------------------------------------------------------

  private checkRateLimit(jobId: string): boolean {
    const now = Date.now();
    let tracker = this.rateTracker.get(jobId);
    if (!tracker || now - tracker.windowStart >= RATE_LIMIT_WINDOW_MS) {
      tracker = { count: 0, windowStart: now };
      this.rateTracker.set(jobId, tracker);
    }
    if (tracker.count >= RATE_LIMIT_EVENTS_PER_SEC) {
      return false;
    }
    tracker.count++;
    return true;
  }
}

// Singleton export — all routes + services share this instance
export const jobEventBroadcaster = new JobEventBroadcaster();
