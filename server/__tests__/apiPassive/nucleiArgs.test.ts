/**
 * Phase 12 Wave 0 — Nyquist stub for Nuclei arg builder.
 * Implementation comes in Wave 1 (12-02-PLAN — scanners/api/nucleiApi.ts).
 * Requirement: TEST-01
 */
import { describe, it } from 'vitest';

describe('nucleiApi: arg builder', () => {
  it.todo('includes -tags misconfig,exposure,graphql,cors exactly');
  it.todo('sets -rl 10 by default, honors opts.rateLimit override');
  it.todo('sets -timeout 10 by default, honors opts.timeoutSec override');
  it.todo('includes -jsonl -silent -retries 0 defensive defaults');
  it.todo('passes -l /dev/stdin (endpoint list via stdin batching)');
  it.todo('sets -t /tmp/nuclei/nuclei-templates (preflight-managed dir)');
});
