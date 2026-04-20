/**
 * Phase 11 — Nyquist stubs for ENRH-03 Arjun param discovery.
 * Task 11-06-T1 (arjun.ts) replaces it.todo with real assertions.
 */
import { describe, it } from 'vitest';
// import placeholder — real imports added when stubs become real tests:
// import { runArjun } from '../../services/scanners/api/arjun';
void 0;

describe('Arjun param discovery (ENRH-03)', () => {
  it.todo('rejects arjunEndpointIds referencing endpoints with method != GET');
  it.todo('rejects arjunEndpointIds referencing endpoints from a different apiId');
  it.todo('spawns arjun with -u URL -w arjun-extended-pt-en.txt -oJ tempfile -m GET -t 10 -T 15');
  it.todo('parses tempfile JSON as dict keyed by URL (not array) via Zod schema');
  it.todo('merges params into queryParams JSONB append-only (dedupe by name)');
  it.todo('cleans tempfile in try/finally even on SIGKILL');
});
