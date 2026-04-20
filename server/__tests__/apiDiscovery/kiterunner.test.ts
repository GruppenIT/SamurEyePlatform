/**
 * Phase 11 — Nyquist stubs for DISC-05 Kiterunner brute-force.
 * Task 11-05-T1 (kiterunner.ts) replaces it.todo with real assertions.
 */
import { describe, it } from 'vitest';
// import placeholder — real imports added when stubs become real tests:
// import { runKiterunner } from '../../services/scanners/api/kiterunner';
void 0;

describe('Kiterunner brute-force (DISC-05)', () => {
  it.todo('default opts.stages.kiterunner is false (opt-in)');
  it.todo('spawns kr scan with -w routes-large.kite -o json -x 5 -j 100');
  it.todo('passes --success-status-codes 200,201,204,301,302,401,403');
  it.todo('passes --fail-status-codes 404,501,502,400');
  it.todo('parses JSONL output with status_code + path per line');
  it.todo('emits discoverySources=["kiterunner"] per endpoint');
});
