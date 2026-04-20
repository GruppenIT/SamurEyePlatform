/**
 * Phase 11 — Nyquist stubs for DISC-06 canonical specHash.
 * Task 11-03-T3 (openapi.ts) replaces it.todo with real assertions.
 */
import { describe, it } from 'vitest';
// import placeholder — real imports added when stubs become real tests:
// import { computeSpecHash } from '../../services/scanners/api/openapi';
void 0;

describe('canonical specHash (DISC-06)', () => {
  it.todo('produces identical hash for semantically equivalent specs with different key order');
  it.todo('produces identical hash for arrays preserved in source order (arrays are NOT sorted)');
  it.todo('recursively canonicalizes nested objects, not only top-level');
  it.todo('returns 64-char hex sha256 string');
  it.todo('differs when a value inside nested array/object changes');
});
