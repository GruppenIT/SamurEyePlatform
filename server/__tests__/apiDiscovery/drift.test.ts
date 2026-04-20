/**
 * Phase 11 — Nyquist stubs for DISC-06 spec drift detection.
 * Task 11-03-T3 replaces it.todo with real assertions.
 */
import { describe, it } from 'vitest';
// import placeholder — real imports added when stubs become real tests:
// import { detectSpecDrift } from '../../services/scanners/api/openapi';
void 0;

describe('spec drift detection (DISC-06)', () => {
  it.todo('logs log.warn with apiId+oldHash+newHash when specHash changes vs apis row');
  it.todo('does not log when hashes match');
  it.todo('updates apis.specHash+apis.specLastFetchedAt via storage.updateApiSpecMetadata');
  it.todo('re-parses spec and upserts endpoints on drift (does not abort)');
});
