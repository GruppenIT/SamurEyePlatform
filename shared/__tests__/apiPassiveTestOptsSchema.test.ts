import { describe, it, expect } from 'vitest';
import { apiPassiveTestOptsSchema } from '../schema';
import type { PassiveTestResult } from '../schema';

describe('apiPassiveTestOptsSchema (Zod)', () => {
  it('Test 1: accepts {} (all opts default) and returns valid empty object', () => {
    const r = apiPassiveTestOptsSchema.safeParse({});
    expect(r.success).toBe(true);
  });

  it('Test 2: accepts { stages: { nucleiPassive: false, authFailure: false, api9Inventory: false } }', () => {
    const r = apiPassiveTestOptsSchema.safeParse({
      stages: { nucleiPassive: false, authFailure: false, api9Inventory: false },
    });
    expect(r.success).toBe(true);
  });

  it('Test 3: rejects unknown field at root (.strict()) — { foo: "bar" } must fail', () => {
    const r = apiPassiveTestOptsSchema.safeParse({ foo: 'bar' });
    expect(r.success).toBe(false);
  });

  it('Test 4: rejects unknown field in stages (.strict()) — { stages: { bolaActive: true } } must fail', () => {
    const r = apiPassiveTestOptsSchema.safeParse({ stages: { bolaActive: true } });
    expect(r.success).toBe(false);
  });

  it('Test 5: accepts credentialIdOverride as uuid and endpointIds as uuid array', () => {
    const r = apiPassiveTestOptsSchema.safeParse({
      credentialIdOverride: '00000000-0000-0000-0000-000000000000',
      endpointIds: ['11111111-1111-1111-1111-111111111111'],
    });
    expect(r.success).toBe(true);
  });

  it('Test 6: accepts dryRun: true and nuclei rateLimit + timeoutSec', () => {
    const r = apiPassiveTestOptsSchema.safeParse({
      dryRun: true,
      nuclei: { rateLimit: 5, timeoutSec: 15 },
    });
    expect(r.success).toBe(true);
  });

  it('Test 7: PassiveTestResult type has expected fields', () => {
    // Type-level test — verifies all required fields exist via assignment
    const result: PassiveTestResult = {
      apiId: 'some-id',
      stagesRun: ['nuclei_passive', 'auth_failure', 'api9_inventory'],
      stagesSkipped: [{ stage: 'nuclei_passive', reason: 'preflight failed' }],
      findingsCreated: 3,
      findingsUpdated: 1,
      findingsByCategory: { api8_misconfiguration_2023: 2 },
      findingsBySeverity: { high: 1, medium: 1, low: 1 },
      cancelled: false,
      dryRun: false,
      durationMs: 1234,
    };
    expect(result.apiId).toBe('some-id');
    expect(result.stagesRun).toContain('nuclei_passive');
    expect(result.durationMs).toBeGreaterThan(0);
  });
});
