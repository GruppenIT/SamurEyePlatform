import { describe, it, expect } from 'vitest';
import { discoverApiOptsSchema } from '../schema';

describe('discoverApiOptsSchema (Zod)', () => {
  it('applies defaults when parsing {}', () => {
    const parsed = discoverApiOptsSchema.parse({});
    expect(parsed.stages).toEqual({ spec: true, crawler: true, kiterunner: false, httpx: true, arjun: false });
    expect(parsed.dryRun).toBe(false);
  });

  it('requires arjunEndpointIds when stages.arjun=true', () => {
    const r = discoverApiOptsSchema.safeParse({ stages: { arjun: true } });
    expect(r.success).toBe(false);
    if (!r.success) expect(JSON.stringify(r.error.issues)).toContain('arjunEndpointIds é obrigatório');
  });

  it('rejects arjunEndpointIds=[] when stages.arjun=true', () => {
    expect(discoverApiOptsSchema.safeParse({ stages: { arjun: true }, arjunEndpointIds: [] }).success).toBe(false);
  });

  it('rejects non-uuid in arjunEndpointIds', () => {
    expect(discoverApiOptsSchema.safeParse({ stages: { arjun: true }, arjunEndpointIds: ['not-uuid'] }).success).toBe(false);
  });

  it('validates credentialIdOverride as uuid', () => {
    expect(discoverApiOptsSchema.safeParse({ credentialIdOverride: '00000000-0000-0000-0000-000000000000' }).success).toBe(true);
    expect(discoverApiOptsSchema.safeParse({ credentialIdOverride: 'not-uuid' }).success).toBe(false);
  });

  it('validates katana.depth range 1..10', () => {
    expect(discoverApiOptsSchema.safeParse({ katana: { depth: 0 } }).success).toBe(false);
    expect(discoverApiOptsSchema.safeParse({ katana: { depth: 11 } }).success).toBe(false);
    expect(discoverApiOptsSchema.safeParse({ katana: { depth: 3 } }).success).toBe(true);
  });

  it('validates kiterunner.rateLimit max 50', () => {
    expect(discoverApiOptsSchema.safeParse({ kiterunner: { rateLimit: 51 } }).success).toBe(false);
    expect(discoverApiOptsSchema.safeParse({ kiterunner: { rateLimit: 10 } }).success).toBe(true);
  });

  it('rejects unknown top-level fields via .strict()', () => {
    expect(discoverApiOptsSchema.safeParse({ unknownField: 'x' }).success).toBe(false);
  });
});
