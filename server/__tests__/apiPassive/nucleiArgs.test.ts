/**
 * Phase 12-02 — nucleiApi: arg builder + JSONL mapper tests
 * TDD GREEN: implementation exists in server/services/scanners/api/nucleiApi.ts
 */
import { describe, it, expect } from 'vitest';
import { buildNucleiArgs, mapNucleiJsonlToEvidence } from '../../services/scanners/api/nucleiApi';
import type { NucleiFinding } from '@shared/schema';

// Minimal valid NucleiFinding for test use
function makeNucleiFinding(overrides: Partial<NucleiFinding> = {}): NucleiFinding {
  return {
    type: 'nuclei',
    target: 'https://example.com',
    severity: 'medium',
    templateId: 'cors-misconfiguration',
    matchedAt: 'https://example.com/api',
    info: {
      name: 'CORS Misconfiguration',
      severity: 'medium',
      tags: ['cors', 'misconfig'],
    },
    host: 'https://example.com',
    ...overrides,
  } as NucleiFinding;
}

describe('buildNucleiArgs', () => {
  it('Test 1: includes -tags misconfig,exposure,graphql,cors exactly', () => {
    const args = buildNucleiArgs({});
    const idx = args.indexOf('-tags');
    expect(idx).toBeGreaterThanOrEqual(0);
    expect(args[idx + 1]).toBe('misconfig,exposure,graphql,cors');
  });

  it('Test 2: default rate limit is 10', () => {
    const args = buildNucleiArgs({});
    const rlIdx = args.indexOf('-rl');
    expect(args[rlIdx + 1]).toBe('10');
  });

  it('Test 2b: default timeout is 10', () => {
    const args = buildNucleiArgs({});
    const toIdx = args.indexOf('-timeout');
    expect(args[toIdx + 1]).toBe('10');
  });

  it('Test 2c: honors opts.rateLimit=5', () => {
    const args = buildNucleiArgs({ rateLimit: 5 });
    const rlIdx = args.indexOf('-rl');
    expect(args[rlIdx + 1]).toBe('5');
  });

  it('Test 2d: honors opts.timeoutSec=20', () => {
    const args = buildNucleiArgs({ timeoutSec: 20 });
    const toIdx = args.indexOf('-timeout');
    expect(args[toIdx + 1]).toBe('20');
  });

  it('Test 3: includes -jsonl', () => {
    expect(buildNucleiArgs({})).toContain('-jsonl');
  });

  it('Test 3b: includes -silent', () => {
    expect(buildNucleiArgs({})).toContain('-silent');
  });

  it('Test 3c: includes -retries 0', () => {
    const args = buildNucleiArgs({});
    const idx = args.indexOf('-retries');
    expect(idx).toBeGreaterThanOrEqual(0);
    expect(args[idx + 1]).toBe('0');
  });

  it('Test 3d: includes templates dir', () => {
    expect(buildNucleiArgs({})).toContain('/tmp/nuclei/nuclei-templates');
  });

  it('Test 4: includes -l /dev/stdin for stdin endpoint list', () => {
    const args = buildNucleiArgs({});
    const lIdx = args.indexOf('-l');
    expect(lIdx).toBeGreaterThanOrEqual(0);
    expect(args[lIdx + 1]).toBe('/dev/stdin');
  });
});
