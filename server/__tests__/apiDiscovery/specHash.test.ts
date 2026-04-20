import { describe, it, expect } from 'vitest';
import { canonicalize, computeCanonicalHash } from '../../services/scanners/api/specHash';

describe('canonical specHash (DISC-06)', () => {
  it('produces identical hash for specs with different top-level key order', () => {
    const a = { openapi: '3.0.0', info: { title: 'x' }, paths: {} };
    const b = { paths: {}, info: { title: 'x' }, openapi: '3.0.0' };
    expect(computeCanonicalHash(a)).toBe(computeCanonicalHash(b));
  });

  it('produces identical hash for nested objects with different key order (recursive)', () => {
    const a = { paths: { '/x': { get: { z: 1, a: 2 } } } };
    const b = { paths: { '/x': { get: { a: 2, z: 1 } } } };
    expect(computeCanonicalHash(a)).toBe(computeCanonicalHash(b));
  });

  it('preserves array order (arrays NOT sorted)', () => {
    const h1 = computeCanonicalHash({ tags: ['b', 'a'] });
    const h2 = computeCanonicalHash({ tags: ['a', 'b'] });
    expect(h1).not.toBe(h2);
  });

  it('returns 64-char lowercase hex sha256', () => {
    const h = computeCanonicalHash({ openapi: '3.0.0' });
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it('differs when a nested value changes', () => {
    const a = { paths: { '/x': { get: { summary: 'list' } } } };
    const b = { paths: { '/x': { get: { summary: 'LIST' } } } };
    expect(computeCanonicalHash(a)).not.toBe(computeCanonicalHash(b));
  });

  it('canonicalize does not mutate input', () => {
    const input = { b: 1, a: 2 };
    const snapshot = JSON.stringify(input);
    canonicalize(input);
    expect(JSON.stringify(input)).toBe(snapshot);
  });

  it('handles primitives and null', () => {
    expect(computeCanonicalHash('x')).toMatch(/^[0-9a-f]{64}$/);
    expect(computeCanonicalHash(null)).toMatch(/^[0-9a-f]{64}$/);
    expect(computeCanonicalHash(42)).toMatch(/^[0-9a-f]{64}$/);
  });
});
