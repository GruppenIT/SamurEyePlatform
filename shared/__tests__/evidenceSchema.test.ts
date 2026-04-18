import { describe, it, expect } from 'vitest';
import { apiFindingEvidenceSchema } from '../schema';

describe('apiFindingEvidenceSchema (FIND-01)', () => {
  const valid = {
    request: { method: 'GET', url: 'https://api.example.com/users/1' },
    response: { status: 200 },
  };

  it('accepts canonical minimal shape', () => {
    expect(() => apiFindingEvidenceSchema.parse(valid)).not.toThrow();
  });

  it('accepts optional bodySnippet up to 8192 chars', () => {
    const withBody = {
      ...valid,
      request: { ...valid.request, bodySnippet: 'x'.repeat(8192) },
      response: { ...valid.response, bodySnippet: 'y'.repeat(100) },
    };
    expect(() => apiFindingEvidenceSchema.parse(withBody)).not.toThrow();
  });

  it('rejects missing request', () => {
    expect(() => apiFindingEvidenceSchema.parse({ response: { status: 200 } })).toThrow();
  });

  it('rejects missing response', () => {
    expect(() => apiFindingEvidenceSchema.parse({ request: valid.request })).toThrow();
  });

  it('rejects unknown top-level keys (.strict)', () => {
    expect(() => apiFindingEvidenceSchema.parse({ ...valid, rogue: 'nope' })).toThrow();
  });

  it('accepts optional extractedValues and context', () => {
    expect(() => apiFindingEvidenceSchema.parse({
      ...valid,
      extractedValues: { jwtAlg: 'none' },
      context: 'JWT accepted with alg: none',
    })).not.toThrow();
  });
});
