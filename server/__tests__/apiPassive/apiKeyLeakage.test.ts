/**
 * Phase 12-02 — authFailure: detectApiKeyLeakage tests
 * TDD GREEN: implementation in server/services/scanners/api/authFailure.ts
 */
import { describe, it, expect } from 'vitest';
import { detectApiKeyLeakage, maskApiKey } from '../../services/scanners/api/authFailure';

describe('maskApiKey', () => {
  it('returns 3-char prefix + *** for normal keys', () => {
    expect(maskApiKey('sk_abc123xyz')).toBe('sk_***');
  });

  it('returns *** for empty key', () => {
    expect(maskApiKey('')).toBe('***');
  });

  it('returns first 3 chars + *** for short keys', () => {
    expect(maskApiKey('abc')).toBe('abc***');
  });
});

describe('authFailure: detectApiKeyLeakage', () => {
  const probes = [
    { endpointId: 'ep-001', endpointUrl: 'https://example.com/api/v1/data', responseBody: '{"result": "ok"}' },
    { endpointId: 'ep-002', endpointUrl: 'https://example.com/api/v1/user', responseBody: '{"user": "test", "token": "sk_abc123xyz"}' },
    { endpointId: 'ep-003', endpointUrl: 'https://example.com/api/v1/health', responseBody: '{"status": "healthy"}' },
  ];

  it('Test 9: returns match when API key substring appears in response body', () => {
    const hit = detectApiKeyLeakage('sk_abc123xyz', probes);
    expect(hit).not.toBeNull();
    expect(hit?.endpointId).toBe('ep-002');
  });

  it('Test 9b: mask-at-source: leakedKeyPrefix = first 3 chars + ***', () => {
    const hit = detectApiKeyLeakage('sk_abc123xyz', probes);
    expect(hit?.evidence.extractedValues?.leakedKeyPrefix).toBe('sk_***');
  });

  it('Test 9c: severity is high', () => {
    const hit = detectApiKeyLeakage('sk_abc123xyz', probes);
    expect(hit?.severity).toBe('high');
  });

  it('Test 9d: owaspCategory is api2_broken_auth_2023', () => {
    const hit = detectApiKeyLeakage('sk_abc123xyz', probes);
    expect(hit?.owaspCategory).toBe('api2_broken_auth_2023');
  });

  it('Test 10: returns null when key does not appear in any body', () => {
    const result = detectApiKeyLeakage('completely-absent-key-xyz999', probes);
    expect(result).toBeNull();
  });

  it('returns null for key shorter than 4 chars', () => {
    const result = detectApiKeyLeakage('abc', probes);
    expect(result).toBeNull();
  });
});
