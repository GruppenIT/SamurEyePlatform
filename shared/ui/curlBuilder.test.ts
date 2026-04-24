import { describe, it, expect } from 'vitest';
import { buildCurlCommand, AUTH_PLACEHOLDER } from './curlBuilder';

describe('buildCurlCommand', () => {
  it('returns null when url is missing', () => {
    const result = buildCurlCommand({ evidence: { method: 'GET' } });
    expect(result).toBeNull();
  });

  it('returns null when method is missing', () => {
    const result = buildCurlCommand({ evidence: { url: 'https://api.example.com/v1/users' } });
    expect(result).toBeNull();
  });

  it('returns null when evidence is null', () => {
    const result = buildCurlCommand({ evidence: null });
    expect(result).toBeNull();
  });

  it('builds correct curl for bearer_jwt POST with requestSchema', () => {
    const result = buildCurlCommand({
      evidence: {
        url: 'https://api.example.com/v1/users',
        method: 'POST',
        authType: 'bearer_jwt',
        requestSchema: { name: 'string' },
      },
    });
    expect(result).not.toBeNull();
    expect(result).toContain('-X POST');
    expect(result).toContain('"https://api.example.com/v1/users"');
    expect(result).toContain('-H "Authorization: Bearer $BEARER_TOKEN"');
    expect(result).toContain('-H "Content-Type: application/json"');
    expect(result).toContain('{"name":"string"}');
  });

  it('NEVER emits real tokens even if headers contains real credentials', () => {
    const result = buildCurlCommand({
      evidence: {
        url: 'https://api.example.com/v1/users',
        method: 'GET',
        authType: 'bearer_jwt',
        headers: { Authorization: 'Bearer abc123' },
      },
    });
    expect(result).not.toContain('abc123');
    expect(result).toContain('$BEARER_TOKEN');
  });

  it('appends ?api_key=$API_KEY to URL for api_key_query (no -H flag)', () => {
    const result = buildCurlCommand({
      evidence: {
        url: 'https://api.example.com/v1/users',
        method: 'GET',
        authType: 'api_key_query',
      },
    });
    expect(result).not.toBeNull();
    expect(result).toContain('?api_key=$API_KEY');
    expect(result).not.toContain('-H "X-API-Key');
  });

  it('appends with & when URL already has query params for api_key_query', () => {
    const result = buildCurlCommand({
      evidence: {
        url: 'https://api.example.com/v1/users?limit=10',
        method: 'GET',
        authType: 'api_key_query',
      },
    });
    expect(result).toContain('&api_key=$API_KEY');
  });

  it('emits --cert and --key flags for mtls (no Authorization header)', () => {
    const result = buildCurlCommand({
      evidence: {
        url: 'https://api.example.com/v1/secure',
        method: 'GET',
        authType: 'mtls',
      },
    });
    expect(result).not.toBeNull();
    expect(result).toContain('--cert $MTLS_CERT --key $MTLS_KEY');
    expect(result).not.toContain('-H "Authorization');
  });

  it('AUTH_PLACEHOLDER exports expected keys including bearer_jwt', () => {
    expect(AUTH_PLACEHOLDER.bearer_jwt).toBe('-H "Authorization: Bearer $BEARER_TOKEN"');
    expect(AUTH_PLACEHOLDER.mtls).toBe('--cert $MTLS_CERT --key $MTLS_KEY');
  });

  it('last line does not end with trailing backslash', () => {
    const result = buildCurlCommand({
      evidence: {
        url: 'https://api.example.com/v1/users',
        method: 'GET',
      },
    });
    expect(result).not.toBeNull();
    const lines = result!.split('\n');
    expect(lines[lines.length - 1]).not.toMatch(/ \\$/);
  });
});
