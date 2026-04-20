/**
 * Phase 11 — Real tests for DISC-01 spec-path probing.
 * Task 11-03-T1 (openapi.ts) — 7 real tests replacing it.todo stubs.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fetchAndParseSpec, KNOWN_SPEC_PATHS } from '../../services/scanners/api/openapi';

describe('spec-first probing (DISC-01)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('iterates KNOWN_SPEC_PATHS in canonical order openapi.json → swagger.json → v3 → v2 → api-docs → swagger-ui.html → docs/openapi', () => {
    expect(KNOWN_SPEC_PATHS).toEqual([
      '/openapi.json',
      '/swagger.json',
      '/v3/api-docs',
      '/v2/api-docs',
      '/api-docs',
      '/swagger-ui.html',
      '/docs/openapi',
    ]);
  });

  it('short-circuits on first response with status 200 and JSON content-type', async () => {
    const mockSpec = { openapi: '3.0.0', info: { title: 'Test', version: '1.0' }, paths: {} };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => mockSpec,
    }));
    const ctrl = new AbortController();
    const result = await fetchAndParseSpec('https://target.example.com', undefined, ctrl.signal);
    expect(result).not.toBeNull();
    expect(result!.specUrl).toBe('https://target.example.com/openapi.json');
    expect(result!.specVersion).toBe('3.0.0');
    expect(result!.specHash).toMatch(/^[0-9a-f]{64}$/);
    // fetch called only once (short-circuits on first hit)
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(1);
  });

  it('skips non-JSON responses (content-type text/html) and advances to next path', async () => {
    const mockSpec = { openapi: '3.0.3', info: { title: 'Test', version: '1.0' }, paths: {} };
    const mockFetch = vi.fn()
      // First call returns HTML (non-JSON) — should be skipped
      .mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'text/html; charset=utf-8' }),
        json: async () => { throw new Error('not json'); },
      })
      // Second call returns JSON — should succeed
      .mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => mockSpec,
      });
    vi.stubGlobal('fetch', mockFetch);
    const ctrl = new AbortController();
    const result = await fetchAndParseSpec('https://target.example.com', undefined, ctrl.signal);
    expect(result).not.toBeNull();
    // First path (/openapi.json) returned HTML, so second path (/swagger.json) succeeded
    expect(result!.specUrl).toBe('https://target.example.com/swagger.json');
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('returns null when no path yields a valid spec (all 7 paths fail)', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      headers: new Headers({}),
    });
    vi.stubGlobal('fetch', mockFetch);
    const ctrl = new AbortController();
    const result = await fetchAndParseSpec('https://target.example.com', undefined, ctrl.signal);
    expect(result).toBeNull();
    // All 7 paths were tried
    expect(mockFetch).toHaveBeenCalledTimes(7);
  });

  it('includes Authorization header when authHeader is provided', async () => {
    const mockSpec = { openapi: '3.0.0', info: { title: 'Test', version: '1.0' }, paths: {} };
    const mockFetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => mockSpec,
    });
    vi.stubGlobal('fetch', mockFetch);
    const ctrl = new AbortController();
    await fetchAndParseSpec('https://target.example.com', 'Bearer mytoken', ctrl.signal);
    const callArgs = mockFetch.mock.calls[0];
    expect(callArgs[1].headers).toMatchObject({ Authorization: 'Bearer mytoken' });
  });

  it('skips path on 401 response and returns null after exhausting all paths', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      headers: new Headers({}),
    });
    vi.stubGlobal('fetch', mockFetch);
    const ctrl = new AbortController();
    // Even with 401, no auth provided — all paths tried, returns null
    const result = await fetchAndParseSpec('https://target.example.com', undefined, ctrl.signal);
    expect(result).toBeNull();
    expect(mockFetch).toHaveBeenCalledTimes(7);
  });

  it('advances past 404 and succeeds on a later path', async () => {
    const mockSpec = { openapi: '3.1.0', info: { title: 'Test', version: '1.0' }, paths: {} };
    const mockFetch = vi.fn()
      // First 4 paths return 404
      .mockResolvedValueOnce({ ok: false, status: 404, headers: new Headers({}) })
      .mockResolvedValueOnce({ ok: false, status: 404, headers: new Headers({}) })
      .mockResolvedValueOnce({ ok: false, status: 404, headers: new Headers({}) })
      .mockResolvedValueOnce({ ok: false, status: 404, headers: new Headers({}) })
      // 5th path (/api-docs) succeeds
      .mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => mockSpec,
      });
    vi.stubGlobal('fetch', mockFetch);
    const ctrl = new AbortController();
    const result = await fetchAndParseSpec('https://target.example.com', undefined, ctrl.signal);
    expect(result).not.toBeNull();
    expect(result!.specUrl).toBe('https://target.example.com/api-docs');
    expect(result!.specVersion).toBe('3.1.0');
  });
});
