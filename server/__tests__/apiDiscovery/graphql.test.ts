/**
 * Phase 11 — Real tests for DISC-03 GraphQL introspection.
 * Task 11-03-T2 (graphql.ts) — 6 real tests replacing it.todo stubs.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import { probeGraphQL, schemaToEndpoints, GRAPHQL_PATHS, INTROSPECTION_QUERY } from '../../services/scanners/api/graphql';

const FIXTURES_DIR = path.join(import.meta.dirname, 'fixtures');

function loadIntrospectionFixture(): { data: { __schema: unknown } } {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, 'graphql-introspection.json'), 'utf-8'));
}

describe('GraphQL introspection (DISC-03)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('POSTs standard introspection query to /graphql, /api/graphql, /query in canonical order', async () => {
    expect(GRAPHQL_PATHS).toEqual(['/graphql', '/api/graphql', '/query']);
    expect(INTROSPECTION_QUERY).toContain('__schema');
    expect(INTROSPECTION_QUERY).toContain('IntrospectionQuery');
  });

  it('short-circuits on first response containing data.__schema', async () => {
    const introspectionResponse = loadIntrospectionFixture();
    const mockFetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: async () => introspectionResponse,
    });
    vi.stubGlobal('fetch', mockFetch);
    const ctrl = new AbortController();
    const result = await probeGraphQL('https://target.example.com', undefined, ctrl.signal);
    expect(result).not.toBeNull();
    expect(result!.endpointPath).toBe('/graphql');
    expect(result!.schema).toBeDefined();
    // Only one fetch call (short-circuited on first hit)
    expect(mockFetch).toHaveBeenCalledTimes(1);
    // Verify POST with Content-Type application/json
    const callArgs = mockFetch.mock.calls[0];
    expect(callArgs[1].method).toBe('POST');
    expect(callArgs[1].headers['Content-Type']).toBe('application/json');
  });

  it('includes Authorization header when authHeader is provided', async () => {
    const introspectionResponse = loadIntrospectionFixture();
    const mockFetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: async () => introspectionResponse,
    });
    vi.stubGlobal('fetch', mockFetch);
    const ctrl = new AbortController();
    await probeGraphQL('https://target.example.com', 'Bearer mytoken', ctrl.signal);
    const callArgs = mockFetch.mock.calls[0];
    expect(callArgs[1].headers['Authorization']).toBe('Bearer mytoken');
  });

  it('advances to /api/graphql then /query on missing __schema, returns null when none work', async () => {
    const mockFetch = vi.fn()
      // /graphql returns 404
      .mockResolvedValueOnce({ ok: false, status: 404 })
      // /api/graphql returns data without __schema (introspection disabled)
      .mockResolvedValueOnce({ ok: true, json: async () => ({ data: {} }) })
      // /query returns 500
      .mockResolvedValueOnce({ ok: false, status: 500 });
    vi.stubGlobal('fetch', mockFetch);
    const ctrl = new AbortController();
    const result = await probeGraphQL('https://target.example.com', undefined, ctrl.signal);
    expect(result).toBeNull();
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });

  it('schemaToEndpoints emits one row per query/mutation field with method=POST', () => {
    const fixture = loadIntrospectionFixture();
    const schema = (fixture.data as { __schema: Parameters<typeof schemaToEndpoints>[0] }).__schema;
    const endpoints = schemaToEndpoints(schema, 'test-api-id', '/graphql');
    // Fixture: Query has 'user' + 'users', Mutation has 'createUser' + 'updateUser' = 4 rows
    expect(endpoints).toHaveLength(4);
    for (const ep of endpoints) {
      expect(ep.method).toBe('POST');
      expect(ep.path).toBe('/graphql');
      expect(ep.discoverySources).toEqual(['spec']);
      expect(ep.apiId).toBe('test-api-id');
    }
  });

  it('schemaToEndpoints stores operationName + operationType + variables in requestSchema', () => {
    const fixture = loadIntrospectionFixture();
    const schema = (fixture.data as { __schema: Parameters<typeof schemaToEndpoints>[0] }).__schema;
    const endpoints = schemaToEndpoints(schema, 'test-api-id', '/graphql');
    // user query field
    const userEndpoint = endpoints.find((e) => e.requestSchema?.operationName === 'user');
    expect(userEndpoint).toBeDefined();
    expect(userEndpoint!.requestSchema!.operationType).toBe('query');
    expect(Array.isArray(userEndpoint!.requestSchema!.variables)).toBe(true);
    // createUser mutation field
    const createUserEndpoint = endpoints.find((e) => e.requestSchema?.operationName === 'createUser');
    expect(createUserEndpoint).toBeDefined();
    expect(createUserEndpoint!.requestSchema!.operationType).toBe('mutation');
  });
});
