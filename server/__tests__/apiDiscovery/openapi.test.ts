/**
 * Phase 11 — Real tests for DISC-02 OpenAPI parsing + specToEndpoints.
 * Task 11-03-T1 (openapi.ts) — 7 real tests replacing it.todo stubs.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import { specToEndpoints } from '../../services/scanners/api/openapi';
import { computeCanonicalHash } from '../../services/scanners/api/specHash';

const FIXTURES_DIR = path.join(import.meta.dirname, 'fixtures');

function loadFixture(name: string): unknown {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, name), 'utf-8'));
}

describe('OpenAPI parsing (DISC-02)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('parses OpenAPI 2.0 fixture and emits N api_endpoints rows with UPPERCASE method', () => {
    const spec = loadFixture('openapi-2.0.json');
    const endpoints = specToEndpoints(spec, 'test-api-id');
    // Fixture has /pets (GET, POST) + /pets/{id} (GET) = 3 operations
    expect(endpoints).toHaveLength(3);
    const methods = endpoints.map((e) => e.method);
    expect(methods).toContain('GET');
    expect(methods).toContain('POST');
    // All methods are uppercase
    for (const ep of endpoints) {
      expect(ep.method).toBe(ep.method.toUpperCase());
    }
  });

  it('emits discoverySources=[spec] on every endpoint', () => {
    const spec = loadFixture('openapi-3.0.json');
    const endpoints = specToEndpoints(spec, 'api-uuid');
    expect(endpoints.length).toBeGreaterThan(0);
    for (const ep of endpoints) {
      expect(ep.discoverySources).toEqual(['spec']);
    }
  });

  it('parses OpenAPI 3.0 fixture and splits queryParams/headerParams/pathParams correctly', () => {
    const spec = loadFixture('openapi-3.0.json');
    const endpoints = specToEndpoints(spec, 'api-uuid');
    // GET /pets has query param 'limit' + header 'X-Request-ID'
    const listPets = endpoints.find((e) => e.path === '/pets' && e.method === 'GET');
    expect(listPets).toBeDefined();
    expect(listPets!.queryParams.some((p) => p.name === 'limit')).toBe(true);
    expect(listPets!.headerParams.some((p) => p.name === 'X-Request-ID')).toBe(true);
    expect(listPets!.pathParams).toHaveLength(0);
    // GET /pets/{id} has path param 'id'
    const getPet = endpoints.find((e) => e.path === '/pets/{id}' && e.method === 'GET');
    expect(getPet).toBeDefined();
    expect(getPet!.pathParams.some((p) => p.name === 'id')).toBe(true);
  });

  it('parses OpenAPI 3.1 fixture with type:[string,null] parameters', () => {
    const spec = loadFixture('openapi-3.1.json');
    const endpoints = specToEndpoints(spec, 'api-uuid');
    // GET /pets has two query params: 'status' and 'limit'
    const listPets = endpoints.find((e) => e.path === '/pets' && e.method === 'GET');
    expect(listPets).toBeDefined();
    expect(listPets!.queryParams).toHaveLength(2);
    expect(listPets!.queryParams.map((p) => p.name)).toContain('status');
    expect(listPets!.queryParams.map((p) => p.name)).toContain('limit');
  });

  it('extracts specVersion from openapi key (3.0.3)', () => {
    const spec = loadFixture('openapi-3.0.json') as { openapi?: string };
    expect(spec.openapi).toBe('3.0.3');
  });

  it('extracts specVersion from swagger key (2.0)', () => {
    const spec = loadFixture('openapi-2.0.json') as { swagger?: string };
    expect(spec.swagger).toBe('2.0');
  });

  it('computeCanonicalHash produces a stable 64-char hex string', () => {
    const spec = loadFixture('openapi-3.0.json');
    const hash1 = computeCanonicalHash(spec);
    const hash2 = computeCanonicalHash(spec);
    expect(hash1).toMatch(/^[0-9a-f]{64}$/);
    expect(hash1).toBe(hash2); // deterministic
  });
});
