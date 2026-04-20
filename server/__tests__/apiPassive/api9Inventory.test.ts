/**
 * Phase 12 Wave 0 — Nyquist stub for API9 Inventory DB queries.
 * Implementation comes in Wave 1 (12-02-PLAN — scanners/api/api9Inventory.ts).
 * Requirement: TEST-01
 */
import { describe, it } from 'vitest';

describe('api9Inventory: DB-derived signals', () => {
  it.todo('detectSpecPubliclyExposed: finds apis with specUrl IS NOT NULL AND specHash IS NOT NULL');
  it.todo('detectSpecPubliclyExposed: emits severity=medium, title="Especificação de API exposta publicamente"');
  it.todo('detectGraphqlIntrospection: finds apis with apiType=graphql and endpoints from spec source');
  it.todo('detectGraphqlIntrospection: emits severity=medium, title="GraphQL introspection habilitado em produção"');
  it.todo('detectHiddenKiterunnerEndpoints: finds api_endpoints with discoverySources=[kiterunner] exclusive');
  it.todo('detectHiddenKiterunnerEndpoints: filters httpxStatus IN (200, 401, 403)');
  it.todo('detectHiddenKiterunnerEndpoints: emits severity=low per endpoint, title="Endpoint oculto descoberto por brute-force"');
  it.todo('returns empty array when API has none of the 3 signals');
});
