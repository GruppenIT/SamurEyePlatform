/**
 * Phase 11 — Nyquist stubs for DISC-02 OpenAPI 2.0/3.0/3.1 parsing.
 * Task 11-03-T2 (openapi.ts) replaces it.todo with real assertions.
 */
import { describe, it } from 'vitest';
// import placeholder — real imports added when stubs become real tests:
// import { parseOpenApiSpec } from '../../services/scanners/api/openapi';
void 0;

describe('OpenAPI parsing (DISC-02)', () => {
  it.todo('parses OpenAPI 2.0 fixture and emits N api_endpoints rows with method+path+requestSchema');
  it.todo('parses OpenAPI 3.0 fixture with nullable fields and oneOf/allOf');
  it.todo('parses OpenAPI 3.1 fixture with type:[string,null] and JSON Schema 2020-12 keywords');
  it.todo('dereferences $ref for local components');
  it.todo('rejects $ref to cross-origin URL and logs warn with specUrl+refUrl');
  it.todo('emits pathParams/queryParams/headerParams arrays per operation');
  it.todo('extracts specVersion from openapi or swagger key');
});
