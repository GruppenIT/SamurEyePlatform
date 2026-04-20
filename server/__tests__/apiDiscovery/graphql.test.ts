/**
 * Phase 11 — Nyquist stubs for DISC-03 GraphQL introspection.
 * Task 11-04-T1 (graphql.ts) replaces it.todo with real assertions.
 */
import { describe, it } from 'vitest';
// import placeholder — real imports added when stubs become real tests:
// import { runGraphqlIntrospection } from '../../services/scanners/api/graphql';
void 0;

describe('GraphQL introspection (DISC-03)', () => {
  it.todo('POSTs standard introspection query to /graphql, /api/graphql, /query in order');
  it.todo('short-circuits on first response containing data.__schema');
  it.todo('retries with auth header on 401/403 when cred compatible');
  it.todo('emits one api_endpoints row per schema.queryType/mutationType/subscriptionType field with method=POST');
  it.todo('stores operationName/operationType/variables under requestSchema');
  it.todo('returns null when data.__schema is absent (introspection disabled)');
});
