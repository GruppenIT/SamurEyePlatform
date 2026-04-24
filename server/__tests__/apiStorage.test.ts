import { describe, it } from 'vitest';

describe('Storage facade — apis (HIER-01)', () => {
  it.todo('createApi inserts row with createdBy = userId and returns with id');
  it.todo('getApi returns row by id, undefined if not found');
  it.todo('listApisByParent filters by parentAssetId and orders by createdAt desc');
  it.todo('promoteApiFromBackfill uses onConflictDoNothing on (parent_asset_id, base_url)');
  it.todo('promoteApiFromBackfill returns null when row already exists (no throw)');
});

describe('Storage facade — api_endpoints (HIER-02)', () => {
  it.todo('createApiEndpoint persists path_params/query_params/header_params JSONB arrays');
  it.todo('createApiEndpoint rejects method outside [GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS] at DB CHECK level');
  it.todo('createApiEndpoint accepts requiresAuth NULL / true / false (tri-valor)');
  it.todo('upsert on (api_id, method, path) merges discoverySources arrays');
  it.todo('listEndpointsByApi returns all endpoints for an api_id');
});

describe('Storage facade — api_findings (FIND-01)', () => {
  it.todo('createApiFinding accepts all 10 OWASP categories');
  it.todo('createApiFinding accepts all 4 status values');
  it.todo('createApiFinding persists evidence JSONB validated by apiFindingEvidenceSchema');
  it.todo('createApiFinding accepts promotedThreatId=NULL');
  it.todo('listFindingsByEndpoint returns findings ordered by createdAt desc');
});
