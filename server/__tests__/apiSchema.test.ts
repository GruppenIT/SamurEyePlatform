import { describe, it } from 'vitest';

describe('Phase 9 schema shape (HIER-01, HIER-02, FIND-01)', () => {
  describe('apis table', () => {
    it.todo('pgTable name is "apis" with id varchar primary key default gen_random_uuid()');
    it.todo('has column parent_asset_id varchar NOT NULL references assets(id) ON DELETE CASCADE');
    it.todo('has column base_url text NOT NULL');
    it.todo('has column api_type api_type_enum NOT NULL');
    it.todo('has nullable columns name, description, spec_url, spec_hash, spec_version, spec_last_fetched_at');
    it.todo('has column created_by varchar NOT NULL references users(id)');
    it.todo('exposes uniqueIndex UQ_apis_parent_base_url on (parent_asset_id, base_url)');
    it.todo('exposes index IDX_apis_parent_asset_id on (parent_asset_id)');
  });

  describe('api_endpoints table', () => {
    it.todo('has column api_id varchar NOT NULL references apis(id) ON DELETE CASCADE');
    it.todo('has column method text NOT NULL with CHECK constraint on allowed HTTP verbs');
    it.todo('has jsonb columns path_params, query_params, header_params each defaulting to []');
    it.todo('has nullable jsonb columns request_schema, response_schema');
    it.todo('has column requires_auth boolean NULLABLE (tri-valor)');
    it.todo('has column discovery_sources text[] NOT NULL default ARRAY[]::text[]');
    it.todo('exposes uniqueIndex UQ_api_endpoints_api_method_path on (api_id, method, path)');
  });

  describe('api_findings table', () => {
    it.todo('has column api_endpoint_id varchar NOT NULL references api_endpoints(id) ON DELETE CASCADE');
    it.todo('has column job_id varchar NULLABLE references jobs(id)');
    it.todo('has column owasp_category owasp_api_category NOT NULL');
    it.todo('has column severity threat_severity NOT NULL (reuses existing enum)');
    it.todo('has column status api_finding_status NOT NULL default open');
    it.todo('has column promoted_threat_id varchar NULLABLE references threats(id) ON DELETE SET NULL');
    it.todo('has column risk_score real NULLABLE');
    it.todo('has column evidence jsonb NOT NULL default empty object');
    it.todo('exposes indexes on endpoint_id, job_id, owasp_category, severity, status');
  });

  describe('enums', () => {
    it.todo('api_type_enum has exactly values [rest, graphql, soap]');
    it.todo('owasp_api_category has exactly 10 values matching OWASP_API_CATEGORY_LABELS keys');
    it.todo('api_finding_status has exactly values [open, triaged, false_positive, closed]');
  });

  describe('insert Zod schemas', () => {
    it.todo('insertApiSchema accepts { parentAssetId, baseUrl, apiType } and rejects missing apiType');
    it.todo('insertApiSchema rejects apiType outside [rest, graphql, soap]');
    it.todo('insertApiSchema omits id, createdAt, createdBy, updatedAt, spec* fields');
    it.todo('insertApiFindingSchema validates evidence through apiFindingEvidenceSchema');
  });
});
