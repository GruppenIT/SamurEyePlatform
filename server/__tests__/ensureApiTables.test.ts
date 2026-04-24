import { describe, it } from 'vitest';

describe('ensureApiTables() (HIER-01, HIER-02, FIND-01)', () => {
  it.todo('creates apis, api_endpoints, api_findings tables on first run');
  it.todo('creates pgEnums api_type_enum, owasp_api_category, api_finding_status when missing');
  it.todo('creates UQ_apis_parent_base_url unique index (quoted identifier)');
  it.todo('creates UQ_api_endpoints_api_method_path unique index (quoted identifier)');
  it.todo('creates IDX_api_findings_* indexes (endpoint_id, job_id, owasp_category, severity, status)');
  it.todo('is idempotent — second run is a no-op; no "relation already exists" error');
  it.todo('logs info-level status for each pg_tables / pg_type / pg_indexes check');
  it.todo('does NOT throw on failure (swallows errors to keep app booting)');
  it.todo('runs AFTER ensureSystemUserExists in initializeDatabaseStructure');
});
