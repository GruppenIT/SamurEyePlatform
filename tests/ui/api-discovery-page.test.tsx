/**
 * Phase 16 — UI-01 — API Discovery Page
 *
 * Wave 0 Nyquist stubs. Promoted to real it() by Plans 02-03 during Waves 2-4.
 * Per 16-VALIDATION.md task map.
 *
 * Requirement: Render a Card with Table listing discovered APIs.
 * Columns: baseUrl, apiType, discoveryMethod, endpointCount, lastExecutionAt.
 * Row click opens Endpoint Drilldown Sheet (UI-02).
 */
import { describe, it } from 'vitest';

describe('UI-01 — API Discovery Page', () => {
  it.todo('renders Card with Table when GET /api/v1/apis returns 3 rows');
  it.todo('table renders columns: baseUrl, apiType, discoveryMethod, endpointCount, lastExecutionAt');
  it.todo('renders empty-state message when API list is empty');
  it.todo('renders loading Skeleton while useQuery isLoading = true');
  it.todo('row click calls setSelectedApiId with the row apiId');
  it.todo('sidebar nav "API Discovery" entry is present inside Operações group');
  it.todo('App router registers path="/journeys/api" rendering ApiDiscoveryPage');
});
