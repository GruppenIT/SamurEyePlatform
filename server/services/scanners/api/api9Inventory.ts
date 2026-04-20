/**
 * Phase 12 TEST-01 — API9 Inventory signals via direct DB queries.
 *
 * Phase 11 CONTEXT explicitly states: "Phase 11 only CREATES rows +
 * enriches. It does NOT create api_findings. Logs signals." Phase 12
 * is the natural consumer of those signals — derive findings from the
 * persisted state of apis/api_endpoints (not from log scraping).
 *
 * These functions run BEFORE the Nuclei scan in the orchestrator to
 * separate origin (DB query vs scanner output) and avoid order dependency.
 *
 * All queries scoped to a single apiId (passed from orchestrator loop).
 */
import { and, eq, inArray, sql } from 'drizzle-orm';
import { db } from '../../../db';
import { apis, apiEndpoints } from '@shared/schema';
import type { ApiFindingEvidence } from '@shared/schema';
import { API_REMEDIATION_TEMPLATES } from '@shared/apiRemediationTemplates';
import { createLogger } from '../../../lib/logger';

const log = createLogger('scanners:api:api9Inventory');

export interface Api9Hit {
  endpointId: string;   // api_endpoints.id (for FK) — for API-level signals use any endpoint of the API
  owaspCategory: 'api9_inventory_2023';
  severity: 'low' | 'medium';
  title: string;
  description: string;
  remediation: string;
  evidence: ApiFindingEvidence;
}

// ---------------------------------------------------------------------------
// Signal 1: Spec publicly exposed
// ---------------------------------------------------------------------------

/**
 * An API with specUrl + specHash populated means Phase 11 successfully
 * fetched the spec unauth (if auth was required, the spec fetch would have
 * been logged as authed). This heuristic assumes the spec is publicly
 * accessible.
 *
 * Returns one hit anchored to the FIRST endpoint of the API (FK requires
 * endpointId). If the API has no endpoints, returns [].
 */
export async function detectSpecPubliclyExposed(apiId: string): Promise<Api9Hit[]> {
  const api = await db.select().from(apis).where(eq(apis.id, apiId)).limit(1);
  if (api.length === 0 || !api[0].specUrl || !api[0].specHash) {
    return [];
  }
  const firstEndpoint = await db
    .select({ id: apiEndpoints.id })
    .from(apiEndpoints)
    .where(eq(apiEndpoints.apiId, apiId))
    .limit(1);
  if (firstEndpoint.length === 0) {
    return [];  // no endpoints to anchor the FK — skip
  }
  const specUrl = api[0].specUrl;
  return [{
    endpointId: firstEndpoint[0].id,
    owaspCategory: 'api9_inventory_2023',
    severity: 'medium',
    title: 'Especificação de API exposta publicamente',
    description: `A especificação da API está publicamente acessível em ${specUrl}, revelando a superfície de ataque completa (endpoints, parâmetros, schemas). API9 Improper Inventory Management.`,
    remediation: API_REMEDIATION_TEMPLATES.api9_inventory_2023.spec_exposed,
    evidence: {
      request: { method: 'GET', url: specUrl },
      response: { status: 200, bodySnippet: undefined },
      extractedValues: {
        specHash: api[0].specHash,
        specVersion: api[0].specVersion ?? null,
        specLastFetchedAt: api[0].specLastFetchedAt?.toISOString() ?? null,
      },
      context: 'API spec persisted without auth requirement — publicly exposed',
    },
  }];
}

// ---------------------------------------------------------------------------
// Signal 2: GraphQL introspection enabled
// ---------------------------------------------------------------------------

/**
 * An API with apiType='graphql' AND endpoints discovered from spec source
 * means Phase 11 successfully performed introspection. In production,
 * introspection should be disabled.
 */
export async function detectGraphqlIntrospection(apiId: string): Promise<Api9Hit[]> {
  const api = await db.select().from(apis).where(eq(apis.id, apiId)).limit(1);
  if (api.length === 0 || api[0].apiType !== 'graphql') {
    return [];
  }
  const specEndpoints = await db
    .select({ id: apiEndpoints.id, path: apiEndpoints.path, discoverySources: apiEndpoints.discoverySources })
    .from(apiEndpoints)
    .where(
      and(
        eq(apiEndpoints.apiId, apiId),
        sql`${apiEndpoints.discoverySources} @> ARRAY['spec']::text[]`,
      ),
    )
    .limit(1);
  if (specEndpoints.length === 0) {
    return [];  // no spec-sourced endpoints — introspection not proven
  }
  return [{
    endpointId: specEndpoints[0].id,
    owaspCategory: 'api9_inventory_2023',
    severity: 'medium',
    title: 'GraphQL introspection habilitado em produção',
    description: `O endpoint GraphQL responde à query __schema/__type, revelando toda a superfície de tipos e resolvers.`,
    remediation: API_REMEDIATION_TEMPLATES.api9_inventory_2023.graphql_introspection,
    evidence: {
      request: { method: 'POST', url: `${api[0].baseUrl}${specEndpoints[0].path}` },
      response: { status: 200 },
      extractedValues: {
        graphqlEndpointPath: specEndpoints[0].path,
        discoverySources: specEndpoints[0].discoverySources,
      },
      context: 'GraphQL introspection query succeeded during Phase 11 discovery',
    },
  }];
}

// ---------------------------------------------------------------------------
// Signal 3: Hidden endpoints from Kiterunner brute-force
// ---------------------------------------------------------------------------

/**
 * Endpoints whose discoverySources contains EXCLUSIVELY 'kiterunner' (no
 * 'spec', 'crawler', or 'manual') AND respond with 200/401/403 (live,
 * even if protected) are undocumented surface — API9 inventory gap.
 *
 * One hit per endpoint, severity=low (many of these in a large API).
 */
export async function detectHiddenKiterunnerEndpoints(apiId: string): Promise<Api9Hit[]> {
  const api = await db.select().from(apis).where(eq(apis.id, apiId)).limit(1);
  if (api.length === 0) return [];

  // array_length = 1 and element = 'kiterunner' — pure brute-force origin.
  const hidden = await db
    .select({
      id: apiEndpoints.id,
      method: apiEndpoints.method,
      path: apiEndpoints.path,
      httpxStatus: apiEndpoints.httpxStatus,
      discoverySources: apiEndpoints.discoverySources,
    })
    .from(apiEndpoints)
    .where(
      and(
        eq(apiEndpoints.apiId, apiId),
        sql`array_length(${apiEndpoints.discoverySources}, 1) = 1`,
        sql`${apiEndpoints.discoverySources} @> ARRAY['kiterunner']::text[]`,
        inArray(apiEndpoints.httpxStatus, [200, 401, 403]),
      ),
    );

  return hidden.map((ep) => ({
    endpointId: ep.id,
    owaspCategory: 'api9_inventory_2023' as const,
    severity: 'low' as const,
    title: 'Endpoint oculto descoberto por brute-force',
    description: `O endpoint ${ep.method} ${ep.path} foi descoberto exclusivamente via brute-force (Kiterunner), não aparece em spec nem crawler. Superfície de ataque não documentada.`,
    remediation: API_REMEDIATION_TEMPLATES.api9_inventory_2023.hidden_endpoint,
    evidence: {
      request: { method: ep.method, url: `${api[0].baseUrl}${ep.path}` },
      response: { status: ep.httpxStatus ?? 0 },
      extractedValues: {
        discoverySources: ep.discoverySources,
        httpxStatus: ep.httpxStatus,
      },
      context: 'Endpoint present only in brute-force results — API9 improper inventory',
    },
  }));
}

// ---------------------------------------------------------------------------
// Convenience aggregate
// ---------------------------------------------------------------------------

/**
 * Runs all 3 API9 DB-derived checks and returns concatenated hits.
 * Each check logs failures independently — aggregate returns what it can.
 */
export async function runApi9Inventory(apiId: string): Promise<Api9Hit[]> {
  const results: Api9Hit[] = [];
  try {
    const specHits = await detectSpecPubliclyExposed(apiId);
    results.push(...specHits);
  } catch (err) {
    log.error({ err, apiId }, 'detectSpecPubliclyExposed failed');
  }
  try {
    const graphqlHits = await detectGraphqlIntrospection(apiId);
    results.push(...graphqlHits);
  } catch (err) {
    log.error({ err, apiId }, 'detectGraphqlIntrospection failed');
  }
  try {
    const hiddenHits = await detectHiddenKiterunnerEndpoints(apiId);
    results.push(...hiddenHits);
  } catch (err) {
    log.error({ err, apiId }, 'detectHiddenKiterunnerEndpoints failed');
  }
  log.info({ apiId, hitsCount: results.length }, 'api9 inventory scan complete');
  return results;
}
