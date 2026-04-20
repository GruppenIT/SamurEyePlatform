import { db } from "../db";
import { apiEndpoints, type ApiEndpoint, type InsertApiEndpoint } from "@shared/schema";
import { eq, desc, sql } from "drizzle-orm";
import { createLogger } from '../lib/logger';

type QueryParam = { name: string; type?: string; required?: boolean; example?: unknown };

const log = createLogger('storage');

export async function listEndpointsByApi(apiId: string): Promise<ApiEndpoint[]> {
  return await db.select().from(apiEndpoints)
    .where(eq(apiEndpoints.apiId, apiId))
    .orderBy(desc(apiEndpoints.createdAt));
}

export async function createApiEndpoint(data: InsertApiEndpoint): Promise<ApiEndpoint> {
  const [created] = await db.insert(apiEndpoints).values(data).returning();
  log.info({ endpointId: created.id, apiId: created.apiId, method: created.method, path: created.path }, 'api endpoint created');
  return created;
}

/**
 * Upsert on UNIQUE (api_id, method, path). When the same endpoint is rediscovered
 * (e.g. crawler after spec), merge discoverySources using PostgreSQL array
 * concatenation + deduplication. Phase 11 discovery writers are the primary
 * consumers; Phase 9 tests assert the merge behavior.
 */
export async function upsertApiEndpoint(data: InsertApiEndpoint): Promise<ApiEndpoint> {
  const [row] = await db.insert(apiEndpoints)
    .values(data)
    .onConflictDoUpdate({
      target: [apiEndpoints.apiId, apiEndpoints.method, apiEndpoints.path],
      set: {
        // Dedupe merge of discovery_sources text[]
        discoverySources: sql`(
          SELECT ARRAY(SELECT DISTINCT unnest(
            ${apiEndpoints.discoverySources} || ${data.discoverySources ?? sql`ARRAY[]::text[]`}
          ))
        )`,
        updatedAt: new Date(),
      },
    })
    .returning();
  log.info({ endpointId: row.id, apiId: row.apiId }, 'api endpoint upserted');
  return row;
}

/**
 * Phase 11 — bulk upsert on UNIQUE (api_id, method, path).
 * Preserves richer data from prior runs: requestSchema/responseSchema/requiresAuth
 * use COALESCE so a crawler row with nulls does not overwrite spec-written schemas.
 * Returns counts computed from returning() createdAt/updatedAt heuristic
 * (row is an insert when createdAt === updatedAt, both set to now() on insert).
 */
export async function upsertApiEndpoints(
  apiId: string,
  rows: InsertApiEndpoint[],
): Promise<{ inserted: number; updated: number }> {
  if (rows.length === 0) return { inserted: 0, updated: 0 };

  // Ensure every row has apiId set (defensive — callers pass per-api).
  const valuesWithApi = rows.map((r) => ({ ...r, apiId }));

  const result = await db.insert(apiEndpoints)
    .values(valuesWithApi)
    .onConflictDoUpdate({
      target: [apiEndpoints.apiId, apiEndpoints.method, apiEndpoints.path],
      set: {
        discoverySources: sql`(
          SELECT ARRAY(SELECT DISTINCT unnest(
            ${apiEndpoints.discoverySources} || EXCLUDED.discovery_sources
          ))
        )`,
        requestSchema: sql`COALESCE(${apiEndpoints.requestSchema}, EXCLUDED.request_schema)`,
        responseSchema: sql`COALESCE(${apiEndpoints.responseSchema}, EXCLUDED.response_schema)`,
        requiresAuth: sql`COALESCE(${apiEndpoints.requiresAuth}, EXCLUDED.requires_auth)`,
        pathParams: sql`CASE WHEN jsonb_array_length(${apiEndpoints.pathParams}) = 0 THEN EXCLUDED.path_params ELSE ${apiEndpoints.pathParams} END`,
        queryParams: sql`CASE WHEN jsonb_array_length(${apiEndpoints.queryParams}) = 0 THEN EXCLUDED.query_params ELSE ${apiEndpoints.queryParams} END`,
        headerParams: sql`CASE WHEN jsonb_array_length(${apiEndpoints.headerParams}) = 0 THEN EXCLUDED.header_params ELSE ${apiEndpoints.headerParams} END`,
        updatedAt: new Date(),
      },
    })
    .returning({ id: apiEndpoints.id, createdAt: apiEndpoints.createdAt, updatedAt: apiEndpoints.updatedAt });

  // Heuristic: row is an insert when createdAt === updatedAt (both set to now() on insert).
  // onConflictDoUpdate assigns updatedAt: new Date() on update, making it strictly
  // greater than createdAt for true updates.
  let inserted = 0;
  let updated = 0;
  for (const row of result) {
    if (row.createdAt.getTime() === row.updatedAt.getTime()) inserted++;
    else updated++;
  }
  log.info({ apiId, total: rows.length, inserted, updated }, 'api endpoints bulk upserted');
  return { inserted, updated };
}

/**
 * Phase 11 ENRH-01/02 — update only the httpx_* enrichment columns.
 * Does NOT touch discoverySources / requestSchema / responseSchema / requiresAuth.
 */
export async function mergeHttpxEnrichment(
  endpointId: string,
  data: {
    status: number | null;
    contentType: string | null;
    tech: string[] | null;
    tls: Record<string, unknown> | null;
  },
): Promise<void> {
  await db.update(apiEndpoints)
    .set({
      httpxStatus: data.status,
      httpxContentType: data.contentType,
      httpxTech: data.tech ?? undefined,
      httpxTls: data.tls ?? undefined,
      httpxLastProbedAt: new Date(),
      updatedAt: new Date(),
    })
    .where(eq(apiEndpoints.id, endpointId));
  log.info({ endpointId, httpxStatus: data.status }, 'httpx enrichment merged');
}

/**
 * Phase 11 ENRH-03 — append newly discovered query params to an endpoint.
 * Dedupe by name: if a param with the same name already exists, keep the existing
 * entry (it may have richer type info from spec). JS-side merge + single UPDATE.
 */
export async function appendQueryParams(
  endpointId: string,
  params: QueryParam[],
): Promise<void> {
  if (params.length === 0) return;
  const [existing] = await db.select({ queryParams: apiEndpoints.queryParams })
    .from(apiEndpoints)
    .where(eq(apiEndpoints.id, endpointId));
  if (!existing) return;
  const current = Array.isArray(existing.queryParams) ? (existing.queryParams as QueryParam[]) : [];
  const seen = new Set(current.map((p) => p.name));
  const appended = [...current];
  let added = 0;
  for (const p of params) {
    if (!seen.has(p.name)) {
      appended.push(p);
      seen.add(p.name);
      added++;
    }
  }
  if (added > 0) {
    await db.update(apiEndpoints)
      .set({ queryParams: appended, updatedAt: new Date() })
      .where(eq(apiEndpoints.id, endpointId));
    log.info({ endpointId, added }, 'query params appended');
  }
}

/**
 * Phase 11 — mark endpoint ids stale by logging only (lastSeenAt is DEFERRED per CONTEXT.md).
 * Returns the ids supplied unchanged; callers use it purely for structured logging.
 */
export async function markEndpointsStale(apiId: string, endpointIds: string[]): Promise<string[]> {
  log.info({ apiId, endpointIdsNotSeen: endpointIds.length }, 'stale endpoints preserved');
  return endpointIds;
}
