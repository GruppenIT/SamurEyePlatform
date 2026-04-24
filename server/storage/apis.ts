import { db } from "../db";
import { apis, apiEndpoints, type Api, type InsertApi } from "@shared/schema";
import { eq, desc, count } from "drizzle-orm";
import { createLogger } from '../lib/logger';


const log = createLogger('storage');

export async function getApi(id: string): Promise<Api | undefined> {
  const [api] = await db.select().from(apis).where(eq(apis.id, id));
  return api;
}

export async function listApis(): Promise<Api[]> {
  return await db.select().from(apis).orderBy(desc(apis.createdAt));
}

export async function listApisByParent(parentAssetId: string): Promise<Api[]> {
  return await db.select().from(apis)
    .where(eq(apis.parentAssetId, parentAssetId))
    .orderBy(desc(apis.createdAt));
}

/**
 * Manual registration (HIER-03). Route-layer validates parent.type='web_application'
 * and normalizes baseUrl before calling here. UNIQUE (parent_asset_id, base_url)
 * enforces dedupe; caller translates code 23505 to HTTP 409.
 */
export async function createApi(data: InsertApi, userId: string): Promise<Api> {
  const [created] = await db.insert(apis)
    .values({ ...data, createdBy: userId })
    .returning();
  log.info({ apiId: created.id, parentAssetId: created.parentAssetId, apiType: created.apiType }, 'api created');
  return created;
}

/**
 * Backfill-only (HIER-04). Idempotent via onConflictDoNothing on the UNIQUE index.
 * Returns null when the API already exists (no throw). createdBy is the system user.
 */
export async function promoteApiFromBackfill(
  parentAssetId: string,
  baseUrl: string,
  apiType: 'rest' | 'graphql' | 'soap',
  opts: { specUrl?: string; systemUserId: string },
): Promise<Api | null> {
  const [created] = await db.insert(apis)
    .values({
      parentAssetId,
      baseUrl,
      apiType,
      specUrl: opts.specUrl ?? null,
      createdBy: opts.systemUserId,
    })
    .onConflictDoNothing({ target: [apis.parentAssetId, apis.baseUrl] })
    .returning();
  if (created) {
    log.info({ apiId: created.id, parentAssetId, baseUrl, apiType, source: 'backfill' }, 'api promoted from backfill');
    return created;
  }
  return null;
}

export interface ApiWithEndpointCount extends Api {
  endpointCount: number;
}

/**
 * Phase 16 UI-01 — List all APIs with a computed endpointCount.
 * Uses LEFT JOIN so APIs with zero endpoints still appear with count=0.
 * Ordering: desc(createdAt) — matches listApis().
 */
export async function listApisWithEndpointCount(): Promise<ApiWithEndpointCount[]> {
  const rows = await db
    .select({
      api: apis,
      endpointCount: count(apiEndpoints.id),
    })
    .from(apis)
    .leftJoin(apiEndpoints, eq(apiEndpoints.apiId, apis.id))
    .groupBy(apis.id)
    .orderBy(desc(apis.createdAt));
  return rows.map((r) => ({
    ...r.api,
    endpointCount: Number(r.endpointCount),
  }));
}

/**
 * Phase 11 DISC-06 — update spec metadata after a successful spec fetch+parse.
 * Stamps specLastFetchedAt = now(); used by drift detection to compare hashes
 * across runs.
 */
export async function updateApiSpecMetadata(
  apiId: string,
  data: { specUrl: string; specVersion: string; specHash: string },
): Promise<Api> {
  const [updated] = await db.update(apis)
    .set({
      specUrl: data.specUrl,
      specVersion: data.specVersion,
      specHash: data.specHash,
      specLastFetchedAt: new Date(),
      updatedAt: new Date(),
    })
    .where(eq(apis.id, apiId))
    .returning();
  log.info({ apiId, specVersion: data.specVersion, specHash: data.specHash.slice(0, 16) + '...' }, 'api spec metadata updated');
  return updated;
}
