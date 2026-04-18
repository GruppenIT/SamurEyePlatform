import { db } from "../db";
import { apiEndpoints, type ApiEndpoint, type InsertApiEndpoint } from "@shared/schema";
import { eq, desc, sql } from "drizzle-orm";
import { createLogger } from '../lib/logger';

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
