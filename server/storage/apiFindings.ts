import { db } from "../db";
import { apiFindings, apiEndpoints, type ApiFinding, type InsertApiFinding } from "@shared/schema";
import { and, eq, ne, desc, inArray } from "drizzle-orm";
import { createLogger } from '../lib/logger';

const log = createLogger('storage');

export async function listFindingsByEndpoint(endpointId: string): Promise<ApiFinding[]> {
  return await db.select().from(apiFindings)
    .where(eq(apiFindings.apiEndpointId, endpointId))
    .orderBy(desc(apiFindings.createdAt));
}

export async function createApiFinding(data: InsertApiFinding): Promise<ApiFinding> {
  const [created] = await db.insert(apiFindings).values(data).returning();
  // Do NOT log the evidence blob — it may contain partial request/response content
  // pre-sanitization (Phase 14 FIND-02 handles that). Log only identifiers + metadata.
  log.info({
    findingId: created.id,
    endpointId: created.apiEndpointId,
    jobId: created.jobId,
    owaspCategory: created.owaspCategory,
    severity: created.severity,
    status: created.status,
  }, 'api finding created');
  return created;
}

/**
 * Filter shape for listApiFindings. At least one of {apiId, endpointId, jobId}
 * MUST be provided (enforced here to avoid full-table scans).
 */
export interface ListApiFindingsFilter {
  apiId?: string;
  endpointId?: string;
  jobId?: string;
  owaspCategory?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  status?: 'open' | 'triaged' | 'false_positive' | 'closed';
  limit?: number;
  offset?: number;
}

/**
 * Upsert an api_finding by composite key (endpointId, owaspCategory, title).
 *
 * Rules (CONTEXT.md §Findings dedupe):
 *  - match with status != 'closed' → UPDATE row (refresh evidence, jobId,
 *    severity, description, remediation, updatedAt); PRESERVE status.
 *  - match with status = 'closed'  → INSERT new row (issue reopened).
 *  - no match                      → INSERT new row.
 *
 * Uses db.transaction to serialize SELECT + INSERT/UPDATE, avoiding races.
 */
export async function upsertApiFindingByKey(
  endpointId: string,
  owaspCategory: InsertApiFinding['owaspCategory'],
  title: string,
  data: InsertApiFinding,
): Promise<{ finding: ApiFinding; action: 'inserted' | 'updated' }> {
  return await db.transaction(async (tx) => {
    // Look for non-closed match (update candidate)
    const existing = await tx
      .select()
      .from(apiFindings)
      .where(
        and(
          eq(apiFindings.apiEndpointId, endpointId),
          eq(apiFindings.owaspCategory, owaspCategory),
          eq(apiFindings.title, title),
          ne(apiFindings.status, 'closed'),
        ),
      )
      .limit(1);

    if (existing.length > 0) {
      const [updated] = await tx
        .update(apiFindings)
        .set({
          evidence: data.evidence,
          jobId: data.jobId ?? null,
          severity: data.severity,
          description: data.description ?? null,
          remediation: data.remediation ?? null,
          updatedAt: new Date(),
        })
        .where(eq(apiFindings.id, existing[0].id))
        .returning();
      log.info(
        {
          findingId: updated.id,
          endpointId,
          owaspCategory,
          severity: updated.severity,
          action: 'updated',
        },
        'api finding upserted (updated)',
      );
      return { finding: updated, action: 'updated' as const };
    }

    // Insert path (no match, OR match but closed)
    const [created] = await tx.insert(apiFindings).values(data).returning();
    log.info(
      {
        findingId: created.id,
        endpointId,
        owaspCategory,
        severity: created.severity,
        action: 'inserted',
      },
      'api finding upserted (inserted)',
    );
    return { finding: created, action: 'inserted' as const };
  });
}

/**
 * List api_findings with filters. At least one of apiId/endpointId/jobId
 * MUST be present in the filter (caller responsibility — helps avoid
 * full-table scans).
 *
 * Joins api_endpoints when filter.apiId is provided.
 */
export async function listApiFindings(
  filter: ListApiFindingsFilter,
): Promise<ApiFinding[]> {
  if (!filter.apiId && !filter.endpointId && !filter.jobId) {
    throw new Error('listApiFindings requires at least one of apiId, endpointId, or jobId');
  }
  const limit = filter.limit ?? 50;
  const offset = filter.offset ?? 0;

  // Scope endpoint IDs first when filter.apiId is provided
  let endpointIdsFromApi: string[] | undefined;
  if (filter.apiId) {
    const rows = await db
      .select({ id: apiEndpoints.id })
      .from(apiEndpoints)
      .where(eq(apiEndpoints.apiId, filter.apiId));
    endpointIdsFromApi = rows.map((r) => r.id);
    if (endpointIdsFromApi.length === 0) {
      return []; // API has no endpoints
    }
  }

  // Build WHERE conditions dynamically
  const conditions = [];
  if (filter.endpointId) {
    conditions.push(eq(apiFindings.apiEndpointId, filter.endpointId));
  } else if (endpointIdsFromApi) {
    conditions.push(inArray(apiFindings.apiEndpointId, endpointIdsFromApi));
  }
  if (filter.jobId) {
    conditions.push(eq(apiFindings.jobId, filter.jobId));
  }
  if (filter.owaspCategory) {
    conditions.push(eq(apiFindings.owaspCategory, filter.owaspCategory as InsertApiFinding['owaspCategory']));
  }
  if (filter.severity) {
    conditions.push(eq(apiFindings.severity, filter.severity));
  }
  if (filter.status) {
    conditions.push(eq(apiFindings.status, filter.status));
  }

  const rows = await db
    .select()
    .from(apiFindings)
    .where(conditions.length === 1 ? conditions[0] : and(...conditions))
    .orderBy(desc(apiFindings.createdAt))
    .limit(limit)
    .offset(offset);

  return rows;
}
