import { db } from "../db";
import { apiFindings, type ApiFinding, type InsertApiFinding } from "@shared/schema";
import { eq, desc } from "drizzle-orm";
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
