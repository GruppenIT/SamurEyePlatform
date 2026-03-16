import { db } from '../db';
import { recommendations } from '@shared/schema';
import type { Recommendation, InsertRecommendation } from '@shared/schema';
import { eq, and } from 'drizzle-orm';
import { createLogger } from '../lib/logger';

const log = createLogger('storage:recommendations');

/**
 * Upserts a recommendation for a threat.
 * On conflict (same threatId), updates all content fields but preserves user-set status.
 */
export async function upsertRecommendation(data: InsertRecommendation & { status?: string }): Promise<Recommendation> {
  const { status, ...contentData } = data as any;

  // If status is explicitly provided (e.g., from syncRecommendationStatus), include it
  const insertData: any = {
    ...contentData,
    updatedAt: new Date(),
  };
  if (status !== undefined) {
    insertData.status = status;
  }

  const [result] = await db
    .insert(recommendations)
    .values(insertData)
    .onConflictDoUpdate({
      target: recommendations.threatId,
      set: {
        templateId: insertData.templateId,
        title: insertData.title,
        whatIsWrong: insertData.whatIsWrong,
        businessImpact: insertData.businessImpact,
        fixSteps: insertData.fixSteps,
        verificationStep: insertData.verificationStep,
        references: insertData.references,
        effortTag: insertData.effortTag,
        roleRequired: insertData.roleRequired,
        hostSpecificData: insertData.hostSpecificData,
        updatedAt: new Date(),
        // Only update status if explicitly provided
        ...(status !== undefined ? { status } : {}),
      },
    })
    .returning();

  return result;
}

/**
 * Returns the recommendation for a specific threat, or undefined if not found.
 */
export async function getRecommendationByThreatId(threatId: string): Promise<Recommendation | undefined> {
  const [result] = await db
    .select()
    .from(recommendations)
    .where(eq(recommendations.threatId, threatId))
    .limit(1);
  return result;
}

/**
 * Returns a filtered list of recommendations.
 */
export async function getRecommendations(filters?: {
  effortTag?: string;
  roleRequired?: string;
  status?: string;
}): Promise<Recommendation[]> {
  const conditions = [];

  if (filters?.effortTag) {
    conditions.push(eq(recommendations.effortTag, filters.effortTag));
  }
  if (filters?.roleRequired) {
    conditions.push(eq(recommendations.roleRequired, filters.roleRequired));
  }
  if (filters?.status) {
    conditions.push(eq(recommendations.status, filters.status));
  }

  if (conditions.length === 0) {
    return db.select().from(recommendations);
  }

  return db.select().from(recommendations).where(and(...conditions));
}
