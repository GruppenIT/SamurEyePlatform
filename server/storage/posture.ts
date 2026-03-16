import { db } from "../db";
import {
  postureSnapshots,
  type PostureSnapshot,
  type InsertPostureSnapshot,
} from "@shared/schema";
import { eq, desc } from "drizzle-orm";
import { createLogger } from '../lib/logger';

const log = createLogger('storage:posture');

/**
 * Inserts a new posture snapshot record.
 */
export async function writePostureSnapshot(data: InsertPostureSnapshot): Promise<PostureSnapshot> {
  const [snapshot] = await db.insert(postureSnapshots).values(data).returning();
  log.info({ snapshotId: snapshot.id, score: snapshot.score, jobId: snapshot.jobId }, 'posture snapshot written');
  return snapshot;
}

/**
 * Returns posture snapshot history, ordered by most recent first.
 * Optionally filtered by journeyId.
 */
export async function getPostureHistory(
  journeyId?: string,
  limit: number = 30,
): Promise<PostureSnapshot[]> {
  if (journeyId) {
    return await db
      .select()
      .from(postureSnapshots)
      .where(eq(postureSnapshots.journeyId, journeyId))
      .orderBy(desc(postureSnapshots.scoredAt))
      .limit(limit);
  }

  return await db
    .select()
    .from(postureSnapshots)
    .orderBy(desc(postureSnapshots.scoredAt))
    .limit(limit);
}

/**
 * Returns the most recent posture snapshot across all journeys.
 */
export async function getLatestPostureSnapshot(): Promise<PostureSnapshot | undefined> {
  const [snapshot] = await db
    .select()
    .from(postureSnapshots)
    .orderBy(desc(postureSnapshots.scoredAt))
    .limit(1);
  return snapshot;
}
