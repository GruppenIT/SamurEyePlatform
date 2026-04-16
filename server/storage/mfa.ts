import { db } from "../db";
import { and, eq, gt, isNull, lt, or } from "drizzle-orm";
import { mfaEmailChallenges } from "@shared/schema";
import type { MfaEmailChallenge, InsertMfaEmailChallenge } from "@shared/schema";

export async function createMfaEmailChallenge(data: InsertMfaEmailChallenge): Promise<MfaEmailChallenge> {
  const [row] = await db.insert(mfaEmailChallenges).values(data).returning();
  return row;
}

export async function getActiveChallenges(userId: string): Promise<MfaEmailChallenge[]> {
  const now = new Date();
  return db
    .select()
    .from(mfaEmailChallenges)
    .where(and(
      eq(mfaEmailChallenges.userId, userId),
      isNull(mfaEmailChallenges.consumedAt),
      gt(mfaEmailChallenges.expiresAt, now),
    ));
}

export async function consumeChallenge(id: string): Promise<void> {
  await db
    .update(mfaEmailChallenges)
    .set({ consumedAt: new Date() })
    .where(eq(mfaEmailChallenges.id, id));
}

export async function countRecentChallenges(userId: string, sinceMs: number): Promise<number> {
  const since = new Date(Date.now() - sinceMs);
  const rows = await db
    .select({ id: mfaEmailChallenges.id })
    .from(mfaEmailChallenges)
    .where(and(
      eq(mfaEmailChallenges.userId, userId),
      gt(mfaEmailChallenges.createdAt, since),
    ));
  return rows.length;
}

export async function cleanupOldChallenges(userId: string): Promise<void> {
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
  await db
    .delete(mfaEmailChallenges)
    .where(and(
      eq(mfaEmailChallenges.userId, userId),
      or(
        lt(mfaEmailChallenges.expiresAt, cutoff),
        lt(mfaEmailChallenges.createdAt, cutoff),
      ),
    ));
}
