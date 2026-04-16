import { db } from "../db";
import { and, eq, gt, isNull, lt } from "drizzle-orm";
import { passwordResetTokens } from "@shared/schema";
import type { PasswordResetToken, InsertPasswordResetToken } from "@shared/schema";

export async function createPasswordResetToken(data: InsertPasswordResetToken): Promise<PasswordResetToken> {
  const [row] = await db.insert(passwordResetTokens).values(data).returning();
  return row;
}

export async function getActivePasswordResetTokens(): Promise<PasswordResetToken[]> {
  const now = new Date();
  return db
    .select()
    .from(passwordResetTokens)
    .where(and(
      isNull(passwordResetTokens.consumedAt),
      gt(passwordResetTokens.expiresAt, now),
    ));
}

export async function consumePasswordResetToken(id: string): Promise<void> {
  await db
    .update(passwordResetTokens)
    .set({ consumedAt: new Date() })
    .where(eq(passwordResetTokens.id, id));
}

export async function consumeAllPasswordResetTokensForUser(userId: string): Promise<void> {
  await db
    .update(passwordResetTokens)
    .set({ consumedAt: new Date() })
    .where(and(
      eq(passwordResetTokens.userId, userId),
      isNull(passwordResetTokens.consumedAt),
    ));
}

export async function cleanupOldPasswordResetTokens(userId: string): Promise<void> {
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
  await db
    .delete(passwordResetTokens)
    .where(and(
      eq(passwordResetTokens.userId, userId),
      lt(passwordResetTokens.createdAt, cutoff),
    ));
}
