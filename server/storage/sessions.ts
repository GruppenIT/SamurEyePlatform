import { db } from "../db";
import {
  activeSessions,
  loginAttempts,
  users,
  type ActiveSession,
  type InsertActiveSession,
  type LoginAttempt,
  type User,
} from "@shared/schema";
import { eq, desc, sql } from "drizzle-orm";
import { getSetting, setSetting } from "./settings";

// Active session operations
export async function createActiveSession(session: InsertActiveSession): Promise<ActiveSession> {
  const [newSession] = await db.insert(activeSessions).values(session).returning();
  return newSession;
}

export async function getActiveSessionBySessionId(sessionId: string): Promise<ActiveSession | undefined> {
  const [session] = await db.select().from(activeSessions).where(eq(activeSessions.sessionId, sessionId));
  return session;
}

export async function getActiveSessionsByUserId(userId: string): Promise<ActiveSession[]> {
  return await db.select()
    .from(activeSessions)
    .where(eq(activeSessions.userId, userId))
    .orderBy(desc(activeSessions.lastActivity));
}

export async function updateActiveSessionLastActivity(sessionId: string): Promise<ActiveSession> {
  const [updated] = await db.update(activeSessions)
    .set({ lastActivity: new Date() })
    .where(eq(activeSessions.sessionId, sessionId))
    .returning();
  return updated;
}

export async function deleteActiveSession(sessionId: string): Promise<void> {
  await db.delete(activeSessions).where(eq(activeSessions.sessionId, sessionId));
}

export async function deleteActiveSessionsByUserId(userId: string): Promise<void> {
  await db.delete(activeSessions).where(eq(activeSessions.userId, userId));
}

export async function cleanupExpiredSessions(): Promise<void> {
  await db.delete(activeSessions).where(sql`${activeSessions.expiresAt} < NOW()`);
}

export async function getAllActiveSessions(limit: number = 100): Promise<(ActiveSession & { user: User })[]> {
  const sessions = await db.select({
    session: activeSessions,
    user: users,
  })
  .from(activeSessions)
  .innerJoin(users, eq(activeSessions.userId, users.id))
  .orderBy(desc(activeSessions.lastActivity))
  .limit(limit);

  return sessions.map(row => ({
    ...row.session,
    user: row.user,
  }));
}

// Login attempt operations (rate limiting)
export async function getLoginAttempt(identifier: string): Promise<LoginAttempt | undefined> {
  const [attempt] = await db.select()
    .from(loginAttempts)
    .where(eq(loginAttempts.identifier, identifier));
  return attempt;
}

export async function upsertLoginAttempt(identifier: string, increment: boolean): Promise<LoginAttempt> {
  const existing = await getLoginAttempt(identifier);

  if (existing) {
    const newAttempts = increment ? existing.attempts + 1 : existing.attempts;
    const [updated] = await db.update(loginAttempts)
      .set({
        attempts: newAttempts,
        lastAttempt: new Date(),
        blockedUntil: newAttempts >= 5 ? new Date(Date.now() + 15 * 60 * 1000) : null, // Block for 15 min after 5 attempts
      })
      .where(eq(loginAttempts.identifier, identifier))
      .returning();
    return updated;
  } else {
    const [newAttempt] = await db.insert(loginAttempts).values({
      identifier,
      attempts: 1,
      lastAttempt: new Date(),
    }).returning();
    return newAttempt;
  }
}

export async function resetLoginAttempts(identifier: string): Promise<void> {
  await db.delete(loginAttempts).where(eq(loginAttempts.identifier, identifier));
}

export async function cleanupOldLoginAttempts(): Promise<void> {
  // Clean up attempts older than 24 hours
  await db.delete(loginAttempts).where(sql`${loginAttempts.lastAttempt} < NOW() - INTERVAL '24 hours'`);
}

// Session version operations
export async function getCurrentSessionVersion(): Promise<number> {
  const setting = await getSetting('session_version');
  return setting ? (setting.value as number) : 1;
}

export async function incrementSessionVersion(userId: string): Promise<number> {
  const currentVersion = await getCurrentSessionVersion();
  const newVersion = currentVersion + 1;
  await setSetting('session_version', newVersion, userId);
  return newVersion;
}
