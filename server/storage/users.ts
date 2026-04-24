import { db } from "../db";
import { users, type User, type UpsertUser } from "@shared/schema";
import { eq, desc } from "drizzle-orm";

export async function getUser(id: string): Promise<User | undefined> {
  const [user] = await db.select().from(users).where(eq(users.id, id));
  return user;
}

type UiPrefs = { theme?: 'light' | 'dark' | 'system'; sidebarCollapsed?: boolean };

export async function upsertUser(userData: UpsertUser): Promise<User> {
  const safe = {
    ...userData,
    uiPreferences: (userData.uiPreferences as UiPrefs | null | undefined),
  };
  const [user] = await db
    .insert(users)
    .values(safe)
    .onConflictDoUpdate({
      target: users.email,
      set: { ...safe, updatedAt: new Date() },
    })
    .returning();
  return user;
}

export async function getUserByEmail(email: string): Promise<User | undefined> {
  const [user] = await db.select().from(users).where(eq(users.email, email));
  return user;
}

export async function updateUserRole(id: string, role: string): Promise<User> {
  const [user] = await db
    .update(users)
    .set({ role: role as any, updatedAt: new Date() })
    .where(eq(users.id, id))
    .returning();
  return user;
}

export async function createUser(userData: { email: string; passwordHash: string; firstName: string; lastName: string; role?: string }): Promise<User> {
  const [user] = await db
    .insert(users)
    .values({
      email: userData.email,
      passwordHash: userData.passwordHash,
      firstName: userData.firstName,
      lastName: userData.lastName,
      role: (userData.role as any) || 'read_only',
    })
    .returning();
  return user;
}

export async function updateUserLastLogin(id: string): Promise<User> {
  const [user] = await db
    .update(users)
    .set({ lastLogin: new Date(), updatedAt: new Date() })
    .where(eq(users.id, id))
    .returning();
  return user;
}

export async function updateUserPassword(id: string, passwordHash: string): Promise<User> {
  const [user] = await db
    .update(users)
    .set({ passwordHash, updatedAt: new Date() })
    .where(eq(users.id, id))
    .returning();
  return user;
}

export async function setMustChangePassword(id: string, mustChange: boolean): Promise<User> {
  const [user] = await db
    .update(users)
    .set({ mustChangePassword: mustChange, updatedAt: new Date() })
    .where(eq(users.id, id))
    .returning();
  return user;
}

export async function getAllUsers(): Promise<User[]> {
  return await db.select().from(users).orderBy(desc(users.createdAt));
}

export async function getUserMfa(id: string): Promise<Pick<User, 'id' | 'email' | 'mfaEnabled' | 'mfaSecretEncrypted' | 'mfaSecretDek' | 'mfaBackupCodes' | 'mfaInvitationDismissed' | 'mfaEnabledAt'> | undefined> {
  const [row] = await db
    .select({
      id: users.id,
      email: users.email,
      mfaEnabled: users.mfaEnabled,
      mfaSecretEncrypted: users.mfaSecretEncrypted,
      mfaSecretDek: users.mfaSecretDek,
      mfaBackupCodes: users.mfaBackupCodes,
      mfaInvitationDismissed: users.mfaInvitationDismissed,
      mfaEnabledAt: users.mfaEnabledAt,
    })
    .from(users)
    .where(eq(users.id, id));
  return row;
}

export async function setUserMfa(
  id: string,
  data: {
    mfaEnabled: boolean;
    mfaSecretEncrypted: string | null;
    mfaSecretDek: string | null;
    mfaBackupCodes: string[] | null;
    mfaEnabledAt: Date | null;
  },
): Promise<void> {
  await db
    .update(users)
    .set({
      mfaEnabled: data.mfaEnabled,
      mfaSecretEncrypted: data.mfaSecretEncrypted,
      mfaSecretDek: data.mfaSecretDek,
      mfaBackupCodes: data.mfaBackupCodes,
      mfaEnabledAt: data.mfaEnabledAt,
      updatedAt: new Date(),
    })
    .where(eq(users.id, id));
}

export async function updateBackupCodes(id: string, codes: string[]): Promise<void> {
  await db
    .update(users)
    .set({ mfaBackupCodes: codes, updatedAt: new Date() })
    .where(eq(users.id, id));
}

export async function dismissMfaInvitation(id: string): Promise<void> {
  await db
    .update(users)
    .set({ mfaInvitationDismissed: true, updatedAt: new Date() })
    .where(eq(users.id, id));
}

export async function updateUserPreferences(
  id: string,
  prefs: { theme?: 'light' | 'dark' | 'system'; sidebarCollapsed?: boolean },
): Promise<void> {
  const [current] = await db.select({ uiPreferences: users.uiPreferences }).from(users).where(eq(users.id, id));
  type Prefs = { theme?: 'light' | 'dark' | 'system'; sidebarCollapsed?: boolean };
  const merged: Prefs = { ...(current?.uiPreferences as Prefs ?? {}), ...prefs };
  await db.update(users).set({ uiPreferences: merged, updatedAt: new Date() }).where(eq(users.id, id));
}

export async function getUserPreferences(id: string): Promise<{ theme?: 'light' | 'dark' | 'system'; sidebarCollapsed?: boolean } | null> {
  const [row] = await db.select({ uiPreferences: users.uiPreferences }).from(users).where(eq(users.id, id));
  return row?.uiPreferences ?? null;
}
