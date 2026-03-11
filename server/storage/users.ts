import { db } from "../db";
import { users, type User, type UpsertUser } from "@shared/schema";
import { eq, desc } from "drizzle-orm";

export async function getUser(id: string): Promise<User | undefined> {
  const [user] = await db.select().from(users).where(eq(users.id, id));
  return user;
}

export async function upsertUser(userData: UpsertUser): Promise<User> {
  const [user] = await db
    .insert(users)
    .values(userData)
    .onConflictDoUpdate({
      target: users.email,
      set: {
        ...userData,
        updatedAt: new Date(),
      },
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
