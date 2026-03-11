import { db } from "../db";
import {
  emailSettings,
  notificationPolicies,
  notificationLog,
  type EmailSettings,
  type NotificationPolicy,
  type InsertNotificationPolicy,
  type NotificationLog,
  type InsertNotificationLog,
} from "@shared/schema";
import { eq, desc } from "drizzle-orm";

// Email settings operations
export async function getEmailSettings(): Promise<EmailSettings | undefined> {
  const [settings] = await db.select().from(emailSettings).limit(1);
  return settings;
}

export async function setEmailSettings(settingsData: Omit<EmailSettings, 'id' | 'updatedAt'>, userId: string): Promise<EmailSettings> {
  const existing = await getEmailSettings();

  if (existing) {
    const [updated] = await db
      .update(emailSettings)
      .set({
        ...settingsData,
        updatedAt: new Date(),
        updatedBy: userId,
      })
      .where(eq(emailSettings.id, existing.id))
      .returning();
    return updated;
  }

  const [created] = await db
    .insert(emailSettings)
    .values({
      ...settingsData,
      updatedBy: userId,
    })
    .returning();
  return created;
}

// Notification policy operations
export async function getNotificationPolicies(): Promise<NotificationPolicy[]> {
  return await db
    .select()
    .from(notificationPolicies)
    .orderBy(notificationPolicies.createdAt);
}

export async function getNotificationPolicy(id: string): Promise<NotificationPolicy | undefined> {
  const [policy] = await db
    .select()
    .from(notificationPolicies)
    .where(eq(notificationPolicies.id, id));
  return policy;
}

export async function createNotificationPolicy(policy: InsertNotificationPolicy, userId: string): Promise<NotificationPolicy> {
  const [created] = await db
    .insert(notificationPolicies)
    .values({
      ...policy,
      createdBy: userId,
    })
    .returning();
  return created;
}

export async function updateNotificationPolicy(id: string, policy: Partial<InsertNotificationPolicy>): Promise<NotificationPolicy> {
  const [updated] = await db
    .update(notificationPolicies)
    .set({
      ...policy,
      updatedAt: new Date(),
    })
    .where(eq(notificationPolicies.id, id))
    .returning();
  return updated;
}

export async function deleteNotificationPolicy(id: string): Promise<void> {
  await db.delete(notificationPolicies).where(eq(notificationPolicies.id, id));
}

// Notification log operations
export async function createNotificationLog(logEntry: InsertNotificationLog): Promise<NotificationLog> {
  const [created] = await db
    .insert(notificationLog)
    .values([{
      ...logEntry,
      emailAddresses: Array.isArray(logEntry.emailAddresses) ? [...logEntry.emailAddresses] : [],
    }])
    .returning();
  return created;
}

export async function getNotificationLogs(limit = 100): Promise<NotificationLog[]> {
  return await db
    .select()
    .from(notificationLog)
    .orderBy(desc(notificationLog.sentAt))
    .limit(limit);
}
