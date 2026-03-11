import { db } from "../db";
import {
  applianceSubscription,
  applianceCommands,
  type ApplianceSubscription,
  type ApplianceCommand,
  type ConsoleCommand,
} from "@shared/schema";
import { eq, and, or, inArray } from "drizzle-orm";
import * as crypto from "crypto";

export async function getSubscription(): Promise<ApplianceSubscription | undefined> {
  const [sub] = await db.select().from(applianceSubscription).limit(1);
  return sub;
}

export async function upsertSubscription(data: Partial<Omit<ApplianceSubscription, 'id'>>, userId?: string): Promise<ApplianceSubscription> {
  const existing = await getSubscription();

  if (existing) {
    const [updated] = await db
      .update(applianceSubscription)
      .set({
        ...data,
        updatedAt: new Date(),
        ...(userId ? { updatedBy: userId } : {}),
      })
      .where(eq(applianceSubscription.id, existing.id))
      .returning();
    return updated;
  }

  // First time: generate appliance ID
  const applianceId = data.applianceId || crypto.randomUUID();
  const [created] = await db
    .insert(applianceSubscription)
    .values({
      applianceId,
      ...data,
      ...(userId ? { updatedBy: userId } : {}),
    })
    .returning();
  return created;
}

export async function updateHeartbeatSuccess(consoleResponse: {
  active: boolean;
  plan: string;
  expiresAt: string | null;
  features: string[];
  tenantId?: string;
  tenantName?: string;
  planSlug?: string;
  maxAppliances?: number;
  isTrial?: boolean;
  durationDays?: number | null;
  message?: string | null;
}): Promise<ApplianceSubscription> {
  const isActive = consoleResponse.active;
  const expiresAt = consoleResponse.expiresAt ? new Date(consoleResponse.expiresAt) : null;
  const now = new Date();
  const isExpired = expiresAt ? expiresAt < now : false;

  let status: 'active' | 'expired';
  if (!isActive) {
    status = 'expired';
  } else {
    status = isExpired ? 'expired' : 'active';
  }

  return upsertSubscription({
    status,
    tenantId: consoleResponse.tenantId,
    tenantName: consoleResponse.tenantName,
    plan: consoleResponse.plan,
    planSlug: consoleResponse.planSlug ?? null,
    maxAppliances: consoleResponse.maxAppliances ?? null,
    isTrial: consoleResponse.isTrial ?? false,
    durationDays: consoleResponse.durationDays ?? null,
    consoleMessage: consoleResponse.message ?? null,
    expiresAt,
    features: consoleResponse.features,
    lastHeartbeatAt: now,
    lastHeartbeatError: null,
    consecutiveFailures: 0,
    graceDeadline: null,
  });
}

export async function updateHeartbeatFailure(error: string): Promise<ApplianceSubscription> {
  const existing = await getSubscription();
  const failures = (existing?.consecutiveFailures || 0) + 1;
  const now = new Date();

  // Set grace deadline on first failure (72h from now)
  let graceDeadline = existing?.graceDeadline;
  let status = existing?.status || 'not_configured' as const;

  if (failures === 1 && !graceDeadline) {
    graceDeadline = new Date(now.getTime() + 72 * 60 * 60 * 1000); // 72h
  }

  // Check if grace period has expired
  if (graceDeadline && now > graceDeadline && status === 'active') {
    status = 'unreachable';
  } else if (status === 'active') {
    status = 'grace_period';
  }

  return upsertSubscription({
    consecutiveFailures: failures,
    lastHeartbeatError: error,
    graceDeadline,
    status,
  });
}

// Appliance Commands
export async function saveReceivedCommands(commands: ConsoleCommand[]): Promise<void> {
  for (const cmd of commands) {
    // Dedup: skip if already received
    const [existing] = await db.select({ id: applianceCommands.id })
      .from(applianceCommands).where(eq(applianceCommands.id, cmd.id)).limit(1);
    if (existing) continue;

    await db.insert(applianceCommands).values({
      id: cmd.id,
      type: cmd.type,
      params: cmd.params || {},
      status: 'pending',
      receivedAt: new Date(),
      reportedToConsole: false,
    });
  }
}

export async function getPendingCommands(): Promise<ApplianceCommand[]> {
  return db.select().from(applianceCommands)
    .where(eq(applianceCommands.status, 'pending'))
    .orderBy(applianceCommands.receivedAt);
}

export async function updateCommandStatus(
  id: string,
  status: 'running' | 'completed' | 'failed',
  extra?: { result?: Record<string, any>; error?: string },
): Promise<void> {
  const now = new Date();
  await db.update(applianceCommands)
    .set({
      status,
      ...(status === 'running' ? { startedAt: now } : {}),
      ...(status === 'completed' || status === 'failed' ? { finishedAt: now } : {}),
      ...(extra?.result ? { result: extra.result } : {}),
      ...(extra?.error ? { error: extra.error } : {}),
    })
    .where(eq(applianceCommands.id, id));
}

export async function getUnreportedCommandResults(): Promise<ApplianceCommand[]> {
  return db.select().from(applianceCommands)
    .where(
      and(
        eq(applianceCommands.reportedToConsole, false),
        or(
          eq(applianceCommands.status, 'running'),
          eq(applianceCommands.status, 'completed'),
          eq(applianceCommands.status, 'failed'),
        ),
      ),
    );
}

export async function markCommandsReported(ids: string[]): Promise<void> {
  if (ids.length === 0) return;
  await db.update(applianceCommands)
    .set({ reportedToConsole: true })
    .where(inArray(applianceCommands.id, ids));
}
