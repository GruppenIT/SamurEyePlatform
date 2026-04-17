import { db } from '../db';
import { actionPlans, actionPlanHistory, actionPlanThreats, actionPlanCommentThreats, actionPlanComments } from '@shared/schema';
import type { ActionPlanHistoryAction } from '@shared/schema';
import { and, desc, eq, inArray, like, sql } from 'drizzle-orm';

export type ActionPlanStatus = 'pending'|'in_progress'|'blocked'|'done'|'cancelled';

export interface StatusTransition {
  from: ActionPlanStatus;
  to: ActionPlanStatus;
  requiresReason: 'block'|'cancel'|'unblock'|null;
}

export const STATUS_TRANSITIONS: StatusTransition[] = [
  { from:'pending',     to:'in_progress', requiresReason:null },
  { from:'pending',     to:'blocked',     requiresReason:'block' },
  { from:'pending',     to:'cancelled',   requiresReason:'cancel' },
  { from:'in_progress', to:'blocked',     requiresReason:'block' },
  { from:'in_progress', to:'done',        requiresReason:null },
  { from:'in_progress', to:'cancelled',   requiresReason:'cancel' },
  { from:'blocked',     to:'pending',     requiresReason:'unblock' },
  { from:'blocked',     to:'in_progress', requiresReason:'unblock' },
  { from:'blocked',     to:'cancelled',   requiresReason:'cancel' },
];

export function getAllowedTransitions(from: ActionPlanStatus) {
  return STATUS_TRANSITIONS.filter(t => t.from === from);
}

export type ValidationResult =
  | { ok: true }
  | { ok: false; message: string; code: 'INVALID_TRANSITION'|'REASON_REQUIRED' };

export function validateStatusTransition(
  from: ActionPlanStatus,
  to: ActionPlanStatus,
  reason?: string
): ValidationResult {
  const t = STATUS_TRANSITIONS.find(x => x.from === from && x.to === to);
  if (!t) return { ok:false, code:'INVALID_TRANSITION', message:`Transição ${from}→${to} não permitida.` };
  if (t.requiresReason && (!reason || reason.trim().length < 3)) {
    return { ok:false, code:'REASON_REQUIRED', message:`Justificativa obrigatória para esta transição.` };
  }
  return { ok:true };
}

/**
 * Generates the next PA-YYYY-NNNN code under an advisory lock to prevent races.
 * MUST be called inside a transaction (pass the tx). Lock releases at transaction end.
 */
export async function generateNextActionPlanCode(tx: typeof db = db): Promise<string> {
  const year = new Date().getFullYear();
  const prefix = `PA-${year}-`;
  const lockKey = BigInt(`0xAC71${year}`);
  await tx.execute(sql`SELECT pg_advisory_xact_lock(${lockKey})`);
  const rows = await tx
    .select({ code: actionPlans.code })
    .from(actionPlans)
    .where(like(actionPlans.code, `${prefix}%`))
    .orderBy(desc(actionPlans.code))
    .limit(1);
  const lastN = rows[0]?.code ? parseInt(rows[0].code.slice(prefix.length), 10) : 0;
  const next = String(lastN + 1).padStart(4, '0');
  return `${prefix}${next}`;
}

type Tx = Parameters<Parameters<typeof db.transaction>[0]>[0];

export async function recordHistory(tx: Tx, params: {
  actionPlanId: string;
  actorId: string;
  action: ActionPlanHistoryAction;
  detailsJson?: unknown;
}) {
  await tx.insert(actionPlanHistory).values({
    actionPlanId: params.actionPlanId,
    actorId: params.actorId,
    action: params.action,
    detailsJson: (params.detailsJson ?? null) as any,
  });
}

export async function applyStatusChange(params: {
  planId: string;
  actorId: string;
  from: ActionPlanStatus;
  to: ActionPlanStatus;
  reason?: string;
}) {
  return db.transaction(async (tx) => {
    const v = validateStatusTransition(params.from, params.to, params.reason);
    if (!v.ok) throw Object.assign(new Error(v.message), { status: 422, code: v.code });

    const patch: Record<string, unknown> = {
      status: params.to,
      updatedAt: new Date(),
    };
    if (params.to === 'blocked') patch.blockReason = params.reason ?? null;
    else patch.blockReason = null;
    if (params.to === 'cancelled') patch.cancelReason = params.reason ?? null;

    await tx.update(actionPlans).set(patch).where(eq(actionPlans.id, params.planId));
    await recordHistory(tx, {
      actionPlanId: params.planId,
      actorId: params.actorId,
      action: 'status_changed',
      detailsJson: { from: params.from, to: params.to, reason: params.reason ?? null },
    });
  });
}

export async function removeThreatFromPlan(params: { planId: string; threatId: string; actorId: string; }) {
  return db.transaction(async (tx) => {
    const commentIds = (await tx.select({ id: actionPlanComments.id })
      .from(actionPlanComments).where(eq(actionPlanComments.actionPlanId, params.planId)))
      .map(r => r.id);

    if (commentIds.length > 0) {
      await tx.delete(actionPlanCommentThreats)
        .where(and(
          inArray(actionPlanCommentThreats.commentId, commentIds),
          eq(actionPlanCommentThreats.threatId, params.threatId),
        ));
    }

    await tx.delete(actionPlanThreats).where(and(
      eq(actionPlanThreats.actionPlanId, params.planId),
      eq(actionPlanThreats.threatId, params.threatId),
    ));

    await recordHistory(tx, {
      actionPlanId: params.planId,
      actorId: params.actorId,
      action: 'threat_removed',
      detailsJson: { threatId: params.threatId },
    });
  });
}
