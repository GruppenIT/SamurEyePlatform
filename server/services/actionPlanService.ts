import { db } from '../db';
import { actionPlans } from '@shared/schema';
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
