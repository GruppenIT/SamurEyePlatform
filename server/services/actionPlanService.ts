import { db } from '../db';
import { actionPlans } from '@shared/schema';
import { and, desc, eq, inArray, like, sql } from 'drizzle-orm';

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
