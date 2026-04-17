import { describe, it, expect, beforeAll } from 'vitest';
import { db } from '../../db';
import { actionPlans, users } from '@shared/schema';
import { generateNextActionPlanCode } from '../actionPlanService';
import { sql } from 'drizzle-orm';
import { validateStatusTransition, getAllowedTransitions } from '../actionPlanService';

const hasDb = !!process.env.DATABASE_URL;

describe.skipIf(!hasDb)('generateNextActionPlanCode', () => {
  let userId: string;
  beforeAll(async () => {
    await db.execute(sql`TRUNCATE action_plans CASCADE`);
    const [u] = await db.select().from(users).limit(1);
    if (!u) throw new Error('No user in DB for test');
    userId = u.id;
  });

  it('generates PA-YYYY-0001 on empty table', async () => {
    const code = await db.transaction(async (tx) => generateNextActionPlanCode(tx));
    expect(code).toMatch(/^PA-\d{4}-0001$/);
  });

  it('generates unique codes under concurrent transactions', async () => {
    await db.execute(sql`TRUNCATE action_plans CASCADE`);
    const results = await Promise.all(
      Array.from({ length: 5 }).map(async () =>
        db.transaction(async (tx) => {
          const code = await generateNextActionPlanCode(tx);
          await tx.insert(actionPlans).values({
            code, title: 't', createdBy: userId,
          });
          return code;
        })
      )
    );
    expect(new Set(results).size).toBe(5);
  });
});

describe('validateStatusTransition', () => {
  it('blocks done → anything', () => {
    const r = validateStatusTransition('done','pending');
    expect(r).toMatchObject({ ok:false, code:'INVALID_TRANSITION' });
  });
  it('blocks cancelled → anything', () => {
    expect(validateStatusTransition('cancelled','in_progress')).toMatchObject({ ok:false });
  });
  it('requires reason for pending → blocked', () => {
    expect(validateStatusTransition('pending','blocked')).toMatchObject({ ok:false, code:'REASON_REQUIRED' });
    expect(validateStatusTransition('pending','blocked','Aguardando firewall')).toEqual({ ok:true });
  });
  it('allows pending → in_progress without reason', () => {
    expect(validateStatusTransition('pending','in_progress')).toEqual({ ok:true });
  });
  it('requires unblock reason for blocked → pending', () => {
    expect(validateStatusTransition('blocked','pending')).toMatchObject({ ok:false, code:'REASON_REQUIRED' });
    expect(validateStatusTransition('blocked','pending','desbloqueado manualmente')).toEqual({ ok:true });
  });
  it('getAllowedTransitions returns only transitions from the given state', () => {
    const from = getAllowedTransitions('pending');
    expect(from.map(t => t.to)).toEqual(['in_progress','blocked','cancelled']);
  });
});
