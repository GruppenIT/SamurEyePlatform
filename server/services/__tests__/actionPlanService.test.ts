import { describe, it, expect, beforeAll } from 'vitest';
import { db } from '../../db';
import { actionPlans, users } from '@shared/schema';
import { generateNextActionPlanCode } from '../actionPlanService';
import { sql } from 'drizzle-orm';
import { validateStatusTransition, getAllowedTransitions } from '../actionPlanService';

// DESTRUCTIVE-TEST GUARD
// These tests TRUNCATE real tables. They only run when:
//   1. DATABASE_URL is set AND
//   2. ALLOW_DESTRUCTIVE_DB_TESTS=1 is explicitly set AND
//   3. NODE_ENV is not 'production'
// Running them against a shared DB will delete all action_plans data.
// Use a dedicated test DB via TEST_DATABASE_URL override in a future iteration.
const ALLOW_DESTRUCTIVE = process.env.ALLOW_DESTRUCTIVE_DB_TESTS === '1';
const hasDb = !!process.env.DATABASE_URL && ALLOW_DESTRUCTIVE;

function assertSafeForDestructiveTests() {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('Refusing to run destructive tests against NODE_ENV=production.');
  }
}

describe.skipIf(!hasDb)('generateNextActionPlanCode', () => {
  let userId: string;
  beforeAll(async () => {
    assertSafeForDestructiveTests();
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
  it('blocks invalid transitions from terminal states', () => {
    // done/cancelled can only reopen to pending or in_progress — not to blocked or back to done/cancelled
    expect(validateStatusTransition('done','blocked')).toMatchObject({ ok:false, code:'INVALID_TRANSITION' });
    expect(validateStatusTransition('done','cancelled')).toMatchObject({ ok:false, code:'INVALID_TRANSITION' });
    expect(validateStatusTransition('cancelled','blocked')).toMatchObject({ ok:false, code:'INVALID_TRANSITION' });
    expect(validateStatusTransition('cancelled','done')).toMatchObject({ ok:false, code:'INVALID_TRANSITION' });
  });
  it('requires reopen reason for done → pending/in_progress', () => {
    expect(validateStatusTransition('done','pending')).toMatchObject({ ok:false, code:'REASON_REQUIRED' });
    expect(validateStatusTransition('done','pending','reabrindo para complemento')).toEqual({ ok:true });
    expect(validateStatusTransition('done','in_progress','voltar a tratar')).toEqual({ ok:true });
  });
  it('requires reopen reason for cancelled → pending/in_progress', () => {
    expect(validateStatusTransition('cancelled','in_progress')).toMatchObject({ ok:false, code:'REASON_REQUIRED' });
    expect(validateStatusTransition('cancelled','in_progress','decidimos retomar')).toEqual({ ok:true });
    expect(validateStatusTransition('cancelled','pending','voltar para backlog')).toEqual({ ok:true });
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
    expect(getAllowedTransitions('pending').map(t => t.to)).toEqual(['in_progress','blocked','cancelled']);
    expect(getAllowedTransitions('done').map(t => t.to)).toEqual(['pending','in_progress']);
    expect(getAllowedTransitions('cancelled').map(t => t.to)).toEqual(['pending','in_progress']);
  });
});

import { applyStatusChange, removeThreatFromPlan } from '../actionPlanService';
import { actionPlanThreats, actionPlanComments, actionPlanCommentThreats, threats, actionPlanHistory } from '@shared/schema';
import { eq, and } from 'drizzle-orm';

describe.skipIf(!hasDb)('applyStatusChange and removeThreatFromPlan', () => {
  let userId: string;
  let planId: string;
  let threatId: string;

  beforeAll(async () => {
    assertSafeForDestructiveTests();
    await db.execute(sql`TRUNCATE action_plans CASCADE`);
    const [u] = await db.select().from(users).limit(1);
    userId = u.id;
    // Seed one threat (or pick existing)
    const existing = await db.select().from(threats).limit(1);
    if (existing.length > 0) {
      threatId = existing[0].id;
    } else {
      throw new Error('No threat in DB — seed one to run integration tests, or skip');
    }
  });

  it('applyStatusChange updates status + records history + clears blockReason when leaving blocked', async () => {
    const [p] = await db.insert(actionPlans).values({
      code: 'PA-TEST-0001', title: 'test plan', createdBy: userId, status: 'pending',
    }).returning();
    planId = p.id;

    await applyStatusChange({ planId, actorId: userId, from: 'pending', to: 'blocked', reason: 'Aguardando firewall' });
    let [row] = await db.select().from(actionPlans).where(eq(actionPlans.id, planId));
    expect(row.status).toBe('blocked');
    expect(row.blockReason).toBe('Aguardando firewall');

    await applyStatusChange({ planId, actorId: userId, from: 'blocked', to: 'in_progress', reason: 'unblocked' });
    [row] = await db.select().from(actionPlans).where(eq(actionPlans.id, planId));
    expect(row.status).toBe('in_progress');
    expect(row.blockReason).toBeNull();

    const history = await db.select().from(actionPlanHistory).where(eq(actionPlanHistory.actionPlanId, planId));
    expect(history.length).toBe(2);
    expect(history.every(h => h.action === 'status_changed')).toBe(true);
  });

  it('removeThreatFromPlan clears comment_threats for that threat while keeping the comment', async () => {
    const [p] = await db.insert(actionPlans).values({
      code: 'PA-TEST-0002', title: 'rm threat', createdBy: userId,
    }).returning();
    const planId2 = p.id;

    await db.insert(actionPlanThreats).values({ actionPlanId: planId2, threatId, addedBy: userId });

    const [c] = await db.insert(actionPlanComments).values({
      actionPlanId: planId2, authorId: userId, content: 'x',
    }).returning();
    await db.insert(actionPlanCommentThreats).values({ commentId: c.id, threatId });

    await removeThreatFromPlan({ planId: planId2, threatId, actorId: userId });

    const links = await db.select().from(actionPlanThreats).where(
      and(eq(actionPlanThreats.actionPlanId, planId2), eq(actionPlanThreats.threatId, threatId))
    );
    expect(links.length).toBe(0);

    const commentLinks = await db.select().from(actionPlanCommentThreats).where(
      and(eq(actionPlanCommentThreats.commentId, c.id), eq(actionPlanCommentThreats.threatId, threatId))
    );
    expect(commentLinks.length).toBe(0);

    // Comment itself still exists
    const [stillComment] = await db.select().from(actionPlanComments).where(eq(actionPlanComments.id, c.id));
    expect(stillComment).toBeTruthy();
  });
});
