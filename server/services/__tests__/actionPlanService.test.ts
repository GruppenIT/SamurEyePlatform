import { describe, it, expect, beforeAll } from 'vitest';
import { db } from '../../db';
import { actionPlans, users } from '@shared/schema';
import { generateNextActionPlanCode } from '../actionPlanService';
import { sql } from 'drizzle-orm';

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
