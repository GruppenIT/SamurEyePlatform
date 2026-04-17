import type { Express, Request, Response } from 'express';
import { isAuthenticatedWithPasswordCheck } from '../localAuth';
import { requireOperator } from './middleware';
import { z } from 'zod';
import { db } from '../db';
import { actionPlans } from '@shared/schema';
import { eq } from 'drizzle-orm';
import { createLogger } from '../lib/logger';

const log = createLogger('routes:action-plans');

/** Throws 403 if the current user isn't the plan's creator or assignee. */
async function assertEditable(planId: string, userId: string): Promise<void> {
  const [row] = await db
    .select({ createdBy: actionPlans.createdBy, assigneeId: actionPlans.assigneeId })
    .from(actionPlans)
    .where(eq(actionPlans.id, planId));
  if (!row) throw Object.assign(new Error('Plano não encontrado.'), { status: 404 });
  if (row.createdBy !== userId && row.assigneeId !== userId) {
    throw Object.assign(
      new Error('Apenas o criador ou responsável pode editar este plano.'),
      { status: 403 }
    );
  }
}

export function registerActionPlanRoutes(app: Express): void {
  // Endpoints will be added in subsequent tasks (C3-C12).
  log.info('action plans route module registered (scaffold — no endpoints yet)');
}
