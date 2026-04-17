import type { Express, Request, Response } from 'express';
import { isAuthenticatedWithPasswordCheck } from '../localAuth';
import { requireOperator } from './middleware';
import { z } from 'zod';
import { db } from '../db';
import { actionPlans } from '@shared/schema';
import { eq } from 'drizzle-orm';
import { createLogger } from '../lib/logger';
import { listActionPlans } from '../storage/actionPlans';

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

const listQuerySchema = z.object({
  status: z.string().optional().transform(s => s?.split(',').filter(Boolean)),
  priority: z.string().optional().transform(s => s?.split(',').filter(Boolean)),
  assigneeId: z.string().optional(),
  search: z.string().max(200).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(25),
  offset: z.coerce.number().int().min(0).default(0),
});

export function registerActionPlanRoutes(app: Express): void {
  log.info('action plans route module registered');

  app.get('/api/v1/action-plans', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const q = listQuerySchema.parse(req.query);
      const { rows, total } = await listActionPlans(q);
      res.json({ rows, total, limit: q.limit, offset: q.offset });
    } catch (err: any) {
      if (err instanceof z.ZodError) return res.status(400).json({ error: err.issues });
      log.error({ err }, 'list action plans failed');
      res.status(500).json({ error: 'Erro ao listar planos.' });
    }
  });
}
