import type { Express, Request, Response } from 'express';
import { isAuthenticatedWithPasswordCheck } from '../localAuth';
import { requireOperator } from './middleware';
import { z } from 'zod';
import { db } from '../db';
import { actionPlans, actionPlanThreats } from '@shared/schema';
import { eq } from 'drizzle-orm';
import { createLogger } from '../lib/logger';
import { listActionPlans, getActionPlanById, getPlanThreats, getPlanComments, getPlanHistory } from '../storage/actionPlans';
import { generateNextActionPlanCode, recordHistory } from '../services/actionPlanService';
import { sanitizeActionPlanHtml } from '../lib/htmlSanitizer';

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

const createSchema = z.object({
  title: z.string().min(1).max(255),
  description: z.string().max(100_000).optional(),
  priority: z.enum(['low','medium','high','critical']).default('medium'),
  assigneeId: z.string().nullable().optional(),
  threatIds: z.array(z.string()).optional(),
});

const patchSchema = z.object({
  title: z.string().min(1).max(255).optional(),
  description: z.string().max(100_000).nullable().optional(),
  priority: z.enum(['low','medium','high','critical']).optional(),
  assigneeId: z.string().nullable().optional(),
}).refine(v => Object.keys(v).length > 0, 'Ao menos um campo obrigatório.');

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

  app.post('/api/v1/action-plans', isAuthenticatedWithPasswordCheck, requireOperator, async (req, res) => {
    try {
      const body = createSchema.parse(req.body);
      const userId = (req.user as any).id as string;

      const result = await db.transaction(async (tx) => {
        const code = await generateNextActionPlanCode(tx as any);
        const [plan] = await tx.insert(actionPlans).values({
          code,
          title: body.title,
          description: body.description ? sanitizeActionPlanHtml(body.description) : null,
          priority: body.priority,
          assigneeId: body.assigneeId ?? null,
          createdBy: userId,
        }).returning();

        if (body.threatIds?.length) {
          await tx.insert(actionPlanThreats).values(
            body.threatIds.map(tid => ({ actionPlanId: plan.id, threatId: tid, addedBy: userId }))
          );
        }

        await recordHistory(tx, {
          actionPlanId: plan.id,
          actorId: userId,
          action: 'created',
          detailsJson: { code, threatIds: body.threatIds ?? [] },
        });

        return plan;
      });

      res.status(201).json(result);
    } catch (err: any) {
      if (err instanceof z.ZodError) return res.status(400).json({ error: err.issues });
      log.error({ err }, 'create plan failed');
      res.status(err.status ?? 500).json({ error: err.message ?? 'Erro ao criar plano.' });
    }
  });

  app.get('/api/v1/action-plans/:id', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const planId = z.string().parse(req.params.id);
      const includeParam = typeof req.query.include === 'string' ? req.query.include : '';
      const include = new Set(includeParam.split(',').filter(Boolean));

      const plan = await getActionPlanById(planId);
      if (!plan) return res.status(404).json({ error: 'Plano não encontrado.' });

      const out: any = { ...plan };
      if (include.has('threats')) out.threats = await getPlanThreats(planId);
      if (include.has('comments')) out.comments = await getPlanComments(planId);
      if (include.has('history')) out.history = await getPlanHistory(planId);

      res.json(out);
    } catch (err: any) {
      if (err instanceof z.ZodError) return res.status(400).json({ error: err.issues });
      log.error({ err }, 'get plan failed');
      res.status(err.status ?? 500).json({ error: err.message ?? 'Erro ao buscar plano.' });
    }
  });

  app.patch('/api/v1/action-plans/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req, res) => {
    try {
      const planId = z.string().parse(req.params.id);
      const body = patchSchema.parse(req.body);
      const userId = (req.user as any).id as string;
      await assertEditable(planId, userId);

      await db.transaction(async (tx) => {
        const [before] = await tx.select().from(actionPlans).where(eq(actionPlans.id, planId));
        if (!before) throw Object.assign(new Error('Plano não encontrado.'), { status: 404 });

        const patch: Record<string, unknown> = { updatedAt: new Date() };
        if (body.title !== undefined) patch.title = body.title;
        if (body.description !== undefined) {
          patch.description = body.description === null ? null : sanitizeActionPlanHtml(body.description);
        }
        if (body.priority !== undefined) patch.priority = body.priority;
        if (body.assigneeId !== undefined) patch.assigneeId = body.assigneeId;

        await tx.update(actionPlans).set(patch).where(eq(actionPlans.id, planId));

        if (body.title !== undefined && body.title !== before.title) {
          await recordHistory(tx, { actionPlanId: planId, actorId: userId, action: 'title_changed', detailsJson: { from: before.title, to: body.title } });
        }
        if (body.description !== undefined) {
          await recordHistory(tx, { actionPlanId: planId, actorId: userId, action: 'description_changed' });
        }
        if (body.priority !== undefined && body.priority !== before.priority) {
          await recordHistory(tx, { actionPlanId: planId, actorId: userId, action: 'priority_changed', detailsJson: { from: before.priority, to: body.priority } });
        }
        if (body.assigneeId !== undefined && body.assigneeId !== before.assigneeId) {
          await recordHistory(tx, { actionPlanId: planId, actorId: userId, action: 'assignee_changed', detailsJson: { from: before.assigneeId, to: body.assigneeId } });
        }
      });

      res.json({ ok: true });
    } catch (err: any) {
      if (err instanceof z.ZodError) return res.status(400).json({ error: err.issues });
      log.error({ err }, 'patch plan failed');
      res.status(err.status ?? 500).json({ error: err.message ?? 'Erro ao atualizar plano.' });
    }
  });
}
