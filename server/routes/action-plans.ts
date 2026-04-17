import type { Express, Request, Response } from 'express';
import { isAuthenticatedWithPasswordCheck } from '../localAuth';
import { requireOperator } from './middleware';
import { z } from 'zod';
import { db } from '../db';
import { actionPlans, actionPlanThreats, actionPlanComments, actionPlanCommentThreats } from '@shared/schema';
import { eq, and, inArray } from 'drizzle-orm';
import { createLogger } from '../lib/logger';
import { listActionPlans } from '../storage/actionPlans';
import { getActionPlanById, getPlanThreats, getPlanComments, getPlanHistory } from '../storage/actionPlans';
import { generateNextActionPlanCode, recordHistory, applyStatusChange, removeThreatFromPlan } from '../services/actionPlanService';
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

const statusSchema = z.object({
  status: z.enum(['pending','in_progress','blocked','done','cancelled']),
  reason: z.string().min(3).max(2000).optional(),
});

export function registerActionPlanRoutes(app: Express): void {
  log.info('action plans route module registered');

  // C3: GET /api/v1/action-plans
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

  // C4: POST /api/v1/action-plans
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

  // C5: GET /api/v1/action-plans/:id
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

  // C6: PATCH /api/v1/action-plans/:id
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

  // C7: PATCH /api/v1/action-plans/:id/status
  app.patch('/api/v1/action-plans/:id/status', isAuthenticatedWithPasswordCheck, requireOperator, async (req, res) => {
    try {
      const planId = z.string().parse(req.params.id);
      const body = statusSchema.parse(req.body);
      const userId = (req.user as any).id as string;
      await assertEditable(planId, userId);

      const [before] = await db.select({ status: actionPlans.status }).from(actionPlans).where(eq(actionPlans.id, planId));
      if (!before) return res.status(404).json({ error: 'Plano não encontrado.' });

      await applyStatusChange({
        planId,
        actorId: userId,
        from: before.status as any,
        to: body.status,
        reason: body.reason,
      });

      res.json({ ok: true });
    } catch (err: any) {
      if (err instanceof z.ZodError) return res.status(400).json({ error: err.issues });
      log.error({ err, planId: req.params.id, to: req.body?.status }, 'status change failed');
      res.status(err.status ?? 500).json({ error: err.message ?? 'Erro ao mudar status.', code: err.code });
    }
  });

  // ── C8: Threats CRUD ────────────────────────────────────────────────────────

  const associateThreatsSchema = z.object({
    threatIds: z.array(z.string()).min(1).max(500),
  });

  // C8.1: POST /api/v1/action-plans/:id/threats
  app.post('/api/v1/action-plans/:id/threats', isAuthenticatedWithPasswordCheck, requireOperator, async (req, res) => {
    try {
      const planId = z.string().parse(req.params.id);
      const body = associateThreatsSchema.parse(req.body);
      const userId = (req.user as any).id as string;
      await assertEditable(planId, userId);

      await db.transaction(async (tx) => {
        await tx.insert(actionPlanThreats)
          .values(body.threatIds.map(tid => ({ actionPlanId: planId, threatId: tid, addedBy: userId })))
          .onConflictDoNothing();

        for (const tid of body.threatIds) {
          await recordHistory(tx as any, {
            actionPlanId: planId,
            actorId: userId,
            action: 'threat_added',
            detailsJson: { threatId: tid },
          });
        }
      });

      res.status(201).json({ ok: true });
    } catch (err: any) {
      if (err instanceof z.ZodError) return res.status(400).json({ error: err.issues });
      log.error({ err }, 'associate threats failed');
      res.status(err.status ?? 500).json({ error: err.message ?? 'Erro ao associar ameaças.' });
    }
  });

  // C8.2: DELETE /api/v1/action-plans/:id/threats/:threatId
  app.delete('/api/v1/action-plans/:id/threats/:threatId', isAuthenticatedWithPasswordCheck, requireOperator, async (req, res) => {
    try {
      const planId = z.string().parse(req.params.id);
      const threatId = z.string().parse(req.params.threatId);
      const userId = (req.user as any).id as string;
      await assertEditable(planId, userId);

      await removeThreatFromPlan({ planId, threatId, actorId: userId });
      res.json({ ok: true });
    } catch (err: any) {
      if (err instanceof z.ZodError) return res.status(400).json({ error: err.issues });
      log.error({ err }, 'remove threat failed');
      res.status(err.status ?? 500).json({ error: err.message ?? 'Erro ao remover ameaça do plano.' });
    }
  });

  // C8.3: GET /api/v1/action-plans/:id/threats
  app.get('/api/v1/action-plans/:id/threats', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const planId = z.string().parse(req.params.id);
      const rows = await getPlanThreats(planId);
      res.json(rows);
    } catch (err: any) {
      if (err instanceof z.ZodError) return res.status(400).json({ error: err.issues });
      log.error({ err }, 'list plan threats failed');
      res.status(err.status ?? 500).json({ error: err.message ?? 'Erro ao listar ameaças.' });
    }
  });

  // ── C9: Comments ────────────────────────────────────────────────────────────

  const createCommentSchema = z.object({
    content: z.string().min(1).max(100_000),
    threatIds: z.array(z.string()).optional(),
  });

  const editCommentSchema = z.object({
    content: z.string().min(1).max(100_000),
  });

  // C9.1: POST /api/v1/action-plans/:id/comments
  app.post('/api/v1/action-plans/:id/comments', isAuthenticatedWithPasswordCheck, requireOperator, async (req, res) => {
    try {
      const planId = z.string().parse(req.params.id);
      const body = createCommentSchema.parse(req.body);
      const userId = (req.user as any).id as string;

      if (body.threatIds && body.threatIds.length > 0) {
        const planThreats = await db.select({ threatId: actionPlanThreats.threatId })
          .from(actionPlanThreats)
          .where(and(
            eq(actionPlanThreats.actionPlanId, planId),
            inArray(actionPlanThreats.threatId, body.threatIds),
          ));
        const validIds = new Set(planThreats.map(r => r.threatId));
        const invalid = body.threatIds.filter(t => !validIds.has(t));
        if (invalid.length > 0) {
          return res.status(400).json({ error: 'Uma ou mais ameaças não pertencem a este plano.', invalidThreatIds: invalid });
        }
      }

      const comment = await db.transaction(async (tx) => {
        const [c] = await tx.insert(actionPlanComments).values({
          actionPlanId: planId,
          authorId: userId,
          content: sanitizeActionPlanHtml(body.content),
        }).returning();

        if (body.threatIds && body.threatIds.length > 0) {
          await tx.insert(actionPlanCommentThreats).values(
            body.threatIds.map(tid => ({ commentId: c.id, threatId: tid }))
          );
        }

        await recordHistory(tx as any, {
          actionPlanId: planId,
          actorId: userId,
          action: 'comment_added',
          detailsJson: { commentId: c.id, threatIds: body.threatIds ?? [] },
        });

        return c;
      });

      res.status(201).json(comment);
    } catch (err: any) {
      if (err instanceof z.ZodError) return res.status(400).json({ error: err.issues });
      log.error({ err }, 'create comment failed');
      res.status(err.status ?? 500).json({ error: err.message ?? 'Erro ao criar comentário.' });
    }
  });

  // C9.2: GET /api/v1/action-plans/:id/comments
  app.get('/api/v1/action-plans/:id/comments', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const planId = z.string().parse(req.params.id);
      const threatId = typeof req.query.threatId === 'string' ? req.query.threatId : undefined;
      const rows = await getPlanComments(planId, threatId);
      res.json(rows);
    } catch (err: any) {
      if (err instanceof z.ZodError) return res.status(400).json({ error: err.issues });
      log.error({ err }, 'list comments failed');
      res.status(err.status ?? 500).json({ error: err.message ?? 'Erro ao listar comentários.' });
    }
  });

  // C9.3: PATCH /api/v1/action-plans/:id/comments/:commentId
  app.patch('/api/v1/action-plans/:id/comments/:commentId', isAuthenticatedWithPasswordCheck, requireOperator, async (req, res) => {
    try {
      const planId = z.string().parse(req.params.id);
      const commentId = z.string().parse(req.params.commentId);
      const body = editCommentSchema.parse(req.body);
      const userId = (req.user as any).id as string;

      const [existing] = await db.select({ authorId: actionPlanComments.authorId, actionPlanId: actionPlanComments.actionPlanId })
        .from(actionPlanComments).where(eq(actionPlanComments.id, commentId));
      if (!existing) return res.status(404).json({ error: 'Comentário não encontrado.' });
      if (existing.actionPlanId !== planId) return res.status(404).json({ error: 'Comentário não pertence a este plano.' });
      if (existing.authorId !== userId) return res.status(403).json({ error: 'Apenas o autor pode editar este comentário.' });

      await db.transaction(async (tx) => {
        await tx.update(actionPlanComments).set({
          content: sanitizeActionPlanHtml(body.content),
          updatedAt: new Date(),
        }).where(eq(actionPlanComments.id, commentId));

        await recordHistory(tx as any, {
          actionPlanId: planId,
          actorId: userId,
          action: 'comment_edited',
          detailsJson: { commentId },
        });
      });

      res.json({ ok: true });
    } catch (err: any) {
      if (err instanceof z.ZodError) return res.status(400).json({ error: err.issues });
      log.error({ err }, 'edit comment failed');
      res.status(err.status ?? 500).json({ error: err.message ?? 'Erro ao editar comentário.' });
    }
  });

  // ── C10: History timeline ───────────────────────────────────────────────────

  // C10: GET /api/v1/action-plans/:id/history
  app.get('/api/v1/action-plans/:id/history', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const planId = z.string().parse(req.params.id);
      const rows = await getPlanHistory(planId);
      res.json(rows);
    } catch (err: any) {
      if (err instanceof z.ZodError) return res.status(400).json({ error: err.issues });
      log.error({ err }, 'list history failed');
      res.status(err.status ?? 500).json({ error: err.message ?? 'Erro ao listar histórico.' });
    }
  });
}
