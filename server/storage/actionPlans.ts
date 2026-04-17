import { db } from '../db';
import {
  actionPlans,
  actionPlanThreats,
  actionPlanComments,
  actionPlanCommentThreats,
  actionPlanHistory,
  users,
  threats,
} from '@shared/schema';
import { alias } from 'drizzle-orm/pg-core';
import { and, asc, desc, eq, ilike, inArray, or, sql } from 'drizzle-orm';

/**
 * Build a SQL fragment that returns a resolved name for a user alias:
 * "First Last" if both names present, else email.
 */
function userNameExpr(u: ReturnType<typeof alias<typeof users, string>>) {
  return sql<string>`coalesce(nullif(trim(concat_ws(' ', ${u.firstName}, ${u.lastName})), ''), ${u.email})`;
}

export interface ListActionPlansFilters {
  status?: string[];
  priority?: string[];
  assigneeId?: string;
  search?: string;
  limit: number;
  offset: number;
}

export async function listActionPlans(filters: ListActionPlansFilters) {
  const creator = alias(users, 'creator');
  const assignee = alias(users, 'assignee');
  const conds = [];
  if (filters.status?.length) conds.push(inArray(actionPlans.status, filters.status as any));
  if (filters.priority?.length) conds.push(inArray(actionPlans.priority, filters.priority as any));
  if (filters.assigneeId) conds.push(eq(actionPlans.assigneeId, filters.assigneeId));
  if (filters.search) {
    const like = `%${filters.search}%`;
    conds.push(or(ilike(actionPlans.title, like), ilike(actionPlans.code, like))!);
  }
  const whereClause = conds.length ? and(...conds) : undefined;

  const rows = await db
    .select({
      id: actionPlans.id,
      code: actionPlans.code,
      title: actionPlans.title,
      status: actionPlans.status,
      priority: actionPlans.priority,
      createdAt: actionPlans.createdAt,
      updatedAt: actionPlans.updatedAt,
      blockReason: actionPlans.blockReason,
      cancelReason: actionPlans.cancelReason,
      creatorId: creator.id,
      creatorName: userNameExpr(creator),
      assigneeId: assignee.id,
      assigneeName: userNameExpr(assignee),
      threatCount: sql<number>`(select count(*)::int from action_plan_threats apt where apt.action_plan_id = ${actionPlans.id})`,
    })
    .from(actionPlans)
    .leftJoin(creator, eq(creator.id, actionPlans.createdBy))
    .leftJoin(assignee, eq(assignee.id, actionPlans.assigneeId))
    .where(whereClause)
    .orderBy(desc(actionPlans.updatedAt))
    .limit(filters.limit)
    .offset(filters.offset);

  const [{ total }] = await db
    .select({ total: sql<number>`count(*)::int` })
    .from(actionPlans)
    .where(whereClause);

  // Shape rows to { ..., createdBy: {id,name}, assignee: {id,name}|null }
  const shaped = rows.map(r => ({
    id: r.id,
    code: r.code,
    title: r.title,
    status: r.status,
    priority: r.priority,
    createdAt: r.createdAt,
    updatedAt: r.updatedAt,
    blockReason: r.blockReason,
    cancelReason: r.cancelReason,
    createdBy: r.creatorId ? { id: r.creatorId, name: r.creatorName } : null,
    assignee: r.assigneeId ? { id: r.assigneeId, name: r.assigneeName } : null,
    threatCount: r.threatCount,
  }));
  return { rows: shaped, total };
}

export async function getActionPlanById(planId: string) {
  const creator = alias(users, 'creator');
  const assignee = alias(users, 'assignee');
  const rows = await db
    .select({
      id: actionPlans.id,
      code: actionPlans.code,
      title: actionPlans.title,
      description: actionPlans.description,
      status: actionPlans.status,
      priority: actionPlans.priority,
      createdAt: actionPlans.createdAt,
      updatedAt: actionPlans.updatedAt,
      blockReason: actionPlans.blockReason,
      cancelReason: actionPlans.cancelReason,
      createdById: actionPlans.createdBy,
      assigneeId: actionPlans.assigneeId,
      creatorId: creator.id,
      creatorName: userNameExpr(creator),
      assigneeName: userNameExpr(assignee),
    })
    .from(actionPlans)
    .leftJoin(creator, eq(creator.id, actionPlans.createdBy))
    .leftJoin(assignee, eq(assignee.id, actionPlans.assigneeId))
    .where(eq(actionPlans.id, planId))
    .limit(1);
  if (rows.length === 0) return null;
  const r = rows[0];
  return {
    id: r.id,
    code: r.code,
    title: r.title,
    description: r.description,
    status: r.status,
    priority: r.priority,
    createdAt: r.createdAt,
    updatedAt: r.updatedAt,
    blockReason: r.blockReason,
    cancelReason: r.cancelReason,
    createdBy: r.creatorId ? { id: r.creatorId, name: r.creatorName } : null,
    assignee: r.assigneeId ? { id: r.assigneeId, name: r.assigneeName } : null,
  };
}

export async function getPlanThreats(planId: string) {
  return db
    .select({
      id: threats.id,
      title: threats.title,
      severity: threats.severity,
      status: threats.status,
      hostId: threats.hostId,
      addedAt: actionPlanThreats.addedAt,
      hasComments: sql<boolean>`exists (
        select 1 from action_plan_comment_threats apct
        inner join action_plan_comments apc on apc.id = apct.comment_id
        where apc.action_plan_id = ${planId} and apct.threat_id = ${threats.id}
      )`,
    })
    .from(actionPlanThreats)
    .innerJoin(threats, eq(threats.id, actionPlanThreats.threatId))
    .where(eq(actionPlanThreats.actionPlanId, planId))
    .orderBy(desc(actionPlanThreats.addedAt));
}

export async function getPlanComments(planId: string, threatIdFilter?: string) {
  const author = alias(users, 'author');
  const commentsQuery = db
    .select({
      id: actionPlanComments.id,
      content: actionPlanComments.content,
      createdAt: actionPlanComments.createdAt,
      updatedAt: actionPlanComments.updatedAt,
      authorId: actionPlanComments.authorId,
      authorName: userNameExpr(author),
    })
    .from(actionPlanComments)
    .leftJoin(author, eq(author.id, actionPlanComments.authorId))
    .where(eq(actionPlanComments.actionPlanId, planId))
    .orderBy(desc(actionPlanComments.createdAt));

  // If filtering by threat, intersect with comment_threats
  const commentRows = threatIdFilter
    ? await db
        .select({
          id: actionPlanComments.id,
          content: actionPlanComments.content,
          createdAt: actionPlanComments.createdAt,
          updatedAt: actionPlanComments.updatedAt,
          authorId: actionPlanComments.authorId,
          authorName: userNameExpr(author),
        })
        .from(actionPlanComments)
        .leftJoin(author, eq(author.id, actionPlanComments.authorId))
        .innerJoin(actionPlanCommentThreats, eq(actionPlanCommentThreats.commentId, actionPlanComments.id))
        .where(and(
          eq(actionPlanComments.actionPlanId, planId),
          eq(actionPlanCommentThreats.threatId, threatIdFilter),
        ))
        .orderBy(desc(actionPlanComments.createdAt))
    : await commentsQuery;

  if (commentRows.length === 0) return [];

  // Fetch all threats attached to these comments in one query
  const commentIds = commentRows.map(c => c.id);
  const attachments = await db
    .select({
      commentId: actionPlanCommentThreats.commentId,
      threatId: threats.id,
      threatTitle: threats.title,
      threatSeverity: threats.severity,
    })
    .from(actionPlanCommentThreats)
    .innerJoin(threats, eq(threats.id, actionPlanCommentThreats.threatId))
    .where(inArray(actionPlanCommentThreats.commentId, commentIds));

  const threatsByComment = new Map<string, { id: string; title: string; severity: string }[]>();
  for (const a of attachments) {
    const list = threatsByComment.get(a.commentId) ?? [];
    list.push({ id: a.threatId, title: a.threatTitle, severity: a.threatSeverity });
    threatsByComment.set(a.commentId, list);
  }

  return commentRows.map(c => ({
    id: c.id,
    content: c.content,
    createdAt: c.createdAt,
    updatedAt: c.updatedAt,
    author: c.authorId ? { id: c.authorId, name: c.authorName } : null,
    threats: threatsByComment.get(c.id) ?? [],
  }));
}

export async function getPlanHistory(planId: string) {
  const actor = alias(users, 'actor');
  const rows = await db
    .select({
      id: actionPlanHistory.id,
      action: actionPlanHistory.action,
      detailsJson: actionPlanHistory.detailsJson,
      createdAt: actionPlanHistory.createdAt,
      actorId: actor.id,
      actorName: userNameExpr(actor),
    })
    .from(actionPlanHistory)
    .leftJoin(actor, eq(actor.id, actionPlanHistory.actorId))
    .where(eq(actionPlanHistory.actionPlanId, planId))
    .orderBy(desc(actionPlanHistory.createdAt));

  return rows.map(r => ({
    id: r.id,
    action: r.action,
    detailsJson: r.detailsJson,
    createdAt: r.createdAt,
    actor: r.actorId ? { id: r.actorId, name: r.actorName } : null,
  }));
}
