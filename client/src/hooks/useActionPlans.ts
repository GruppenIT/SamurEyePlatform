import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";

// ─── Types ───────────────────────────────────────────────────────────────────

export type ActionPlanStatus =
  | "pending"
  | "in_progress"
  | "blocked"
  | "done"
  | "cancelled";

export type ActionPlanPriority = "low" | "medium" | "high" | "critical";

export interface ActionPlanRef {
  id: string;
  name: string;
}

export interface ActionPlanListItem {
  id: string;
  code: string;
  title: string;
  status: ActionPlanStatus;
  priority: ActionPlanPriority;
  createdAt: string;
  updatedAt: string;
  blockReason: string | null;
  cancelReason: string | null;
  createdBy: ActionPlanRef | null;
  assignee: ActionPlanRef | null;
  threatCount: number;
}

export interface ActionPlanListResponse {
  rows: ActionPlanListItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface ActionPlanDetail extends ActionPlanListItem {
  description: string | null;
  threats?: ActionPlanThreatItem[];
  comments?: ActionPlanComment[];
  history?: ActionPlanHistoryEntry[];
}

export interface ActionPlanThreatItem {
  id: string;
  title: string;
  severity: string;
  status: string;
  hostId: string | null;
  addedAt: string;
  hasComments: boolean;
}

export interface ActionPlanComment {
  id: string;
  content: string;
  createdAt: string;
  updatedAt: string | null;
  author: ActionPlanRef | null;
  threats: { id: string; title: string; severity: string }[];
}

export interface ActionPlanHistoryEntry {
  id: string;
  action: string;
  detailsJson: Record<string, unknown> | null;
  createdAt: string;
  actor: ActionPlanRef | null;
}

export interface ActionPlanAssignee {
  id: string;
  name: string;
  email: string;
}

// Filter types for list query
export interface ActionPlanFilters {
  status?: ActionPlanStatus[] | ActionPlanStatus;
  priority?: ActionPlanPriority[] | ActionPlanPriority;
  assigneeId?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

// ─── Query key helpers ────────────────────────────────────────────────────────

const AP_KEYS = {
  list: (filters?: ActionPlanFilters) =>
    ["action-plans", "list", filters ?? {}] as const,
  detail: (id: string) => ["action-plans", id] as const,
  assignees: () => ["action-plans", "assignees"] as const,
  threats: (id: string) => ["action-plans", id, "threats"] as const,
  comments: (id: string, threatId?: string) =>
    ["action-plans", id, "comments", threatId ?? null] as const,
  history: (id: string) => ["action-plans", id, "history"] as const,
};

// ─── List & Detail ────────────────────────────────────────────────────────────

/**
 * Fetches paginated list of action plans, optionally filtered.
 */
export function useActionPlans(filters?: ActionPlanFilters) {
  const params = new URLSearchParams();
  if (filters) {
    Object.entries(filters).forEach(([k, v]) => {
      if (v !== undefined && v !== null) {
        const s = Array.isArray(v) ? v.join(',') : String(v);
        if (s.length > 0) params.append(k, s);
      }
    });
  }
  const qs = params.toString();
  const url = qs
    ? `/api/v1/action-plans?${qs}`
    : "/api/v1/action-plans";

  return useQuery<ActionPlanListResponse>({
    queryKey: AP_KEYS.list(filters),
    queryFn: async () => {
      const res = await fetch(url, { credentials: "include" });
      if (!res.ok) {
        const text = (await res.text()) || res.statusText;
        throw new Error(`${res.status}: ${text}`);
      }
      return res.json();
    },
    retry: false,
  });
}

/**
 * Fetches a single action plan by ID.
 * @param includes - comma-separated list of relations to include (e.g. "threats,comments")
 */
export function useActionPlan(id: string, includes?: string) {
  const qs = includes ? `?include=${encodeURIComponent(includes)}` : "";
  const url = `/api/v1/action-plans/${id}${qs}`;

  return useQuery<ActionPlanDetail>({
    queryKey: AP_KEYS.detail(id),
    queryFn: async () => {
      const res = await fetch(url, { credentials: "include" });
      if (!res.ok) {
        const text = (await res.text()) || res.statusText;
        throw new Error(`${res.status}: ${text}`);
      }
      return res.json();
    },
    enabled: !!id,
    retry: false,
  });
}

/**
 * Fetches the list of users that can be assigned to action plans.
 */
export function useActionPlanAssignees() {
  return useQuery<ActionPlanAssignee[]>({
    queryKey: AP_KEYS.assignees(),
    queryFn: async () => {
      const res = await fetch("/api/v1/action-plans/assignees", {
        credentials: "include",
      });
      if (!res.ok) {
        const text = (await res.text()) || res.statusText;
        throw new Error(`${res.status}: ${text}`);
      }
      return res.json();
    },
    retry: false,
  });
}

// ─── Threats sub-resource ─────────────────────────────────────────────────────

/**
 * Fetches threats associated with a given action plan.
 */
export function useActionPlanThreats(id: string) {
  return useQuery<ActionPlanThreatItem[]>({
    queryKey: AP_KEYS.threats(id),
    queryFn: async () => {
      const res = await fetch(`/api/v1/action-plans/${id}/threats`, {
        credentials: "include",
      });
      if (!res.ok) {
        const text = (await res.text()) || res.statusText;
        throw new Error(`${res.status}: ${text}`);
      }
      return res.json();
    },
    enabled: !!id,
    retry: false,
  });
}

// ─── Comments sub-resource ────────────────────────────────────────────────────

/**
 * Fetches comments for an action plan, optionally scoped to a specific threat.
 */
export function useActionPlanComments(id: string, threatId?: string) {
  const qs = threatId ? `?threatId=${encodeURIComponent(threatId)}` : "";
  const url = `/api/v1/action-plans/${id}/comments${qs}`;

  return useQuery<ActionPlanComment[]>({
    queryKey: AP_KEYS.comments(id, threatId),
    queryFn: async () => {
      const res = await fetch(url, { credentials: "include" });
      if (!res.ok) {
        const text = (await res.text()) || res.statusText;
        throw new Error(`${res.status}: ${text}`);
      }
      return res.json();
    },
    enabled: !!id,
    retry: false,
  });
}

// ─── History sub-resource ─────────────────────────────────────────────────────

/**
 * Fetches the change history for an action plan.
 */
export function useActionPlanHistory(id: string) {
  return useQuery<ActionPlanHistoryEntry[]>({
    queryKey: AP_KEYS.history(id),
    queryFn: async () => {
      const res = await fetch(`/api/v1/action-plans/${id}/history`, {
        credentials: "include",
      });
      if (!res.ok) {
        const text = (await res.text()) || res.statusText;
        throw new Error(`${res.status}: ${text}`);
      }
      return res.json();
    },
    enabled: !!id,
    retry: false,
  });
}

// ─── Create / Update mutations ────────────────────────────────────────────────

export interface CreateActionPlanInput {
  title: string;
  description?: string;
  priority?: ActionPlanPriority;
  assigneeId?: string | null;
  threatIds?: string[];
}

/**
 * Creates a new action plan.
 * Invalidates: ['action-plans', 'list']
 */
export function useCreateActionPlan() {
  const queryClient = useQueryClient();

  return useMutation<ActionPlanDetail, Error, CreateActionPlanInput>({
    mutationFn: async (data) => {
      const res = await apiRequest("POST", "/api/v1/action-plans", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["action-plans", "list"] });
    },
  });
}

export interface UpdateActionPlanInput {
  id: string;
  data: {
    title?: string;
    description?: string | null;
    priority?: ActionPlanPriority;
    assigneeId?: string | null;
  };
}

/**
 * Updates fields on an existing action plan.
 * Invalidates: ['action-plans', id] + ['action-plans', 'list']
 */
export function useUpdateActionPlan() {
  const queryClient = useQueryClient();

  return useMutation<ActionPlanDetail, Error, UpdateActionPlanInput>({
    mutationFn: async ({ id, data }) => {
      const res = await apiRequest("PATCH", `/api/v1/action-plans/${id}`, data);
      return res.json();
    },
    onSuccess: (_result, { id }) => {
      queryClient.invalidateQueries({ queryKey: ["action-plans", id] });
      queryClient.invalidateQueries({ queryKey: ["action-plans", "list"] });
    },
  });
}

export interface ChangeActionPlanStatusInput {
  id: string;
  status: ActionPlanStatus;
  reason?: string;
}

/**
 * Changes the status of an action plan (includes reason fields for blocked/cancelled).
 * Invalidates: ['action-plans', id] + ['action-plans', 'list'] + history
 */
export function useChangeActionPlanStatus() {
  const queryClient = useQueryClient();

  return useMutation<ActionPlanDetail, Error, ChangeActionPlanStatusInput>({
    mutationFn: async ({ id, ...data }) => {
      const res = await apiRequest(
        "PATCH",
        `/api/v1/action-plans/${id}/status`,
        data,
      );
      return res.json();
    },
    onSuccess: (_result, { id }) => {
      queryClient.invalidateQueries({ queryKey: ["action-plans", id] });
      queryClient.invalidateQueries({ queryKey: ["action-plans", "list"] });
      queryClient.invalidateQueries({
        queryKey: ["action-plans", id, "history"],
      });
    },
  });
}

// ─── Threat association mutations ─────────────────────────────────────────────

export interface AssociateThreatsInput {
  id: string;
  threatIds: string[];
}

/**
 * Associates one or more threats with an action plan.
 * Invalidates: threats + history + detail (for threatCount)
 */
export function useAssociateThreats() {
  const queryClient = useQueryClient();

  return useMutation<unknown, Error, AssociateThreatsInput>({
    mutationFn: async ({ id, threatIds }) => {
      const res = await apiRequest(
        "POST",
        `/api/v1/action-plans/${id}/threats`,
        { threatIds },
      );
      return res.json();
    },
    onSuccess: (_result, { id }) => {
      queryClient.invalidateQueries({
        queryKey: ["action-plans", id, "threats"],
      });
      queryClient.invalidateQueries({
        queryKey: ["action-plans", id, "history"],
      });
      queryClient.invalidateQueries({ queryKey: ["action-plans", id] });
      queryClient.invalidateQueries({ queryKey: ["action-plans", "plan-links"] });
    },
  });
}

export interface RemoveThreatInput {
  id: string;
  threatId: string;
}

/**
 * Removes a threat association from an action plan.
 * Invalidates: threats + history + detail + comments (threat-scoped ones may be gone)
 */
export function useRemoveThreat() {
  const queryClient = useQueryClient();

  return useMutation<unknown, Error, RemoveThreatInput>({
    mutationFn: async ({ id, threatId }) => {
      const res = await apiRequest(
        "DELETE",
        `/api/v1/action-plans/${id}/threats/${threatId}`,
      );
      // DELETE may return 204 with no body
      if (res.status === 204) return null;
      return res.json();
    },
    onSuccess: (_result, { id }) => {
      queryClient.invalidateQueries({
        queryKey: ["action-plans", id, "threats"],
      });
      queryClient.invalidateQueries({
        queryKey: ["action-plans", id, "history"],
      });
      queryClient.invalidateQueries({ queryKey: ["action-plans", id] });
      // Invalidate ALL comment variants for this plan (prefix match)
      queryClient.invalidateQueries({
        queryKey: ["action-plans", id, "comments"],
      });
      queryClient.invalidateQueries({ queryKey: ["action-plans", "plan-links"] });
    },
  });
}

// ─── Comment mutations ────────────────────────────────────────────────────────

export interface CreateCommentInput {
  id: string;
  content: string;
  threatIds?: string[];
}

/**
 * Posts a new comment on an action plan.
 * Invalidates all comment variants (prefix match) + history.
 */
export function useCreateComment() {
  const queryClient = useQueryClient();

  return useMutation<ActionPlanComment, Error, CreateCommentInput>({
    mutationFn: async ({ id, content, threatIds }) => {
      const res = await apiRequest(
        "POST",
        `/api/v1/action-plans/${id}/comments`,
        { content, ...(threatIds ? { threatIds } : {}) },
      );
      return res.json();
    },
    onSuccess: (_result, { id }) => {
      // Prefix invalidation covers all threatId variants
      queryClient.invalidateQueries({
        queryKey: ["action-plans", id, "comments"],
      });
      queryClient.invalidateQueries({
        queryKey: ["action-plans", id, "history"],
      });
    },
  });
}

export interface UpdateCommentInput {
  id: string;
  commentId: string;
  content: string;
}

/**
 * Edits an existing comment on an action plan.
 * Invalidates all comment variants + history.
 */
export function useUpdateComment() {
  const queryClient = useQueryClient();

  return useMutation<ActionPlanComment, Error, UpdateCommentInput>({
    mutationFn: async ({ id, commentId, content }) => {
      const res = await apiRequest(
        "PATCH",
        `/api/v1/action-plans/${id}/comments/${commentId}`,
        { content },
      );
      return res.json();
    },
    onSuccess: (_result, { id }) => {
      queryClient.invalidateQueries({
        queryKey: ["action-plans", id, "comments"],
      });
      queryClient.invalidateQueries({
        queryKey: ["action-plans", id, "history"],
      });
    },
  });
}

// ─── Plan Links (threat→plan bulk lookup) ────────────────────────────────────

export interface PlanLink {
  id: string;
  code: string;
  title: string;
  status: ActionPlanStatus;
}

/**
 * Bulk lookup: for a list of threat IDs, returns the plans each threat belongs to.
 * Uses POST /api/v1/action-plans/plan-links (body instead of query string for large lists).
 */
export function usePlanLinks(threatIds: string[]) {
  const stableIds = [...threatIds].sort().join(',');
  return useQuery<Record<string, PlanLink[]>>({
    queryKey: ['action-plans', 'plan-links', stableIds],
    enabled: threatIds.length > 0,
    queryFn: async () => {
      const res = await fetch('/api/v1/action-plans/plan-links', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threatIds }),
      });
      if (!res.ok) throw new Error('Erro ao buscar ligações com planos.');
      return res.json();
    },
  });
}

// ─── Upload helper (plain async function — not a hook) ────────────────────────

/**
 * Uploads an image for use inside action plan rich-text descriptions.
 * Call directly from editor paste/drop handlers — not a hook.
 */
export async function uploadActionPlanImage(
  file: File | Blob,
): Promise<{ url: string }> {
  const fd = new FormData();
  fd.append("image", file);
  const res = await fetch("/api/v1/action-plans/upload-image", {
    method: "POST",
    credentials: "include",
    body: fd,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Upload falhou" }));
    throw new Error(err.error ?? "Upload falhou");
  }
  return res.json();
}
