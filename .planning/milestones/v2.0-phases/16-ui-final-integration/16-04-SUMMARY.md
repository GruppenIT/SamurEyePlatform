---
phase: 16-ui-final-integration
plan: "04"
subsystem: client-ui
tags: [react, threats-page, owasp, curl, false-positive, ui-testing]
dependency_graph:
  requires: ["16-01", "16-02"]
  provides: ["UI-03", "UI-04", "UI-05"]
  affects: ["client/src/pages/threats.tsx"]
tech_stack:
  added: []
  patterns:
    - "Radix AlertDialog for confirmation flows"
    - "IIFE pattern for conditional Dialog content (avoids unnecessary renders)"
    - "Radix JSDOM polyfill pattern (hasPointerCapture, scrollIntoView, ResizeObserver)"
    - "url.includes() mock differentiation for multi-endpoint fetch tests"
key_files:
  created: []
  modified:
    - client/src/pages/threats.tsx
    - tests/ui/findings-owasp-filter.test.tsx
    - tests/ui/curl-reproduction.test.tsx
    - tests/ui/false-positive-marking.test.tsx
decisions:
  - "Added React default import to threats.tsx — required for OwaspBadge JSX function in vitest jsdom env (previously worked in Vite due to automatic JSX transform, jsdom requires explicit React)"
  - "Clipboard mock must be set AFTER dialog is open (before setupAndOpenCurlDialog call causes window.navigator to reinitialize in JSDOM)"
  - "Toast DOM assertions not possible without Toaster in renderWithProviders — verified via mutation side-effects (opacity-50 class) instead of toast text; documented as E2E boundary"
  - "url.includes() dispatch in fetch mocks differentiates GET /api/threats from PATCH /api/v1/api-findings — prevents threats.filter() crash on non-array refetch response"
  - "sourceFilter state delegates filtering to backend via ?source=api_security query param — no client-side source filtering"
metrics:
  duration: "~28 minutes"
  completed_date: "2026-04-20"
  tasks: 2
  files: 4
---

# Phase 16 Plan 04: Threats Page API Security Extensions Summary

threats.tsx extended with sourceFilter Select + conditional OWASP column via getOwaspBadgeInfo + Reproduzir Dialog using buildCurlCommand + Falso Positivo AlertDialog + PATCH mutation; 22 UI tests green across 3 files.

## Tasks Completed

### Task 1: Extend threats.tsx with source filter + OWASP column + Reproduzir Dialog + Falso Positivo AlertDialog

**Scope:** 224 lines added to `client/src/pages/threats.tsx` (2170 → 2394 lines)

**Imports added:**
- `Terminal`, `ShieldOff` from lucide-react
- `AlertDialog`, `AlertDialogAction`, `AlertDialogCancel`, `AlertDialogContent`, `AlertDialogDescription`, `AlertDialogFooter`, `AlertDialogHeader`, `AlertDialogTitle` from `@/components/ui/alert-dialog`
- `buildCurlCommand` from `@shared/ui/curlBuilder`
- `getOwaspBadgeInfo` from `@shared/ui/owaspBadge`
- `React` default import (added for OwaspBadge JSX compatibility in jsdom)

**State added:**
- `sourceFilter: "all" | "api_security"` — drives query param + column visibility
- `curlDialogThreat: Threat | null` — controls Reproduzir Dialog
- `falsePositiveAlertThreat: Threat | null` — controls Falso Positivo AlertDialog
- `falsePositiveIds: Set<string>` — tracks locally confirmed false positives for visual feedback

**Key behaviors:**
- `useQuery` updated: `queryKey: ["/api/threats", { source: sourceFilter }]` + custom `queryFn` adding `?source=api_security` query param — delegates filtering to backend, no client-side source filter
- `OwaspBadge` inline component renders `info.codigo` (e.g. "API1:2023") with severity color + tooltip `info.titulo`; falls back to gray N/A badge when `getOwaspBadgeInfo` returns null
- `falsePositiveMutation` mirrors `changeStatusMutation` pattern: PATCH `/api/v1/api-findings/${findingId}` + onSuccess toast + invalidateQueries + local state update
- Reproduzir Dialog guards against `***` artifacts (defensive, `buildCurlCommand` already prevents real tokens)
- renderThreatRow and renderParentGroup both conditionally render OWASP cell + action buttons when `sourceFilter === 'api_security'`

**TypeScript:** 0 errors in `client/src/pages/threats.tsx` (pre-existing errors in server files untouched)

### Task 2: Promote UI-03/04/05 test stubs to real assertions

**Test files promoted:**

| File | it.todo before | it() after | All pass |
|------|---------------|-----------|---------|
| findings-owasp-filter.test.tsx | 7 | 7 | Yes |
| curl-reproduction.test.tsx | 7 | 7 | Yes |
| false-positive-marking.test.tsx | 7 | 8 | Yes |

**Total: 22 tests green**

## Tricky Mocking Decisions

### 1. Radix UI JSDOM polyfills
Radix Select and Dialog require browser APIs absent in JSDOM:
- `Element.prototype.hasPointerCapture` — polyfilled to `() => false`
- `Element.prototype.setPointerCapture` / `releasePointerCapture` — polyfilled as no-ops
- `Element.prototype.scrollIntoView` — polyfilled as no-op (required by Radix Select dropdown)
- `global.ResizeObserver` — polyfilled as no-op class

Without these, Select click interactions fail with `TypeError` at the Radix internals level.

### 2. navigator.clipboard mock ordering
`navigator.clipboard` must be mocked AFTER the dialog opens. Setting it before `setupAndOpenCurlDialog` (which calls `renderWithProviders`) causes JSDOM to reinitialize, losing the mock. Correct pattern:
```js
await setupAndOpenCurlDialog(threats);
const btn = await screen.findByTestId('button-copy-curl');
(window as any).navigator = { ...window.navigator, clipboard: { writeText } };
fireEvent.click(btn); // fireEvent bypasses pointer-events:none overlay
```

### 3. fireEvent vs userEvent inside dialogs
Radix Dialog sets `body { pointer-events: none }` while open. `userEvent.click` respects CSS pointer events (blocks); `fireEvent.click` dispatches native DOM events (bypasses CSS). All button clicks INSIDE the Dialog use `fireEvent.click`.

### 4. Toast DOM assertion deferred
`<Toaster>` is only mounted in `App.tsx`, not in `renderWithProviders`. Toast text ("Finding marcado como falso positivo", "Copiado") cannot be queried from DOM in test env. Strategy:
- curl tests: verify `writeText` was called + content contains `curl` (writeText is the precondition for toast)
- false-positive tests: verify `opacity-50` class applied (side effect of onSuccess callback) + PATCH call verified via fetch mock

### 5. fetch mock differentiation for mutations + refetch
After `falsePositiveMutation` succeeds, `queryClient.invalidateQueries` triggers a refetch of `/api/threats`. If the fetch mock returns `{}` for ALL subsequent calls, `threats.filter()` crashes (object is not an array). Fix:
```js
vi.fn().mockImplementation((url: string) => {
  if (url.includes('/api/v1/api-findings/')) return { ok: true, json: async () => ({}) };
  return { ok: true, json: async () => [threat] };
});
```

### 6. AssociateToPlanDialog mock
threats.tsx imports `AssociateToPlanDialog` which internally calls `useAssociateThreats`. The mock covers:
- `@/components/action-plan/AssociateToPlanDialog` → `AssociateToPlanDialog: () => null`
- `@/hooks/useActionPlans` → all hooks mocked (usePlanLinks, useActionPlans, useAssociateThreats, useCreateActionPlan, useUpdateActionPlan)

## sourceFilter Backend Delegation Confirmation

The `sourceFilter` state is passed to the backend via URL query parameter, not filtered client-side:
```typescript
const { data: threats = [], isLoading } = useQuery<(Threat & { host?: Host })[]>({
  queryKey: ["/api/threats", { source: sourceFilter }],
  queryFn: async () => {
    const qs = sourceFilter !== "all" ? `?source=${encodeURIComponent(sourceFilter)}` : "";
    const res = await fetch(`/api/threats${qs}`, { credentials: "include" });
    ...
  },
});
```

Test verification (UI-03 test 6): `fetchMock.mock.calls` checked to contain a call with `url.includes('source=api_security')`.

## Parent Group Rendering Note

The `renderParentGroup` function required the same modifications as `renderThreatRow`:
- Conditional OWASP `<TableCell>` before the Acoes cell
- Conditional Reproduzir + Falso Positivo buttons in the Acoes cell

No unexpected interactions — the parent group row structure mirrors the standalone row structure for the new columns. Children (rendered via `renderThreatRow` inside `CollapsibleContent`) inherit the same conditional rendering through the closure over `sourceFilter` and `falsePositiveIds`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing critical import] Added React default import to threats.tsx**
- **Found during:** Task 2 (first test run)
- **Issue:** OwaspBadge function component uses JSX. Vite's automatic JSX transform handles this in production, but vitest jsdom requires explicit `React` in scope for class component pattern
- **Fix:** Added `import React, { ... } from "react"` replacing `import { ... } from "react"`
- **Files modified:** client/src/pages/threats.tsx
- **Commit:** 10e9c61

## Self-Check: PASSED

- client/src/pages/threats.tsx: FOUND (2394 lines)
- tests/ui/findings-owasp-filter.test.tsx: FOUND (7 it() tests, all pass)
- tests/ui/curl-reproduction.test.tsx: FOUND (7 it() tests, all pass)
- tests/ui/false-positive-marking.test.tsx: FOUND (8 it() tests, all pass)
- Commits: 7bf0d20 (Task 1), 10e9c61 (Task 2) — both present in git log
