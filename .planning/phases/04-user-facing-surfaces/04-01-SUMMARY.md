---
phase: 04-user-facing-surfaces
plan: "01"
subsystem: client-ui
tags: [threats, collapsible, grouping, evidence, recommendation, dialog]
dependency_graph:
  requires:
    - 03-02-PLAN.md  # recommendations engine + /api/threats/:id/recommendation endpoint
  provides:
    - Redesigned threats page with parent/child grouping (UIFN-03)
    - Structured threat detail dialog: Problema/Impacto/Correcao (UIFN-01)
    - Human-readable evidence display with Portuguese labels (UIFN-02)
    - Remediation preview on each parent threat group (UIFN-04)
  affects:
    - client/src/pages/threats.tsx
tech_stack:
  added: []
  patterns:
    - Radix Collapsible for expandable threat groups
    - Lazy useQuery with enabled flag for per-threat recommendation fetch
    - Client-side useMemo grouping: parents / childMap / standalone
    - dl/dt/dd grid for evidence key-value display (no JSON.stringify)
key_files:
  created: []
  modified:
    - client/src/pages/threats.tsx
decisions:
  - Filters applied to parents with child propagation: parent shown if any child matches filter
  - Evidence keys skipped from generic table: stdout, command (handled separately as AD-specific sections)
  - RemediationPreview fetched for all visible parents (v1 acceptable; typically 5-15 groups)
  - JSON.stringify removed from all rendered JSX; only present in code comments
metrics:
  duration: ~25min
  completed: "2026-03-16"
  tasks_completed: 1
  files_modified: 1
---

# Phase 4 Plan 1: Threats Page Redesign Summary

**One-liner:** Rewrote threats.tsx with Radix Collapsible parent/child grouping, lazy recommendation fetches for preview and dialog, and EVIDENCE_LABELS-driven dl/dt/dd evidence display replacing all JSON.stringify output.

## What Was Built

### UIFN-03: Parent/Child Threat Grouping

Client-side `useMemo` partitions the flat `/api/threats` response into three buckets:
- `parents`: `groupingKey !== null AND parentThreatId === null`
- `childMap`: Map indexed by `parentThreatId`
- `standalone`: both null

Only parents and standalone threats render in the top-level table. Children appear inside their parent's `CollapsibleContent`. Filters propagate: a parent is shown if it directly matches OR if any child matches the active filters.

### UIFN-04: Remediation Preview on Parent Groups

`RemediationPreview` component makes a lazy `useQuery` call to `/api/threats/:id/recommendation` (staleTime 60s) for each visible parent. Shows `fixSteps[0]` truncated to 80 chars + `effortTag` Badge inline below the threat title.

### UIFN-01: Structured Threat Detail Dialog

Replaced the flat description block with three explicit sections:
1. **Problema** — `recommendation.whatIsWrong` or `threat.description` as fallback
2. **Impacto** — `recommendation.businessImpact` or "Impacto nao avaliado" as fallback
3. **Correcao** — `recommendation.fixSteps[]` as numbered list + `verificationStep` + `references[]`

Dialog header shows `effortTag` and `roleRequired` Badges from the recommendation.

### UIFN-02: Human-Readable Evidence Display

`EVIDENCE_LABELS` constant maps 20+ JSONB keys to Portuguese display labels. `EvidenceTable` component renders entries as a `dl` CSS grid (2 cols), `dt` for label, `dd` for value. `renderEvidenceValue` handles arrays (bulleted), nested objects (key:value concatenation), primitives — never calls `JSON.stringify`. AD-specific fields (testId, command, stdout-parsed table) still get their dedicated sections; generic keys flow through `EvidenceTable`.

## Preserved Functionality

- Severity and status tile filters (click to toggle)
- Search, severity, status, host filter dropdowns
- Bulk select + bulk status change modal
- Individual status change modal with justification + hibernation date
- CSV export
- Status history in detail dialog
- All `data-testid` attributes for existing test IDs

## Deviations from Plan

None - plan executed exactly as written.

## Self-Check

### Files Exist
- `client/src/pages/threats.tsx` — FOUND (rewritten, 700+ lines)

### TypeScript
- No errors in `threats.tsx` when running `npx tsc --noEmit`
- Pre-existing errors in sidebar.tsx, assets.tsx, server/replitAuth.ts, cveService.ts, jobQueue.ts are unrelated to this plan

### No JSON.stringify in Rendered Output
- Grep confirms `JSON.stringify` appears only in comments, not JSX

## Self-Check: PASSED
