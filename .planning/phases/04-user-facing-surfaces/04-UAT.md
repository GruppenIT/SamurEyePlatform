---
status: complete
phase: 04-user-facing-surfaces
source: [04-01-SUMMARY.md, 04-02-SUMMARY.md, 04-03-SUMMARY.md, 04-04-SUMMARY.md]
started: 2026-03-17T12:00:00Z
updated: 2026-03-17T13:10:00Z
---

## Current Test

[testing complete]

## Tests

### 1. Parent/Child Threat Grouping
expected: Navigate to /threats. Parent threats appear in main table with expand controls. Expanding a parent reveals child threats nested inside. Standalone threats also appear in top-level table. Filters propagate to children.
result: pass

### 2. Remediation Preview on Parent Groups
expected: Each parent threat group on /threats shows a brief remediation preview below the title — first fix step truncated to ~80 chars and an effort badge (e.g., "minutes", "hours").
result: pass

### 3. Structured Threat Detail Dialog
expected: Clicking a threat opens a detail dialog with three sections: Problema (what's wrong), Impacto (business impact), Correcao (numbered fix steps + verification + references). Dialog header shows effort and role badges.
result: pass

### 4. Human-Readable Evidence Display
expected: In the threat detail dialog, evidence data displays as a labeled grid with Portuguese labels (e.g., "Porta", "Protocolo") — no raw JSON visible. Arrays show as bullet lists, nested objects as key:value pairs.
result: pass

### 5. Action Plan Page
expected: Navigate to /action-plan. Page shows prioritized remediation cards ranked by contextual score (highest first). Each card shows: threat title, severity badge, contextual score, what's wrong, first fix step preview, effort badge (color-coded), role badge, and projected score delta with arrow icon.
result: pass

### 6. Action Plan Filters
expected: On /action-plan, three filter dropdowns (effort, role, journey type) are visible. Selecting a filter value narrows the displayed cards. Selecting "all" resets the filter.
result: pass

### 7. Sidebar "Plano de Acao" Link
expected: In the sidebar under the "Inteligencia" group, a "Plano de Acao" entry with a ClipboardList icon appears between Ameacas and Relatorios. Clicking it navigates to /action-plan.
result: pass

### 8. Posture Score Hero
expected: On /postura (dashboard), the top section shows the current posture score in large bold text, color-coded by range. A delta arrow (green up / red down / gray minus) shows change vs previous snapshot. A small sparkline chart shows score trend over time. Below: total open, critical, and high threat counts.
result: issue
reported: "contraste muito ruim no sparkline. quase nao enxergo."
severity: cosmetic

### 9. Journey Coverage Grid
expected: On /postura, a 2-column grid of 4 cards appears — one per journey type (attack_surface, ad_security, edr_av, web_application). Each card shows: Portuguese label, icon, last run date (dd/MM/yyyy HH:mm or "Nunca executada"), status icon (green check / red X / gray circle), and open threat count badge.
result: pass

### 10. Top Actions Section
expected: On /postura, a "Top Actions" section shows up to 3 prioritized action cards from the action plan. Each card shows: title, what's wrong summary, fix preview, effort/role badges, and projected score delta in green.
result: pass

### 11. WebSocket Auto-Refresh
expected: While viewing /postura, when a background job completes (completed/failed/timeout), the dashboard data auto-refreshes without manual page reload — score, coverage, and top actions update.
result: skipped
reason: No background job available to trigger; requires running journey to validate

### 12. Journey Comparison Delta
expected: On /postura, a journey comparison section shows the delta between the two most recent posture snapshots: score change, open threat count change, critical and high count changes. Icons are color-coded (green=improved, red=worsened, gray=stable). If fewer than 2 snapshots exist, shows fallback message "execute pelo menos duas jornadas".
result: pass

## Summary

total: 12
passed: 10
issues: 1
pending: 0
skipped: 1

## Gaps

- truth: "Sparkline chart on posture hero has visible, readable contrast"
  status: failed
  reason: "User reported: contraste muito ruim no sparkline. quase nao enxergo."
  severity: cosmetic
  test: 8
  root_cause: ""
  artifacts: []
  missing: []
  debug_session: ""
