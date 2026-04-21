---
phase: 16-ui-final-integration
plan: "05"
subsystem: ui-wizard
tags:
  - ui
  - wizard
  - api-security
  - ui-06
  - safe-03
  - safe-04
  - safe-01
  - react-hook-form
  - zod
dependency_graph:
  requires:
    - 16-01  # estimateRequests shared helper
    - 16-03  # api-discovery.tsx page (insertion point for button)
    - 15-04  # executeApiSecurity + POST /api/v1/jobs/:id/abort pattern
    - 15-02  # authorizationAck schema column + journeyTypeEnum 'api_security'
    - 15-03  # MAX_API_RATE_LIMIT=50 constant
  provides:
    - ApiSecurityWizard 4-step Dialog component
    - POST /api/v1/jobs route for api_security type
    - UI-06 requirement fully satisfied
  affects:
    - client/src/components/forms/api-security-wizard.tsx
    - client/src/pages/api-discovery.tsx
    - server/routes/jobs.ts
    - tests/ui/journey-wizard.test.tsx
    - tests/routes/jobs-api-security.test.ts
tech_stack:
  added: []
  patterns:
    - 4-step wizard Dialog with useState step counter
    - react-hook-form + zodResolver + Controller for multi-step form
    - useMutation (TanStack Query) for POST /api/v1/jobs
    - queryData pre-population in tests (avoids fetch mocking)
    - __none__ sentinel for Radix Select empty-value workaround
    - explicit React import for jsdom compatibility
key_files:
  created:
    - client/src/components/forms/api-security-wizard.tsx  # 586 lines — 4-step wizard
  modified:
    - client/src/pages/api-discovery.tsx   # wizardOpen state + Nova Jornada API button
    - server/routes/jobs.ts                # POST /api/v1/jobs route (api_security)
    - tests/ui/journey-wizard.test.tsx     # 14 it.todo → 12 real it() passing
    - tests/routes/jobs-api-security.test.ts  # 7 it.todo → 7 real it() passing
decisions:
  - "POST /api/v1/jobs added to server/routes/jobs.ts (was missing — Phase 15 only delivered abort route). Wizard cannot function without a create endpoint. Rule 3 auto-add."
  - "Criar nova credencial button shows toast directing user to /credentials page (not nested Dialog). Inline Dialog nesting deemed too complex per plan deviation allowance — documented."
  - "estimateRequests endpointCount fallback=100 when no assets selected or no API linked to selected assets. Documented as plan-specified behavior."
  - "Radix Select rejects empty-string value — used __none__ sentinel for no-credential placeholder option (Rule 1 bug fix)."
  - "Explicit React import added to api-security-wizard.tsx — required for jsdom vitest environment. Consistent with Phase 16 STATE.md decision."
  - "queryData pre-population pattern used in wizard test (not fetch mock) — consistent with other Phase 16 UI tests."
metrics:
  duration_seconds: 460
  completed_date: "2026-04-20"
  tasks_completed: 2
  files_modified: 5
  tests_added: 19
  tests_total_phase16: 90
---

# Phase 16 Plan 05: ApiSecurityWizard UI-06 Summary

**One-liner:** 4-step wizard Dialog (`api-security-wizard.tsx`, 586 lines) for `api_security` journeys — Zod validation enforces `authorizationAck` (SAFE-04), `rateLimit` 1-50 (SAFE-01), CONTEXT.md defaults; wired via `POST /api/v1/jobs` route; 12 UI + 7 route tests GREEN.

## What Was Built

### ApiSecurityWizard Component (`client/src/components/forms/api-security-wizard.tsx`)

586-line Dialog-based 4-step wizard for creating `api_security` journeys:

- **Step 1 (Alvos):** nome input (min 1 char required) + asset multi-select Checkbox list from `/api/assets` + targetBaseUrl optional. "Próximo" disabled until both name and ≥1 asset selected.
- **Step 2 (Autenticação):** credentialId Select from `/api/v1/api-credentials` + "Criar nova credencial" button (shows toast → /credentials page, deviation documented) + authorizationAck Checkbox with red label (SAFE-04). "Próximo" disabled until authorizationAck=true.
- **Step 3 (Configuração):** 3 Discovery toggles + 7 Testing toggles (CONTEXT.md locked defaults: specFirst=ON, crawler=ON, kiterunner=OFF, misconfigs=ON, auth=ON, bola=OFF, bfla=OFF, bopla=OFF, rateLimitTest=ON, ssrf=OFF) + rateLimit Input[type=number] min=1 max=50 default=10 + destructiveEnabled Checkbox with red warning banner (SAFE-03) + estimateRequests Badge (`~N requests estimados`, reactive).
- **Step 4 (Confirmação):** Read-only `<dl>` summary of all fields + dryRun Checkbox + "Criar Jornada" button.

**Submit payload** (exact match for Phase 15 backend contract):
```json
{
  "type": "api_security",
  "name": "...",
  "params": {
    "assetIds": ["..."],
    "authorizationAck": true,
    "apiSecurityConfig": {
      "discovery": { "specFirst": true, "crawler": true, "kiterunner": false },
      "testing": { "misconfigs": true, "auth": true, "bola": false, "bfla": false, "bopla": false, "rateLimit": true, "ssrf": false },
      "rateLimit": 10,
      "destructiveEnabled": false,
      "dryRun": false
    }
  }
}
```

### api-discovery.tsx Changes

- Added `wizardOpen` state + `Nova Jornada API` Button (`data-testid="button-new-journey"`) in CardHeader.
- Mounted `<ApiSecurityWizard open={wizardOpen} onOpenChange={setWizardOpen} />` adjacent to Sheet.

### POST /api/v1/jobs Route (`server/routes/jobs.ts`)

New endpoint that was missing (Phase 15 only delivered `/api/v1/jobs/:id/abort`):

1. Validates body with Zod (`createApiSecurityJobSchema`)
2. Rejects `authorizationAck=false` with 400 pt-BR message (SAFE-04)
3. Rejects `rateLimit > MAX_API_RATE_LIMIT(50)` with 400 (SAFE-01)
4. `storage.createJourney()` → `jobQueue.executeJobNow()` → `storage.logAudit()` → 201

## Test Results

| File | it.todo Before | Real it() After | Status |
|------|---------------|-----------------|--------|
| `tests/ui/journey-wizard.test.tsx` | 14 | 12 | GREEN |
| `tests/routes/jobs-api-security.test.ts` | 7 | 7 | GREEN |
| **All Phase 16 suites** | — | 90 | GREEN |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Missing] Added POST /api/v1/jobs route**
- **Found during:** Task 1 — wizard's submit calls this endpoint but it didn't exist
- **Issue:** Phase 15 delivered `/api/v1/jobs/:id/abort` but NOT the base POST route for creation
- **Fix:** Added `POST /api/v1/jobs` handler in `server/routes/jobs.ts` with SAFE-01/04 validation
- **Files modified:** server/routes/jobs.ts
- **Commit:** 869f959

**2. [Rule 1 - Bug] Radix Select rejects empty-string value**
- **Found during:** Task 2 test run — `Error: A <Select.Item /> must have a value prop that is not an empty string`
- **Issue:** Radix UI Select component throws at runtime when SelectItem has value=""
- **Fix:** Changed placeholder credential item to use `__none__` sentinel; onValueChange maps `__none__` → undefined
- **Files modified:** client/src/components/forms/api-security-wizard.tsx
- **Commit:** 6536122

**3. [Rule 1 - Bug] Missing explicit React import for jsdom**
- **Found during:** Task 2 first test run — `ReferenceError: React is not defined`
- **Issue:** Vite's automatic JSX transform doesn't inject React in jsdom vitest environment
- **Fix:** Added `import React from "react"` to api-security-wizard.tsx (matches Phase 16 STATE.md pattern)
- **Files modified:** client/src/components/forms/api-security-wizard.tsx
- **Commit:** 6536122

### Design Deviations (Documented)

**"Criar nova credencial" button:** Plan allowed a fallback to toast if inline Dialog nesting is too complex. Implemented as toast: "Abra /credentials em outra aba para criar uma nova credencial, então retorne ao wizard." Consistent with the plan's stated deviation allowance.

**estimateRequests fallback=100:** When no assets selected OR no API linked to selected assets, endpointCount defaults to 100. Plan-specified behavior, documented here.

## Self-Check: PASSED

Files created/modified:
- FOUND: client/src/components/forms/api-security-wizard.tsx
- FOUND: client/src/pages/api-discovery.tsx
- FOUND: server/routes/jobs.ts
- FOUND: tests/ui/journey-wizard.test.tsx
- FOUND: tests/routes/jobs-api-security.test.ts

Commits verified:
- 869f959: feat(16-05): implement ApiSecurityWizard 4-step Dialog + POST /api/v1/jobs route + wire button in api-discovery
- 6536122: feat(16-05): promote UI-06 wizard + jobs-api-security route tests (12+7 real it() passing)

Tests: 19 new tests GREEN (12 UI + 7 route); All Phase 16 suites 90 tests GREEN.
