/**
 * Phase 16 — UI-06 — Journey Wizard (4-Step)
 *
 * Wave 0 Nyquist stubs. Promoted to real it() by Plan 04 during Wave 3.
 * Per 16-VALIDATION.md task map.
 *
 * Requirement: 4-step wizard Dialog for creating api_security journeys.
 * Step 1: name + asset multi-select + targetUrl.
 * Step 2: authorizationAck Checkbox (red warning, required to proceed).
 * Step 3: stage toggles with default state per CONTEXT.md + rate limit slider.
 * Step 4: read-only summary + dryRun Checkbox + submit.
 */
import { describe, it } from 'vitest';

describe('UI-06 — Journey Wizard (4 Steps)', () => {
  // Step 1
  it.todo('Step 1: name input, asset multi-select, and targetUrl input all render');
  it.todo('Step 1: "Próximo" button is disabled when name is empty');
  it.todo('Step 1: "Próximo" button is disabled when no assets are selected');

  // Step 2
  it.todo('Step 2: authorizationAck Checkbox renders with red warning label "Confirmo que tenho autorização para testar estes alvos"');
  it.todo('Step 2: "Próximo" button is blocked (disabled) when authorizationAck = false');
  it.todo('Step 2: "Criar nova credencial" opens nested Dialog without closing the wizard Dialog');

  // Step 3
  it.todo('Step 3: default stage toggles match CONTEXT.md — specFirst=ON, crawler=ON, kiterunner=OFF, misconfigs=ON, auth=ON, bola=OFF, bfla=OFF, bopla=OFF, rateLimit=ON, ssrf=OFF');
  it.todo('Step 3: destructiveEnabled Checkbox renders red warning label and defaults to false');
  it.todo('Step 3: rateLimit input/slider is clamped to [1, 50] — value 51 is rejected or coerced to 50');
  it.todo('Step 3: Badge "~N requests estimados" updates reactively when endpointCount or stage toggles change');

  // Step 4
  it.todo('Step 4: renders read-only summary of all wizard fields from steps 1-3');
  it.todo('Step 4: dryRun Checkbox is present and defaults to false');
  it.todo('Step 4: "Criar Jornada" submit button calls POST /api/v1/jobs with type=api_security and full config payload');

  // Navigation
  it.todo('"Anterior" button is enabled at step >= 2 and decrements the step counter');
});
