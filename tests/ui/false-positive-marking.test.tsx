/**
 * Phase 16 — UI-05 — False Positive Marking
 *
 * Wave 0 Nyquist stubs. Promoted to real it() by Plan 03 during Wave 2.
 * Per 16-VALIDATION.md task map.
 *
 * Requirement: "Falso Positivo" action per row (only when sourceFilter=api_security).
 * Opens AlertDialog with pt-BR message. Confirmar calls PATCH /api/v1/api-findings/:id.
 * Toast on success. queryClient invalidated with /api/threats key.
 */
import { describe, it } from 'vitest';

describe('UI-05 — False Positive Marking', () => {
  it.todo('"Falso Positivo" action button is rendered per row when sourceFilter = "api_security"');
  it.todo('AlertDialog opens on "Falso Positivo" click with pt-BR confirmation message');
  it.todo('AlertDialog message contains "Marcar como falso positivo? Esta ação é registrada no audit log."');
  it.todo('"Cancelar" button closes AlertDialog WITHOUT calling the PATCH mutation');
  it.todo('"Confirmar" button calls PATCH /api/v1/api-findings/:id with body {falsePositive: true}');
  it.todo('toast "Finding marcado como falso positivo" fires on mutation onSuccess');
  it.todo('queryClient.invalidateQueries called with key containing "/api/threats" after success');
});
