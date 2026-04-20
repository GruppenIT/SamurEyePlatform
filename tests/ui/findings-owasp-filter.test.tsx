/**
 * Phase 16 — UI-03 — Findings OWASP Source Filter
 *
 * Wave 0 Nyquist stubs. Promoted to real it() by Plan 03 during Wave 2.
 * Per 16-VALIDATION.md task map.
 *
 * Requirement: Add source filter Select to /threats page.
 * source=api_security shows OWASP badge column using getOwaspBadgeInfo.
 * OWASP badge displays info.codigo (e.g. "API1:2023") not the raw key.
 * Fallback "N/A" badge in gray when owaspCategory is absent.
 */
import { describe, it } from 'vitest';

describe('UI-03 — Findings OWASP Source Filter', () => {
  it.todo('Select[source] renders with options including "all" and "api_security"');
  it.todo('changing source to "api_security" triggers queryClient refetch with updated queryKey');
  it.todo('OWASP badge column renders ONLY when sourceFilter === "api_security"');
  it.todo('OWASP badge text uses info.codigo (e.g. "API1:2023") not raw owaspCategory key');
  it.todo('OWASP badge color class matches finding severity (getSeverityColor)');
  it.todo('renders fallback "N/A" badge in gray when finding has no owaspCategory in evidence');
  it.todo('source filter "all" hides OWASP badge column and shows all threats');
});
