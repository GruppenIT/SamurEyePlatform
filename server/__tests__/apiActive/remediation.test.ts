/**
 * Phase 13 Wave 0 — Nyquist stub for 5 new remediation template entries.
 * Implementation comes in Wave 1 (13-02-PLAN — shared/apiRemediationTemplates.ts).
 * Requirements: TEST-03, TEST-04, TEST-05, TEST-06, TEST-07
 */
import { describe, it } from 'vitest';

describe('shared/apiRemediationTemplates: Phase 13 extensions', () => {
  it.todo('exports API_REMEDIATION_TEMPLATES with existing Phase 12 keys preserved (api2_broken_auth_2023, api8_misconfiguration_2023, api9_inventory_2023)');
  it.todo('adds api1_bola_2023 pt-BR string (object-level ACL guidance)');
  it.todo('adds api3_bopla_2023 pt-BR string (allow-list explícita + reject sensitive properties)');
  it.todo('adds api4_rate_limit_2023 pt-BR string (429 + Retry-After guidance)');
  it.todo('adds api5_bfla_2023 pt-BR string (RBAC backend validation)');
  it.todo('adds api7_ssrf_2023 pt-BR string (URL allow-list + block private ranges + cloud metadata 169.254.169.254)');
  it.todo('type ApiRemediationTemplate still derived via typeof (no manual interface)');
});
