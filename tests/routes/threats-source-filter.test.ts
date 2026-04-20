/**
 * Phase 16 — UI-03 Backend — GET /api/threats?source=api_security
 *
 * Wave 0 Nyquist stubs. Promoted to real it() by Plan 03 during Wave 2.
 * Per 16-VALIDATION.md task map.
 *
 * Requirement: Extend threats route to accept optional source filter.
 * source=api_security returns only rows with source='api_security'.
 * No source param = backward-compatible (return all).
 * getThreatsWithHosts signature accepts optional source?: string.
 */
import { describe, it } from 'vitest';

describe('GET /api/threats — source filter', () => {
  it.todo('GET /api/threats?source=api_security returns only rows where source = "api_security"');
  it.todo('GET /api/threats without source param returns all rows (backward compatibility preserved)');
  it.todo('GET /api/threats?source=invalid_source returns 400 or empty array (decision documented in Plan 03)');
  it.todo('source filter composes correctly with existing severity filter');
  it.todo('source filter composes correctly with existing status filter');
  it.todo('getThreatsWithHosts DB function accepts optional source?: string parameter');
});
