/**
 * Phase 12 Wave 0 — Nyquist stub for findings dedupe upsert.
 * Implementation comes in Wave 2 (12-03-PLAN — storage/apiFindings.ts).
 * Requirements: TEST-01, TEST-02
 */
import { describe, it } from 'vitest';

describe('storage/apiFindings: upsertApiFindingByKey', () => {
  it.todo('inserts new row when (endpointId, owaspCategory, title) does not exist');
  it.todo('updates existing row when match found and status != closed');
  it.todo('preserves status when updating (does not reset to open)');
  it.todo('refreshes evidence + jobId + updatedAt on update');
  it.todo('inserts NEW row when match exists but status=closed (reopen)');
  it.todo('returns { finding, action: "inserted" | "updated" }');
  it.todo('uses db.transaction to serialize SELECT + INSERT/UPDATE');
});
