/**
 * Phase 13 Wave 0 — Nyquist stub for BOLA scanner (TEST-03 / API1).
 * Implementation comes in Wave 1 (13-02-PLAN — scanners/api/bola.ts).
 * Requirement: TEST-03
 */
import { describe, it } from 'vitest';

describe('scanners/api/bola: pairCredentials', () => {
  it.todo('generates C(n,2) ordered unique pairs from n creds (no mirrored (B,A))');
  it.todo('caps to maxCredentials (default 4) → max 6 pairs');
  it.todo('returns [] when fewer than 2 creds provided');
});

describe('scanners/api/bola: harvestObjectIds', () => {
  it.todo('extracts up to 3 IDs from JSON body fields matching /^(id|uuid|pk)$/i (case-insensitive)');
  it.todo('accepts both arrays (scans each element) and single objects');
  it.todo('returns [] when body is non-object, null, or contains no matching keys');
  it.todo('returns [] when body is not JSON-parseable (caller guards)');
});

describe('scanners/api/bola: testCrossAccess finding criterion', () => {
  it.todo('emits BolaHit severity=high when cred B gets status < 400 AND body.length > 0');
  it.todo('suppresses finding when response body contains "forbidden" / "unauthorized" / "permission denied" (case-insensitive)');
  it.todo('evidence.extractedValues includes credentialAId, credentialBId, objectId, endpointPath');
  it.todo('title is the deterministic pt-BR string "Acesso não autorizado a objeto via credencial secundária"');
  it.todo('substitutePathId replaces OpenAPI {id}/{userId}/{anyParam} tokens with harvested ID');
  it.todo('falls back to ?id=<val> appended when path has no {param} template');
});

describe('scanners/api/bola: scope filters', () => {
  it.todo('filters endpoints to method=GET only');
  it.todo('filters endpoints to requiresAuth=true only');
  it.todo('selects list-like endpoints (path has no {param} OR ends in plural/list) for harvest');
});
