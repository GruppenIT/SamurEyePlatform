/**
 * Phase 13 Wave 0 — Nyquist stub for apiActiveTestOptsSchema Zod validation.
 * Implementation of the schema itself is in Wave 0 Task 1 (shared/schema.ts).
 * These stubs get turned into real assertions by Wave 0 Task 1 or earliest consumer.
 * Requirements: TEST-03, TEST-04, TEST-05, TEST-06, TEST-07
 */
import { describe, it } from 'vitest';

describe('shared/schema: apiActiveTestOptsSchema', () => {
  it.todo('accepts empty object {} (all opts default)');
  it.todo('accepts all 5 stages explicitly disabled: bola/bfla/bopla/rateLimit/ssrf = false');
  it.todo('rejects unknown field at root (.strict())');
  it.todo('rejects unknown field inside stages (.strict())');
  it.todo('accepts destructiveEnabled=true + credentialIds array + endpointIds array');
  it.todo('accepts dryRun=true');
  it.todo('rateLimit sub: accepts burstSize=20/windowMs=2000; rejects burstSize=51 (max 50)');
  it.todo('rateLimit sub: rejects rateLimit.endpointIds with 6 entries (max 5)');
  it.todo('ssrf sub: accepts interactshUrl=https://oast.me; rejects invalid URL string');
  it.todo('bola sub: accepts maxCredentials=4/maxIdsPerEndpoint=3; rejects maxCredentials=7 (max 6)');
  it.todo('bola sub: rejects maxIdsPerEndpoint=6 (max 5)');
});

describe('shared/schema: ActiveTestResult interface shape', () => {
  it.todo('has fields apiId, stagesRun, stagesSkipped, findingsCreated, findingsUpdated');
  it.todo('has fields findingsByCategory, findingsBySeverity, cancelled, dryRun, durationMs, credentialsUsed');
  it.todo('stagesRun union type is "bola" | "bfla" | "bopla" | "rate_limit" | "ssrf" (rate_limit with underscore)');
});

describe('shared/schema: BOPLA_SENSITIVE_KEYS constant', () => {
  it.todo('exports exactly 10 keys in order: is_admin, isAdmin, admin, role, roles, permissions, superuser, owner, verified, email_verified');
  it.todo('type BoplaSensitiveKey inferred from const array (not widened to string)');
});
