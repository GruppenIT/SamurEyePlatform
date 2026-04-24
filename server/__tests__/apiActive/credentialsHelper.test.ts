/**
 * Phase 13 Wave 0 — Nyquist stub for cred-listing consumer contract.
 * Implementation comes in Wave 1/Wave 2 (13-02-PLAN / 13-03-PLAN — bola.ts / orchestrator).
 * No new storage method is added; this covers the consumer pattern.
 * Requirements: TEST-03, TEST-04
 */
import { describe, it } from 'vitest';

describe('BOLA + BFLA: listApiCredentials({apiId}) consumer pattern', () => {
  it.todo('BOLA scanner calls listApiCredentials({apiId}) to fetch all creds for pairing');
  it.todo('BOLA caps list to bola.maxCredentials (default 4) before pairing');
  it.todo('BFLA scanner consumes same listApiCredentials({apiId}) output for low-priv ranking');
  it.todo('returns list sorted by priority ASC (Phase 10 storage default) — highest priority int = lowest privilege');
  it.todo('filters unsupported auth types (hmac/oauth2_client_credentials/mtls): logs skip + omits from test set');
  it.todo('supported auth types for Phase 13: bearer_jwt, api_key_header, api_key_query, basic');
  it.todo('orchestrator: credentialIds override replaces listApiCredentials result when provided');
});
