/**
 * Phase 11 — Nyquist stubs for DISC-04 Katana crawler.
 * Task 11-04-T2 (katana.ts) replaces it.todo with real assertions.
 */
import { describe, it } from 'vitest';
// import placeholder — real imports added when stubs become real tests:
// import { runKatana } from '../../services/scanners/api/katana';
void 0;

describe('Katana crawler (DISC-04)', () => {
  it.todo('spawns katana with -xhr -fx -jc -d 3 -fs rdn -jsonl flags');
  it.todo('parses JSONL stdout into { url, method, response_type } records');
  it.todo('emits discoverySources=["crawler"] per endpoint');
  it.todo('injects -H Authorization when cred is bearer_jwt/basic/api_key_header');
  it.todo('skips auth and logs warn when cred is api_key_query or hmac');
  it.todo('mints OAuth2 token before crawl when cred is oauth2_client_credentials');
  it.todo('passes tempfile cert/key/ca flags when cred is mtls');
  it.todo('respects AbortSignal via processTracker and returns partial results on cancel');
});
