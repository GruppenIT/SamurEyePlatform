/**
 * Phase 11 — Nyquist stubs for ENRH-01/02 httpx enrichment.
 * Task 11-05-T2 (httpx.ts) replaces it.todo with real assertions.
 */
import { describe, it } from 'vitest';
// import placeholder — real imports added when stubs become real tests:
// import { runHttpxEnrichment, mapRequiresAuth } from '../../services/scanners/api/httpx';
void 0;

describe('httpx enrichment (ENRH-01/02)', () => {
  it.todo('spawns httpx with -json -sc -ct -td -tls-grab -silent -timeout 10 -rl 50');
  it.todo('feeds URLs via stdin one per line');
  it.todo('parses JSONL output into { url, status_code, content_type, tech[], tls{} }');
  it.todo('mapRequiresAuth returns true on 401 or 403');
  it.todo('mapRequiresAuth returns false on 200, 201, 204, 301, 302');
  it.todo('mapRequiresAuth returns null on 400, 404, 500, 502, timeout');
  it.todo('second auth probe runs only when requiresAuth=true and cred compatible');
  it.todo('second probe overwrites httpxStatus but preserves content-type/tech if newly absent');
});
