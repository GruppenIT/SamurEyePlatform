/**
 * Phase 13 Wave 0 — Nyquist stub for route handler + CLI.
 * Implementation comes in Wave 3 (13-04-PLAN — routes/apis.ts + scripts/runApiActiveTests.ts).
 * Requirements: TEST-03, TEST-04, TEST-05, TEST-06, TEST-07
 */
import { describe, it } from 'vitest';

describe('POST /api/v1/apis/:id/test/active', () => {
  it.todo('requires authentication (401 if not logged)');
  it.todo('requires operator or global_administrator role (403 if readonly_analyst)');
  it.todo('rejects body with unknown field via Zod .strict() (400)');
  it.todo('returns 404 when apiId does not exist');
  it.todo('parses body as apiActiveTestOptsSchema and passes to runApiActiveTests');
  it.todo('returns 201 with ActiveTestResult shape on success');
  it.todo('writes audit log entry with actorId + action=api_active_test_started + objectType=api + objectId=apiId + before=null + after={jobId, stages, destructiveEnabled}');
  it.todo('returns 500 with pt-BR message when runApiActiveTests throws');
  it.todo('pt-BR error messages ("API não encontrada", "Opções de teste ativo inválidas")');
});

describe('CLI server/scripts/runApiActiveTests.ts', () => {
  it.todo('--help prints usage to stderr and exits 0');
  it.todo('--api=<uuid> required; exits 1 with error when missing');
  it.todo('supports toggle flags --no-bola / --no-bfla / --no-bopla / --no-ssrf / --rate-limit / --destructive / --dry-run');
  it.todo('supports --credential=<uuid> (repeatable) for credentialIds override');
  it.todo('prints ActiveTestResult as JSON to stdout, progress/logs to stderr');
  it.todo('exit code 0 on success, 2 on cancelled, 1 on error');
  it.todo('uses import.meta.url === pathToFileURL(process.argv[1]).href guard (test-safe)');
});
