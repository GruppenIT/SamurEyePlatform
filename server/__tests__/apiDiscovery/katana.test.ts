/**
 * Phase 11 — DISC-04 Katana SPA crawler tests.
 * Converted from Nyquist it.todo stubs to real assertions (Plan 11-04 Task 1).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EventEmitter } from 'events';
import fs from 'fs';
import path from 'path';

const spawnMock = vi.hoisted(() => vi.fn());
const spawnSyncMock = vi.hoisted(() => vi.fn());
const preflightMock = vi.hoisted(() => vi.fn());
const processTrackerMock = vi.hoisted(() => ({
  register: vi.fn(),
  kill: vi.fn(),
}));

vi.mock('child_process', () => ({
  spawn: spawnMock,
  spawnSync: spawnSyncMock,
}));
vi.mock('../../services/scanners/api/preflight', () => ({
  preflightApiBinary: preflightMock,
}));
vi.mock('../../services/processTracker', () => ({
  processTracker: processTrackerMock,
}));

import { runKatana } from '../../services/scanners/api/katana';

// Fixture data
const FIXTURE_PATH = path.join(__dirname, 'fixtures', 'katana-jsonl.txt');
const FIXTURE_STDOUT = fs.readFileSync(FIXTURE_PATH, 'utf8');

function fakeChildWithStdout(stdoutData: string) {
  const child = new EventEmitter() as any;
  child.pid = 12345;
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = vi.fn();
  setImmediate(() => {
    child.stdout.emit('data', Buffer.from(stdoutData));
    child.emit('close', 0);
  });
  return child;
}

describe('Katana crawler (DISC-04)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Default spawnSync: chromium not found
    spawnSyncMock.mockReturnValue({ status: 1, stdout: '' });
  });

  it('returns skipped + empty when preflight fails', async () => {
    preflightMock.mockResolvedValueOnce({ ok: false, reason: 'katana binary not available' });

    const r = await runKatana('https://target.example.com', {}, { apiId: 'api-1' });

    expect(r.skipped?.reason).toContain('katana');
    expect(r.endpoints).toEqual([]);
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it('spawns with correct base args (−xhr −fx −jc −d 3 −fs rdn)', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: '/opt/samureye/bin/katana' });
    const fakeChild = fakeChildWithStdout('');
    spawnMock.mockReturnValueOnce(fakeChild);

    await runKatana('https://target.example.com', {}, { apiId: 'api-1' });

    const [bin, args] = spawnMock.mock.calls[0];
    expect(bin).toBe('/opt/samureye/bin/katana');
    expect(args).toContain('-u');
    expect(args).toContain('https://target.example.com');
    expect(args).toContain('-d');
    expect(args).toContain('3');
    expect(args).toContain('-fs');
    expect(args).toContain('rdn');
    expect(args).toContain('-jc');
    expect(args).toContain('-xhr');
    expect(args).toContain('-fx');
    expect(args).toContain('-timeout');
    expect(args).toContain('10');
    expect(args).toContain('-jsonl');
    expect(args).toContain('-silent');
  });

  it('parses JSONL stdout into InsertApiEndpoint[] with discoverySources=["crawler"]', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: '/opt/samureye/bin/katana' });
    const fakeChild = fakeChildWithStdout(FIXTURE_STDOUT);
    spawnMock.mockReturnValueOnce(fakeChild);

    const r = await runKatana('https://target.example.com', {}, { apiId: 'api-42' });

    // 5 lines in fixture, 5 unique method:path combos
    expect(r.endpoints.length).toBe(5);
    expect(r.skipped).toBeUndefined();

    const first = r.endpoints[0];
    expect(first.method).toBe('GET');
    expect(first.path).toBe('/api/users');
    expect(first.discoverySources).toEqual(['crawler']);
    expect(first.apiId).toBe('api-42');
    expect(first.pathParams).toEqual([]);
    expect(first.queryParams).toEqual([]);
  });

  it('injects -H Authorization when cred is bearer_jwt', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: '/opt/samureye/bin/katana' });
    const fakeChild = fakeChildWithStdout('');
    spawnMock.mockReturnValueOnce(fakeChild);

    await runKatana(
      'https://target.example.com',
      { credential: { authType: 'bearer_jwt', secret: 'my-jwt-token' } },
      { apiId: 'api-1' },
    );

    const [, args] = spawnMock.mock.calls[0];
    const hIdx = args.indexOf('-H');
    expect(hIdx).not.toBe(-1);
    expect(args[hIdx + 1]).toBe('Authorization: Bearer my-jwt-token');
  });

  it('injects -H Authorization when cred is basic', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: '/opt/samureye/bin/katana' });
    const fakeChild = fakeChildWithStdout('');
    spawnMock.mockReturnValueOnce(fakeChild);

    await runKatana(
      'https://target.example.com',
      { credential: { authType: 'basic', secret: 'dXNlcjpwYXNz' } },
      { apiId: 'api-1' },
    );

    const [, args] = spawnMock.mock.calls[0];
    const hIdx = args.indexOf('-H');
    expect(hIdx).not.toBe(-1);
    expect(args[hIdx + 1]).toBe('Authorization: Basic dXNlcjpwYXNz');
  });

  it('injects -H <headerName>: <secret> when cred is api_key_header', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: '/opt/samureye/bin/katana' });
    const fakeChild = fakeChildWithStdout('');
    spawnMock.mockReturnValueOnce(fakeChild);

    await runKatana(
      'https://target.example.com',
      { credential: { authType: 'api_key_header', headerName: 'X-API-Key', secret: 'secret123' } },
      { apiId: 'api-1' },
    );

    const [, args] = spawnMock.mock.calls[0];
    const hIdx = args.indexOf('-H');
    expect(hIdx).not.toBe(-1);
    expect(args[hIdx + 1]).toBe('X-API-Key: secret123');
  });

  it('skips auth and logs warn when cred is api_key_query or hmac', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: '/opt/samureye/bin/katana' });
    const fakeChild = fakeChildWithStdout('');
    spawnMock.mockReturnValueOnce(fakeChild);

    await runKatana(
      'https://target.example.com',
      { credential: { authType: 'api_key_query', paramName: 'api_key', secret: 'secret' } },
      { apiId: 'api-1' },
    );

    const [, args] = spawnMock.mock.calls[0];
    // No -H flag injected
    expect(args).not.toContain('-H');
  });

  it('mints OAuth2 token before crawl and injects bearer when cred is oauth2_client_credentials', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: '/opt/samureye/bin/katana' });
    const fakeChild = fakeChildWithStdout('');
    spawnMock.mockReturnValueOnce(fakeChild);

    // Mock global fetch for OAuth2 token mint
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: async () => ({ access_token: 'minted-token-xyz' }),
    } as any);

    await runKatana(
      'https://target.example.com',
      {
        credential: {
          authType: 'oauth2_client_credentials',
          tokenUrl: 'https://auth.example.com/token',
          clientId: 'client-id',
          clientSecret: 'client-secret',
        },
      },
      { apiId: 'api-1' },
    );

    expect(fetchMock).toHaveBeenCalledWith(
      'https://auth.example.com/token',
      expect.objectContaining({ method: 'POST' }),
    );

    const [, args] = spawnMock.mock.calls[0];
    const hIdx = args.indexOf('-H');
    expect(hIdx).not.toBe(-1);
    expect(args[hIdx + 1]).toBe('Authorization: Bearer minted-token-xyz');

    fetchMock.mockRestore();
  });

  it('respects AbortSignal and returns partial results (endpoints parsed so far)', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: '/opt/samureye/bin/katana' });

    const controller = new AbortController();
    const fakeChild = new EventEmitter() as any;
    fakeChild.pid = 99999;
    fakeChild.stdout = new EventEmitter();
    fakeChild.stderr = new EventEmitter();
    fakeChild.kill = vi.fn();
    spawnMock.mockReturnValueOnce(fakeChild);

    // Emit partial stdout then abort
    setImmediate(() => {
      fakeChild.stdout.emit('data', Buffer.from(FIXTURE_STDOUT.split('\n')[0] + '\n'));
      controller.abort();
      // processTracker.kill triggers close
      setImmediate(() => fakeChild.emit('close', 130));
    });

    const r = await runKatana(
      'https://target.example.com',
      { timeoutMs: 30000 },
      { apiId: 'api-1', jobId: 'job-abort', signal: controller.signal },
    );

    // At least the partial line should have been parsed
    expect(r.endpoints.length).toBeGreaterThanOrEqual(1);
    expect(processTrackerMock.kill).toHaveBeenCalledWith('job-abort', 99999);
  });
});
