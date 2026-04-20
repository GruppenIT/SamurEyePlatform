/**
 * Phase 11 — DISC-05 Kiterunner brute-force route discovery tests.
 * Converted from Nyquist it.todo stubs to real assertions (Plan 11-04 Task 2).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EventEmitter } from 'events';
import fs from 'fs';
import path from 'path';

const spawnMock = vi.hoisted(() => vi.fn());
const preflightMock = vi.hoisted(() => vi.fn());
const processTrackerMock = vi.hoisted(() => ({
  register: vi.fn(),
  kill: vi.fn(),
}));

vi.mock('child_process', () => ({
  spawn: spawnMock,
}));
vi.mock('../../services/scanners/api/preflight', () => ({
  preflightApiBinary: preflightMock,
}));
vi.mock('../../services/processTracker', () => ({
  processTracker: processTrackerMock,
}));

import { runKiterunner } from '../../services/scanners/api/kiterunner';

// Fixture data (5 lines: 401, 200, 200, 403, 200)
const FIXTURE_PATH = path.join(__dirname, 'fixtures', 'kiterunner-json.txt');
const FIXTURE_STDOUT = fs.readFileSync(FIXTURE_PATH, 'utf8');

function fakeChildWithStdout(stdoutData: string) {
  const child = new EventEmitter() as any;
  child.pid = 54321;
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = vi.fn();
  setImmediate(() => {
    child.stdout.emit('data', Buffer.from(stdoutData));
    child.emit('close', 0);
  });
  return child;
}

describe('Kiterunner brute-force (DISC-05)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns skipped + empty when preflight fails', async () => {
    preflightMock.mockResolvedValueOnce({ ok: false, reason: 'kiterunner binary not available' });

    const r = await runKiterunner('https://target.example.com', {}, { apiId: 'api-1' });

    expect(r.skipped?.reason).toContain('kiterunner');
    expect(r.endpoints).toEqual([]);
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it('spawns kr scan with -w routes-large.kite -o json -x 5 -j 100 flags', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: 'kr' });
    const fakeChild = fakeChildWithStdout('');
    spawnMock.mockReturnValueOnce(fakeChild);

    await runKiterunner('https://target.example.com', {}, { apiId: 'api-1' });

    const [bin, args] = spawnMock.mock.calls[0];
    expect(bin).toBe('kr');
    expect(args[0]).toBe('scan');
    expect(args[1]).toBe('https://target.example.com');
    expect(args).toContain('-w');
    const wIdx = args.indexOf('-w');
    expect(args[wIdx + 1]).toContain('routes-large.kite');
    expect(args).toContain('-o');
    expect(args[args.indexOf('-o') + 1]).toBe('json');
    expect(args).toContain('-x');
    expect(args[args.indexOf('-x') + 1]).toBe('5');
    expect(args).toContain('-j');
    expect(args[args.indexOf('-j') + 1]).toBe('100');
  });

  it('passes --success-status-codes 200,201,204,301,302,401,403', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: 'kr' });
    const fakeChild = fakeChildWithStdout('');
    spawnMock.mockReturnValueOnce(fakeChild);

    await runKiterunner('https://target.example.com', {}, { apiId: 'api-1' });

    const [, args] = spawnMock.mock.calls[0];
    expect(args).toContain('--success-status-codes');
    const sIdx = args.indexOf('--success-status-codes');
    expect(args[sIdx + 1]).toBe('200,201,204,301,302,401,403');
  });

  it('passes --fail-status-codes 404,501,502,400', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: 'kr' });
    const fakeChild = fakeChildWithStdout('');
    spawnMock.mockReturnValueOnce(fakeChild);

    await runKiterunner('https://target.example.com', {}, { apiId: 'api-1' });

    const [, args] = spawnMock.mock.calls[0];
    expect(args).toContain('--fail-status-codes');
    const fIdx = args.indexOf('--fail-status-codes');
    expect(args[fIdx + 1]).toBe('404,501,502,400');
  });

  it('parses JSONL output into InsertApiEndpoint[] with discoverySources=["kiterunner"]', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: 'kr' });
    const fakeChild = fakeChildWithStdout(FIXTURE_STDOUT);
    spawnMock.mockReturnValueOnce(fakeChild);

    const r = await runKiterunner('https://target.example.com', {}, { apiId: 'api-42' });

    // All 5 fixture lines have success status codes (401, 200, 200, 403, 200)
    expect(r.endpoints.length).toBe(5);
    expect(r.skipped).toBeUndefined();

    const first = r.endpoints[0];
    expect(first.method).toBe('GET');
    expect(first.path).toBe('/api/admin');
    expect(first.discoverySources).toEqual(['kiterunner']);
    expect(first.apiId).toBe('api-42');
    expect(first.pathParams).toEqual([]);
    expect(first.queryParams).toEqual([]);
  });

  it('filters out status codes not in SUCCESS_STATUSES (e.g. 500)', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: 'kr' });
    const badLineStdout = [
      '{"method":"GET","path":"/api/users","status_code":200,"content_length":512,"target":"https://target"}',
      '{"method":"GET","path":"/api/error","status_code":500,"content_length":10,"target":"https://target"}',
      '{"method":"GET","path":"/api/not-found","status_code":404,"content_length":0,"target":"https://target"}',
    ].join('\n');
    const fakeChild = fakeChildWithStdout(badLineStdout);
    spawnMock.mockReturnValueOnce(fakeChild);

    const r = await runKiterunner('https://target.example.com', {}, { apiId: 'api-1' });

    // Only /api/users (200) should pass; 500 and 404 filtered out
    expect(r.endpoints.length).toBe(1);
    expect(r.endpoints[0].path).toBe('/api/users');
  });

  it('replaces -x 5 with -x <rateLimit> when opts.rateLimit is provided', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: 'kr' });
    const fakeChild = fakeChildWithStdout('');
    spawnMock.mockReturnValueOnce(fakeChild);

    await runKiterunner('https://target.example.com', { rateLimit: 10 }, { apiId: 'api-1' });

    const [, args] = spawnMock.mock.calls[0];
    const xIdx = args.indexOf('-x');
    expect(xIdx).not.toBe(-1);
    expect(args[xIdx + 1]).toBe('10');
  });

  it('registers with processTracker using name "kiterunner" and calls kill on abort', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: 'kr' });

    const controller = new AbortController();
    const fakeChild = new EventEmitter() as any;
    fakeChild.pid = 77777;
    fakeChild.stdout = new EventEmitter();
    fakeChild.stderr = new EventEmitter();
    fakeChild.kill = vi.fn();
    spawnMock.mockReturnValueOnce(fakeChild);

    setImmediate(() => {
      controller.abort();
      setImmediate(() => fakeChild.emit('close', 130));
    });

    await runKiterunner(
      'https://target.example.com',
      { timeoutMs: 30000 },
      { apiId: 'api-1', jobId: 'job-kr-abort', signal: controller.signal },
    );

    expect(processTrackerMock.register).toHaveBeenCalledWith(
      'job-kr-abort',
      'kiterunner',
      fakeChild,
      'api-discovery:kiterunner',
    );
    expect(processTrackerMock.kill).toHaveBeenCalledWith('job-kr-abort', 77777);
  });
});
