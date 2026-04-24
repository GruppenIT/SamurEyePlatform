/**
 * Phase 11 — ENRH-01/02 httpx enrichment tests.
 * Converted from Nyquist it.todo stubs to real assertions (Plan 11-05 Task 1).
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

import { runHttpx, mapRequiresAuth } from '../../services/scanners/api/httpx';

// Fixture data
const FIXTURE_PATH = path.join(__dirname, 'fixtures', 'httpx-json.txt');
const FIXTURE_STDOUT = fs.readFileSync(FIXTURE_PATH, 'utf8');

function fakeChildWithStdout(stdoutData: string, stdinMock?: { write: ReturnType<typeof vi.fn>; end: ReturnType<typeof vi.fn> }) {
  const child = new EventEmitter() as any;
  child.pid = 12345;
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.stdin = stdinMock ?? { write: vi.fn(), end: vi.fn() };
  child.kill = vi.fn();
  setImmediate(() => {
    child.stdout.emit('data', Buffer.from(stdoutData));
    child.emit('close', 0);
  });
  return child;
}

describe('httpx enrichment (ENRH-01/02)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('spawns httpx with -json -sc -ct -td -tls-grab -silent -timeout 10 -rl 50', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: '/opt/samureye/bin/httpx' });
    const fakeChild = fakeChildWithStdout('');
    spawnMock.mockReturnValueOnce(fakeChild);

    await runHttpx(['https://target.example.com/api/users'], {}, {});

    const [bin, args] = spawnMock.mock.calls[0];
    expect(bin).toBe('/opt/samureye/bin/httpx');
    expect(args).toContain('-json');
    expect(args).toContain('-sc');
    expect(args).toContain('-ct');
    expect(args).toContain('-td');
    expect(args).toContain('-tls-grab');
    expect(args).toContain('-silent');
    expect(args).toContain('-timeout');
    expect(args).toContain('10');
    expect(args).toContain('-rl');
    expect(args).toContain('50');
  });

  it('feeds URLs via stdin one per line', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: '/opt/samureye/bin/httpx' });
    const stdinMock = { write: vi.fn(), end: vi.fn() };
    const fakeChild = fakeChildWithStdout('', stdinMock);
    spawnMock.mockReturnValueOnce(fakeChild);

    const urls = ['https://target.example.com/api/users', 'https://target.example.com/api/admin'];
    await runHttpx(urls, {}, {});

    expect(stdinMock.write).toHaveBeenCalledWith(
      'https://target.example.com/api/users\nhttps://target.example.com/api/admin\n',
    );
    expect(stdinMock.end).toHaveBeenCalled();
  });

  it('parses JSONL output into HttpxEnrichment[] with url, status, contentType, tech, tls', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: '/opt/samureye/bin/httpx' });
    const fakeChild = fakeChildWithStdout(FIXTURE_STDOUT);
    spawnMock.mockReturnValueOnce(fakeChild);

    const r = await runHttpx(['https://target.example.com/api/users'], {}, {});

    // 5 lines in fixture
    expect(r.results.length).toBe(5);
    expect(r.skipped).toBeUndefined();

    const first = r.results[0];
    expect(first.url).toBe('https://target.example.com/api/users');
    expect(first.status).toBe(200);
    expect(first.contentType).toBe('application/json');
    expect(first.tech).toEqual(['Express', 'Node.js', 'React']);
    expect(first.tls).not.toBeNull();
    expect(first.tls?.tls_version).toBe('tls13');
  });

  it('mapRequiresAuth returns true on 401 or 403', () => {
    expect(mapRequiresAuth(401)).toBe(true);
    expect(mapRequiresAuth(403)).toBe(true);
  });

  it('mapRequiresAuth returns false on 200, 201, 204, 301, 302, 307, 308', () => {
    expect(mapRequiresAuth(200)).toBe(false);
    expect(mapRequiresAuth(201)).toBe(false);
    expect(mapRequiresAuth(204)).toBe(false);
    expect(mapRequiresAuth(301)).toBe(false);
    expect(mapRequiresAuth(302)).toBe(false);
    expect(mapRequiresAuth(307)).toBe(false);
    expect(mapRequiresAuth(308)).toBe(false);
  });

  it('mapRequiresAuth returns null on 400, 404, 500, 502, 0 (unknown/timeout)', () => {
    expect(mapRequiresAuth(400)).toBeNull();
    expect(mapRequiresAuth(404)).toBeNull();
    expect(mapRequiresAuth(500)).toBeNull();
    expect(mapRequiresAuth(502)).toBeNull();
    expect(mapRequiresAuth(0)).toBeNull();
    expect(mapRequiresAuth(null)).toBeNull();
    expect(mapRequiresAuth(undefined)).toBeNull();
  });

  it('returns skipped + empty results when preflight fails', async () => {
    preflightMock.mockResolvedValueOnce({ ok: false, reason: 'httpx binary not available' });

    const r = await runHttpx(['https://target.example.com/api/users'], {}, {});

    expect(r.skipped?.reason).toContain('httpx');
    expect(r.results).toEqual([]);
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it('injects -H Authorization when opts.authHeader is provided', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: '/opt/samureye/bin/httpx' });
    const fakeChild = fakeChildWithStdout('');
    spawnMock.mockReturnValueOnce(fakeChild);

    await runHttpx(
      ['https://target.example.com/api/admin'],
      { authHeader: 'Bearer my-jwt-token' },
      {},
    );

    const [, args] = spawnMock.mock.calls[0];
    const hIdx = args.indexOf('-H');
    expect(hIdx).not.toBe(-1);
    expect(args[hIdx + 1]).toContain('Authorization');
    expect(args[hIdx + 1]).toContain('my-jwt-token');
  });

  it('respects AbortSignal and calls processTracker.kill', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: '/opt/samureye/bin/httpx' });

    const controller = new AbortController();
    const fakeChild = new EventEmitter() as any;
    fakeChild.pid = 99999;
    fakeChild.stdout = new EventEmitter();
    fakeChild.stderr = new EventEmitter();
    fakeChild.stdin = { write: vi.fn(), end: vi.fn() };
    fakeChild.kill = vi.fn();
    spawnMock.mockReturnValueOnce(fakeChild);

    setImmediate(() => {
      controller.abort();
      setImmediate(() => fakeChild.emit('close', 130));
    });

    const r = await runHttpx(
      ['https://target.example.com/api/users'],
      {},
      { jobId: 'job-abort-httpx', signal: controller.signal },
    );

    expect(processTrackerMock.kill).toHaveBeenCalledWith('job-abort-httpx', 99999);
    expect(r.results).toBeDefined();
  });
});
