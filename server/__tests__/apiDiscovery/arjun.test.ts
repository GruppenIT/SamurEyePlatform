/**
 * Phase 11 — ENRH-03 Arjun param discovery tests.
 * Converted from Nyquist it.todo stubs to real assertions (Plan 11-05 Task 2).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EventEmitter } from 'events';
import path from 'path';
import fs from 'fs';

const spawnMock = vi.hoisted(() => vi.fn());
const preflightMock = vi.hoisted(() => vi.fn());
const processTrackerMock = vi.hoisted(() => ({
  register: vi.fn(),
  kill: vi.fn(),
}));

// Capture mkdtemp/readFile/rm mocks before module loading
const mkdtempMock = vi.hoisted(() => vi.fn());
const readFileMock = vi.hoisted(() => vi.fn());
const rmMock = vi.hoisted(() => vi.fn());

vi.mock('child_process', () => ({
  spawn: spawnMock,
}));
vi.mock('../../services/scanners/api/preflight', () => ({
  preflightApiBinary: preflightMock,
}));
vi.mock('../../services/processTracker', () => ({
  processTracker: processTrackerMock,
}));
vi.mock('fs/promises', async (importOriginal) => {
  const original = await importOriginal<typeof import('fs/promises')>();
  return {
    ...original,
    mkdtemp: mkdtempMock,
    readFile: readFileMock,
    rm: rmMock,
  };
});

import { runArjun, ArjunOutputSchema } from '../../services/scanners/api/arjun';

// Fixture data
const FIXTURE_PATH = path.join(__dirname, 'fixtures', 'arjun-output.json');
const FIXTURE_JSON = fs.readFileSync(FIXTURE_PATH, 'utf8');

const TARGET_URL = 'https://target.example.com/api/search';
const FAKE_TEMP_DIR = '/tmp/api-discovery-test-123abc';
const FAKE_TEMP_FILE = `${FAKE_TEMP_DIR}/arjun.json`;

function fakeChildProcess() {
  const child = new EventEmitter() as any;
  child.pid = 12345;
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = vi.fn();
  setImmediate(() => {
    child.stdout.emit('data', Buffer.from(''));
    child.emit('close', 0);
  });
  return child;
}

describe('Arjun param discovery (ENRH-03)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mkdtempMock.mockResolvedValue(FAKE_TEMP_DIR);
    rmMock.mockResolvedValue(undefined);
  });

  it('spawns arjun with -u URL -w wordlist -oJ tempfile -m GET -t 10 -T 15', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: '/opt/samureye/venv-security/bin/arjun' });
    const child = fakeChildProcess();
    spawnMock.mockReturnValueOnce(child);
    readFileMock.mockResolvedValueOnce('{}');

    await runArjun(TARGET_URL, {}, { jobId: 'job-1' });

    const [bin, args] = spawnMock.mock.calls[0];
    expect(bin).toBe('/opt/samureye/venv-security/bin/arjun');
    expect(args).toContain('-u');
    expect(args).toContain(TARGET_URL);
    expect(args).toContain('-w');
    // default wordlist
    const wIdx = args.indexOf('-w');
    expect(args[wIdx + 1]).toContain('arjun-extended-pt-en.txt');
    expect(args).toContain('-oJ');
    // tempfile is inside the mkdtemp dir
    const oJIdx = args.indexOf('-oJ');
    expect(args[oJIdx + 1]).toContain(FAKE_TEMP_DIR);
    expect(args).toContain('-m');
    expect(args).toContain('GET');
    expect(args).toContain('-t');
    expect(args).toContain('10');
    expect(args).toContain('-T');
    expect(args).toContain('15');
  });

  it('parses tempfile JSON as dict keyed by URL (not array) via Zod schema and returns params', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: '/opt/samureye/venv-security/bin/arjun' });
    const child = fakeChildProcess();
    spawnMock.mockReturnValueOnce(child);
    // Single-entry fixture keyed by TARGET_URL
    const fixtureEntry = {
      [TARGET_URL]: {
        method: 'GET',
        params: ['q', 'limit', 'offset', 'sort'],
        headers: { 'User-Agent': 'Arjun/2.2.7' },
      },
    };
    readFileMock.mockResolvedValueOnce(JSON.stringify(fixtureEntry));

    const r = await runArjun(TARGET_URL, {}, {});

    expect(r.params).toEqual(['q', 'limit', 'offset', 'sort']);
    expect(r.skipped).toBeUndefined();
  });

  it('parses multi-URL fixture file and selects correct URL entry', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: '/opt/samureye/venv-security/bin/arjun' });
    const child = fakeChildProcess();
    spawnMock.mockReturnValueOnce(child);
    readFileMock.mockResolvedValueOnce(FIXTURE_JSON);

    const r = await runArjun(TARGET_URL, {}, {});

    // Fixture has TARGET_URL with params [q, limit, offset, sort]
    expect(r.params).toEqual(['q', 'limit', 'offset', 'sort']);
  });

  it('returns skipped + empty params when preflight fails without creating tempfile', async () => {
    preflightMock.mockResolvedValueOnce({ ok: false, reason: 'arjun binary not available' });

    const r = await runArjun(TARGET_URL, {}, {});

    expect(r.skipped?.reason).toContain('arjun');
    expect(r.params).toEqual([]);
    expect(spawnMock).not.toHaveBeenCalled();
    expect(mkdtempMock).not.toHaveBeenCalled();
  });

  it('cleans tempdir in try/finally even when readFile throws (simulating SIGKILL)', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: '/opt/samureye/venv-security/bin/arjun' });
    const child = fakeChildProcess();
    spawnMock.mockReturnValueOnce(child);
    // Simulate file not written (SIGKILL path)
    readFileMock.mockRejectedValueOnce(new Error('ENOENT: no such file or directory'));

    const r = await runArjun(TARGET_URL, {}, { jobId: 'job-sigkill' });

    // Still returns empty params (not an error)
    expect(r.params).toEqual([]);
    // Cleanup MUST have run via finally
    expect(rmMock).toHaveBeenCalledWith(FAKE_TEMP_DIR, { recursive: true, force: true });
  });

  it('respects AbortSignal and calls processTracker.kill, then still cleans tempdir', async () => {
    preflightMock.mockResolvedValueOnce({ ok: true, resolvedPath: '/opt/samureye/venv-security/bin/arjun' });

    const controller = new AbortController();
    const child = new EventEmitter() as any;
    child.pid = 77777;
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = vi.fn();
    spawnMock.mockReturnValueOnce(child);

    setImmediate(() => {
      controller.abort();
      setImmediate(() => child.emit('close', 130));
    });

    readFileMock.mockRejectedValueOnce(new Error('ENOENT'));

    await runArjun(TARGET_URL, {}, { jobId: 'job-abort-arjun', signal: controller.signal });

    expect(processTrackerMock.kill).toHaveBeenCalledWith('job-abort-arjun', 77777);
    // Cleanup must still run
    expect(rmMock).toHaveBeenCalledWith(FAKE_TEMP_DIR, { recursive: true, force: true });
  });

  it('ArjunOutputSchema validates dict-keyed JSON (not array) — rejects array input', () => {
    // Valid dict-keyed structure
    const valid = {
      'https://example.com/search': {
        method: 'GET',
        params: ['q', 'limit'],
      },
    };
    expect(() => ArjunOutputSchema.parse(valid)).not.toThrow();

    // Array input must fail validation
    const invalid = [{ method: 'GET', params: ['q'] }];
    expect(() => ArjunOutputSchema.parse(invalid)).toThrow();
  });
});
