/**
 * FND-009 Security Tests: SSH host fingerprint verification (TOFU)
 *
 * These tests verify that the verifyHostFingerprint function correctly
 * implements Trust On First Use:
 * - First connection: store fingerprint
 * - Subsequent connections: detect fingerprint changes
 * - Non-blocking: never reject connections
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock storage before importing the module under test
const mockFindHostByTarget = vi.fn();
const mockUpdateHost = vi.fn();
vi.mock('../storage', () => ({
  storage: {
    findHostByTarget: (...args: any[]) => mockFindHostByTarget(...args),
    updateHost: (...args: any[]) => mockUpdateHost(...args),
  },
}));

// Mock encryption (required by sshCollector import chain)
vi.mock('../services/encryption', () => ({ encryptionService: {} }));

import { verifyHostFingerprint } from '../services/collectors/sshCollector';

beforeEach(() => {
  vi.clearAllMocks();
});

const FINGERPRINT_A = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
const FINGERPRINT_B = 'ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00';

// ---------------------------------------------------------------------------
// TOFU: First connection — store fingerprint
// ---------------------------------------------------------------------------
describe('first connection (no stored fingerprint)', () => {
  it('stores fingerprint and returns trusted', async () => {
    mockFindHostByTarget.mockResolvedValue({
      id: 'host-1',
      sshHostFingerprint: null,
    });
    mockUpdateHost.mockResolvedValue({});

    const result = await verifyHostFingerprint('192.168.1.10', FINGERPRINT_A);

    expect(result.trusted).toBe(true);
    expect(result.changed).toBe(false);
    expect(mockUpdateHost).toHaveBeenCalledWith('host-1', {
      sshHostFingerprint: FINGERPRINT_A,
    });
  });

  it('stores fingerprint when field is undefined', async () => {
    mockFindHostByTarget.mockResolvedValue({
      id: 'host-2',
      sshHostFingerprint: undefined,
    });
    mockUpdateHost.mockResolvedValue({});

    const result = await verifyHostFingerprint('10.0.0.1', FINGERPRINT_A);

    expect(result.trusted).toBe(true);
    expect(mockUpdateHost).toHaveBeenCalledWith('host-2', {
      sshHostFingerprint: FINGERPRINT_A,
    });
  });
});

// ---------------------------------------------------------------------------
// TOFU: Subsequent connection — fingerprint matches
// ---------------------------------------------------------------------------
describe('subsequent connection (fingerprint matches)', () => {
  it('returns trusted without updating DB', async () => {
    mockFindHostByTarget.mockResolvedValue({
      id: 'host-1',
      sshHostFingerprint: FINGERPRINT_A,
    });

    const result = await verifyHostFingerprint('192.168.1.10', FINGERPRINT_A);

    expect(result.trusted).toBe(true);
    expect(result.changed).toBe(false);
    expect(mockUpdateHost).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// TOFU: Fingerprint changed — potential MITM
// ---------------------------------------------------------------------------
describe('fingerprint changed (potential MITM)', () => {
  it('returns trusted=true but changed=true with previous fingerprint', async () => {
    mockFindHostByTarget.mockResolvedValue({
      id: 'host-1',
      sshHostFingerprint: FINGERPRINT_A,
    });
    mockUpdateHost.mockResolvedValue({});

    const result = await verifyHostFingerprint('192.168.1.10', FINGERPRINT_B);

    expect(result.trusted).toBe(true);
    expect(result.changed).toBe(true);
    expect(result.previousFingerprint).toBe(FINGERPRINT_A);
  });

  it('updates DB with new fingerprint (TOFU accepts new key)', async () => {
    mockFindHostByTarget.mockResolvedValue({
      id: 'host-1',
      sshHostFingerprint: FINGERPRINT_A,
    });
    mockUpdateHost.mockResolvedValue({});

    await verifyHostFingerprint('192.168.1.10', FINGERPRINT_B);

    expect(mockUpdateHost).toHaveBeenCalledWith('host-1', {
      sshHostFingerprint: FINGERPRINT_B,
    });
  });
});

// ---------------------------------------------------------------------------
// Host not found in DB
// ---------------------------------------------------------------------------
describe('host not in database', () => {
  it('returns trusted without any DB writes', async () => {
    mockFindHostByTarget.mockResolvedValue(undefined);

    const result = await verifyHostFingerprint('10.99.99.99', FINGERPRINT_A);

    expect(result.trusted).toBe(true);
    expect(result.changed).toBe(false);
    expect(mockUpdateHost).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Error handling (non-blocking)
// ---------------------------------------------------------------------------
describe('error handling', () => {
  it('returns trusted even if storage throws', async () => {
    mockFindHostByTarget.mockRejectedValue(new Error('DB connection lost'));

    const result = await verifyHostFingerprint('192.168.1.10', FINGERPRINT_A);

    expect(result.trusted).toBe(true);
    expect(result.changed).toBe(false);
  });

  it('returns trusted even if updateHost throws', async () => {
    mockFindHostByTarget.mockResolvedValue({
      id: 'host-1',
      sshHostFingerprint: null,
    });
    mockUpdateHost.mockRejectedValue(new Error('write failed'));

    const result = await verifyHostFingerprint('192.168.1.10', FINGERPRINT_A);

    // The error is caught internally — still trusted
    expect(result.trusted).toBe(true);
  });
});
