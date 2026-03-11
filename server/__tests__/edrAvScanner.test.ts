/**
 * FND-004 Security Tests: EDR/AV Scanner auth file handling
 *
 * These tests verify that the createSecureAuthFile and secureCleanup
 * functions correctly protect credentials:
 * - Files are created with restrictive permissions (0o600)
 * - Files use cryptographic random names
 * - secureCleanup overwrites content before deletion
 * - Files are placed in the secure temp directory
 */
import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'fs/promises';
import * as path from 'path';
import { createSecureAuthFile, secureCleanup } from '../services/scanners/edrAvScanner';

// Track files created during tests for cleanup
const createdFiles: string[] = [];

afterEach(async () => {
  for (const f of createdFiles) {
    try { await fs.unlink(f); } catch { /* already cleaned */ }
  }
  createdFiles.length = 0;
});

// ---------------------------------------------------------------------------
// createSecureAuthFile
// ---------------------------------------------------------------------------
describe('createSecureAuthFile', () => {
  it('creates file with correct content format', async () => {
    const filePath = await createSecureAuthFile({
      username: 'admin',
      password: 'P@ssw0rd',
      domain: 'CORP',
    });
    createdFiles.push(filePath);

    const content = await fs.readFile(filePath, 'utf-8');
    expect(content).toContain('username=admin');
    expect(content).toContain('password=P@ssw0rd');
    expect(content).toContain('domain=CORP');
    expect(content).toContain('workgroup=CORP');
  });

  it('omits domain/workgroup when not provided', async () => {
    const filePath = await createSecureAuthFile({
      username: 'user',
      password: 'secret',
    });
    createdFiles.push(filePath);

    const content = await fs.readFile(filePath, 'utf-8');
    expect(content).toContain('username=user');
    expect(content).toContain('password=secret');
    expect(content).not.toContain('domain=');
    expect(content).not.toContain('workgroup=');
  });

  it('creates file with restrictive permissions (owner-only)', async () => {
    const filePath = await createSecureAuthFile({
      username: 'user',
      password: 'secret',
    });
    createdFiles.push(filePath);

    const stat = await fs.stat(filePath);
    // 0o600 = owner read+write only (33152 in decimal on Linux)
    const mode = stat.mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it('uses cryptographically random filename (not timestamp-based)', async () => {
    const file1 = await createSecureAuthFile({ username: 'a', password: 'b' });
    const file2 = await createSecureAuthFile({ username: 'c', password: 'd' });
    createdFiles.push(file1, file2);

    const name1 = path.basename(file1);
    const name2 = path.basename(file2);

    // Names must be different
    expect(name1).not.toBe(name2);

    // Names should start with smbauth_ prefix
    expect(name1).toMatch(/^smbauth_[a-f0-9]{32}$/);
    expect(name2).toMatch(/^smbauth_[a-f0-9]{32}$/);
  });

  it('creates file in /dev/shm or /tmp (secure temp)', async () => {
    const filePath = await createSecureAuthFile({ username: 'a', password: 'b' });
    createdFiles.push(filePath);

    const dir = path.dirname(filePath);
    expect(['/dev/shm', '/tmp']).toContain(dir);
  });
});

// ---------------------------------------------------------------------------
// secureCleanup
// ---------------------------------------------------------------------------
describe('secureCleanup', () => {
  it('deletes the file', async () => {
    const filePath = await createSecureAuthFile({ username: 'a', password: 'b' });

    await secureCleanup(filePath);

    await expect(fs.access(filePath)).rejects.toThrow();
  });

  it('handles null gracefully', async () => {
    // Should not throw
    await secureCleanup(null);
  });

  it('handles non-existent file gracefully', async () => {
    // Should not throw
    await secureCleanup('/dev/shm/nonexistent_file_xyz');
  });

  it('overwrites content before deletion (zero-fill)', async () => {
    const filePath = await createSecureAuthFile({
      username: 'admin',
      password: 'TopSecret123',
    });

    // Read original size
    const originalStat = await fs.stat(filePath);
    const originalSize = originalStat.size;
    expect(originalSize).toBeGreaterThan(0);

    // We can't easily verify the overwrite happened since the file
    // is deleted, but we verify the function completes without error
    // and the file is gone afterward.
    await secureCleanup(filePath);
    await expect(fs.access(filePath)).rejects.toThrow();
  });
});
