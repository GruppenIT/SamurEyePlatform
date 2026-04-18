import { describe, it, expect } from 'vitest';
import { persistImage, resolveImagePath, UPLOAD_DIR } from '../imageUpload';
import { readFile } from 'fs/promises';
import path from 'path';

// Minimum viable PNG: 8-byte signature + minimal IHDR is needed for file-type to recognize.
// Use a known-good tiny PNG (1x1 transparent):
const TINY_PNG = Buffer.from([
  0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A,
  0x00,0x00,0x00,0x0D,0x49,0x48,0x44,0x52,
  0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,
  0x08,0x06,0x00,0x00,0x00,0x1F,0x15,0xC4,
  0x89,0x00,0x00,0x00,0x0D,0x49,0x44,0x41,
  0x54,0x78,0x9C,0x62,0x00,0x01,0x00,0x00,
  0x05,0x00,0x01,0x0D,0x0A,0x2D,0xB4,0x00,
  0x00,0x00,0x00,0x49,0x45,0x4E,0x44,0xAE,
  0x42,0x60,0x82,
]);

describe('persistImage', () => {
  it('rejects non-image buffer', async () => {
    await expect(persistImage(Buffer.from('hello world'))).rejects.toThrow(/inválido/);
  });
  it('accepts valid PNG buffer', async () => {
    const { filename, url } = await persistImage(TINY_PNG);
    expect(filename).toMatch(/\.png$/);
    expect(url).toBe(`/api/v1/action-plans/images/${filename}`);
    const onDisk = await readFile(path.join(UPLOAD_DIR, filename));
    expect(onDisk.length).toBeGreaterThan(0);
  });
});

describe('resolveImagePath', () => {
  it('blocks path traversal', () => {
    expect(() => resolveImagePath('../../etc/passwd')).toThrow();
  });
  it('resolves valid filename', () => {
    const p = resolveImagePath('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.png');
    expect(p).toContain(UPLOAD_DIR);
  });
});
