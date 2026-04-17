import multer from 'multer';
import { randomUUID } from 'crypto';
import { fileTypeFromBuffer } from 'file-type';
import { mkdir, writeFile } from 'fs/promises';
import path from 'path';

const MAX_BYTES = 5 * 1024 * 1024;
const ALLOWED_MIME = new Set(['image/png','image/jpeg','image/gif','image/webp']);
const MIME_TO_EXT: Record<string, string> = {
  'image/png':'png','image/jpeg':'jpg','image/gif':'gif','image/webp':'webp',
};

export const UPLOAD_DIR = process.env.SAMUREYE_UPLOAD_DIR
  ?? (process.env.NODE_ENV === 'production'
      ? '/var/lib/samureye/uploads/action-plans'
      : path.resolve(process.cwd(), 'uploads/action-plans'));

export const uploadMemory = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_BYTES, files: 1 },
});

export async function persistImage(buffer: Buffer): Promise<{ filename: string; url: string }> {
  const ft = await fileTypeFromBuffer(buffer);
  if (!ft || !ALLOWED_MIME.has(ft.mime)) {
    throw Object.assign(new Error('Formato de imagem inválido.'), { status: 415 });
  }
  const ext = MIME_TO_EXT[ft.mime];
  const filename = `${randomUUID()}.${ext}`;
  await mkdir(UPLOAD_DIR, { recursive: true });
  await writeFile(path.join(UPLOAD_DIR, filename), buffer);
  return { filename, url: `/api/v1/action-plans/images/${filename}` };
}

export function resolveImagePath(filename: string): string {
  if (!/^[a-f0-9-]+\.(png|jpe?g|gif|webp)$/i.test(filename)) {
    throw Object.assign(new Error('Nome inválido'), { status: 400 });
  }
  const resolved = path.resolve(UPLOAD_DIR, filename);
  if (!resolved.startsWith(path.resolve(UPLOAD_DIR))) {
    throw Object.assign(new Error('Path traversal'), { status: 400 });
  }
  return resolved;
}
