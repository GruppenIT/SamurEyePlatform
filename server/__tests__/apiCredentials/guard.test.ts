/**
 * Phase 10 — ensureApiCredentialTables() guard tests.
 *
 * Follows the same pattern as threatGrouping.test.ts / mfaService.test.ts:
 * the db module is mocked, so no DATABASE_URL is required. We record every
 * `db.execute` call to assert the guard's SQL lookup/CREATE sequence is
 * idempotent, that errors do not propagate (fallback mode), and that the
 * order of invocation in initializeDatabaseStructure is correct.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

// ---------------------------------------------------------------------------
// Mock state (hoisted so vi.mock factory can reference it)
// ---------------------------------------------------------------------------
const mockState = vi.hoisted(() => {
  // Each call recorded: { sqlText, params }
  const calls: Array<{ sql: string }> = [];

  // Controls what execute() returns. Default: empty (so guard thinks objects
  // don't exist yet and proceeds to CREATE).
  const responses = {
    enumExists: false,
    tableExists: false,
    indexes: new Set<string>(), // names of indexes that "exist"
    throwOn: null as null | RegExp, // when set, execute() throws if sql matches
  };

  function reset() {
    calls.length = 0;
    responses.enumExists = false;
    responses.tableExists = false;
    responses.indexes = new Set();
    responses.throwOn = null;
  }

  const execute = vi.fn(async (sqlObj: any) => {
    // drizzle's sql tagged template produces an object; stringify it for matching.
    const text =
      typeof sqlObj === 'string'
        ? sqlObj
        : // drizzle SQL object has .queryChunks / .toQuery — fall back to JSON
          JSON.stringify(sqlObj).slice(0, 500);
    calls.push({ sql: text });

    if (responses.throwOn && responses.throwOn.test(text)) {
      throw new Error('simulated db error');
    }

    // Pattern-match the lookups to respond with expected rowCount
    if (/pg_type.*api_auth_type/.test(text)) {
      return { rowCount: responses.enumExists ? 1 : 0, rows: [] };
    }
    if (/pg_tables.*api_credentials/.test(text)) {
      return { rowCount: responses.tableExists ? 1 : 0, rows: [] };
    }
    const idxMatch = text.match(/(IDX_api_credentials_[a-z_]+|UQ_api_credentials_[a-z_]+)/);
    if (idxMatch && /pg_indexes/.test(text)) {
      return { rowCount: responses.indexes.has(idxMatch[1]) ? 1 : 0, rows: [] };
    }
    // CREATE / default
    return { rowCount: 0, rows: [] };
  });

  return { calls, responses, reset, execute };
});

vi.mock('../../db', () => ({
  db: {
    execute: mockState.execute,
    select: () => ({ from: () => ({ where: () => Promise.resolve([]) }) }),
    insert: () => ({
      values: () => ({ onConflictDoNothing: () => Promise.resolve([]) }),
    }),
  },
  pool: {},
}));

// ---------------------------------------------------------------------------
// Import under test (AFTER vi.mock)
// ---------------------------------------------------------------------------
import { ensureApiCredentialTables } from '../../storage/database-init';

beforeEach(() => {
  mockState.reset();
});

// ---------------------------------------------------------------------------
describe('ensureApiCredentialTables (Phase 10 — guard idempotente)', () => {
  describe('idempotencia', () => {
    it('primeira execucao cria enum api_auth_type via CREATE TYPE', async () => {
      await ensureApiCredentialTables();
      const created = mockState.calls.some((c) =>
        /CREATE TYPE api_auth_type AS ENUM/.test(c.sql),
      );
      expect(created).toBe(true);
    });

    it('segunda execucao detecta enum existente em pg_type e nao recria', async () => {
      mockState.responses.enumExists = true;
      await ensureApiCredentialTables();
      const created = mockState.calls.some((c) =>
        /CREATE TYPE api_auth_type AS ENUM/.test(c.sql),
      );
      expect(created).toBe(false);
    });

    it('primeira execucao cria tabela api_credentials', async () => {
      await ensureApiCredentialTables();
      const created = mockState.calls.some((c) =>
        /CREATE TABLE IF NOT EXISTS api_credentials/.test(c.sql),
      );
      expect(created).toBe(true);
    });

    it('segunda execucao detecta tabela em pg_tables e nao recria', async () => {
      mockState.responses.tableExists = true;
      await ensureApiCredentialTables();
      const created = mockState.calls.some((c) =>
        /CREATE TABLE IF NOT EXISTS api_credentials/.test(c.sql),
      );
      expect(created).toBe(false);
    });

    it('primeira execucao cria todos indexes (IDX_api_credentials_api_id, IDX_api_credentials_priority, UQ_api_credentials_name_created_by)', async () => {
      await ensureApiCredentialTables();
      expect(
        mockState.calls.some((c) =>
          /CREATE INDEX .*IDX_api_credentials_api_id.* ON api_credentials/.test(c.sql),
        ),
      ).toBe(true);
      expect(
        mockState.calls.some((c) =>
          /CREATE INDEX .*IDX_api_credentials_priority.* ON api_credentials/.test(c.sql),
        ),
      ).toBe(true);
      expect(
        mockState.calls.some((c) =>
          /CREATE UNIQUE INDEX .*UQ_api_credentials_name_created_by.* ON api_credentials/.test(
            c.sql,
          ),
        ),
      ).toBe(true);
    });

    it('segunda execucao detecta cada index em pg_indexes e nao recria', async () => {
      mockState.responses.indexes = new Set([
        'IDX_api_credentials_api_id',
        'IDX_api_credentials_priority',
        'UQ_api_credentials_name_created_by',
      ]);
      await ensureApiCredentialTables();
      const createdAny = mockState.calls.some((c) =>
        /CREATE (UNIQUE )?INDEX .*api_credentials.* ON api_credentials/.test(c.sql),
      );
      expect(createdAny).toBe(false);
    });
  });

  describe('fallback mode (nao relancar erro)', () => {
    it('erro durante criacao da enum nao propaga — log.error + return', async () => {
      mockState.responses.throwOn = /CREATE TYPE api_auth_type/;
      await expect(ensureApiCredentialTables()).resolves.toBeUndefined();
    });

    it('erro durante criacao da tabela nao propaga — app continua bootando', async () => {
      mockState.responses.enumExists = true;
      mockState.responses.throwOn = /CREATE TABLE IF NOT EXISTS api_credentials/;
      await expect(ensureApiCredentialTables()).resolves.toBeUndefined();
    });
  });

  describe('ordem de invocacao no boot', () => {
    it('ensureApiCredentialTables() e chamado APOS ensureApiTables() em initializeDatabaseStructure', async () => {
      const fs = await import('node:fs/promises');
      const src = await fs.readFile('server/storage/database-init.ts', 'utf8');
      const initBlock =
        src.match(/export async function initializeDatabaseStructure[\s\S]+?\n\}/)?.[0] ?? '';
      expect(initBlock).toContain('ensureApiTables()');
      expect(initBlock).toContain('ensureApiCredentialTables()');
      const apiIdx = initBlock.indexOf('ensureApiTables()');
      const credIdx = initBlock.indexOf('ensureApiCredentialTables()');
      expect(apiIdx).toBeGreaterThan(-1);
      expect(credIdx).toBeGreaterThan(apiIdx);
    });
  });
});
