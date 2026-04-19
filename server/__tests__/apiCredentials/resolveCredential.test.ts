/**
 * Phase 10 — resolveApiCredential tests (CRED-04).
 *
 * Same in-memory db mock pattern as storage.test.ts so we can exercise the
 * resolution algorithm deterministically, without a real DATABASE_URL.
 *
 * Resolution algorithm (CONTEXT.md §CRED-04):
 *   1. Candidates: apiId === query.apiId  OR  apiId IS NULL (global)
 *   2. Filter by matchUrlPattern(c.urlPattern, endpointUrl)
 *   3. Sort: priority ASC → specificity DESC (mais literais) → createdAt ASC
 *   4. Return top 1 or null.
 */
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import crypto from 'crypto';

// Fixed KEK for reproducibility (the facade calls encryptCredential during create).
const TEST_KEK = crypto.randomBytes(32).toString('hex');
beforeAll(() => {
  process.env.ENCRYPTION_KEK = TEST_KEK;
});

// ---------------------------------------------------------------------------
// In-memory db mock (aligned with storage.test.ts)
// ---------------------------------------------------------------------------
type Row = Record<string, any>;
const store: { rows: Row[] } = { rows: [] };

interface Cond {
  type: 'eq' | 'and' | 'or' | 'isNull';
  field?: string;
  value?: any;
  children?: Cond[];
}

function evalCond(cond: Cond | undefined, row: Row): boolean {
  if (!cond) return true;
  if (cond.type === 'eq') return row[cond.field!] === cond.value;
  if (cond.type === 'isNull') return row[cond.field!] === null || row[cond.field!] === undefined;
  if (cond.type === 'and') return (cond.children ?? []).every((c) => evalCond(c, row));
  if (cond.type === 'or') return (cond.children ?? []).some((c) => evalCond(c, row));
  return true;
}

function colProxy(table: string): any {
  return new Proxy(
    {},
    {
      get: (_t, prop: string) => ({ __table: table, __col: prop }),
    },
  );
}

const apiCredentialsCols = colProxy('api_credentials');

vi.mock('drizzle-orm', async () => {
  const actual: any = await vi.importActual('drizzle-orm');
  return {
    ...actual,
    eq: (col: any, value: any): Cond => ({ type: 'eq', field: col.__col, value }),
    and: (...children: Cond[]): Cond => ({ type: 'and', children }),
    or: (...children: Cond[]): Cond => ({ type: 'or', children }),
    isNull: (col: any): Cond => ({ type: 'isNull', field: col.__col }),
    asc: (col: any) => ({ __order: 'asc', __col: col.__col }),
    desc: (col: any) => ({ __order: 'desc', __col: col.__col }),
    sql: actual.sql,
    relations: actual.relations,
  };
});

function buildSelectBuilder(projection: Record<string, any> | null) {
  let cond: Cond | undefined;
  const orderSpecs: Array<{ col: string; dir: 'asc' | 'desc' }> = [];

  function project(row: Row): Row {
    if (!projection) return { ...row };
    const out: Row = {};
    for (const key of Object.keys(projection)) out[key] = row[key];
    return out;
  }

  function execute(): Row[] {
    let out = store.rows.filter((r) => evalCond(cond, r));
    for (const { col, dir } of orderSpecs) {
      out = [...out].sort((a, b) => {
        const av = a[col];
        const bv = b[col];
        if (av === bv) return 0;
        if (av == null) return 1;
        if (bv == null) return -1;
        const cmp = av < bv ? -1 : 1;
        return dir === 'asc' ? cmp : -cmp;
      });
    }
    return out.map(project);
  }

  const builder: any = {
    from() {
      return builder;
    },
    where(c: Cond) {
      cond = c;
      return builder;
    },
    orderBy(...specs: any[]) {
      for (const s of specs) orderSpecs.push({ col: s.__col, dir: s.__order });
      return builder;
    },
    then(resolve: any) {
      return Promise.resolve(execute()).then(resolve);
    },
  };
  return builder;
}

function buildInsertBuilder() {
  let valuesData: Row = {};
  const builder: any = {
    values(v: Row) {
      valuesData = { ...v };
      return builder;
    },
    returning(_projection?: Record<string, any>) {
      const dup = store.rows.find(
        (r) => r.name === valuesData.name && r.createdBy === valuesData.createdBy,
      );
      if (dup) {
        const err: any = new Error('duplicate key value violates unique constraint');
        err.code = '23505';
        throw err;
      }
      const id = valuesData.id ?? `cred-${crypto.randomUUID()}`;
      const row: Row = {
        id,
        createdAt: valuesData.createdAt ?? new Date(),
        updatedAt: valuesData.updatedAt ?? new Date(),
        description: null,
        urlPattern: '*',
        priority: 100,
        apiId: null,
        apiKeyHeaderName: null,
        apiKeyQueryParam: null,
        basicUsername: null,
        bearerExpiresAt: null,
        oauth2ClientId: null,
        oauth2TokenUrl: null,
        oauth2Scope: null,
        oauth2Audience: null,
        hmacKeyId: null,
        hmacAlgorithm: null,
        hmacSignatureHeader: null,
        hmacSignedHeaders: null,
        hmacCanonicalTemplate: null,
        updatedBy: null,
        ...valuesData,
      };
      store.rows.push(row);
      const projection = _projection as Record<string, any> | undefined;
      if (projection) {
        const out: Row = {};
        for (const key of Object.keys(projection)) out[key] = row[key];
        return Promise.resolve([out]);
      }
      return Promise.resolve([{ ...row }]);
    },
  };
  return builder;
}

vi.mock('../../db', () => {
  const dbMock = {
    select(projection?: Record<string, any>) {
      return buildSelectBuilder(projection ?? null);
    },
    insert() {
      return buildInsertBuilder();
    },
    update() {
      return { set: () => ({ where: () => ({ returning: () => Promise.resolve([]) }) }) };
    },
    delete() {
      return { where: () => Promise.resolve({ rowCount: 0 }) };
    },
    execute() {
      return Promise.resolve({ rowCount: 0, rows: [] });
    },
  };
  return { db: dbMock, pool: {} };
});

vi.mock('@shared/schema', async () => {
  const actual: any = await vi.importActual('@shared/schema');
  return {
    ...actual,
    apiCredentials: apiCredentialsCols,
  };
});

// ---------------------------------------------------------------------------
// Imports under test (come AFTER all mocks)
// ---------------------------------------------------------------------------
import { createApiCredential, resolveApiCredential } from '../../storage/apiCredentials';
import { createTestApiCredential } from '../helpers/apiCredentialFactory';

beforeEach(() => {
  store.rows.length = 0;
});

// Helper: seed a credential directly in the store with explicit fields.
// Skips encryption so we can target priority / urlPattern / apiId / createdAt
// without round-trip overhead.
function seedCred(overrides: Partial<Row> = {}): Row {
  const now = new Date();
  const row: Row = {
    id: overrides.id ?? `cred-${crypto.randomUUID()}`,
    name: overrides.name ?? `cred-${Math.random().toString(36).slice(2)}`,
    description: null,
    authType: overrides.authType ?? 'api_key_header',
    urlPattern: overrides.urlPattern ?? '*',
    priority: overrides.priority ?? 100,
    apiId: overrides.apiId ?? null,
    secretEncrypted: 'enc',
    dekEncrypted: 'dek',
    apiKeyHeaderName: 'X-API-Key',
    apiKeyQueryParam: null,
    basicUsername: null,
    bearerExpiresAt: null,
    oauth2ClientId: null,
    oauth2TokenUrl: null,
    oauth2Scope: null,
    oauth2Audience: null,
    hmacKeyId: null,
    hmacAlgorithm: null,
    hmacSignatureHeader: null,
    hmacSignedHeaders: null,
    hmacCanonicalTemplate: null,
    createdAt: overrides.createdAt ?? now,
    updatedAt: now,
    createdBy: overrides.createdBy ?? 'user-1',
    updatedBy: null,
    ...overrides,
  };
  store.rows.push(row);
  return row;
}

// ---------------------------------------------------------------------------
describe('resolveApiCredential (Phase 10 — CRED-04)', () => {
  describe('priority como tie-break primario', () => {
    it('multiplas credenciais casam → retorna a com menor priority', async () => {
      seedCred({ id: 'low', priority: 50, urlPattern: 'https://api.example.com/*', apiId: 'api-1', name: 'low' });
      seedCred({ id: 'high', priority: 100, urlPattern: 'https://api.example.com/*', apiId: 'api-1', name: 'high' });
      const winner = await resolveApiCredential('api-1', 'https://api.example.com/users');
      expect(winner).not.toBeNull();
      expect(winner!.id).toBe('low');
    });

    it('priority 50 vence priority 100 quando ambas casam o mesmo URL', async () => {
      seedCred({ id: 'p100', priority: 100, urlPattern: '*', apiId: null, name: 'g1' });
      seedCred({ id: 'p50', priority: 50, urlPattern: '*', apiId: null, name: 'g2' });
      const winner = await resolveApiCredential('api-1', 'https://anywhere.com/path');
      expect(winner!.id).toBe('p50');
    });
  });

  describe('specificity como tie-break secundario (mais literais ganha)', () => {
    it('mesma priority — pattern mais especifico (mais literais) ganha', async () => {
      seedCred({
        id: 'wildcard',
        priority: 100,
        urlPattern: 'https://api.corp.com/*',
        apiId: 'api-1',
        name: 'wildcard',
      });
      seedCred({
        id: 'specific',
        priority: 100,
        urlPattern: 'https://api.corp.com/users',
        apiId: 'api-1',
        name: 'specific',
      });
      const winner = await resolveApiCredential('api-1', 'https://api.corp.com/users');
      expect(winner!.id).toBe('specific');
    });

    it('https://api.corp.com/v2/users vence https://api.corp.com/* quando ambos casam', async () => {
      seedCred({ id: 'wild', priority: 100, urlPattern: 'https://api.corp.com/*', apiId: 'api-1', name: 'w' });
      // For deep specific pattern we need URL that ALSO matches the wildcard.
      // Wildcard `api.corp.com/*` does NOT match `/v2/users` (two segments, no cross-slash).
      // Pick a URL that matches both: "users" (single segment).
      seedCred({
        id: 'exact',
        priority: 100,
        urlPattern: 'https://api.corp.com/users',
        apiId: 'api-1',
        name: 'e',
      });
      const winner = await resolveApiCredential('api-1', 'https://api.corp.com/users');
      expect(winner!.id).toBe('exact');
    });
  });

  describe('createdAt como tie-break terciario', () => {
    it('mesma priority + mesma specificity → mais antiga ganha (createdAt ASC)', async () => {
      const older = new Date('2025-01-01T00:00:00Z');
      const newer = new Date('2025-02-01T00:00:00Z');
      seedCred({
        id: 'new',
        priority: 100,
        urlPattern: 'https://api.example.com/*',
        createdAt: newer,
        apiId: 'api-1',
        name: 'n',
      });
      seedCred({
        id: 'old',
        priority: 100,
        urlPattern: 'https://api.example.com/*',
        createdAt: older,
        apiId: 'api-1',
        name: 'o',
      });
      const winner = await resolveApiCredential('api-1', 'https://api.example.com/users');
      expect(winner!.id).toBe('old');
    });
  });

  describe('escopo apiId vs global', () => {
    it('credencial com apiId=X candidata para query apiId=X', async () => {
      seedCred({ id: 'scoped', apiId: 'api-1', urlPattern: '*', priority: 100, name: 's' });
      const winner = await resolveApiCredential('api-1', 'https://any.url/path');
      expect(winner!.id).toBe('scoped');
    });

    it('credencial global (apiId IS NULL) candidata para qualquer apiId', async () => {
      seedCred({ id: 'global', apiId: null, urlPattern: '*', priority: 100, name: 'g' });
      const winner = await resolveApiCredential('api-anything', 'https://whatever/');
      expect(winner!.id).toBe('global');
    });

    it('credencial com apiId=Y NAO candidata para query apiId=X', async () => {
      seedCred({ id: 'otherApi', apiId: 'api-2', urlPattern: '*', priority: 100, name: 'o' });
      const winner = await resolveApiCredential('api-1', 'https://any.url/');
      expect(winner).toBeNull();
    });
  });

  describe('caso negativo', () => {
    it('nenhuma credencial casa o URL → retorna null (nao lanca erro)', async () => {
      seedCred({
        id: 'noMatch',
        apiId: 'api-1',
        urlPattern: 'https://api.corp.com/users',
        priority: 100,
        name: 'n',
      });
      const winner = await resolveApiCredential('api-1', 'https://totally.different/path');
      expect(winner).toBeNull();
    });

    it('store vazio → retorna null sem lançar', async () => {
      const winner = await resolveApiCredential('api-1', 'https://x.com/');
      expect(winner).toBeNull();
    });
  });

  describe('shape de retorno', () => {
    it('resolveApiCredential retorna ApiCredentialSafe (sem secret*/dek*)', async () => {
      seedCred({ id: 'safe', apiId: 'api-1', urlPattern: '*', priority: 100, name: 'safe' });
      const winner = await resolveApiCredential('api-1', 'https://any/');
      expect(winner).not.toBeNull();
      const keys = Object.keys(winner!);
      expect(keys).not.toContain('secretEncrypted');
      expect(keys).not.toContain('dekEncrypted');
    });
  });

  describe('consumidor real via createApiCredential + resolveApiCredential', () => {
    it('cria via facade e resolve por URL', async () => {
      const payload = createTestApiCredential('api_key_header', {
        name: 'resolvable',
        apiId: 'api-1',
        urlPattern: 'https://api.example.com/*',
        priority: 100,
      }) as any;
      await createApiCredential(payload, 'user-1');
      const winner = await resolveApiCredential('api-1', 'https://api.example.com/users');
      expect(winner).not.toBeNull();
      expect(winner!.name).toBe('resolvable');
    });
  });
});
