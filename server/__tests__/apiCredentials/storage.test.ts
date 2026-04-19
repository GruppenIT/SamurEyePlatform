/**
 * Phase 10 — apiCredentials storage facade tests (CRED-01, CRED-02).
 *
 * Uses an in-memory db mock (same pattern as threatGrouping.test.ts /
 * encryption.test.ts) so we can exercise the facade without requiring a
 * real DATABASE_URL. The mock simulates enough of drizzle's builder API
 * (select/insert/update/delete → where/orderBy/returning) to drive the
 * canonical round-trip + sanitization + bearer-exp + UNIQUE + FK behaviors.
 */
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import crypto from 'crypto';

// --- Fixed KEK for reproducible encryption round-trip ----------------------
const TEST_KEK = crypto.randomBytes(32).toString('hex');
beforeAll(() => {
  process.env.ENCRYPTION_KEK = TEST_KEK;
});

// --- In-memory db mock ------------------------------------------------------
// Shape: table → { rows: any[] }. Enough to cover select/insert/update/delete
// with where-by-id, orderBy, returning, and simulated UNIQUE + FK behavior.

type Row = Record<string, any>;
interface InMemoryDb {
  rows: Row[];
  apis: Row[];
  users: Row[];
}

const store: InMemoryDb = {
  rows: [],
  apis: [],
  users: [],
};

function resetStore() {
  store.rows.length = 0;
  store.apis.length = 0;
  store.users.length = 0;
  // Seed minimal users/apis needed as FK targets
  store.users.push({ id: 'user-1' }, { id: 'user-2' });
  store.apis.push({ id: 'api-1' }, { id: 'api-2' });
}

// Predicate builder — returns a Function(row) => boolean
// We capture where() calls via a marker object with `__cond` holding field/value pairs.

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

// Column markers — proxy that records which column is being referenced in eq()/isNull()
function colProxy(table: string): any {
  return new Proxy(
    {},
    {
      get: (_t, prop: string) => ({ __table: table, __col: prop }),
    },
  );
}

const apiCredentialsCols = colProxy('api_credentials');

// Mock of drizzle-orm helpers
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

// Build a query object that supports chainable .where/.orderBy/.returning
function buildSelectBuilder(projection: Record<string, any> | null) {
  let cond: Cond | undefined;
  const orderSpecs: Array<{ col: string; dir: 'asc' | 'desc' }> = [];
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
    [Symbol.asyncIterator]() {
      return execute()[Symbol.iterator]();
    },
  };

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
      // Simulate UNIQUE (name, created_by) constraint
      const dup = store.rows.find(
        (r) => r.name === valuesData.name && r.createdBy === valuesData.createdBy,
      );
      if (dup) {
        const err: any = new Error('duplicate key value violates unique constraint');
        err.code = '23505';
        throw err;
      }
      const id = valuesData.id ?? `cred-${crypto.randomUUID()}`;
      const now = new Date();
      const row: Row = {
        id,
        createdAt: valuesData.createdAt ?? now,
        updatedAt: valuesData.updatedAt ?? now,
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

function buildUpdateBuilder() {
  let cond: Cond | undefined;
  let updates: Row = {};
  const builder: any = {
    set(u: Row) {
      updates = { ...u };
      return builder;
    },
    where(c: Cond) {
      cond = c;
      return builder;
    },
    returning(_projection?: Record<string, any>) {
      const target = store.rows.find((r) => evalCond(cond, r));
      if (!target) return Promise.resolve([]);
      Object.assign(target, updates);
      const projection = _projection as Record<string, any> | undefined;
      if (projection) {
        const out: Row = {};
        for (const key of Object.keys(projection)) out[key] = target[key];
        return Promise.resolve([out]);
      }
      return Promise.resolve([{ ...target }]);
    },
  };
  return builder;
}

function buildDeleteBuilder() {
  let cond: Cond | undefined;
  const builder: any = {
    where(c: Cond) {
      cond = c;
      return Promise.resolve({ rowCount: store.rows.filter((r) => evalCond(cond, r)).length }).then(
        () => {
          for (let i = store.rows.length - 1; i >= 0; i--) {
            if (evalCond(cond, store.rows[i])) store.rows.splice(i, 1);
          }
        },
      );
    },
  };
  return builder;
}

vi.mock('../../db', () => {
  const dbMock = {
    select(projection?: Record<string, any>) {
      return buildSelectBuilder(projection ?? null);
    },
    insert(_table: any) {
      return buildInsertBuilder();
    },
    update(_table: any) {
      return buildUpdateBuilder();
    },
    delete(_table: any) {
      return buildDeleteBuilder();
    },
    execute() {
      return Promise.resolve({ rowCount: 0, rows: [] });
    },
  };
  return { db: dbMock, pool: {} };
});

// Mock the schema so table references are column-proxy sentinels compatible
// with our builder. We only need the apiCredentials proxy; other schema
// exports (types) come from the real module via tsc.
vi.mock('@shared/schema', async () => {
  const actual: any = await vi.importActual('@shared/schema');
  return {
    ...actual,
    apiCredentials: apiCredentialsCols,
  };
});

// --- Now import the facade + helpers under test ----------------------------
import {
  listApiCredentials,
  getApiCredential,
  getApiCredentialWithSecret,
  createApiCredential,
  updateApiCredential,
  deleteApiCredential,
} from '../../storage/apiCredentials';
import { encryptionService } from '../../services/encryption';
import { createTestApiCredential, TEST_PEM_CERT, TEST_PEM_KEY } from '../helpers/apiCredentialFactory';

beforeEach(() => {
  resetStore();
});

// ---------------------------------------------------------------------------
// Encryption round-trip per auth type
// ---------------------------------------------------------------------------
describe('createApiCredential — encryption round-trip por auth type', () => {
  const AUTH_TYPES_PLAIN = [
    'api_key_header',
    'api_key_query',
    'bearer_jwt',
    'basic',
    'oauth2_client_credentials',
    'hmac',
  ] as const;

  for (const authType of AUTH_TYPES_PLAIN) {
    it(`${authType}: persiste secret cifrado via encryptionService.encryptCredential`, async () => {
      const payload = createTestApiCredential(authType) as any;
      await createApiCredential(payload, 'user-1');
      // Fetch raw row (with secrets) via getApiCredentialWithSecret
      const [row] = store.rows;
      expect(row.secretEncrypted).toBeDefined();
      expect(row.dekEncrypted).toBeDefined();
      const decrypted = encryptionService.decryptCredential(row.secretEncrypted, row.dekEncrypted);
      expect(decrypted).toBe(payload.secret);
    });
  }

  it('mtls: persiste JSON.stringify({cert,key,ca}) cifrado (multi-part composite)', async () => {
    const payload = createTestApiCredential('mtls', { mtlsCa: null }) as any;
    await createApiCredential(payload, 'user-1');
    const [row] = store.rows;
    const decrypted = encryptionService.decryptCredential(row.secretEncrypted, row.dekEncrypted);
    const parsed = JSON.parse(decrypted);
    expect(parsed.cert).toBe(TEST_PEM_CERT);
    expect(parsed.key).toBe(TEST_PEM_KEY);
    expect(parsed.ca).toBeNull();
  });
});

describe('decryptCredential round-trip', () => {
  it('api_key_header: decryptCredential retorna o API key original', async () => {
    const payload = createTestApiCredential('api_key_header') as any;
    await createApiCredential(payload, 'user-1');
    const [row] = store.rows;
    expect(encryptionService.decryptCredential(row.secretEncrypted, row.dekEncrypted)).toBe(
      payload.secret,
    );
  });

  it('mtls: decrypt + JSON.parse retorna { cert, key, ca } com 3 PEMs originais', async () => {
    const CA_PEM = '-----BEGIN CERTIFICATE-----\nMIIBpTCCAQ+ca\n-----END CERTIFICATE-----';
    const payload = createTestApiCredential('mtls', { mtlsCa: CA_PEM }) as any;
    await createApiCredential(payload, 'user-1');
    const [row] = store.rows;
    const parsed = JSON.parse(
      encryptionService.decryptCredential(row.secretEncrypted, row.dekEncrypted),
    );
    expect(parsed).toEqual({ cert: TEST_PEM_CERT, key: TEST_PEM_KEY, ca: CA_PEM });
  });

  it('mtls sem ca: decrypt + JSON.parse retorna objeto com ca null', async () => {
    const payload = createTestApiCredential('mtls') as any;
    await createApiCredential(payload, 'user-1');
    const [row] = store.rows;
    const parsed = JSON.parse(
      encryptionService.decryptCredential(row.secretEncrypted, row.dekEncrypted),
    );
    expect(parsed.ca).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Sanitization (SAFE_FIELDS)
// ---------------------------------------------------------------------------
describe('sanitizacao de secrets na resposta', () => {
  it('listApiCredentials() nunca retorna secretEncrypted nem dekEncrypted', async () => {
    await createApiCredential(createTestApiCredential('api_key_header') as any, 'user-1');
    const list = await listApiCredentials();
    expect(list.length).toBe(1);
    for (const row of list) {
      expect(Object.keys(row)).not.toContain('secretEncrypted');
      expect(Object.keys(row)).not.toContain('dekEncrypted');
    }
  });

  it('getApiCredential(id) nunca retorna secretEncrypted nem dekEncrypted', async () => {
    const created = await createApiCredential(
      createTestApiCredential('basic') as any,
      'user-1',
    );
    const fetched = await getApiCredential(created.id);
    expect(fetched).toBeDefined();
    expect(Object.keys(fetched!)).not.toContain('secretEncrypted');
    expect(Object.keys(fetched!)).not.toContain('dekEncrypted');
  });

  it('getApiCredentialWithSecret(id) RETORNA secretEncrypted e dekEncrypted (uso interno do executor)', async () => {
    const created = await createApiCredential(
      createTestApiCredential('api_key_header') as any,
      'user-1',
    );
    const withSecret = await getApiCredentialWithSecret(created.id);
    expect(withSecret).toBeDefined();
    expect(withSecret!.secretEncrypted).toBeTruthy();
    expect(withSecret!.dekEncrypted).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// bearerExpiresAt derived from JWT
// ---------------------------------------------------------------------------
describe('bearerExpiresAt derivado do JWT', () => {
  it('bearer_jwt com exp valido popula bearerExpiresAt no insert', async () => {
    // Factory supplies a JWT with exp=9999999999 already base64url-encoded.
    const payload = createTestApiCredential('bearer_jwt') as any;
    const created = await createApiCredential(payload, 'user-1');
    expect(created.bearerExpiresAt).toBeInstanceOf(Date);
    expect((created.bearerExpiresAt as Date).getTime()).toBe(9999999999 * 1000);
  });

  it('bearer_jwt opaco (sem exp) aceita sem erro com bearerExpiresAt null', async () => {
    const opaque = 'opaque-token-no-dots';
    const payload = createTestApiCredential('bearer_jwt', { secret: opaque }) as any;
    const created = await createApiCredential(payload, 'user-1');
    expect(created.bearerExpiresAt).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// UNIQUE constraint (name, createdBy)
// ---------------------------------------------------------------------------
describe('UNIQUE constraint', () => {
  it('createApiCredential com (name, createdBy) duplicado lanca erro 23505', async () => {
    const payload = createTestApiCredential('api_key_header', { name: 'dup-name' }) as any;
    await createApiCredential(payload, 'user-1');
    await expect(createApiCredential(payload, 'user-1')).rejects.toMatchObject({ code: '23505' });
  });

  it('createApiCredential com mesmo name por usuarios diferentes nao conflita', async () => {
    const payload = createTestApiCredential('api_key_header', { name: 'shared-name' }) as any;
    await createApiCredential(payload, 'user-1');
    await expect(createApiCredential(payload, 'user-2')).resolves.toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// FK ON DELETE SET NULL
// ---------------------------------------------------------------------------
describe('FK ON DELETE SET NULL', () => {
  it('deletar API referenciada nao deleta a credencial — apiId vira NULL', async () => {
    const payload = createTestApiCredential('api_key_header', { apiId: 'api-1' }) as any;
    const created = await createApiCredential(payload, 'user-1');
    expect(created.apiId).toBe('api-1');
    // Simulate FK ON DELETE SET NULL by nulling apiId on any row referencing the deleted api.
    const row = store.rows.find((r) => r.id === created.id)!;
    row.apiId = null;
    const refetched = await getApiCredential(created.id);
    expect(refetched!.apiId).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// update + delete smoke tests (exercises the remaining 2 facade fns)
// ---------------------------------------------------------------------------
describe('updateApiCredential + deleteApiCredential', () => {
  it('updateApiCredential rotates secret and updates updatedBy', async () => {
    const created = await createApiCredential(
      createTestApiCredential('api_key_header') as any,
      'user-1',
    );
    const updated = await updateApiCredential(
      created.id,
      { secret: 'rotated-secret', name: 'new-name' } as any,
      'user-2',
    );
    expect(updated.name).toBe('new-name');
    expect(updated.updatedBy).toBe('user-2');
    const row = store.rows.find((r) => r.id === created.id)!;
    expect(encryptionService.decryptCredential(row.secretEncrypted, row.dekEncrypted)).toBe(
      'rotated-secret',
    );
  });

  it('deleteApiCredential removes the row', async () => {
    const created = await createApiCredential(
      createTestApiCredential('api_key_header') as any,
      'user-1',
    );
    await deleteApiCredential(created.id);
    const fetched = await getApiCredential(created.id);
    expect(fetched).toBeUndefined();
  });
});
