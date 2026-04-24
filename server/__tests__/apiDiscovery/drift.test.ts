/**
 * Phase 11 DISC-06 — spec drift detection real tests.
 * Covers: no drift (null hash), no drift (same hash), drift detected (log.warn),
 * and updateApiSpecMetadata called with new hash even on drift.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// --- Mocks (hoisted before imports) ---
const storageMock = vi.hoisted(() => ({
  getApi: vi.fn(),
  updateApiSpecMetadata: vi.fn().mockResolvedValue({}),
  upsertApiEndpoints: vi.fn().mockResolvedValue({ inserted: 0, updated: 0 }),
  listEndpointsByApi: vi.fn().mockResolvedValue([]),
  markEndpointsStale: vi.fn().mockResolvedValue([]),
  resolveApiCredential: vi.fn().mockResolvedValue(null),
  getApiCredential: vi.fn().mockResolvedValue(null),
  getApiCredentialWithSecret: vi.fn().mockResolvedValue(undefined),
  mergeHttpxEnrichment: vi.fn().mockResolvedValue(undefined),
  appendQueryParams: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../storage', () => ({ storage: storageMock }));

const warnSpy = vi.hoisted(() => vi.fn());
vi.mock('../../lib/logger', () => ({
  createLogger: () => ({
    info: vi.fn(),
    warn: warnSpy,
    error: vi.fn(),
    debug: vi.fn(),
  }),
}));

// Mock scanners — fetchAndParseSpec returns a fixed hash.
vi.mock('../../services/scanners/api/openapi', () => ({
  fetchAndParseSpec: vi.fn().mockResolvedValue({
    spec: { openapi: '3.0.0', paths: {} },
    specUrl: 'https://target/openapi.json',
    specHash: 'new_hash_xxx',
    specVersion: '3.0.0',
  }),
  specToEndpoints: vi.fn().mockReturnValue([]),
}));

vi.mock('../../services/scanners/api/graphql', () => ({
  probeGraphQL: vi.fn().mockResolvedValue(null),
  schemaToEndpoints: vi.fn().mockReturnValue([]),
}));

vi.mock('../../services/scanners/api/katana', () => ({
  runKatana: vi.fn().mockResolvedValue({ skipped: { reason: 'test' }, endpoints: [] }),
}));

vi.mock('../../services/scanners/api/kiterunner', () => ({
  runKiterunner: vi.fn().mockResolvedValue({ skipped: { reason: 'test' }, endpoints: [] }),
}));

vi.mock('../../services/scanners/api/httpx', () => ({
  runHttpx: vi.fn().mockResolvedValue({ results: [] }),
  mapRequiresAuth: vi.fn().mockReturnValue(null),
}));

vi.mock('../../services/scanners/api/arjun', () => ({
  runArjun: vi.fn().mockResolvedValue({ params: [] }),
}));

import { discoverApi } from '../../services/journeys/apiDiscovery';

// Minimal opts — only spec stage enabled to isolate drift logic.
const specOnlyOpts = {
  stages: { spec: true, crawler: false, kiterunner: false, httpx: false, arjun: false },
  dryRun: false,
} as any;

describe('spec drift detection (DISC-06)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset mocks to defaults after clearAllMocks wipes them.
    storageMock.updateApiSpecMetadata.mockResolvedValue({});
    storageMock.upsertApiEndpoints.mockResolvedValue({ inserted: 0, updated: 0 });
    storageMock.listEndpointsByApi.mockResolvedValue([]);
    storageMock.markEndpointsStale.mockResolvedValue([]);
    storageMock.resolveApiCredential.mockResolvedValue(null);
    storageMock.getApiCredential.mockResolvedValue(null);
    storageMock.getApiCredentialWithSecret.mockResolvedValue(undefined);
    storageMock.mergeHttpxEnrichment.mockResolvedValue(undefined);
    storageMock.appendQueryParams.mockResolvedValue(undefined);
  });

  it('no log.warn when api.spec_hash is null (first probe)', async () => {
    storageMock.getApi.mockResolvedValueOnce({
      id: 'api-1',
      baseUrl: 'https://target',
      apiType: 'rest',
      specHash: null,
    });

    const r = await discoverApi('api-1', specOnlyOpts);

    expect(r.specFetched?.driftDetected).toBe(false);
    // warnSpy might be called for other reasons but NOT for 'spec drift detected'
    const driftCalls = warnSpy.mock.calls.filter((c) => c[1] === 'spec drift detected');
    expect(driftCalls).toHaveLength(0);
    expect(storageMock.updateApiSpecMetadata).toHaveBeenCalled();
  });

  it('no log.warn when hash unchanged', async () => {
    storageMock.getApi.mockResolvedValueOnce({
      id: 'api-1',
      baseUrl: 'https://target',
      apiType: 'rest',
      specHash: 'new_hash_xxx', // same as what fetchAndParseSpec returns
    });

    const r = await discoverApi('api-1', specOnlyOpts);

    expect(r.specFetched?.driftDetected).toBe(false);
    const driftCalls = warnSpy.mock.calls.filter((c) => c[1] === 'spec drift detected');
    expect(driftCalls).toHaveLength(0);
  });

  it('log.warn fires with oldHash and newHash when drift detected', async () => {
    storageMock.getApi.mockResolvedValueOnce({
      id: 'api-1',
      baseUrl: 'https://target',
      apiType: 'rest',
      specHash: 'old_hash', // different from 'new_hash_xxx'
    });

    const r = await discoverApi('api-1', specOnlyOpts);

    expect(r.specFetched?.driftDetected).toBe(true);
    const driftCall = warnSpy.mock.calls.find((c) => c[1] === 'spec drift detected');
    expect(driftCall).toBeDefined();
    expect(driftCall![0]).toMatchObject({
      apiId: 'api-1',
      oldHash: 'old_hash',
      newHash: 'new_hash_xxx',
    });
  });

  it('updateApiSpecMetadata called with new hash even on drift (pipeline does not abort)', async () => {
    storageMock.getApi.mockResolvedValueOnce({
      id: 'api-1',
      baseUrl: 'https://target',
      apiType: 'rest',
      specHash: 'old_hash', // drift scenario
    });

    await discoverApi('api-1', specOnlyOpts);

    expect(storageMock.updateApiSpecMetadata).toHaveBeenCalledWith(
      'api-1',
      expect.objectContaining({
        specHash: 'new_hash_xxx',
        specVersion: '3.0.0',
      }),
    );
    // Endpoints also upserted — pipeline continued
    expect(storageMock.upsertApiEndpoints).toHaveBeenCalled();
  });
});
