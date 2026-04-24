// Phase 11 — API Discovery & Enrichment orchestrator.
// Sequences spec → crawler → kiterunner → httpx → arjun per CONTEXT.md.
// Each stage fails independently (log + skip); pipeline continues.
// Partial results persist on cancel — endpoints already upserted are NOT rolled back.
import type { Api, ApiEndpoint, InsertApiEndpoint } from '@shared/schema';
import type { DiscoverApiOpts } from '@shared/schema';
import { createLogger } from '../../lib/logger';
import { storage } from '../../storage';
import { fetchAndParseSpec, specToEndpoints } from '../scanners/api/openapi';
import { probeGraphQL, schemaToEndpoints } from '../scanners/api/graphql';
import { runKatana, type KatanaCredential } from '../scanners/api/katana';
import { runKiterunner } from '../scanners/api/kiterunner';
import { runHttpx, mapRequiresAuth } from '../scanners/api/httpx';
import { runArjun } from '../scanners/api/arjun';

const log = createLogger('journeys:apiDiscovery');

const ARJUN_WORDLIST = '/opt/samureye/wordlists/arjun-extended-pt-en.txt';

export interface DiscoveryResult {
  apiId: string;
  stagesRun: Array<'spec' | 'crawler' | 'kiterunner' | 'httpx' | 'arjun'>;
  stagesSkipped: Array<{ stage: string; reason: string }>;
  endpointsDiscovered: number;
  endpointsUpdated: number;
  endpointsStale: string[];
  newEndpointIds: string[]; // IDs of endpoints inserted for the first time this run
  specFetched?: {
    url: string;
    version: string;
    hash: string;
    driftDetected: boolean;
  };
  cancelled: boolean;
  durationMs: number;
}

export async function discoverApi(
  apiId: string,
  opts: DiscoverApiOpts,
  jobId?: string,
): Promise<DiscoveryResult> {
  const startedAt = Date.now();
  const controller = new AbortController();
  const signal = controller.signal;

  const stagesRun: DiscoveryResult['stagesRun'] = [];
  const stagesSkipped: DiscoveryResult['stagesSkipped'] = [];
  let endpointsDiscovered = 0;
  let endpointsUpdated = 0;
  const allNewEndpointIds: string[] = [];
  let specFetched: DiscoveryResult['specFetched'] | undefined;
  let cancelled = false;

  const api = await storage.getApi(apiId);
  if (!api) {
    throw new Error(`API não encontrada: ${apiId}`);
  }

  // dryRun forces off crawler/kiterunner/arjun — explicit override semantics.
  // spec and httpx are kept on.
  const effectiveStages = {
    spec: opts.stages.spec ?? true,
    crawler: opts.dryRun ? false : (opts.stages.crawler ?? true),
    kiterunner: opts.dryRun ? false : (opts.stages.kiterunner ?? false),
    httpx: opts.stages.httpx ?? true,
    arjun: opts.dryRun ? false : (opts.stages.arjun ?? false),
  };

  log.info(
    { apiId, jobId, baseUrl: api.baseUrl, apiType: api.apiType, stages: effectiveStages, dryRun: opts.dryRun ?? false },
    'discoverApi started',
  );

  // ─── STAGE: SPEC ─────────────────────────────────────────────────────────────
  if (effectiveStages.spec) {
    try {
      const specResult = await runSpecStage(api, opts, signal);
      if (specResult) {
        stagesRun.push('spec');
        specFetched = specResult.specFetched;
        const counts = await storage.upsertApiEndpoints(apiId, specResult.endpoints);
        endpointsDiscovered += counts.inserted;
        endpointsUpdated += counts.updated;
        allNewEndpointIds.push(...counts.newEndpointIds);
      } else {
        stagesSkipped.push({ stage: 'spec', reason: 'no spec found' });
      }
    } catch (err) {
      log.error({ err: String(err), apiId, stage: 'spec' }, 'stage failed');
      stagesSkipped.push({ stage: 'spec', reason: String(err) });
    }
  } else {
    stagesSkipped.push({ stage: 'spec', reason: opts.dryRun ? 'dryRun' : 'disabled' });
  }

  if (signal.aborted) { cancelled = true; return await finalize(); }

  // ─── STAGE: CRAWLER (Katana) ──────────────────────────────────────────────────
  if (effectiveStages.crawler) {
    try {
      const credential = await buildKatanaCredential(apiId, api.baseUrl, opts.credentialIdOverride);
      const katanaResult = await runKatana(
        api.baseUrl,
        { depth: opts.katana?.depth, headless: opts.katana?.headless, credential },
        { apiId, jobId, signal },
      );
      if (katanaResult.skipped) {
        stagesSkipped.push({ stage: 'crawler', reason: katanaResult.skipped.reason });
      } else {
        stagesRun.push('crawler');
        const counts = await storage.upsertApiEndpoints(apiId, katanaResult.endpoints);
        endpointsDiscovered += counts.inserted;
        endpointsUpdated += counts.updated;
        allNewEndpointIds.push(...counts.newEndpointIds);
      }
    } catch (err) {
      log.error({ err: String(err), apiId, stage: 'crawler' }, 'stage failed');
      stagesSkipped.push({ stage: 'crawler', reason: String(err) });
    }
  } else {
    stagesSkipped.push({ stage: 'crawler', reason: opts.dryRun ? 'dryRun' : 'disabled' });
  }

  if (signal.aborted) { cancelled = true; return await finalize(); }

  // ─── STAGE: KITERUNNER (opt-in) ───────────────────────────────────────────────
  if (effectiveStages.kiterunner) {
    try {
      const krResult = await runKiterunner(
        api.baseUrl,
        { rateLimit: opts.kiterunner?.rateLimit },
        { apiId, jobId, signal },
      );
      if (krResult.skipped) {
        stagesSkipped.push({ stage: 'kiterunner', reason: krResult.skipped.reason });
      } else {
        stagesRun.push('kiterunner');
        const counts = await storage.upsertApiEndpoints(apiId, krResult.endpoints);
        endpointsDiscovered += counts.inserted;
        endpointsUpdated += counts.updated;
        allNewEndpointIds.push(...counts.newEndpointIds);
      }
    } catch (err) {
      log.error({ err: String(err), apiId, stage: 'kiterunner' }, 'stage failed');
      stagesSkipped.push({ stage: 'kiterunner', reason: String(err) });
    }
  } else {
    stagesSkipped.push({
      stage: 'kiterunner',
      reason: opts.dryRun ? 'dryRun' : 'disabled (opt-in)',
    });
  }

  if (signal.aborted) { cancelled = true; return await finalize(); }

  // ─── STAGE: HTTPX (2-pass) ────────────────────────────────────────────────────
  let allEndpoints: ApiEndpoint[] = [];
  if (effectiveStages.httpx) {
    try {
      allEndpoints = await storage.listEndpointsByApi(apiId);
      const urls = allEndpoints.map((e) => buildFullUrl(api.baseUrl, e.path));

      {
        const pass1 = await runHttpx(urls, {}, { jobId, signal });
        if (pass1.skipped) {
          stagesSkipped.push({ stage: 'httpx', reason: pass1.skipped.reason });
        } else {
          stagesRun.push('httpx');

          // Pass 1: merge enrichment; build requiresAuth index.
          for (const ep of allEndpoints) {
            const fullUrl = buildFullUrl(api.baseUrl, ep.path);
            const pr = pass1.results.find((r) => r.inputUrl === fullUrl || r.url === fullUrl);
            if (!pr) continue;
            await storage.mergeHttpxEnrichment(ep.id, {
              status: pr.status,
              contentType: pr.contentType,
              tech: pr.tech,
              tls: pr.tls,
            });
          }

          // Pass 2: auth probe for endpoints flagged requiresAuth=true with compatible cred.
          const authItems: Array<{ url: string; endpointId: string; authHeader: string }> = [];
          for (const ep of allEndpoints) {
            const fullUrl = buildFullUrl(api.baseUrl, ep.path);
            const pr = pass1.results.find((r) => r.inputUrl === fullUrl || r.url === fullUrl);
            if (pr?.requiresAuth === true) {
              const authHeader = await resolveCompatibleAuthHeader(
                apiId,
                fullUrl,
                opts.credentialIdOverride,
              );
              if (authHeader) {
                authItems.push({ url: fullUrl, endpointId: ep.id, authHeader });
              }
            }
          }

          if (authItems.length > 0) {
            // Group by authHeader (typically one per API).
            const grouped = new Map<string, string[]>();
            for (const item of authItems) {
              if (!grouped.has(item.authHeader)) grouped.set(item.authHeader, []);
              grouped.get(item.authHeader)!.push(item.url);
            }
            for (const [authHeader, groupUrls] of grouped) {
              const pass2 = await runHttpx(groupUrls, { authHeader }, { jobId, signal });
              if (!pass2.skipped) {
                for (const ep of allEndpoints) {
                  const fullUrl = buildFullUrl(api.baseUrl, ep.path);
                  const pr = pass2.results.find((r) => r.inputUrl === fullUrl || r.url === fullUrl);
                  if (!pr) continue;
                  await storage.mergeHttpxEnrichment(ep.id, {
                    status: pr.status,
                    contentType: pr.contentType,
                    tech: pr.tech,
                    tls: pr.tls,
                  });
                }
              }
            }
          }
        }
      }
    } catch (err) {
      log.error({ err: String(err), apiId, stage: 'httpx' }, 'stage failed');
      stagesSkipped.push({ stage: 'httpx', reason: String(err) });
    }
  } else {
    stagesSkipped.push({ stage: 'httpx', reason: opts.dryRun ? 'dryRun' : 'disabled' });
  }

  if (signal.aborted) { cancelled = true; return await finalize(); }

  // ─── STAGE: ARJUN (opt-in + user-selected) ────────────────────────────────────
  if (effectiveStages.arjun) {
    try {
      if (!opts.arjunEndpointIds || opts.arjunEndpointIds.length === 0) {
        throw new Error('arjunEndpointIds obrigatório quando stages.arjun=true');
      }
      if (allEndpoints.length === 0) {
        allEndpoints = await storage.listEndpointsByApi(apiId);
      }
      const endpointsById = new Map(allEndpoints.map((e) => [e.id, e]));
      const selected: ApiEndpoint[] = [];
      for (const id of opts.arjunEndpointIds) {
        const ep = endpointsById.get(id);
        if (!ep) throw new Error(`arjunEndpointId ${id} não existe em api_endpoints`);
        if (ep.apiId !== apiId) throw new Error(`arjunEndpointId ${id} pertence a apiId diferente`);
        if (ep.method !== 'GET') throw new Error(`arjunEndpointId ${id} inválido: method=${ep.method} (deve ser GET)`);
        selected.push(ep);
      }
      stagesRun.push('arjun');
      for (const ep of selected) {
        if (signal.aborted) break;
        const url = buildFullUrl(api.baseUrl, ep.path);
        const result = await runArjun(url, { wordlistPath: ARJUN_WORDLIST }, { jobId, signal });
        if (result.skipped) {
          log.warn({ endpointId: ep.id, reason: result.skipped.reason }, 'arjun skipped for endpoint');
          continue;
        }
        if (result.params.length > 0) {
          await storage.appendQueryParams(ep.id, result.params.map((name) => ({ name })));
        }
      }
    } catch (err) {
      log.error({ err: String(err), apiId, stage: 'arjun' }, 'stage failed');
      stagesSkipped.push({ stage: 'arjun', reason: String(err) });
    }
  } else {
    stagesSkipped.push({
      stage: 'arjun',
      reason: opts.dryRun ? 'dryRun' : 'disabled (opt-in)',
    });
  }

  if (signal.aborted) cancelled = true;
  return await finalize();

  // ─── Closure helpers ──────────────────────────────────────────────────────────

  async function finalize(): Promise<DiscoveryResult> {
    let endpointsStale: string[] = [];
    try {
      const currentAll = await storage.listEndpointsByApi(apiId);
      const runStart = new Date(startedAt);
      const staleIds = currentAll
        .filter((e) => e.updatedAt < runStart)
        .map((e) => e.id);
      if (staleIds.length > 0) {
        endpointsStale = await storage.markEndpointsStale(apiId, staleIds);
      }
    } catch (err) {
      log.warn({ err: String(err), apiId }, 'failed to compute stale endpoints');
    }

    const result: DiscoveryResult = {
      apiId,
      stagesRun,
      stagesSkipped,
      endpointsDiscovered,
      endpointsUpdated,
      endpointsStale,
      newEndpointIds: [...new Set(allNewEndpointIds)], // dedupe across stages
      specFetched,
      cancelled,
      durationMs: Date.now() - startedAt,
    };
    log.info(
      {
        ...result,
        specFetched: result.specFetched
          ? { url: result.specFetched.url, driftDetected: result.specFetched.driftDetected }
          : undefined,
      },
      'discoverApi finished',
    );
    return result;
  }
}

// ─── Stage helpers ───────────────────────────────────────────────────────────

async function runSpecStage(
  api: Api,
  opts: DiscoverApiOpts,
  signal: AbortSignal,
): Promise<{ endpoints: InsertApiEndpoint[]; specFetched: DiscoveryResult['specFetched'] } | null> {
  if (api.apiType === 'graphql') {
    const authHeader = await resolveCompatibleAuthHeader(api.id, api.baseUrl, opts.credentialIdOverride);
    const probe = await probeGraphQL(api.baseUrl, authHeader, signal);
    if (!probe) return null;
    const endpoints = schemaToEndpoints(probe.schema, api.id, probe.endpointPath);

    // Compute hash for GraphQL schema
    const { computeCanonicalHash } = await import('../scanners/api/specHash');
    const specHash = computeCanonicalHash(probe.schema);
    const driftDetected = api.specHash !== null && api.specHash !== specHash;
    if (driftDetected) {
      log.warn({ apiId: api.id, oldHash: api.specHash, newHash: specHash }, 'spec drift detected');
    }
    const specUrl = new URL(probe.endpointPath, api.baseUrl).toString();
    await storage.updateApiSpecMetadata(api.id, { specUrl, specVersion: 'GraphQL', specHash });
    return {
      endpoints,
      specFetched: { url: specUrl, version: 'GraphQL', hash: specHash, driftDetected },
    };
  }

  // REST/OpenAPI path — unauth first, retry with compatible cred on failure.
  let result = await fetchAndParseSpec(api.baseUrl, undefined, signal);
  if (!result) {
    const authHeader = await resolveCompatibleAuthHeader(api.id, api.baseUrl, opts.credentialIdOverride);
    if (authHeader) {
      result = await fetchAndParseSpec(api.baseUrl, authHeader, signal);
    }
  }
  if (!result) return null;

  const driftDetected = api.specHash !== null && api.specHash !== result.specHash;
  if (driftDetected) {
    log.warn(
      { apiId: api.id, oldHash: api.specHash, newHash: result.specHash },
      'spec drift detected',
    );
  }
  await storage.updateApiSpecMetadata(api.id, {
    specUrl: result.specUrl,
    specVersion: result.specVersion,
    specHash: result.specHash,
  });
  return {
    endpoints: specToEndpoints(result.spec, api.id),
    specFetched: {
      url: result.specUrl,
      version: result.specVersion,
      hash: result.specHash,
      driftDetected,
    },
  };
}

async function resolveCompatibleAuthHeader(
  apiId: string,
  url: string,
  credIdOverride: string | undefined,
): Promise<string | undefined> {
  // Compatible for spec/graphql/httpx: api_key_header, bearer_jwt, basic, oauth2.
  // Incompatible: hmac, mtls (katana handles mtls internally), api_key_query.
  const credSafe = credIdOverride
    ? await storage.getApiCredential(credIdOverride)
    : await storage.resolveApiCredential(apiId, url);
  if (!credSafe) return undefined;

  const incompat = ['hmac', 'mtls', 'api_key_query'];
  if (incompat.includes(credSafe.authType)) {
    log.warn({ apiId, authType: credSafe.authType }, 'spec auth skip — incompatible cred type');
    return undefined;
  }

  const withSecret = await storage.getApiCredentialWithSecret(credSafe.id);
  if (!withSecret) return undefined;

  switch (withSecret.authType) {
    case 'api_key_header':
      return `${withSecret.apiKeyHeaderName ?? 'X-API-Key'}: ${withSecret.secretDecrypted}`;
    case 'bearer_jwt':
      return `Bearer ${withSecret.secretDecrypted}`;
    case 'basic':
      return `Basic ${withSecret.secretDecrypted}`;
    case 'oauth2_client_credentials': {
      const token = await mintOAuth2TokenCached(withSecret);
      return token ? `Bearer ${token}` : undefined;
    }
    default:
      return undefined;
  }
}

async function buildKatanaCredential(
  apiId: string,
  baseUrl: string,
  credIdOverride: string | undefined,
): Promise<KatanaCredential | undefined> {
  const credSafe = credIdOverride
    ? await storage.getApiCredential(credIdOverride)
    : await storage.resolveApiCredential(apiId, baseUrl);
  if (!credSafe) return undefined;

  const withSecret = await storage.getApiCredentialWithSecret(credSafe.id);
  if (!withSecret) return undefined;

  switch (withSecret.authType) {
    case 'api_key_header':
      return {
        authType: 'api_key_header',
        headerName: withSecret.apiKeyHeaderName ?? 'X-API-Key',
        secret: withSecret.secretDecrypted,
      };
    case 'bearer_jwt':
      return { authType: 'bearer_jwt', secret: withSecret.secretDecrypted };
    case 'basic':
      return { authType: 'basic', secret: withSecret.secretDecrypted };
    case 'oauth2_client_credentials':
      return {
        authType: 'oauth2_client_credentials',
        tokenUrl: withSecret.oauth2TokenUrl ?? '',
        clientId: withSecret.oauth2ClientId ?? '',
        clientSecret: withSecret.secretDecrypted,
        scope: withSecret.oauth2Scope ?? undefined,
      };
    case 'mtls': {
      const mtlsData = JSON.parse(withSecret.secretDecrypted) as {
        cert: string;
        key: string;
        ca?: string;
      };
      return {
        authType: 'mtls',
        credId: withSecret.id,
        cert: mtlsData.cert,
        key: mtlsData.key,
        ca: mtlsData.ca,
      };
    }
    case 'api_key_query':
      return {
        authType: 'api_key_query',
        paramName: withSecret.apiKeyQueryParam ?? 'api_key',
        secret: withSecret.secretDecrypted,
      };
    case 'hmac':
      return { authType: 'hmac' };
    default:
      return undefined;
  }
}

function buildFullUrl(baseUrl: string, path: string): string {
  try {
    return new URL(path, baseUrl).toString();
  } catch {
    return `${baseUrl.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`;
  }
}

// ─── OAuth2 token cache (in-memory, per-process, per run) ────────────────────
// Ephemeral: not persisted. Phase 15 can centralize caching if needed.
const oauth2Cache = new Map<string, { token: string; expiresAt: number }>();

async function mintOAuth2TokenCached(
  cred: {
    id: string;
    oauth2TokenUrl?: string | null;
    oauth2ClientId?: string | null;
    secretDecrypted: string;
    oauth2Scope?: string | null;
  },
): Promise<string | null> {
  const now = Date.now();
  const cached = oauth2Cache.get(cred.id);
  if (cached && cached.expiresAt > now) return cached.token;

  if (!cred.oauth2TokenUrl || !cred.oauth2ClientId) return null;

  try {
    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: cred.oauth2ClientId,
      client_secret: cred.secretDecrypted,
      ...(cred.oauth2Scope ? { scope: cred.oauth2Scope } : {}),
    });
    const res = await fetch(cred.oauth2TokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { access_token?: string; expires_in?: number };
    if (!data.access_token) return null;
    // Cache with 30s buffer before expiry (per Phase 10 CONTEXT.md).
    const ttlMs = ((data.expires_in ?? 3600) - 30) * 1000;
    oauth2Cache.set(cred.id, { token: data.access_token, expiresAt: now + ttlMs });
    return data.access_token;
  } catch {
    return null;
  }
}

// Re-export mapRequiresAuth for downstream consumers (Phase 15+).
export { mapRequiresAuth };
