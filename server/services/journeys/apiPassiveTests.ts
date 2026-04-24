/**
 * Phase 12 — API Passive Security Testing orchestrator.
 *
 * Composes 3 stages (in order): api9_inventory (DB query) →
 * nuclei_passive (Nuclei scan) → auth_failure (in-house TS vectors).
 * Each stage fails independently (log + skip); pipeline continues.
 *
 * Partial results persist on cancel — findings already upserted are NOT
 * rolled back (pattern replicated from Phase 11 apiDiscovery.ts).
 *
 * dryRun=true loads fixtures from server/__tests__/fixtures/api-passive/
 * and prefixes all finding titles with "[DRY-RUN] ". No HTTP request or
 * process spawn occurs.
 */
import { readFile } from 'fs/promises';
import { join } from 'path';
import type {
  ApiPassiveTestOpts,
  PassiveTestResult,
  InsertApiFinding,
} from '@shared/schema';
import { NucleiFindingSchema } from '@shared/schema';
import { createLogger } from '../../lib/logger';
import { storage } from '../../storage';
import { jobQueue } from '../jobQueue';
import { encryptionService } from '../encryption';
import {
  runNucleiPassive,
  mapNucleiJsonlToEvidence,
  type NucleiPassiveHit,
} from '../scanners/api/nucleiApi';
import {
  forgeJwtAlgNone,
  injectKid,
  KID_INJECTION_PAYLOADS,
  checkTokenReuse,
  detectApiKeyLeakage,
  buildAlgNoneHit,
  buildKidInjectionHit,
  type AuthFailureHit,
} from '../scanners/api/authFailure';
import { runApi9Inventory, type Api9Hit } from '../scanners/api/api9Inventory';

const log = createLogger('journeys:apiPassiveTests');

const FIXTURE_DIR = join(process.cwd(), 'server/__tests__/fixtures/api-passive');
const FIXTURE_NUCLEI_JSONL = 'nuclei-passive-mock.jsonl';
const FIXTURE_ALG_NONE_RESPONSE = 'jwt-alg-none-response.json';
const FIXTURE_KID_RESPONSE = 'jwt-kid-injection-response.json';
const FIXTURE_EXPIRED_RESPONSE = 'jwt-expired-response.json';
const FIXTURE_LEAKAGE_RESPONSE = 'api-key-leakage-body.json';

type StageName = 'api9_inventory' | 'nuclei_passive' | 'auth_failure';

export async function runApiPassiveTests(
  apiId: string,
  opts: ApiPassiveTestOpts,
  jobId?: string,
): Promise<PassiveTestResult> {
  const startedAt = Date.now();
  const controller = new AbortController();
  const signal = controller.signal;

  const stagesRun: StageName[] = [];
  const stagesSkipped: Array<{ stage: string; reason: string }> = [];
  const findingsByCategory: Record<string, number> = {};
  const findingsBySeverity: Record<string, number> = {};
  let findingsCreated = 0;
  let findingsUpdated = 0;
  let cancelled = false;

  const api = await storage.getApi(apiId);
  if (!api) {
    throw new Error(`API não encontrada: ${apiId}`);
  }

  const endpoints = await storage.listEndpointsByApi(apiId);
  const targetEndpoints = opts.endpointIds?.length
    ? endpoints.filter((e) => opts.endpointIds!.includes(e.id))
    : endpoints;

  const effectiveStages = {
    api9Inventory: opts.stages?.api9Inventory ?? true,
    nucleiPassive: opts.stages?.nucleiPassive ?? true,
    authFailure: opts.stages?.authFailure ?? true,
  };
  const dryRun = opts.dryRun ?? false;
  const titlePrefix = dryRun ? '[DRY-RUN] ' : '';

  // ---- Helper: persist a hit via upsertApiFindingByKey + update counters ----
  const persistHit = async (
    hit: NucleiPassiveHit | AuthFailureHit | Api9Hit,
  ): Promise<void> => {
    const title = `${titlePrefix}${hit.title}`;
    const insert: InsertApiFinding = {
      apiEndpointId: hit.endpointId,
      jobId: jobId ?? null,
      owaspCategory: hit.owaspCategory,
      severity: hit.severity,
      title,
      description: hit.description ?? null,
      remediation: hit.remediation ?? null,
      evidence: hit.evidence,
      status: 'open',
    };
    try {
      const { action } = await storage.upsertApiFindingByKey(
        hit.endpointId,
        hit.owaspCategory,
        title,
        insert,
      );
      if (action === 'inserted') findingsCreated++;
      else findingsUpdated++;
      findingsByCategory[hit.owaspCategory] = (findingsByCategory[hit.owaspCategory] ?? 0) + 1;
      findingsBySeverity[hit.severity] = (findingsBySeverity[hit.severity] ?? 0) + 1;
    } catch (err) {
      log.error(
        { err, apiId, endpointId: hit.endpointId, owaspCategory: hit.owaspCategory },
        'failed to persist passive finding',
      );
    }
  };

  // ---- Helper: check cancellation ----
  const checkCancel = (): boolean => {
    if (jobId && jobQueue.isJobCancelled(jobId)) {
      log.info({ apiId, jobId }, 'passive tests cancelled — exiting cooperatively');
      cancelled = true;
      controller.abort();
      return true;
    }
    return false;
  };

  // ---- Stage 1: api9_inventory ----
  if (effectiveStages.api9Inventory) {
    if (checkCancel()) return finalize();
    try {
      stagesRun.push('api9_inventory');
      const hits = await runApi9Inventory(apiId);
      for (const hit of hits) {
        await persistHit(hit);
      }
      log.info({ apiId, stage: 'api9_inventory', hitsCount: hits.length }, 'stage complete');
    } catch (err) {
      // Remove from stagesRun if it failed before any persistence
      const idx = stagesRun.indexOf('api9_inventory');
      if (idx >= 0) stagesRun.splice(idx, 1);
      log.error({ err, apiId, stage: 'api9_inventory' }, 'stage failed');
      stagesSkipped.push({ stage: 'api9_inventory', reason: err instanceof Error ? err.message : 'unknown' });
    }
  } else {
    stagesSkipped.push({ stage: 'api9_inventory', reason: 'disabled' });
  }

  // ---- Stage 2: nuclei_passive ----
  if (effectiveStages.nucleiPassive) {
    if (checkCancel()) return finalize();
    try {
      const nucleiEndpoints = targetEndpoints.map((e) => ({
        id: e.id,
        fullUrl: `${api.baseUrl}${e.path}`,
      }));
      let hits: NucleiPassiveHit[];
      if (dryRun) {
        hits = await loadNucleiFixtureHits(nucleiEndpoints);
        stagesRun.push('nuclei_passive');
      } else {
        const result = await runNucleiPassive(
          nucleiEndpoints,
          { rateLimit: opts.nuclei?.rateLimit, timeoutSec: opts.nuclei?.timeoutSec },
          { apiId, jobId, signal },
        );
        if (result.skipped) {
          stagesSkipped.push({ stage: 'nuclei_passive', reason: result.skipped.reason });
          hits = [];
        } else {
          stagesRun.push('nuclei_passive');
          hits = result.findings;
        }
      }
      for (const hit of hits) {
        if (checkCancel()) return finalize();
        await persistHit(hit);
      }
      log.info({ apiId, stage: 'nuclei_passive', hitsCount: hits.length, dryRun }, 'stage complete');
    } catch (err) {
      log.error({ err, apiId, stage: 'nuclei_passive' }, 'stage failed');
      stagesSkipped.push({ stage: 'nuclei_passive', reason: err instanceof Error ? err.message : 'unknown' });
    }
  } else {
    stagesSkipped.push({ stage: 'nuclei_passive', reason: 'disabled' });
  }

  // ---- Stage 3: auth_failure ----
  if (effectiveStages.authFailure) {
    if (checkCancel()) return finalize();
    stagesRun.push('auth_failure');
    let anyRan = false;
    for (const ep of targetEndpoints) {
      if (checkCancel()) return finalize();
      if (ep.requiresAuth !== true) {
        log.debug({ endpointId: ep.id, requiresAuth: ep.requiresAuth }, 'auth_failure skipped — requiresAuth != true');
        continue;
      }
      const credId = opts.credentialIdOverride;
      const cred = credId
        ? await storage.getApiCredential(credId)
        : await storage.resolveApiCredential(apiId, ep.path);
      if (!cred) {
        log.debug({ endpointId: ep.id }, 'auth_failure skipped — no compatible credential');
        continue;
      }
      // Only bearer_jwt + api_key_header + api_key_query are in-scope for Phase 12 (CONTEXT.md)
      if (cred.authType !== 'bearer_jwt' && cred.authType !== 'api_key_header' && cred.authType !== 'api_key_query') {
        log.debug({ endpointId: ep.id, authType: cred.authType }, 'auth_failure skipped — auth type out of scope');
        continue;
      }
      anyRan = true;
      const endpointUrl = `${api.baseUrl}${ep.path}`;
      try {
        if (cred.authType === 'bearer_jwt') {
          await runJwtVectors(cred.id, ep.id, endpointUrl, dryRun, persistHit);
        } else {
          // api_key_header / api_key_query → leakage check only
          await runApiKeyLeakageVector(cred.id, ep.id, endpointUrl, targetEndpoints, api.baseUrl, dryRun, persistHit);
        }
      } catch (err) {
        log.error({ err, endpointId: ep.id, vector: cred.authType }, 'auth_failure vector failed');
      }
    }
    if (!anyRan) {
      stagesSkipped.push({ stage: 'auth_failure', reason: 'no endpoints eligible (requiresAuth/credential)' });
      // remove auth_failure from stagesRun since nothing actually ran
      const idx = stagesRun.indexOf('auth_failure');
      if (idx >= 0) stagesRun.splice(idx, 1);
    }
  } else {
    stagesSkipped.push({ stage: 'auth_failure', reason: 'disabled' });
  }

  return finalize();

  // -------------------------------------------------------------------------
  // Finalizers
  // -------------------------------------------------------------------------

  function finalize(): PassiveTestResult {
    const durationMs = Date.now() - startedAt;
    const result: PassiveTestResult = {
      apiId,
      stagesRun,
      stagesSkipped,
      findingsCreated,
      findingsUpdated,
      findingsByCategory,
      findingsBySeverity,
      cancelled,
      dryRun,
      durationMs,
    };
    log.info(
      {
        apiId,
        jobId,
        stagesRun: stagesRun.length,
        stagesSkipped: stagesSkipped.length,
        findingsCreated,
        findingsUpdated,
        cancelled,
        dryRun,
        durationMs,
      },
      'api passive tests complete',
    );
    return result;
  }
}

// ---------------------------------------------------------------------------
// Helpers — dryRun fixture loading
// ---------------------------------------------------------------------------

async function loadNucleiFixtureHits(
  endpoints: Array<{ id: string; fullUrl: string }>,
): Promise<NucleiPassiveHit[]> {
  if (endpoints.length === 0) return [];
  const raw = await readFile(join(FIXTURE_DIR, FIXTURE_NUCLEI_JSONL), 'utf8');
  const lines = raw.split('\n').filter((l) => l.trim().length > 0);
  const hits: NucleiPassiveHit[] = [];
  for (const line of lines) {
    try {
      const parsed = JSON.parse(line);
      const safe = NucleiFindingSchema.safeParse(parsed);
      if (!safe.success) continue;
      // Fixture findings get mapped against the FIRST endpoint — dryRun is about determinism, not URL matching.
      hits.push(mapNucleiJsonlToEvidence(safe.data, endpoints[0].id));
    } catch {
      continue;
    }
  }
  return hits;
}

async function runJwtVectors(
  credId: string,
  endpointId: string,
  endpointUrl: string,
  dryRun: boolean,
  persistHit: (hit: AuthFailureHit) => Promise<void>,
): Promise<void> {
  // CONTEXT.md §Auth-failure: NEVER log or store full tokens. Mask at source.
  if (dryRun) {
    // Load 3 JWT fixtures; emit deterministic findings.
    const [algNone, kid, expired] = await Promise.all([
      readFile(join(FIXTURE_DIR, FIXTURE_ALG_NONE_RESPONSE), 'utf8'),
      readFile(join(FIXTURE_DIR, FIXTURE_KID_RESPONSE), 'utf8'),
      readFile(join(FIXTURE_DIR, FIXTURE_EXPIRED_RESPONSE), 'utf8'),
    ]);
    const algParsed = JSON.parse(algNone) as { status: number; body: string };
    const kidParsed = JSON.parse(kid) as { status: number; body: string };
    const expParsed = JSON.parse(expired) as { status: number; body: string };
    await persistHit(buildAlgNoneHit({
      endpointId, endpointUrl, originalAlg: 'RS256',
      responseStatus: algParsed.status, responseBodySnippet: algParsed.body,
    }));
    await persistHit(buildKidInjectionHit({
      endpointId, endpointUrl, payloadLabel: KID_INJECTION_PAYLOADS[0].label, originalKid: null,
      responseStatus: kidParsed.status, responseBodySnippet: kidParsed.body,
    }));
    // Token reuse via synthetic expired JWT for dryRun
    const reuseResult = await checkTokenReuse({
      endpointId, endpointUrl,
      expiredJwt: buildSyntheticExpiredJwtForDryRun(),
      probeFn: async () => ({ status: expParsed.status, bodySnippet: expParsed.body }),
    });
    if (reuseResult.hit) await persistHit(reuseResult.hit);
    return;
  }

  // Real execution: fetch cred secret, forge tokens, probe endpoint.
  const credWithSecret = await storage.getApiCredentialWithSecret(credId);
  if (!credWithSecret) return;
  const originalJwt = encryptionService.decryptCredential(
    credWithSecret.secretEncrypted,
    credWithSecret.dekEncrypted,
  );

  // Vector 1: alg:none
  try {
    const { forged, originalAlg } = forgeJwtAlgNone(originalJwt);
    const resp = await probeWithJwt(endpointUrl, forged);
    if (resp.status < 400) {
      await persistHit(buildAlgNoneHit({
        endpointId, endpointUrl, originalAlg,
        responseStatus: resp.status, responseBodySnippet: resp.body,
      }));
    }
  } catch (err) {
    log.debug({ err: err instanceof Error ? err.message : err, endpointId }, 'alg:none vector skipped');
  }

  // Vector 2: kid injection (4 payloads → max 1 finding per endpoint, first hit wins)
  for (const payload of KID_INJECTION_PAYLOADS) {
    await sleep(1000); // rate cap per CONTEXT.md (1s delay between requests)
    try {
      const forged = injectKid(originalJwt, payload.value);
      const resp = await probeWithJwt(endpointUrl, forged);
      if (resp.status < 400) {
        await persistHit(buildKidInjectionHit({
          endpointId, endpointUrl, payloadLabel: payload.label, originalKid: null,
          responseStatus: resp.status, responseBodySnippet: resp.body,
        }));
        break; // first hit wins — don't flood
      }
    } catch (err) {
      log.debug({ err: err instanceof Error ? err.message : err, payload: payload.label }, 'kid vector skipped');
    }
  }

  // Vector 3: token reuse
  await sleep(1000);
  try {
    const reuseResult = await checkTokenReuse({
      endpointId, endpointUrl, expiredJwt: originalJwt,
      probeFn: async (jwt) => {
        const r = await probeWithJwt(endpointUrl, jwt);
        return { status: r.status, bodySnippet: r.body };
      },
    });
    if (reuseResult.hit) await persistHit(reuseResult.hit);
  } catch (err) {
    log.debug({ err: err instanceof Error ? err.message : err, endpointId }, 'token reuse vector skipped');
  }
}

async function runApiKeyLeakageVector(
  credId: string,
  endpointId: string,
  endpointUrl: string,
  allEndpoints: Array<{ id: string; path: string; method: string }>,
  baseUrl: string,
  dryRun: boolean,
  persistHit: (hit: AuthFailureHit) => Promise<void>,
): Promise<void> {
  if (dryRun) {
    const raw = await readFile(join(FIXTURE_DIR, FIXTURE_LEAKAGE_RESPONSE), 'utf8');
    const parsed = JSON.parse(raw) as { leakedKey: string; body: string };
    // parsed.leakedKey is the literal key for the mock; mask-at-source applied in detectApiKeyLeakage.
    const hit = detectApiKeyLeakage(parsed.leakedKey, [
      { endpointId, endpointUrl, responseBody: parsed.body },
    ]);
    if (hit) await persistHit(hit);
    return;
  }

  // Real: decrypt cred; probe up to 5 GET endpoints; scan bodies for substring match.
  const credWithSecret = await storage.getApiCredentialWithSecret(credId);
  if (!credWithSecret) return;
  const apiKey = encryptionService.decryptCredential(
    credWithSecret.secretEncrypted,
    credWithSecret.dekEncrypted,
  );
  const getEndpoints = allEndpoints.filter((e) => e.method === 'GET').slice(0, 5);
  const probes: Array<{ endpointId: string; endpointUrl: string; responseBody: string }> = [];
  for (const ep of getEndpoints) {
    await sleep(1000);
    try {
      const url = `${baseUrl}${ep.path}`;
      const resp = await probeWithApiKey(url, credWithSecret, apiKey);
      probes.push({ endpointId: ep.id, endpointUrl: url, responseBody: resp.body });
    } catch (err) {
      log.debug({ err: err instanceof Error ? err.message : err, endpointId: ep.id }, 'leakage probe skipped');
    }
  }
  const hit = detectApiKeyLeakage(apiKey, probes);
  if (hit) await persistHit(hit);
}

// ---------------------------------------------------------------------------
// HTTP probe helpers (native fetch — no extra deps)
// ---------------------------------------------------------------------------

async function probeWithJwt(url: string, jwt: string): Promise<{ status: number; body: string }> {
  const resp = await fetch(url, {
    method: 'GET',
    headers: { Authorization: `Bearer ${jwt}` },
  });
  const body = await resp.text();
  return { status: resp.status, body: body.slice(0, 8192) };
}

async function probeWithApiKey(
  url: string,
  cred: { authType: string; apiKeyHeaderName?: string | null; apiKeyQueryParam?: string | null },
  apiKey: string,
): Promise<{ status: number; body: string }> {
  let requestUrl = url;
  const headers: Record<string, string> = {};
  if (cred.authType === 'api_key_header' && cred.apiKeyHeaderName) {
    headers[cred.apiKeyHeaderName] = apiKey;
  } else if (cred.authType === 'api_key_query' && cred.apiKeyQueryParam) {
    const sep = url.includes('?') ? '&' : '?';
    requestUrl = `${url}${sep}${encodeURIComponent(cred.apiKeyQueryParam)}=${encodeURIComponent(apiKey)}`;
  }
  const resp = await fetch(requestUrl, { method: 'GET', headers });
  const body = await resp.text();
  return { status: resp.status, body: body.slice(0, 8192) };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Deterministic expired JWT for dryRun — hardcoded payload with exp in 2020.
function buildSyntheticExpiredJwtForDryRun(): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' }), 'utf8').toString('base64url');
  const payload = Buffer.from(JSON.stringify({ exp: 1577836800, sub: 'test' }), 'utf8').toString('base64url');
  return `${header}.${payload}.signature`;
}
