/**
 * Phase 13 — API Active Security Testing orchestrator.
 *
 * Composes 5 stages (in order): bola → bfla → bopla → rate_limit → ssrf.
 * Each stage fails independently (log + skip); pipeline continues.
 *
 * Gates:
 *   - BOPLA: always skipped unless opts.destructiveEnabled=true
 *   - rateLimit: always skipped unless opts.stages.rateLimit=true (explicit opt-in)
 *
 * Cooperative cancel: jobQueue.isJobCancelled(jobId) checked between each stage
 * AND inside the BOLA credential-pair loop. Partial results persist on cancel.
 *
 * dryRun=true loads fixtures from server/__tests__/fixtures/api-active/
 * and prefixes finding titles with "[DRY-RUN]". No HTTP requests or Nuclei spawns.
 *
 * SAFE-06: Never log complete secrets. Credential IDs masked as prefix-3 + '***'.
 */
import { readFile } from 'fs/promises';
import { join } from 'path';
import type { ApiActiveTestOpts, ActiveTestResult, InsertApiFinding } from '@shared/schema';
import { BOPLA_SENSITIVE_KEYS } from '@shared/schema';
import { createLogger } from '../../lib/logger';
import { storage } from '../../storage';
import { encryptionService } from '../encryption';
import { jobQueue } from '../jobQueue';
import { listApiCredentials } from '../../storage/apiCredentials';
import {
  pairCredentials,
  harvestObjectIds,
  testCrossAccess,
  buildAuthHeaders,
  buildAccessUrl,
  type BolaHit,
} from '../scanners/api/bola';
import {
  identifyLowPrivCreds,
  matchAdminEndpoint,
  testPrivEscalation,
  type BflaHit,
} from '../scanners/api/bfla';
import {
  fetchSeedBody,
  verifyReflection,
  type BoplaHit,
} from '../scanners/api/bopla';
import {
  buildBurst,
  detectThrottling,
  type RateLimitHit,
} from '../scanners/api/rateLimit';
import {
  identifyUrlParams,
  runSsrfNuclei,
  type SsrfHit,
  type SsrfParam,
} from '../scanners/api/ssrfNuclei';
import { preflightNuclei } from './nucleiPreflight';

const log = createLogger('journeys:apiActiveTests');

const FIXTURE_DIR = join(process.cwd(), 'server/__tests__/fixtures/api-active');
const FIXTURE_BOLA = 'bola-crossaccess-response.json';
const FIXTURE_BFLA = 'bfla-admin-success.json';
const FIXTURE_BOPLA_BEFORE = 'bopla-reflection-before.json';
const FIXTURE_BOPLA_AFTER = 'bopla-reflection-after.json';
const FIXTURE_RATE_LIMIT = 'rate-limit-burst-responses.json';
const FIXTURE_SSRF = 'ssrf-nuclei-interaction.jsonl';

type ActiveStageName = 'bola' | 'bfla' | 'bopla' | 'rate_limit' | 'ssrf';

/** Minimal in-process credential shape for scanners (decrypted secret). */
interface CredWithSecret {
  id: string;
  authType: string;
  priority: number;
  description: string | null;
  apiKeyHeaderName?: string | null;
  apiKeyQueryParam?: string | null;
  basicUsername?: string | null;
  secret: string;
}

export async function runApiActiveTests(
  apiId: string,
  opts: ApiActiveTestOpts,
  jobId?: string,
): Promise<ActiveTestResult> {
  const startedAt = Date.now();
  const controller = new AbortController();
  const signal = controller.signal;

  const stagesRun: ActiveStageName[] = [];
  const stagesSkipped: Array<{ stage: string; reason: string }> = [];
  const findingsByCategory: Record<string, number> = {};
  const findingsBySeverity: Record<string, number> = {};
  let findingsCreated = 0;
  let findingsUpdated = 0;
  let cancelled = false;
  const usedCredentialIds = new Set<string>();

  const api = await storage.getApi(apiId);
  if (!api) {
    throw new Error(`API não encontrada: ${apiId}`);
  }

  const endpoints = await storage.listEndpointsByApi(apiId);
  const targetEndpoints = opts.endpointIds?.length
    ? endpoints.filter((e) => opts.endpointIds!.includes(e.id))
    : endpoints;

  // Load credentials once at orchestrator entry — shared across stages.
  // SAFE-06: listApiCredentials returns safe fields only; secrets loaded below.
  const credSafe = await listApiCredentials({ apiId });
  const credIds = opts.credentialIds?.length
    ? opts.credentialIds.filter((id) => credSafe.some((c) => c.id === id))
    : credSafe.map((c) => c.id);

  // Decrypt credentials (secret) for in-process scanners.
  // SAFE-06: never log full secret — only credentialId prefix-3+*** in logs.
  const credsWithSecrets: CredWithSecret[] = [];
  for (const id of credIds) {
    const credFull = await storage.getApiCredentialWithSecret(id);
    if (!credFull) continue;
    try {
      const secret = encryptionService.decryptCredential(
        credFull.secretEncrypted,
        credFull.dekEncrypted,
      );
      credsWithSecrets.push({
        id: credFull.id,
        authType: credFull.authType,
        priority: credFull.priority,
        description: credFull.description ?? null,
        apiKeyHeaderName: credFull.apiKeyHeaderName ?? null,
        apiKeyQueryParam: credFull.apiKeyQueryParam ?? null,
        basicUsername: credFull.basicUsername ?? null,
        secret,
      });
    } catch (err) {
      const maskedId = id.slice(0, 3) + '***';
      log.warn({ credId: maskedId, err: err instanceof Error ? err.message : err }, 'failed to decrypt credential — skipped');
    }
  }

  const dryRun = opts.dryRun ?? false;
  const titlePrefix = dryRun ? '[DRY-RUN] ' : '';

  // ---- Helper: persist a hit + update counters ----
  type AnyHit = BolaHit | BflaHit | BoplaHit | RateLimitHit | SsrfHit;
  const persistHit = async (hit: AnyHit): Promise<void> => {
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
        'failed to persist active finding',
      );
    }
  };

  // ---- Helper: cooperative cancel ----
  const checkCancel = (): boolean => {
    if (jobId && jobQueue.isJobCancelled(jobId)) {
      log.info({ apiId, jobId }, 'active tests cancelled — exiting cooperatively');
      cancelled = true;
      controller.abort();
      return true;
    }
    return false;
  };

  // =====================================================================
  // Stage 1: BOLA (API1)
  // =====================================================================
  if (opts.stages?.bola ?? true) {
    if (checkCancel()) return finalize();
    if (credsWithSecrets.length < 2) {
      stagesSkipped.push({
        stage: 'bola',
        reason: 'BOLA requer ≥2 credenciais — menos de 2 disponíveis',
      });
    } else {
      try {
        stagesRun.push('bola');
        const bolaOpts = opts.bola;
        const maxCreds = bolaOpts?.maxCredentials ?? 4;
        const maxIds = bolaOpts?.maxIdsPerEndpoint ?? 3;
        const pairs = pairCredentials(credsWithSecrets, maxCreds);

        // GET endpoints with requiresAuth=true (BOLA scope per CONTEXT.md)
        const getEndpoints = targetEndpoints.filter(
          (e) => e.method === 'GET' && e.requiresAuth === true,
        );

        for (const [credAPair, credBPair] of pairs) {
          if (checkCancel()) return finalize();
          usedCredentialIds.add(credAPair.id);
          usedCredentialIds.add(credBPair.id);

          // Resolve full cred objects (pairs only carry { id })
          const credA = credsWithSecrets.find((c) => c.id === credAPair.id);
          const credB = credsWithSecrets.find((c) => c.id === credBPair.id);
          if (!credA || !credB) continue;

          // Build auth helpers for credA (harvest) and credB (cross-access)
          let credAAuth: ReturnType<typeof buildAuthHeaders>;
          let credBAuth: ReturnType<typeof buildAuthHeaders>;
          try {
            credAAuth = buildAuthHeaders({ ...credA });
            credBAuth = buildAuthHeaders({ ...credB });
          } catch (err) {
            const maskedA = credA.id.slice(0, 3) + '***';
            log.debug(
              { err: err instanceof Error ? err.message : err, credId: maskedA },
              'bola: unsupported auth type — skipping pair',
            );
            continue;
          }

          for (const ep of getEndpoints) {
            if (checkCancel()) return finalize();

            // Harvest object IDs using credA
            let harvestedIds: Array<string | number> = [];
            if (dryRun) {
              // dryRun: use fixture IDs
              try {
                const raw = await readFile(join(FIXTURE_DIR, FIXTURE_BOLA), 'utf8');
                const body = JSON.parse(raw) as unknown;
                harvestedIds = harvestObjectIds(body, maxIds);
                if (harvestedIds.length === 0) harvestedIds = ['fixture-id-001', 'fixture-id-002'];
              } catch {
                harvestedIds = ['fixture-id-001', 'fixture-id-002'];
              }
            } else {
              try {
                // Only try harvest on list-like paths (no {param} tokens)
                // Non-list endpoints will yield empty IDs → skip
                const harvestUrl = buildAccessUrl(api.baseUrl, ep.path, '');
                // Actually call GET and harvest from real response
                const resp = await fetch(harvestUrl.replace(/\?id=$/,''), {
                  method: 'GET',
                  headers: credAAuth.headers,
                });
                if (resp.status < 400) {
                  const text = await resp.text();
                  try {
                    const body = JSON.parse(text) as unknown;
                    harvestedIds = harvestObjectIds(body, maxIds);
                  } catch {
                    // non-JSON — skip
                  }
                }
              } catch (err) {
                log.debug(
                  { err: err instanceof Error ? err.message : err, endpointId: ep.id },
                  'bola harvest failed — skipping endpoint',
                );
              }
            }

            if (harvestedIds.length === 0) continue;

            // Test cross-access with credB for each harvested ID
            for (const objectId of harvestedIds) {
              if (checkCancel()) return finalize();

              let hit: BolaHit | null;
              if (dryRun) {
                // dryRun: simulate finding using fixture data
                hit = {
                  endpointId: ep.id,
                  owaspCategory: 'api1_bola_2023',
                  severity: 'high',
                  title: 'Acesso não autorizado a objeto via credencial secundária',
                  description: `[DRY-RUN] Credencial B acessou objeto de propriedade de credencial A. Endpoint: ${ep.path}.`,
                  remediation: '',
                  evidence: {
                    request: { method: 'GET', url: `${api.baseUrl}${ep.path}` },
                    response: { status: 200, bodySnippet: '{"id":"fixture-id-001","name":"fixture"}' },
                    extractedValues: {
                      credentialAId: credA.id.slice(0, 3) + '***',
                      credentialBId: credB.id.slice(0, 3) + '***',
                      objectId: String(objectId).slice(0, 3) + '***',
                      endpointPath: ep.path,
                    },
                    context: 'BOLA cross-identity object access — dryRun fixture',
                  },
                };
              } else {
                hit = await testCrossAccess({
                  endpointId: ep.id,
                  endpointPath: ep.path,
                  baseUrl: api.baseUrl,
                  objectId,
                  credentialAId: credA.id,
                  credentialBId: credB.id,
                  credentialBHeaders: credBAuth.headers,
                  credentialBQueryParam: credBAuth.queryParam,
                }).catch((err) => {
                  log.error(
                    { err: err instanceof Error ? err.message : err, endpointId: ep.id },
                    'bola testCrossAccess error',
                  );
                  return null;
                });
              }

              if (hit) await persistHit(hit);
            }
          }
        }
        log.info({ apiId, stage: 'bola', pairsCount: pairs.length }, 'bola stage complete');
      } catch (err) {
        log.error({ err, apiId, stage: 'bola' }, 'bola stage failed');
        stagesSkipped.push({
          stage: 'bola',
          reason: err instanceof Error ? err.message : 'unknown',
        });
      }
    }
  } else {
    stagesSkipped.push({ stage: 'bola', reason: 'disabled' });
  }

  // =====================================================================
  // Stage 2: BFLA (API5)
  // =====================================================================
  if (opts.stages?.bfla ?? true) {
    if (checkCancel()) return finalize();
    try {
      const lowPrivCreds = identifyLowPrivCreds(credsWithSecrets);
      if (lowPrivCreds.length === 0) {
        stagesSkipped.push({
          stage: 'bfla',
          reason: 'BFLA requer ≥2 creds com privilégios distintos — não identificadas',
        });
      } else {
        stagesRun.push('bfla');
        const adminEndpoints = targetEndpoints.filter(
          (e) => matchAdminEndpoint(e.path) !== null,
        );

        for (const ep of adminEndpoints) {
          if (checkCancel()) return finalize();
          const matchedPattern = matchAdminEndpoint(ep.path) ?? 'unknown';

          for (const lowPrivCredSignal of lowPrivCreds) {
            if (checkCancel()) return finalize();
            usedCredentialIds.add(lowPrivCredSignal.id);

            // Resolve full cred with secret (signal only carries id/priority/description/authType)
            const lowPrivCred = credsWithSecrets.find((c) => c.id === lowPrivCredSignal.id);
            if (!lowPrivCred) continue;

            let credHeaders: Record<string, string>;
            try {
              const authResult = buildAuthHeaders({ ...lowPrivCred });
              credHeaders = authResult.headers;
            } catch {
              continue;
            }

            let hit: BflaHit | null;
            if (dryRun) {
              // dryRun: read fixture and simulate finding
              try {
                const raw = await readFile(join(FIXTURE_DIR, FIXTURE_BFLA), 'utf8');
                const fixture = JSON.parse(raw) as { status: number; body: string };
                if (fixture.status < 400) {
                  hit = {
                    endpointId: ep.id,
                    owaspCategory: 'api5_bfla_2023',
                    severity: 'high',
                    title: 'Privilégio administrativo acessível via credencial de baixo privilégio',
                    description: `[DRY-RUN] Credencial de baixo privilégio acessou endpoint administrativo ${ep.path} com status ${fixture.status}.`,
                    remediation: '',
                    evidence: {
                      request: { method: 'GET', url: `${api.baseUrl}${ep.path}` },
                      response: { status: fixture.status, bodySnippet: fixture.body },
                      extractedValues: {
                        credentialId: lowPrivCred.id.slice(0, 3) + '***',
                        priorityLevel: lowPrivCred.priority,
                        matchedPattern,
                        endpointPath: ep.path,
                      },
                      context: 'BFLA — low-privilege credential accessed admin-level endpoint — dryRun fixture',
                    },
                  };
                } else {
                  hit = null;
                }
              } catch {
                hit = null;
              }
            } else {
              const endpointUrl = `${api.baseUrl}${ep.path}`;
              hit = await testPrivEscalation({
                endpointId: ep.id,
                endpointPath: ep.path,
                endpointUrl,
                lowPrivCredId: lowPrivCred.id,
                lowPrivPriority: lowPrivCred.priority,
                matchedPattern,
                lowPrivHeaders: credHeaders,
              }).catch((err) => {
                log.error(
                  { err: err instanceof Error ? err.message : err, endpointId: ep.id },
                  'bfla testPrivEscalation error',
                );
                return null;
              });
            }

            if (hit) await persistHit(hit);
          }
        }
        log.info(
          { apiId, stage: 'bfla', adminEndpointsCount: adminEndpoints.length },
          'bfla stage complete',
        );
      }
    } catch (err) {
      log.error({ err, apiId, stage: 'bfla' }, 'bfla stage failed');
      stagesSkipped.push({
        stage: 'bfla',
        reason: err instanceof Error ? err.message : 'unknown',
      });
    }
  } else {
    stagesSkipped.push({ stage: 'bfla', reason: 'disabled' });
  }

  // =====================================================================
  // Stage 3: BOPLA / Mass Assignment (API3)
  // Gate: opts.destructiveEnabled MUST be true (default false).
  // =====================================================================
  if (opts.stages?.bopla ?? true) {
    if (checkCancel()) return finalize();
    if (!opts.destructiveEnabled) {
      stagesSkipped.push({ stage: 'bopla', reason: 'destructive gate not enabled' });
      log.info({ apiId }, 'bopla stage skipped — destructiveEnabled=false');
    } else {
      try {
        const credential = credsWithSecrets[0];
        if (!credential) {
          stagesSkipped.push({ stage: 'bopla', reason: 'nenhuma credencial disponível' });
        } else {
          stagesRun.push('bopla');
          usedCredentialIds.add(credential.id);

          let credHeaders: Record<string, string>;
          try {
            credHeaders = buildAuthHeaders({ ...credential }).headers;
          } catch (err) {
            stagesSkipped.push({
              stage: 'bopla',
              reason: `auth type not supported: ${err instanceof Error ? err.message : 'unknown'}`,
            });
            const idx = stagesRun.indexOf('bopla');
            if (idx >= 0) stagesRun.splice(idx, 1);
            return finalize();
          }

          const putPatchEndpoints = targetEndpoints.filter(
            (e) => (e.method === 'PUT' || e.method === 'PATCH') && e.requiresAuth === true,
          );

          for (const ep of putPatchEndpoints) {
            if (checkCancel()) return finalize();

            const resourceUrl = `${api.baseUrl}${ep.path}`;

            let seedBody: Record<string, unknown> | null;
            if (dryRun) {
              try {
                const raw = await readFile(join(FIXTURE_DIR, FIXTURE_BOPLA_BEFORE), 'utf8');
                seedBody = JSON.parse(raw) as Record<string, unknown>;
              } catch {
                seedBody = null;
              }
            } else {
              seedBody = await fetchSeedBody(resourceUrl, credHeaders).catch((err) => {
                log.debug(
                  { err: err instanceof Error ? err.message : err, endpointId: ep.id },
                  'bopla seed fetch failed — skipping endpoint',
                );
                return null;
              });
            }

            if (!seedBody) continue;

            for (const key of BOPLA_SENSITIVE_KEYS) {
              if (checkCancel()) return finalize();

              if (dryRun) {
                // dryRun: check if key appears in after fixture with changed value
                try {
                  const afterRaw = await readFile(join(FIXTURE_DIR, FIXTURE_BOPLA_AFTER), 'utf8');
                  const afterBody = JSON.parse(afterRaw) as Record<string, unknown>;
                  const beforeValue = seedBody[key];
                  const afterValue = afterBody[key];
                  if (afterValue !== undefined && afterValue !== beforeValue) {
                    const CRITICAL_KEYS_SET = new Set(['is_admin', 'role', 'superuser']);
                    const severity: 'critical' | 'high' = CRITICAL_KEYS_SET.has(key) ? 'critical' : 'high';
                    const title = `Campo sensível aceito em PUT/PATCH sem validação (${key})`;
                    await persistHit({
                      endpointId: ep.id,
                      owaspCategory: 'api3_bopla_2023',
                      severity,
                      title,
                      description: `[DRY-RUN] Campo sensível '${key}' refletido após injeção em ${ep.method} ${ep.path}.`,
                      remediation: '',
                      evidence: {
                        request: {
                          method: ep.method as 'PUT' | 'PATCH',
                          url: resourceUrl,
                          bodySnippet: JSON.stringify({ ...seedBody, [key]: afterValue }).slice(0, 512),
                        },
                        response: { status: 200, bodySnippet: afterRaw.slice(0, 512) },
                        extractedValues: {
                          injectedKey: key,
                          originalValue: beforeValue ?? null,
                          reflectedValue: afterValue,
                          endpointPath: ep.path,
                        },
                        context: `BOPLA mass assignment — key ${key} reflected (dryRun fixture)`,
                      },
                    } as BoplaHit);
                  }
                } catch {
                  continue;
                }
              } else {
                const hit = await verifyReflection({
                  endpointId: ep.id,
                  resourceUrl,
                  seedBody,
                  key,
                  authHeaders: credHeaders,
                  method: ep.method as 'PUT' | 'PATCH',
                }).catch((err) => {
                  log.debug(
                    { err: err instanceof Error ? err.message : err, endpointId: ep.id, key },
                    'bopla verifyReflection error',
                  );
                  return null;
                });
                if (hit) await persistHit(hit);
              }
            }
          }
          log.info(
            { apiId, stage: 'bopla', endpointsCount: putPatchEndpoints.length },
            'bopla stage complete',
          );
        }
      } catch (err) {
        log.error({ err, apiId, stage: 'bopla' }, 'bopla stage failed');
        stagesSkipped.push({
          stage: 'bopla',
          reason: err instanceof Error ? err.message : 'unknown',
        });
      }
    }
  } else {
    stagesSkipped.push({ stage: 'bopla', reason: 'disabled' });
  }

  // =====================================================================
  // Stage 4: Rate-limit absence (API4) — opt-in only
  // =====================================================================
  if (opts.stages?.rateLimit === true) {
    if (checkCancel()) return finalize();
    try {
      stagesRun.push('rate_limit');
      const rlOpts = opts.rateLimit;
      const burstSize = Math.min(rlOpts?.burstSize ?? 20, 50);
      const windowMs = rlOpts?.windowMs ?? 2000;

      const rlEndpointIds = rlOpts?.endpointIds;
      const candidateEndpoints = rlEndpointIds?.length
        ? targetEndpoints.filter((e) => rlEndpointIds.includes(e.id))
        : targetEndpoints
            .filter((e) => e.method === 'GET' && e.requiresAuth === true && (e as { httpxStatus?: number }).httpxStatus === 200)
            .sort((a, b) => a.path.localeCompare(b.path))
            .slice(0, 1);

      const credential = credsWithSecrets[0];
      if (!credential) {
        stagesSkipped.push({ stage: 'rate_limit', reason: 'nenhuma credencial disponível' });
        const idx = stagesRun.indexOf('rate_limit');
        if (idx >= 0) stagesRun.splice(idx, 1);
      } else {
        usedCredentialIds.add(credential.id);
        let credHeaders: Record<string, string>;
        try {
          credHeaders = buildAuthHeaders({ ...credential }).headers;
        } catch (err) {
          stagesSkipped.push({
            stage: 'rate_limit',
            reason: `auth type not supported: ${err instanceof Error ? err.message : 'unknown'}`,
          });
          const idx = stagesRun.indexOf('rate_limit');
          if (idx >= 0) stagesRun.splice(idx, 1);
          return finalize();
        }

        for (const ep of candidateEndpoints) {
          if (checkCancel()) return finalize();
          const endpointUrl = `${api.baseUrl}${ep.path}`;

          let responses: Array<{ status: number; headers: Record<string, string> }>;
          if (dryRun) {
            const raw = await readFile(join(FIXTURE_DIR, FIXTURE_RATE_LIMIT), 'utf8');
            responses = JSON.parse(raw) as typeof responses;
          } else {
            responses = await buildBurst({
              url: endpointUrl,
              authHeaders: credHeaders,
              burstSize,
            });
            // Safety net: 30s delay between burst tests per CONTEXT.md
            await new Promise((r) => setTimeout(r, 30_000));
          }

          const hit = detectThrottling({
            endpointId: ep.id,
            endpointPath: ep.path,
            endpointUrl,
            responses,
            burstSize,
            windowMs,
          });

          if (hit) await persistHit(hit);
        }
        log.info(
          {
            apiId,
            stage: 'rate_limit',
            burstSize,
            windowMs,
            endpointsCount: candidateEndpoints.length,
          },
          'rate_limit stage complete',
        );
      }
    } catch (err) {
      log.error({ err, apiId, stage: 'rate_limit' }, 'rate_limit stage failed');
      stagesSkipped.push({
        stage: 'rate_limit',
        reason: err instanceof Error ? err.message : 'unknown',
      });
    }
  } else {
    stagesSkipped.push({ stage: 'rate_limit', reason: 'opt-in not enabled' });
  }

  // =====================================================================
  // Stage 5: SSRF (API7) — Nuclei + interactsh
  // =====================================================================
  if (opts.stages?.ssrf ?? true) {
    if (checkCancel()) return finalize();
    try {
      // Preflight Nuclei before any spawn — skip stage on failure, don't abort pipeline.
      const preflight = await preflightNuclei(log);
      if (!preflight.ok) {
        stagesSkipped.push({
          stage: 'ssrf',
          reason: `nuclei preflight failed: ${preflight.reason ?? 'unknown'}`,
        });
      } else {
        stagesRun.push('ssrf');
        const credential = credsWithSecrets[0] ?? null;
        if (credential) usedCredentialIds.add(credential.id);

        let credHeaders: Record<string, string> | undefined;
        if (credential) {
          try {
            credHeaders = buildAuthHeaders({ ...credential }).headers;
          } catch {
            credHeaders = undefined;
          }
        }

        // Build target URLs: endpoints with URL-like params in their schema
        const ssrfTargets: Array<{ url: string; endpointId: string; paramName: string }> = [];
        for (const ep of targetEndpoints) {
          const rawParams: SsrfParam[] = [
            ...((ep as { query_params?: SsrfParam[] }).query_params ?? []),
            ...((ep as { request_params?: SsrfParam[] }).request_params ?? []),
          ];
          const urlLikeParams = identifyUrlParams(rawParams);
          for (const param of urlLikeParams) {
            ssrfTargets.push({
              url: `${api.baseUrl}${ep.path}`,
              endpointId: ep.id,
              paramName: param.name,
            });
          }
        }

        if (dryRun) {
          // dryRun: parse SSRF fixture JSONL
          try {
            const raw = await readFile(join(FIXTURE_DIR, FIXTURE_SSRF), 'utf8');
            const lines = raw.split('\n').filter((l) => l.trim().length > 0);
            for (const line of lines) {
              try {
                const parsed = JSON.parse(line) as Record<string, unknown>;
                const endpointId = ssrfTargets[0]?.endpointId ?? targetEndpoints[0]?.id;
                if (!endpointId) continue;
                const paramName = ssrfTargets[0]?.paramName ?? 'url';
                const hit: SsrfHit = {
                  endpointId,
                  owaspCategory: 'api7_ssrf_2023',
                  severity: 'high',
                  title: `SSRF confirmado via interação out-of-band em parâmetro ${paramName}`,
                  description: `[DRY-RUN] SSRF OOB detectado no parâmetro '${paramName}'. Fixture interaction=${String(parsed.interaction)}.`,
                  remediation: '',
                  evidence: {
                    request: { method: 'GET', url: `${api.baseUrl}` },
                    response: { status: 200 },
                    extractedValues: {
                      paramName,
                      interactsh_interaction_type: 'dns',
                      interactshUrl: 'dry***',
                      templateId: String(parsed['template-id'] ?? ''),
                    },
                    context: 'SSRF OOB interaction confirmed via Nuclei interactsh — dryRun fixture',
                  },
                };
                await persistHit(hit);
              } catch {
                continue;
              }
            }
          } catch (err) {
            log.debug({ err: err instanceof Error ? err.message : err }, 'ssrf dryRun fixture read failed');
          }
        } else {
          const ssrfResult = await runSsrfNuclei(
            ssrfTargets,
            {
              interactshUrl: opts.ssrf?.interactshUrl ?? process.env['INTERACTSH_URL'],
            },
            {
              apiId,
              jobId,
              signal,
            },
          );

          if (ssrfResult.skipped) {
            stagesSkipped.push({ stage: 'ssrf', reason: ssrfResult.skipped.reason });
            const idx = stagesRun.indexOf('ssrf');
            if (idx >= 0) stagesRun.splice(idx, 1);
          } else {
            for (const hit of ssrfResult.findings) {
              await persistHit(hit);
            }
          }
        }

        log.info(
          {
            apiId,
            stage: 'ssrf',
            ssrfTargetsCount: ssrfTargets.length,
          },
          'ssrf stage complete',
        );
      }
    } catch (err) {
      log.error({ err, apiId, stage: 'ssrf' }, 'ssrf stage failed');
      stagesSkipped.push({
        stage: 'ssrf',
        reason: err instanceof Error ? err.message : 'unknown',
      });
    }
  } else {
    stagesSkipped.push({ stage: 'ssrf', reason: 'disabled' });
  }

  return finalize();

  // ---- Finalizer (inner closure — reads closed-over vars) ----
  function finalize(): ActiveTestResult {
    const durationMs = Date.now() - startedAt;
    const result: ActiveTestResult = {
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
      credentialsUsed: usedCredentialIds.size,
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
        credentialsUsed: usedCredentialIds.size,
      },
      'api active tests complete',
    );
    return result;
  }
}
