/**
 * Phase 15 — Nyquist tests for journey orchestration requirements.
 * Promoted from it.todo during Plans 15-02 (JRNY-01/02 schema) and 15-04 (executor).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mocks scoped per test (vi.hoisted keeps them TDZ-safe)
const mocks = vi.hoisted(() => ({
  logAuditCalls: [] as any[],
  getApi: vi.fn(),
  listApiCredentials: vi.fn(),
  discoverApi: vi.fn(),
  runApiPassiveTests: vi.fn(),
  runApiActiveTests: vi.fn(),
  isJobCancelled: vi.fn().mockReturnValue(false),
  pinoLogs: [] as string[],
}));

vi.mock('../storage', () => ({
  storage: {
    getApi: mocks.getApi,
    logAudit: vi.fn(async (entry: any) => {
      mocks.logAuditCalls.push(entry);
      return { id: 'audit-1', ...entry, createdAt: new Date() };
    }),
  },
}));

vi.mock('../storage/apiCredentials', () => ({
  listApiCredentials: mocks.listApiCredentials,
}));

vi.mock('../services/journeys/apiDiscovery', () => ({
  discoverApi: mocks.discoverApi,
}));

vi.mock('../services/journeys/apiPassiveTests', () => ({
  runApiPassiveTests: mocks.runApiPassiveTests,
}));

vi.mock('../services/journeys/apiActiveTests', () => ({
  runApiActiveTests: mocks.runApiActiveTests,
}));

vi.mock('../services/jobQueue', () => ({
  jobQueue: {
    isJobCancelled: mocks.isJobCancelled,
    markJobAsCancelled: vi.fn(),
    emit: vi.fn(),
    on: vi.fn(),
  },
}));

// Stub all other journey executor deps (minimal)
vi.mock('../services/threatEngine', () => ({ threatEngine: { processJobResults: vi.fn(), processJourneyCompletion: vi.fn() } }));
vi.mock('../services/encryption', () => ({ encryptionService: {} }));
vi.mock('../services/scanners/networkScanner', () => ({ networkScanner: {} }));
vi.mock('../services/scanners/vulnScanner', () => ({ vulnScanner: {} }));
vi.mock('../services/scanners/adScanner', () => ({ ADScanner: class {} }));
vi.mock('../services/scanners/edrAvScanner', () => ({ EDRAVScanner: class {} }));
vi.mock('../services/hostService', () => ({ hostService: {} }));
vi.mock('../services/processTracker', () => ({ processTracker: { killAll: vi.fn() } }));
vi.mock('../services/cveService', () => ({ cveService: {} }));
vi.mock('../services/hostEnricher', () => ({ hostEnricher: { registerCollector: vi.fn() } }));
vi.mock('../services/collectors/wmiCollector', () => ({ WMICollector: class {} }));
vi.mock('../services/collectors/sshCollector', () => ({ SSHCollector: class {} }));
vi.mock('../storage/edrDeployments', () => ({ insertEdrDeployment: vi.fn() }));
vi.mock('../services/journeys/urls', () => ({ buildWebAppUrl: vi.fn(), detectWebScheme: vi.fn(), normalizeTarget: vi.fn() }));
vi.mock('../services/journeys/nucleiPreflight', () => ({ preflightNuclei: vi.fn() }));
vi.mock('../db', () => ({ db: {} }));

describe('JRNY-01 — journey_type enum contains api_security', () => {
  it('shared/schema.ts journeyTypeEnum array inclui "api_security" como 5o valor', async () => {
    const { journeyTypeEnum } = await import('@shared/schema');
    expect(journeyTypeEnum.enumValues).toEqual([
      'attack_surface', 'ad_security', 'edr_av', 'web_application', 'api_security'
    ]);
  });

  it('switch statement em journeyExecutor.ts roteia case api_security para executeApiSecurity()', async () => {
    mocks.getApi.mockResolvedValue({ id: 'api-1', baseUrl: 'https://api.test' });
    mocks.listApiCredentials.mockResolvedValue([]);
    mocks.discoverApi.mockResolvedValue({ endpointsDiscovered: 0, stagesRun: [], durationMs: 10 });
    mocks.runApiPassiveTests.mockResolvedValue({ findingsCreated: 0, durationMs: 10 });
    mocks.runApiActiveTests.mockResolvedValue({ findingsCreated: 0, durationMs: 10 });

    const { journeyExecutor } = await import('../services/journeyExecutor');
    const journey: any = {
      id: 'j1', type: 'api_security', createdBy: 'user-1',
      authorizationAck: true, params: { apiId: 'api-1' },
    };
    const progresses: number[] = [];
    await journeyExecutor.executeJourney(journey, 'job-1', (p: any) => progresses.push(p.progress));
    expect(mocks.discoverApi).toHaveBeenCalledWith('api-1', expect.any(Object), 'job-1');
  });
});

describe('JRNY-02 — authorizationAck é obrigatório antes de iniciar api_security', () => {
  beforeEach(() => {
    mocks.logAuditCalls.length = 0;
    mocks.getApi.mockResolvedValue({ id: 'api-1', baseUrl: 'https://api.test' });
    mocks.listApiCredentials.mockResolvedValue([]);
    mocks.discoverApi.mockReset();
  });

  it('executeApiSecurity lança Error "requer acknowledgment" se journey.authorizationAck !== true', async () => {
    const { journeyExecutor } = await import('../services/journeyExecutor');
    const journey: any = {
      id: 'j1', type: 'api_security', createdBy: 'user-1',
      authorizationAck: false, params: { apiId: 'api-1' },
    };
    await expect(journeyExecutor.executeJourney(journey, 'job-1', () => {}))
      .rejects.toThrow(/requer acknowledgment/);
    expect(mocks.discoverApi).not.toHaveBeenCalled();
  });

  it('migration adiciona coluna authorization_ack boolean NOT NULL DEFAULT false em journeys', async () => {
    const { journeys } = await import('@shared/schema');
    expect(journeys.authorizationAck).toBeDefined();
    expect(journeys.authorizationAck.notNull).toBe(true);
    expect(journeys.authorizationAck.default).toBe(false);
    expect(journeys.authorizationAck.name).toBe('authorization_ack');
  });

  it('insertJourneySchema (derivado via createInsertSchema) inclui authorizationAck como boolean', async () => {
    const { insertJourneySchema } = await import('@shared/schema');
    const result = insertJourneySchema.safeParse({
      name: 'test', type: 'api_security', authorizationAck: true,
      params: {}, targetSelectionMode: 'individual', selectedTags: [], enableCveDetection: false,
    });
    expect(result.success).toBe(true);
  });
});

describe('JRNY-03 — discovery+testing opts fluem do journey.params para os sub-orchestrators', () => {
  beforeEach(() => {
    mocks.getApi.mockResolvedValue({ id: 'api-1', baseUrl: 'https://api.test' });
    mocks.listApiCredentials.mockResolvedValue([]);
    mocks.discoverApi.mockResolvedValue({ endpointsDiscovered: 0, stagesRun: [], durationMs: 10 });
    mocks.runApiPassiveTests.mockResolvedValue({ findingsCreated: 0, durationMs: 10 });
    mocks.runApiActiveTests.mockResolvedValue({ findingsCreated: 0, durationMs: 10 });
  });

  it('executeApiSecurity lê journey.params.discoveryOpts e passa para discoverApi()', async () => {
    const { journeyExecutor } = await import('../services/journeyExecutor');
    const discoveryOpts = { stages: { spec: true, kiterunner: true, crawler: false, httpx: true, arjun: false }, dryRun: true };
    const journey: any = {
      id: 'j1', type: 'api_security', createdBy: 'user-1',
      authorizationAck: true, params: { apiId: 'api-1', discoveryOpts },
    };
    await journeyExecutor.executeJourney(journey, 'job-1', () => {});
    expect(mocks.discoverApi).toHaveBeenCalledWith('api-1', discoveryOpts, 'job-1');
  });

  it('executeApiSecurity lê journey.params.passiveOpts e passa para runApiPassiveTests()', async () => {
    const { journeyExecutor } = await import('../services/journeyExecutor');
    const passiveOpts = { stages: { nucleiPassive: true, authFailure: false, api9Inventory: true }, dryRun: true };
    const journey: any = {
      id: 'j1', type: 'api_security', createdBy: 'user-1',
      authorizationAck: true, params: { apiId: 'api-1', passiveOpts },
    };
    await journeyExecutor.executeJourney(journey, 'job-1', () => {});
    expect(mocks.runApiPassiveTests).toHaveBeenCalledWith('api-1', passiveOpts, 'job-1');
  });

  it('executeApiSecurity lê journey.params.activeOpts e passa para runApiActiveTests()', async () => {
    const { journeyExecutor } = await import('../services/journeyExecutor');
    const activeOpts = { stages: { bola: true, bfla: true, bopla: false, rateLimit: false, ssrf: true }, destructiveEnabled: true };
    const journey: any = {
      id: 'j1', type: 'api_security', createdBy: 'user-1',
      authorizationAck: true, params: { apiId: 'api-1', activeOpts },
    };
    await journeyExecutor.executeJourney(journey, 'job-1', () => {});
    expect(mocks.runApiActiveTests).toHaveBeenCalledWith('api-1', expect.objectContaining({ destructiveEnabled: true }), 'job-1');
  });
});

describe('SAFE-03 — destructive gate antes de active tests', () => {
  beforeEach(() => {
    mocks.getApi.mockResolvedValue({ id: 'api-1', baseUrl: 'https://api.test' });
    mocks.listApiCredentials.mockResolvedValue([]);
    mocks.discoverApi.mockReset();
    mocks.discoverApi.mockResolvedValue({ endpointsDiscovered: 0, stagesRun: [], durationMs: 10 });
    mocks.runApiPassiveTests.mockReset();
    mocks.runApiPassiveTests.mockResolvedValue({ findingsCreated: 0, durationMs: 10 });
    mocks.runApiActiveTests.mockReset();
    mocks.runApiActiveTests.mockResolvedValue({ findingsCreated: 0, durationMs: 10 });
  });

  it('quando opts.destructiveEnabled=false, activeOpts sanitizados antes de runApiActiveTests', async () => {
    const { journeyExecutor } = await import('../services/journeyExecutor');
    const journey: any = {
      id: 'j1', type: 'api_security', createdBy: 'user-1',
      authorizationAck: true,
      params: { apiId: 'api-1', activeOpts: { destructiveEnabled: false } },
    };
    await journeyExecutor.executeJourney(journey, 'job-1', () => {});
    const call = mocks.runApiActiveTests.mock.calls.find(c => c[0] === 'api-1');
    expect(call![1].destructiveEnabled).toBe(false);
  });

  it('quando opts.destructiveEnabled=true, activeOpts passam inalterados para runApiActiveTests', async () => {
    const { journeyExecutor } = await import('../services/journeyExecutor');
    const journey: any = {
      id: 'j1', type: 'api_security', createdBy: 'user-1',
      authorizationAck: true,
      params: { apiId: 'api-1', activeOpts: { destructiveEnabled: true } },
    };
    await journeyExecutor.executeJourney(journey, 'job-1', () => {});
    const call = mocks.runApiActiveTests.mock.calls.find(c => c[0] === 'api-1');
    expect(call![1].destructiveEnabled).toBe(true);
  });
});

describe('SAFE-04 — audit log ao início e fim da execução', () => {
  beforeEach(() => {
    mocks.logAuditCalls.length = 0;
    mocks.getApi.mockResolvedValue({ id: 'api-1', baseUrl: 'https://api.test' });
    mocks.listApiCredentials.mockResolvedValue([
      { id: 'cred-uuid-1', apiId: 'api-1', authType: 'bearer_jwt', name: 'c1', urlPattern: '*', priority: 1 },
      { id: 'cred-uuid-2', apiId: 'api-1', authType: 'api_key_header', name: 'c2', urlPattern: '*', priority: 2 },
    ]);
    mocks.discoverApi.mockResolvedValue({ endpointsDiscovered: 5, stagesRun: [], durationMs: 10 });
    mocks.runApiPassiveTests.mockResolvedValue({ findingsCreated: 3, durationMs: 10 });
    mocks.runApiActiveTests.mockResolvedValue({ findingsCreated: 2, durationMs: 10 });
  });

  it('logAudit chamado com action="start", objectType="api_security_journey" no início', async () => {
    const { journeyExecutor } = await import('../services/journeyExecutor');
    const journey: any = {
      id: 'j1', type: 'api_security', createdBy: 'user-1',
      authorizationAck: true, params: { apiId: 'api-1' },
    };
    await journeyExecutor.executeJourney(journey, 'job-1', () => {});
    const startEntry = mocks.logAuditCalls.find(e => e.action === 'start');
    expect(startEntry).toBeDefined();
    expect(startEntry.objectType).toBe('api_security_journey');
    expect(startEntry.objectId).toBe('job-1');
    expect(startEntry.actorId).toBe('user-1');
  });

  it('logAudit chamado com action="complete" (ou "failed") com outcome + findingsCount + duration no fim', async () => {
    const { journeyExecutor } = await import('../services/journeyExecutor');
    const journey: any = {
      id: 'j1', type: 'api_security', createdBy: 'user-1',
      authorizationAck: true, params: { apiId: 'api-1' },
    };
    await journeyExecutor.executeJourney(journey, 'job-1', () => {});
    const completeEntry = mocks.logAuditCalls.find(e => e.action === 'complete');
    expect(completeEntry).toBeDefined();
    expect(completeEntry.after.outcome).toBe('completed');
    expect(completeEntry.after.findingsCount).toBe(5); // 3 passive + 2 active
    expect(typeof completeEntry.after.durationMs).toBe('number');
  });

  it('audit log after.credentialIds contém apenas UUIDs (sem secretEncrypted/dekEncrypted)', async () => {
    const { journeyExecutor } = await import('../services/journeyExecutor');
    const journey: any = {
      id: 'j1', type: 'api_security', createdBy: 'user-1',
      authorizationAck: true, params: { apiId: 'api-1' },
    };
    await journeyExecutor.executeJourney(journey, 'job-1', () => {});
    const startEntry = mocks.logAuditCalls.find(e => e.action === 'start');
    expect(startEntry.after.credentialIds).toEqual(['cred-uuid-1', 'cred-uuid-2']);
    const serialized = JSON.stringify(startEntry.after);
    expect(serialized).not.toMatch(/secretEncrypted|dekEncrypted/);
  });
});

describe('SAFE-06 — logs nunca contêm request body, credenciais ou tokens', () => {
  beforeEach(() => {
    mocks.getApi.mockResolvedValue({ id: 'api-1', baseUrl: 'https://api.test' });
    mocks.listApiCredentials.mockResolvedValue([]);
    mocks.discoverApi.mockResolvedValue({ endpointsDiscovered: 0, stagesRun: [], durationMs: 10 });
    mocks.runApiPassiveTests.mockResolvedValue({ findingsCreated: 0, durationMs: 10 });
    mocks.runApiActiveTests.mockResolvedValue({ findingsCreated: 0, durationMs: 10 });
  });

  it('durante dryRun, pino output não contém regex /(password|token|apiKey|authorization|bearer|secret)/i com valores reais', async () => {
    // Capture console output (pino goes to stdout in dev; test env uses console)
    const writes: string[] = [];
    const origStdoutWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk: any) => {
      writes.push(String(chunk));
      return true;
    }) as any;

    try {
      const { journeyExecutor } = await import('../services/journeyExecutor');
      const journey: any = {
        id: 'j1', type: 'api_security', createdBy: 'user-1',
        authorizationAck: true,
        params: { apiId: 'api-1', discoveryOpts: { dryRun: true, stages: {} } },
      };
      await journeyExecutor.executeJourney(journey, 'job-1', () => {});
    } finally {
      process.stdout.write = origStdoutWrite;
    }

    const combined = writes.join('');
    // Forbidden: actual secret-looking values (not field names)
    expect(combined).not.toMatch(/"password"\s*:\s*"[^"]+"/i);
    expect(combined).not.toMatch(/"apiKey"\s*:\s*"[^"]{5,}"/i);
    expect(combined).not.toMatch(/Bearer\s+[A-Za-z0-9_\-\.]{20,}/);
    expect(combined).not.toMatch(/"secretEncrypted"\s*:\s*"[^"]+"/);
  });

  it('logs emitidos em executeApiSecurity só contêm campos permitidos: jobId, apiId, endpointId, stage, duration, statusCode, findingId, severity, category', async () => {
    // Static analysis — read journeyExecutor.ts source and grep for forbidden log field names
    const fs = await import('node:fs/promises');
    const source = await fs.readFile('server/services/journeyExecutor.ts', 'utf8');
    // Locate executeApiSecurity method body (from "private async executeApiSecurity" to the NEXT top-level method or class close)
    const start = source.indexOf('private async executeApiSecurity');
    expect(start).toBeGreaterThan(0);
    const end = source.indexOf('\n  }\n', start) + 4; // find first method-closing brace
    const body = source.slice(start, end);
    // Forbidden: passing request body, full credential objects, authorization headers to log calls
    expect(body).not.toMatch(/log\.(info|warn|error)\([^)]*body:/);
    expect(body).not.toMatch(/log\.(info|warn|error)\([^)]*credential:/);
    expect(body).not.toMatch(/log\.(info|warn|error)\([^)]*token:/);
    expect(body).not.toMatch(/log\.(info|warn|error)\([^)]*apiKey:/);
    expect(body).not.toMatch(/log\.(info|warn|error)\([^)]*password:/);
    expect(body).not.toMatch(/log\.(info|warn|error)\([^)]*authorization:/);
  });
});
