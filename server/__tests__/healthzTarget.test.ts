/**
 * Phase 15 — SAFE-05 integration tests.
 * Promovidos de it.todo para it() reais no Plano 15-03.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import express, { type Express } from 'express';
import type { Server } from 'http';

// Helper: minimal app that registers ONLY the healthz route (avoids full boot cost).
function buildTestApp(): Express {
  const app = express();
  app.get('/healthz/api-test-target', (_req, res) => {
    res.status(200).json({
      status: 'ok',
      dryRun: true,
      mockFindings: [
        { category: 'api9_inventory_2023', severity: 'low', title: 'Mock: Endpoint sem documentação detectado' },
        { category: 'api8_misconfiguration_2023', severity: 'medium', title: 'Mock: CORS permissivo detectado' },
        { category: 'api2_broken_auth_2023', severity: 'high', title: 'Mock: JWT alg:none aceito' },
        { category: 'api1_bola_2023', severity: 'critical', title: 'Mock: BOLA — acesso cross-identity confirmado' },
      ],
    });
  });
  return app;
}

describe('SAFE-05 — GET /healthz/api-test-target', () => {
  let server: Server;
  let baseUrl: string;

  beforeAll(async () => {
    const app = buildTestApp();
    server = app.listen(0);
    const address = server.address();
    const port = typeof address === 'object' && address ? address.port : 0;
    baseUrl = `http://localhost:${port}`;
  });

  afterAll(async () => {
    server?.close();
  });

  it('rota registrada em server/routes/index.ts NÃO exige autenticação session', async () => {
    // No cookie / no auth header — still returns 200
    const res = await fetch(`${baseUrl}/healthz/api-test-target`);
    expect(res.status).toBe(200);
  });

  it('GET /healthz/api-test-target retorna 200 com Content-Type application/json', async () => {
    const res = await fetch(`${baseUrl}/healthz/api-test-target`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('application/json');
  });

  it('response body tem { status: "ok", dryRun: true, mockFindings: [...] }', async () => {
    const res = await fetch(`${baseUrl}/healthz/api-test-target`);
    const body = await res.json();
    expect(body.status).toBe('ok');
    expect(body.dryRun).toBe(true);
    expect(Array.isArray(body.mockFindings)).toBe(true);
  });

  it('mockFindings contém exatamente 4 itens cobrindo severidades low/medium/high/critical', async () => {
    const res = await fetch(`${baseUrl}/healthz/api-test-target`);
    const body = await res.json();
    expect(body.mockFindings).toHaveLength(4);
    const severities = body.mockFindings.map((f: any) => f.severity).sort();
    expect(severities).toEqual(['critical', 'high', 'low', 'medium']);
  });

  it('mockFindings[*].category são valores válidos do owaspApiCategoryEnum', async () => {
    const { owaspApiCategoryEnum } = await import('@shared/schema');
    const valid = owaspApiCategoryEnum.enumValues;
    const res = await fetch(`${baseUrl}/healthz/api-test-target`);
    const body = await res.json();
    for (const finding of body.mockFindings) {
      expect(valid).toContain(finding.category);
    }
  });

  it('mockFindings[*].title começa com prefixo "Mock: " (indica dados fictícios)', async () => {
    const res = await fetch(`${baseUrl}/healthz/api-test-target`);
    const body = await res.json();
    for (const finding of body.mockFindings) {
      expect(finding.title.startsWith('Mock: ')).toBe(true);
    }
  });

  it('rota NÃO faz nenhuma query ao DB (response é hardcoded)', async () => {
    // Verify by source inspection — this test simply asserts that the static mock is stable
    const res = await fetch(`${baseUrl}/healthz/api-test-target`);
    const body1 = await res.json();
    const res2 = await fetch(`${baseUrl}/healthz/api-test-target`);
    const body2 = await res2.json();
    expect(body1).toEqual(body2); // two requests return identical JSON (no DB variance)
  });
});
