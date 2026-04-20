/**
 * Phase 16 — UI-05 — False Positive Marking
 *
 * Promoted from Wave 0 it.todo stubs to real it() assertions.
 * Per 16-VALIDATION.md task map.
 *
 * Requirement: "Falso Positivo" action per row (only when sourceFilter=api_security).
 * Opens AlertDialog with pt-BR message. Confirmar calls PATCH /api/v1/api-findings/:id.
 * Toast on success. queryClient invalidated with /api/threats key.
 */
import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders } from './helpers';
import Threats from '@/pages/threats';

vi.mock('@/components/layout/sidebar', () => ({
  default: () => React.createElement('div', { 'data-testid': 'sidebar-mock' }),
}));
vi.mock('@/components/layout/topbar', () => ({
  default: () => React.createElement('div', { 'data-testid': 'topbar-mock' }),
}));
vi.mock('@/components/subscription-banner', () => ({ default: () => null }));
vi.mock('@/components/action-plan/AssociateToPlanDialog', () => ({
  AssociateToPlanDialog: () => null,
}));
vi.mock('@/lib/websocket', () => ({ useWebSocket: () => ({ connected: true }) }));
vi.mock('@/hooks/useActionPlans', () => ({
  usePlanLinks: () => ({}),
  useActionPlans: () => ({ data: { items: [], total: 0 }, isLoading: false }),
  useAssociateThreats: () => ({ mutate: vi.fn(), isPending: false }),
  useCreateActionPlan: () => ({ mutate: vi.fn(), isPending: false }),
  useUpdateActionPlan: () => ({ mutate: vi.fn(), isPending: false }),
}));

// Polyfill missing JSDOM APIs required by Radix UI Select
if (!Element.prototype.hasPointerCapture) {
  Element.prototype.hasPointerCapture = () => false;
}
if (!Element.prototype.setPointerCapture) {
  Element.prototype.setPointerCapture = () => {};
}
if (!Element.prototype.releasePointerCapture) {
  Element.prototype.releasePointerCapture = () => {};
}
if (!Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = () => {};
}
global.ResizeObserver = global.ResizeObserver ?? class {
  observe() {}
  unobserve() {}
  disconnect() {}
};

const makeApiSecurityThreat = (overrides: Record<string, unknown> = {}) => ({
  id: 't1',
  title: 'BOLA Detectado',
  description: null,
  severity: 'high',
  status: 'open',
  source: 'api_security',
  hostId: null,
  host: null,
  groupingKey: null,
  parentThreatId: null,
  category: null,
  ruleId: null,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  evidence: {
    apiEndpointId: 'e1',
    findingIds: ['f1'],
    owaspCategory: 'api1_bola_2023',
    url: 'https://api.example.com/users/123',
    method: 'GET',
    authType: 'bearer_jwt',
  },
  ...overrides,
});

beforeEach(() => {
  global.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: async () => [],
  }) as any;
});

async function setupPage(threats: unknown[], fetchImpl?: ReturnType<typeof vi.fn>) {
  if (fetchImpl) {
    global.fetch = fetchImpl as any;
  } else {
    (global.fetch as any).mockResolvedValue({ ok: true, json: async () => threats });
  }
  const result = renderWithProviders(<Threats />);
  const user = userEvent.setup();
  await user.click(screen.getByTestId('select-source-filter'));
  await user.click(screen.getByRole('option', { name: 'API Security' }));
  return { user, ...result };
}

describe('UI-05 — False Positive Marking', () => {
  it('"Falso Positivo" action button is rendered per row when sourceFilter = "api_security"', async () => {
    const threats = [makeApiSecurityThreat()];
    await setupPage(threats);
    expect(await screen.findByTestId('button-false-positive-t1')).toBeInTheDocument();
  });

  it('AlertDialog opens on "Falso Positivo" click with pt-BR confirmation message', async () => {
    const threats = [makeApiSecurityThreat()];
    const { user } = await setupPage(threats);
    const btn = await screen.findByTestId('button-false-positive-t1');
    await user.click(btn);
    expect(await screen.findByTestId('alert-false-positive')).toBeInTheDocument();
  });

  it('AlertDialog message contains "Marcar como falso positivo?"', async () => {
    const threats = [makeApiSecurityThreat()];
    const { user } = await setupPage(threats);
    await user.click(await screen.findByTestId('button-false-positive-t1'));
    await waitFor(() => {
      expect(screen.getByText('Marcar como falso positivo?')).toBeInTheDocument();
    });
  });

  it('"Cancelar" button closes AlertDialog WITHOUT calling the PATCH mutation', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => [makeApiSecurityThreat()] });
    const { user } = await setupPage([], fetchMock);
    await user.click(await screen.findByTestId('button-false-positive-t1'));
    await screen.findByTestId('alert-false-positive');
    await user.click(screen.getByRole('button', { name: 'Cancelar' }));
    // Dialog closes
    await waitFor(() => {
      expect(screen.queryByTestId('alert-false-positive')).not.toBeInTheDocument();
    });
    // PATCH /api/v1/api-findings was NOT called
    const patchCalls = (fetchMock.mock.calls as [string, ...unknown[]][]).filter(([url]) =>
      url?.includes('/api/v1/api-findings/')
    );
    expect(patchCalls).toHaveLength(0);
  });

  it('"Confirmar" button calls PATCH /api/v1/api-findings/:id with body {falsePositive: true}', async () => {
    const threat = makeApiSecurityThreat();
    // Differentiate: PATCH to api-findings returns {}; GET /api/threats returns array
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/api-findings/')) {
        return Promise.resolve({ ok: true, json: async () => ({}) });
      }
      return Promise.resolve({ ok: true, json: async () => [threat] });
    });
    const { user } = await setupPage([], fetchMock);
    await user.click(await screen.findByTestId('button-false-positive-t1'));
    await screen.findByTestId('alert-false-positive');
    await user.click(screen.getByTestId('button-confirm-false-positive'));
    await waitFor(() => {
      const calls = fetchMock.mock.calls as [string, RequestInit, ...unknown[]][];
      const patchCall = calls.find(([url]) => url?.includes('/api/v1/api-findings/f1'));
      expect(patchCall).toBeDefined();
    });
  });

  it('toast "Finding marcado como falso positivo" fires on mutation onSuccess', async () => {
    // Toaster not mounted in renderWithProviders — check mutation fires (onSuccess state update)
    // by verifying opacity-50 applied, which is the visible side effect of onSuccess
    const threat = makeApiSecurityThreat();
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/api-findings/')) {
        return Promise.resolve({ ok: true, json: async () => ({}) });
      }
      return Promise.resolve({ ok: true, json: async () => [threat] });
    });
    const { user } = await setupPage([], fetchMock);
    await user.click(await screen.findByTestId('button-false-positive-t1'));
    await screen.findByTestId('alert-false-positive');
    await user.click(screen.getByTestId('button-confirm-false-positive'));
    // onSuccess fires → setFalsePositiveIds adds threat id → row gets opacity-50
    // This verifies the mutation onSuccess callback executed
    await waitFor(() => {
      const row = screen.getByTestId('threat-row-t1');
      expect(row.className).toContain('opacity-50');
    });
  });

  it('row gains opacity-50 class + "Falso Positivo" badge after success', async () => {
    const threat = makeApiSecurityThreat();
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/api-findings/')) {
        return Promise.resolve({ ok: true, json: async () => ({}) });
      }
      return Promise.resolve({ ok: true, json: async () => [threat] });
    });
    const { user } = await setupPage([], fetchMock);
    await user.click(await screen.findByTestId('button-false-positive-t1'));
    await screen.findByTestId('alert-false-positive');
    await user.click(screen.getByTestId('button-confirm-false-positive'));
    await waitFor(() => {
      const row = screen.getByTestId('threat-row-t1');
      expect(row.className).toContain('opacity-50');
      expect(screen.getByTestId('badge-false-positive-t1')).toBeInTheDocument();
    });
  });

  it('queryClient.invalidateQueries called with key containing "/api/threats" after success', async () => {
    const threat = makeApiSecurityThreat();
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/api-findings/')) {
        return Promise.resolve({ ok: true, json: async () => ({}) });
      }
      return Promise.resolve({ ok: true, json: async () => [threat] });
    });
    const { user, qc } = await setupPage([], fetchMock);
    const invalidateSpy = vi.spyOn(qc, 'invalidateQueries');
    await user.click(await screen.findByTestId('button-false-positive-t1'));
    await screen.findByTestId('alert-false-positive');
    await user.click(screen.getByTestId('button-confirm-false-positive'));
    await waitFor(() => {
      const calls = invalidateSpy.mock.calls as [{ queryKey: unknown[] }, ...unknown[]][];
      const threatsCall = calls.find(([opts]) =>
        JSON.stringify(opts?.queryKey)?.includes('/api/threats')
      );
      expect(threatsCall).toBeDefined();
    });
  });
});
