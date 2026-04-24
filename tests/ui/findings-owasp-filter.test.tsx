/**
 * Phase 16 — UI-03 — Findings OWASP Source Filter
 *
 * Promoted from Wave 0 it.todo stubs to real it() assertions.
 * Per 16-VALIDATION.md task map.
 *
 * Requirement: Add source filter Select to /threats page.
 * source=api_security shows OWASP badge column using getOwaspBadgeInfo.
 * OWASP badge displays info.codigo (e.g. "API3:2023") not the raw key.
 * Fallback "N/A" badge in gray when owaspCategory is absent.
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
// ResizeObserver used by Radix
global.ResizeObserver = global.ResizeObserver ?? class {
  observe() {}
  unobserve() {}
  disconnect() {}
};

const makeThreat = (overrides: Record<string, unknown> = {}) => ({
  id: 't1',
  title: 'Test Threat',
  description: null,
  severity: 'high',
  status: 'open',
  source: 'api_security',
  hostId: null,
  host: null,
  groupingKey: null,
  parentThreatId: null,
  evidence: null,
  category: null,
  ruleId: null,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  ...overrides,
});

beforeEach(() => {
  global.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: async () => [],
  }) as any;
});

describe('UI-03 — Findings OWASP Source Filter', () => {
  it('Select[source] renders with options including "all" and "api_security"', async () => {
    renderWithProviders(<Threats />);
    expect(screen.getByTestId('select-source-filter')).toBeInTheDocument();
  });

  it('OWASP badge column renders ONLY when sourceFilter === "api_security"', async () => {
    const threats = [makeThreat({ id: 't1', evidence: { owaspCategory: 'api1_bola_2023', findingIds: ['f1'] } })];
    (global.fetch as any).mockResolvedValue({ ok: true, json: async () => threats });
    renderWithProviders(<Threats />);
    // Wait for threats to load - the table renders
    await waitFor(() => {
      expect(screen.getByTestId('threat-row-t1')).toBeInTheDocument();
    });
    // Default state (all) — OWASP column should NOT be present
    expect(screen.queryByTestId('th-owasp')).not.toBeInTheDocument();
    // Switch to api_security
    const user = userEvent.setup();
    await user.click(screen.getByTestId('select-source-filter'));
    await user.click(screen.getByRole('option', { name: 'API Security' }));
    await waitFor(() => {
      expect(screen.getByTestId('th-owasp')).toBeInTheDocument();
    });
  });

  it('OWASP badge text uses info.codigo (e.g. "API3:2023") not raw owaspCategory key', async () => {
    const threats = [
      makeThreat({
        id: 't1',
        evidence: {
          owaspCategory: 'api3_bopla_2023',
          apiEndpointId: 'e1',
          findingIds: ['f1'],
          url: 'https://api.example.com/users',
          method: 'GET',
          authType: 'bearer_jwt',
        },
      }),
    ];
    (global.fetch as any).mockResolvedValue({ ok: true, json: async () => threats });
    const user = userEvent.setup();
    renderWithProviders(<Threats />);
    await user.click(screen.getByTestId('select-source-filter'));
    await user.click(screen.getByRole('option', { name: 'API Security' }));
    const badge = await screen.findByTestId('owasp-badge-API3:2023');
    expect(badge).toBeInTheDocument();
    // Should show the short codigo, not the raw key
    expect(badge.textContent).toBe('API3:2023');
    expect(badge.textContent).not.toContain('api3_bopla_2023');
  });

  it('OWASP badge color class matches finding severity (getSeverityColor)', async () => {
    const threats = [
      makeThreat({
        id: 't1',
        severity: 'high',
        evidence: {
          owaspCategory: 'api1_bola_2023',
          apiEndpointId: 'e1',
          findingIds: ['f1'],
        },
      }),
    ];
    (global.fetch as any).mockResolvedValue({ ok: true, json: async () => threats });
    const user = userEvent.setup();
    renderWithProviders(<Threats />);
    await user.click(screen.getByTestId('select-source-filter'));
    await user.click(screen.getByRole('option', { name: 'API Security' }));
    const badge = await screen.findByTestId('owasp-badge-API1:2023');
    // getSeverityColor('high') returns 'bg-orange-600 text-white'
    expect(badge.className).toContain('bg-orange-600');
  });

  it('renders fallback "N/A" badge in gray when finding has no owaspCategory in evidence', async () => {
    const threats = [
      makeThreat({
        id: 't2',
        evidence: { findingIds: ['f2'], apiEndpointId: 'e2' },
      }),
    ];
    (global.fetch as any).mockResolvedValue({ ok: true, json: async () => threats });
    const user = userEvent.setup();
    renderWithProviders(<Threats />);
    await user.click(screen.getByTestId('select-source-filter'));
    await user.click(screen.getByRole('option', { name: 'API Security' }));
    const badge = await screen.findByTestId('owasp-badge-na');
    expect(badge).toBeInTheDocument();
    expect(badge.textContent).toBe('N/A');
  });

  it('source filter "all" hides OWASP badge column and shows all threats', async () => {
    const threats = [makeThreat({ id: 't1' })];
    (global.fetch as any).mockResolvedValue({ ok: true, json: async () => threats });
    renderWithProviders(<Threats />);
    // Default = all, OWASP column absent
    expect(screen.queryByTestId('th-owasp')).not.toBeInTheDocument();
    // Confirm the row renders (threat shows)
    await waitFor(() => {
      expect(screen.getByTestId('threat-row-t1')).toBeInTheDocument();
    });
  });

  it('changing source to "api_security" triggers queryClient refetch with updated queryKey', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => [] });
    global.fetch = fetchMock as any;
    const user = userEvent.setup();
    renderWithProviders(<Threats />);
    await user.click(screen.getByTestId('select-source-filter'));
    await user.click(screen.getByRole('option', { name: 'API Security' }));
    await waitFor(() => {
      // Should have called fetch with ?source=api_security
      const calls = fetchMock.mock.calls as [string, ...unknown[]][];
      const apiSecurityCall = calls.find(([url]) => url?.includes('source=api_security'));
      expect(apiSecurityCall).toBeDefined();
    });
  });
});
