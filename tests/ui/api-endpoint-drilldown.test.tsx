/**
 * Phase 16 — UI-02 — API Endpoint Drilldown Sheet
 *
 * Promoted from Wave 0 it.todo stubs to real it() assertions.
 *
 * Requirement: Sheet slides open from the right showing endpoints grouped by path.
 * Each path-group is a Collapsible. METHOD_COLORS drives Badge color.
 * requiresAuth=true shows a lock icon or badge.
 * Param chips: path=orange, query=blue, header=purple.
 */
import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { screen, within, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders } from './helpers';
import ApiDiscovery from '@/pages/api-discovery';

// Mock layout components
vi.mock('@/components/layout/sidebar', () => ({
  default: () => <div data-testid="sidebar-mock" />,
}));
vi.mock('@/components/layout/topbar', () => ({
  default: ({ title }: { title: string }) => <div data-testid="topbar-mock">{title}</div>,
}));

const makeApi = (id = 'a1') => ({
  id,
  parentAssetId: 'asset1',
  baseUrl: 'https://api.example.com',
  apiType: 'rest' as const,
  name: null,
  description: null,
  specUrl: null,
  specHash: null,
  specVersion: null,
  specLastFetchedAt: null,
  createdAt: new Date().toISOString(),
  createdBy: 'user1',
  updatedAt: new Date().toISOString(),
  endpointCount: 3,
  lastExecutionAt: null,
  discoveryMethod: null,
});

const makeEndpoint = (overrides: Partial<Record<string, unknown>> = {}) => ({
  id: 'e1',
  apiId: 'a1',
  method: 'GET',
  path: '/users',
  pathParams: [],
  queryParams: [],
  headerParams: [],
  requestSchema: null,
  responseSchema: null,
  requiresAuth: false,
  discoverySources: ['spec'],
  httpxStatus: 200,
  httpxContentType: null,
  httpxTech: null,
  httpxTls: null,
  httpxLastProbedAt: null,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  ...overrides,
});

// Helper: render page, click on api row to open Sheet
async function renderWithSheetOpen(apiId = 'a1', endpoints: unknown[] = []) {
  const user = userEvent.setup();
  const api = makeApi(apiId);
  renderWithProviders(<ApiDiscovery />, {
    queryData: {
      '/api/v1/apis': [api],
      [`/api/v1/apis/${apiId}/endpoints`]: endpoints,
    },
  });
  const row = screen.getByTestId(`api-row-${apiId}`);
  await user.click(row);
  // Get the Sheet dialog
  const dialog = screen.getByRole('dialog');
  return { user, dialog };
}

describe('UI-02 — API Endpoint Drilldown Sheet', () => {
  it('Sheet opens when selectedApiId prop is set (not null)', async () => {
    const { dialog } = await renderWithSheetOpen('a1', []);
    // Sheet is present as a dialog role
    expect(dialog).toBeInTheDocument();
    // Sheet title shows the API baseUrl
    within(dialog).getByText('https://api.example.com');
  });

  it('endpoints grouped by path: one Collapsible rendered per distinct path', async () => {
    const endpoints = [
      makeEndpoint({ id: 'e1', method: 'GET', path: '/users' }),
      makeEndpoint({ id: 'e2', method: 'POST', path: '/users' }),
      makeEndpoint({ id: 'e3', method: 'DELETE', path: '/users/:id' }),
    ];
    await renderWithSheetOpen('a1', endpoints);

    // Two distinct paths → two CollapsibleTrigger groups
    expect(screen.getByTestId('group-/users')).toBeInTheDocument();
    expect(screen.getByTestId('group-/users/:id')).toBeInTheDocument();
  });

  it('method Badge color applies METHOD_COLORS (e.g. GET → green class)', async () => {
    const endpoints = [makeEndpoint({ id: 'e1', method: 'GET', path: '/items' })];
    await renderWithSheetOpen('a1', endpoints);

    // Expand the group: click the button inside the Collapsible (CollapsibleTrigger asChild wraps button)
    const groupRoot = screen.getByTestId('group-/items');
    const triggerButton = groupRoot.querySelector('button')!;
    fireEvent.click(triggerButton);

    // Method badge for GET should have green classes from METHOD_COLORS.GET
    const badge = screen.getByTestId('method-badge-GET');
    expect(badge).toBeInTheDocument();
    // CLASS from METHOD_COLORS.GET = 'bg-green-600/20 text-green-500'
    expect(badge.className).toContain('green');
  });

  it('requiresAuth=true renders lock icon or "Auth" badge indicator', async () => {
    const endpoints = [
      makeEndpoint({ id: 'e1', method: 'POST', path: '/secure', requiresAuth: true }),
    ];
    await renderWithSheetOpen('a1', endpoints);

    const groupRoot = screen.getByTestId('group-/secure');
    const triggerButton = groupRoot.querySelector('button')!;
    fireEvent.click(triggerButton);

    const authBadge = screen.getByTestId('auth-badge');
    expect(authBadge).toBeInTheDocument();
    expect(within(authBadge).getByText('Auth')).toBeInTheDocument();
  });

  it('path param chip renders with orange Tailwind class', async () => {
    const endpoints = [
      makeEndpoint({
        id: 'e1',
        method: 'GET',
        path: '/items/:id',
        pathParams: [{ name: 'id', type: 'string' }],
      }),
    ];
    await renderWithSheetOpen('a1', endpoints);

    const groupRoot = screen.getByTestId('group-/items/:id');
    const triggerButton = groupRoot.querySelector('button')!;
    fireEvent.click(triggerButton);

    const chip = screen.getByTestId('chip-path-id');
    expect(chip).toBeInTheDocument();
    // PARAM_COLORS.path = 'bg-orange-500/20 text-orange-600'
    expect(chip.className).toContain('orange');
  });

  it('query param chip renders with blue Tailwind class', async () => {
    const endpoints = [
      makeEndpoint({
        id: 'e1',
        method: 'GET',
        path: '/search',
        queryParams: [{ name: 'q', type: 'string' }],
      }),
    ];
    await renderWithSheetOpen('a1', endpoints);

    const groupRoot = screen.getByTestId('group-/search');
    const triggerButton = groupRoot.querySelector('button')!;
    fireEvent.click(triggerButton);

    const chip = screen.getByTestId('chip-query-q');
    expect(chip).toBeInTheDocument();
    // PARAM_COLORS.query = 'bg-blue-500/20 text-blue-500'
    expect(chip.className).toContain('blue');
  });

  it('header param chip renders with purple Tailwind class', async () => {
    const endpoints = [
      makeEndpoint({
        id: 'e1',
        method: 'GET',
        path: '/protected',
        headerParams: [{ name: 'x-api-key', type: 'string' }],
      }),
    ];
    await renderWithSheetOpen('a1', endpoints);

    const groupRoot = screen.getByTestId('group-/protected');
    const triggerButton = groupRoot.querySelector('button')!;
    fireEvent.click(triggerButton);

    const chip = screen.getByTestId('chip-header-x-api-key');
    expect(chip).toBeInTheDocument();
    // PARAM_COLORS.header = 'bg-purple-500/20 text-purple-500'
    expect(chip.className).toContain('purple');
  });

  it('renders empty-state "Nenhum endpoint descoberto" when endpoints array is empty', async () => {
    await renderWithSheetOpen('a1', []);
    expect(screen.getByTestId('endpoints-empty')).toBeInTheDocument();
    expect(screen.getByText(/Nenhum endpoint descoberto/)).toBeInTheDocument();
  });
});
