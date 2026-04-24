/**
 * Phase 16 — UI-06 — Journey Wizard (4-Step)
 *
 * Promoted from it.todo stubs — Plan 05.
 * Per 16-VALIDATION.md task map.
 *
 * Requirement: 4-step wizard Dialog for creating api_security journeys.
 * Step 1: name + asset multi-select + targetUrl.
 * Step 2: authorizationAck Checkbox (red warning, required to proceed).
 * Step 3: stage toggles with default state per CONTEXT.md + rate limit input.
 * Step 4: read-only summary + dryRun Checkbox + submit.
 */
import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders } from './helpers';
import ApiSecurityWizard from '@/components/forms/api-security-wizard';

const ASSET_A1 = { id: 'a1', type: 'web_application', value: 'https://x/api' };
const ASSET_A2 = { id: 'a2', type: 'web_application', value: 'https://y/api' };

const DEFAULT_QUERY_DATA = {
  '/api/assets': [ASSET_A1, ASSET_A2],
  '/api/v1/apis': [],
  '/api/v1/api-credentials': [],
};

function mockFetchSuccess() {
  return vi.fn((_url: any, init?: any) => {
    const u = String(_url);
    if (u.includes('/api/v1/jobs') && init?.method === 'POST') {
      return Promise.resolve({
        ok: true,
        status: 201,
        json: async () => ({ id: 'job-1', journeyId: 'jrny-1' }),
      });
    }
    return Promise.resolve({ ok: true, status: 200, json: async () => ({}) });
  }) as any;
}

beforeEach(() => {
  global.fetch = mockFetchSuccess();
});

afterEach(() => {
  vi.restoreAllMocks();
});

// Helper: advance from step 1 to step 2
async function advanceToStep2(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByTestId('input-name'), 'Minha Jornada');
  // Asset checkboxes come from pre-populated query cache
  const chk = await screen.findByTestId('asset-checkbox-a1');
  await user.click(chk);
  await user.click(screen.getByTestId('button-next'));
  await screen.findByTestId('wizard-step-2');
}

// Helper: advance to step 3
async function advanceToStep3(user: ReturnType<typeof userEvent.setup>) {
  await advanceToStep2(user);
  await user.click(screen.getByTestId('checkbox-authorization-ack'));
  await user.click(screen.getByTestId('button-next'));
  await screen.findByTestId('wizard-step-3');
}

// Helper: advance to step 4
async function advanceToStep4(user: ReturnType<typeof userEvent.setup>) {
  await advanceToStep3(user);
  await user.click(screen.getByTestId('button-next'));
  await screen.findByTestId('wizard-step-4');
}

describe('UI-06 — ApiSecurityWizard 4-step Dialog', () => {
  it('renders step 1 initially with all 4 stepper indicators', () => {
    renderWithProviders(<ApiSecurityWizard open={true} onOpenChange={() => {}} />, {
      queryData: DEFAULT_QUERY_DATA,
    });
    expect(screen.getByTestId('wizard-step-1')).toBeInTheDocument();
    expect(screen.queryByTestId('wizard-step-2')).not.toBeInTheDocument();
    expect(screen.getByTestId('step-indicator-1')).toBeInTheDocument();
    expect(screen.getByTestId('step-indicator-2')).toBeInTheDocument();
    expect(screen.getByTestId('step-indicator-3')).toBeInTheDocument();
    expect(screen.getByTestId('step-indicator-4')).toBeInTheDocument();
  });

  it('step 1 "Próximo" is disabled when name is empty', () => {
    renderWithProviders(<ApiSecurityWizard open={true} onOpenChange={() => {}} />, {
      queryData: DEFAULT_QUERY_DATA,
    });
    const next = screen.getByTestId('button-next');
    expect(next).toBeDisabled();
  });

  it('step 1 "Próximo" is disabled when name filled but no assets selected', async () => {
    const user = userEvent.setup();
    renderWithProviders(<ApiSecurityWizard open={true} onOpenChange={() => {}} />, {
      queryData: DEFAULT_QUERY_DATA,
    });
    await user.type(screen.getByTestId('input-name'), 'Test');
    // No assets checked — button must remain disabled
    await waitFor(() => {
      expect(screen.getByTestId('button-next')).toBeDisabled();
    });
  });

  it('step 1 → step 2: "Próximo" enabled and advances after name + asset selected', async () => {
    const user = userEvent.setup();
    renderWithProviders(<ApiSecurityWizard open={true} onOpenChange={() => {}} />, {
      queryData: DEFAULT_QUERY_DATA,
    });
    await user.type(screen.getByTestId('input-name'), 'Teste Journey');
    const chk = await screen.findByTestId('asset-checkbox-a1');
    await user.click(chk);
    await waitFor(() => {
      expect(screen.getByTestId('button-next')).not.toBeDisabled();
    });
    await user.click(screen.getByTestId('button-next'));
    expect(await screen.findByTestId('wizard-step-2')).toBeInTheDocument();
  });

  it('step 2 "Próximo" is disabled when authorizationAck unchecked', async () => {
    const user = userEvent.setup();
    renderWithProviders(<ApiSecurityWizard open={true} onOpenChange={() => {}} />, {
      queryData: DEFAULT_QUERY_DATA,
    });
    await advanceToStep2(user);
    // authorizationAck is unchecked by default — next must be disabled
    expect(screen.getByTestId('button-next')).toBeDisabled();
  });

  it('step 2 → step 3: checking authorizationAck enables "Próximo" and advances', async () => {
    const user = userEvent.setup();
    renderWithProviders(<ApiSecurityWizard open={true} onOpenChange={() => {}} />, {
      queryData: DEFAULT_QUERY_DATA,
    });
    await advanceToStep2(user);
    await user.click(screen.getByTestId('checkbox-authorization-ack'));
    await waitFor(() => {
      expect(screen.getByTestId('button-next')).not.toBeDisabled();
    });
    await user.click(screen.getByTestId('button-next'));
    expect(await screen.findByTestId('wizard-step-3')).toBeInTheDocument();
  });

  it('step 3 defaults match CONTEXT.md locked values', async () => {
    const user = userEvent.setup();
    renderWithProviders(<ApiSecurityWizard open={true} onOpenChange={() => {}} />, {
      queryData: DEFAULT_QUERY_DATA,
    });
    await advanceToStep3(user);

    // specFirst=ON, crawler=ON, kiterunner=OFF per CONTEXT.md
    expect(screen.getByTestId('toggle-specFirst')).toBeChecked();
    expect(screen.getByTestId('toggle-crawler')).toBeChecked();
    expect(screen.getByTestId('toggle-kiterunner')).not.toBeChecked();

    // misconfigs=ON, auth=ON, bola=OFF per CONTEXT.md
    expect(screen.getByTestId('toggle-misconfigs')).toBeChecked();
    expect(screen.getByTestId('toggle-auth')).toBeChecked();
    expect(screen.getByTestId('toggle-bola')).not.toBeChecked();
    expect(screen.getByTestId('toggle-bfla')).not.toBeChecked();
    expect(screen.getByTestId('toggle-bopla')).not.toBeChecked();
    expect(screen.getByTestId('toggle-rateLimitTest')).toBeChecked();
    expect(screen.getByTestId('toggle-ssrf')).not.toBeChecked();

    // rateLimit default=10
    const rateLimitInput = screen.getByTestId('input-rate-limit') as HTMLInputElement;
    expect(rateLimitInput.value).toBe('10');

    // destructiveEnabled default=false
    expect(screen.getByTestId('checkbox-destructive')).not.toBeChecked();
  });

  it('step 3 estimated-requests Badge renders with ~N requests text', async () => {
    const user = userEvent.setup();
    renderWithProviders(<ApiSecurityWizard open={true} onOpenChange={() => {}} />, {
      queryData: DEFAULT_QUERY_DATA,
    });
    await advanceToStep3(user);
    const badge = screen.getByTestId('estimated-requests');
    expect(badge.textContent).toMatch(/~\d+ requests estimados/);
  });

  it('step 3 destructive warning banner appears only when destructiveEnabled toggled on', async () => {
    const user = userEvent.setup();
    renderWithProviders(<ApiSecurityWizard open={true} onOpenChange={() => {}} />, {
      queryData: DEFAULT_QUERY_DATA,
    });
    await advanceToStep3(user);
    // Initially no warning
    expect(screen.queryByTestId('destructive-warning')).not.toBeInTheDocument();
    // Toggle on
    await user.click(screen.getByTestId('checkbox-destructive'));
    await waitFor(() => {
      expect(screen.getByTestId('destructive-warning')).toBeInTheDocument();
    });
  });

  it('"Anterior" button appears at step >= 2 and returns to previous step', async () => {
    const user = userEvent.setup();
    renderWithProviders(<ApiSecurityWizard open={true} onOpenChange={() => {}} />, {
      queryData: DEFAULT_QUERY_DATA,
    });
    // Step 1: no Anterior
    expect(screen.queryByTestId('button-previous')).not.toBeInTheDocument();
    // Advance to step 2
    await advanceToStep2(user);
    expect(screen.getByTestId('button-previous')).toBeInTheDocument();
    // Click Anterior → back to step 1
    await user.click(screen.getByTestId('button-previous'));
    expect(await screen.findByTestId('wizard-step-1')).toBeInTheDocument();
  });

  it('step 4 renders read-only summary and "Criar Jornada" button', async () => {
    const user = userEvent.setup();
    renderWithProviders(<ApiSecurityWizard open={true} onOpenChange={() => {}} />, {
      queryData: DEFAULT_QUERY_DATA,
    });
    await advanceToStep4(user);
    expect(screen.getByTestId('wizard-step-4')).toBeInTheDocument();
    expect(screen.getByTestId('button-submit')).toBeInTheDocument();
    // Summary shows journey name
    expect(screen.getByTestId('summary-name').textContent).toBe('Minha Jornada');
    expect(screen.getByTestId('summary-assets').textContent).toContain('1 asset');
    // dryRun checkbox present and unchecked by default
    expect(screen.getByTestId('checkbox-dry-run')).not.toBeChecked();
  });

  it('step 4 submit calls POST /api/v1/jobs with type=api_security and authorizationAck=true', async () => {
    const fetchSpy = vi.fn((_url: any, init?: any) => {
      const u = String(_url);
      if (u.includes('/api/v1/jobs') && init?.method === 'POST') {
        const body = JSON.parse(init.body as string);
        expect(body.type).toBe('api_security');
        expect(body.params.authorizationAck).toBe(true);
        expect(body.params.apiSecurityConfig.rateLimit).toBe(10);
        expect(body.params.apiSecurityConfig.dryRun).toBe(false);
        return Promise.resolve({
          ok: true,
          status: 201,
          json: async () => ({ id: 'job-1', journeyId: 'jrny-1' }),
        });
      }
      return Promise.resolve({ ok: true, status: 200, json: async () => ({}) });
    }) as any;
    global.fetch = fetchSpy;

    const user = userEvent.setup();
    renderWithProviders(<ApiSecurityWizard open={true} onOpenChange={() => {}} />, {
      queryData: DEFAULT_QUERY_DATA,
    });
    await advanceToStep4(user);
    await act(async () => {
      await user.click(screen.getByTestId('button-submit'));
    });
    // fetch called with /api/v1/jobs POST
    const postCalls = fetchSpy.mock.calls.filter(
      ([url, opts]: any) => String(url).includes('/api/v1/jobs') && opts?.method === 'POST',
    );
    expect(postCalls.length).toBeGreaterThan(0);
  });
});
