import React from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Router } from 'wouter';
import { memoryLocation } from 'wouter/memory-location';
import { render } from '@testing-library/react';
import type { ReactNode } from 'react';

export function renderWithProviders(
  ui: ReactNode,
  opts?: { initialPath?: string; queryData?: Record<string, unknown> },
) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  });

  if (opts?.queryData) {
    for (const [key, data] of Object.entries(opts.queryData)) {
      qc.setQueryData([key], data);
    }
  }

  const { hook } = memoryLocation({ path: opts?.initialPath ?? '/' });

  return {
    qc,
    ...render(
      <QueryClientProvider client={qc}>
        <Router hook={hook}>{ui}</Router>
      </QueryClientProvider>,
    ),
  };
}
