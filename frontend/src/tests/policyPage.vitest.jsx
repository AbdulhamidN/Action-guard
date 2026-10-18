import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { PolicyPage } from '../pages/admin/PolicyPage.jsx';
import * as authStorage from '../services/authStorage.js';
import policyFixture from '../../../docs/api-examples/admin-policy.json';

describe('Admin Policy Rules & Decision Matrix (Module 12c-1)', () => {
  let queryClient;
  const originalFetch = global.fetch;

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } }
    });
    authStorage.setAdminToken('agadm_test_token_valid');
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    queryClient.clear();
  });

  function renderPolicyPage() {
    global.fetch = vi.fn().mockImplementation((url) => {
      if (url.includes('/api/v1/admin/policy')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => policyFixture
        });
      }
      return Promise.reject(new Error(`Unexpected URL: ${url}`));
    });

    return render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <PolicyPage />
        </MemoryRouter>
      </QueryClientProvider>
    );
  }

  it('renders policy metadata loaded from authentic admin-policy.json fixture', async () => {
    renderPolicyPage();

    await waitFor(() => {
      expect(screen.getByTestId('policy-title')).toHaveTextContent('Authoritative Security Policy Rules');
      expect(screen.getByText('Policy ID: default-v1')).toBeInTheDocument();
      expect(screen.getByText('Schema Version: 1.0.0')).toBeInTheDocument();
      expect(screen.getByText('Authoritative ActionGuard Module 8 Baseline Policy')).toBeInTheDocument();
    });
  });

  it('renders 4x4 baseline decision matrix with correct tier-sensitivity intersections', async () => {
    renderPolicyPage();

    await waitFor(() => {
      expect(screen.getByTestId('base-matrix-table')).toBeInTheDocument();
    });

    // Check low-low -> allow
    expect(screen.getByTestId('matrix-cell-low-low')).toHaveTextContent('allow');
    // Check medium-medium -> monitor
    expect(screen.getByTestId('matrix-cell-medium-medium')).toHaveTextContent('monitor');
    // Check high-high -> delay
    expect(screen.getByTestId('matrix-cell-high-high')).toHaveTextContent('delay');
    // Check critical-critical -> block
    expect(screen.getByTestId('matrix-cell-critical-critical')).toHaveTextContent('block');
  });

  it('renders escalation override rules with rule IDs and minimum decisions', async () => {
    renderPolicyPage();

    await waitFor(() => {
      expect(screen.getByTestId('escalation-rules-card')).toBeInTheDocument();
    });

    expect(screen.getByText('esc_impossible_travel')).toBeInTheDocument();
    expect(screen.getByText('esc_takeover_progression')).toBeInTheDocument();
    expect(screen.getByText('esc_credential_cascade')).toBeInTheDocument();
  });

  it('renders fail-safe fallback boundaries and enforcement execution modes', async () => {
    renderPolicyPage();

    await waitFor(() => {
      expect(screen.getByTestId('fail-safe-card')).toBeInTheDocument();
      expect(screen.getByTestId('enforcement-modes-card')).toBeInTheDocument();
    });

    // Enforcement modes display 'automatic'
    expect(screen.getAllByText('automatic').length).toBeGreaterThan(0);
  });

  it('renders default action sensitivity catalog mapping actions to risk sensitivity', async () => {
    renderPolicyPage();

    await waitFor(() => {
      expect(screen.getByTestId('sensitivities-catalog-card')).toBeInTheDocument();
    });

    expect(screen.getByText('password_change')).toBeInTheDocument();
    expect(screen.getByText('high_impact_action')).toBeInTheDocument();
    expect(screen.getByText('recovery_email_change')).toBeInTheDocument();
  });
});
