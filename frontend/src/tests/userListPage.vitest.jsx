import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { UserListPage } from '../pages/admin/UserListPage.jsx';
import * as authStorage from '../services/authStorage.js';
import usersFixture from '../../../docs/api-examples/admin-users.json';

describe('Admin User Directory (Module 12c-1)', () => {
  let queryClient;
  const originalFetch = global.fetch;

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false }
      }
    });
    authStorage.setAdminToken('agadm_test_token_valid');
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    queryClient.clear();
  });

  function renderUserList() {
    return render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <UserListPage />
        </MemoryRouter>
      </QueryClientProvider>
    );
  }

  it('renders users list loaded from authentic admin-users.json fixture', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => usersFixture
    });

    renderUserList();

    expect(screen.getByTestId('user-list-title')).toHaveTextContent('User Directory & Session Posture');

    await waitFor(() => {
      expect(screen.getByText('alex.security@actionguard.test')).toBeInTheDocument();
      expect(screen.getByText('contained.target@actionguard.test')).toBeInTheDocument();
      expect(screen.getByText('sam.operator@actionguard.test')).toBeInTheDocument();
    });

    // Check risk badge for alex (critical)
    expect(screen.getByTestId('tier-badge-critical')).toBeInTheDocument();
    // Sam has high risk
    expect(screen.getByTestId('tier-badge-high')).toBeInTheDocument();
  });

  it('debounces search input by 300ms before sending query with search parameter', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => usersFixture
    });

    renderUserList();

    const searchInput = screen.getByTestId('user-search-input');

    // Type query
    fireEvent.change(searchInput, { target: { value: 'alex' } });

    // Immediately after typing, fetch has NOT been called for search='alex'
    expect(global.fetch).not.toHaveBeenCalledWith(
      expect.stringContaining('search=alex'),
      expect.anything()
    );

    // After debounce delay, fetch is called with search parameter
    await waitFor(
      () => {
        expect(global.fetch).toHaveBeenCalledWith(
          expect.stringContaining('search=alex'),
          expect.anything()
        );
      },
      { timeout: 1500 }
    );
  });

  it('handles pagination controls and page boundary button states', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        users: usersFixture.users,
        total: 25 // 25 users = 3 pages with limit 10
      })
    });

    renderUserList();

    await waitFor(() => {
      expect(screen.getByText('Page 1 of 3')).toBeInTheDocument();
    });

    const prevBtn = screen.getByTestId('pagination-prev');
    const nextBtn = screen.getByTestId('pagination-next');

    // Previous is disabled on page 1
    expect(prevBtn).toBeDisabled();
    expect(nextBtn).toBeEnabled();

    // Click next page
    fireEvent.click(nextBtn);

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('offset=10'),
        expect.anything()
      );
    });
  });

  it('renders containment lockout badge when locked_until is present in future', async () => {
    const futureDate = new Date(Date.now() + 3600000).toISOString();
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        users: [
          {
            id: 'usr_locked_demo',
            email: 'locked.user@actionguard.test',
            created_at: '2026-10-18T00:00:00Z',
            locked_until: futureDate,
            latest_risk_tier: 'critical',
            active_sessions: 0
          }
        ],
        total: 1
      })
    });

    renderUserList();

    await waitFor(() => {
      expect(screen.getByText(/Locked until/i)).toBeInTheDocument();
    });
  });

  it('renders malicious markup safely as plain text to prevent XSS injection', async () => {
    const maliciousPayload = '<img src=x onerror=alert(1)>';
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        users: [
          {
            id: maliciousPayload,
            email: maliciousPayload,
            created_at: '2026-10-18T00:00:00Z',
            locked_until: null,
            latest_risk_tier: null,
            active_sessions: 0
          }
        ],
        total: 1
      })
    });

    renderUserList();

    await waitFor(() => {
      // Must be safely rendered as text content, not an img element
      expect(screen.getAllByText(maliciousPayload).length).toBeGreaterThan(0);
      expect(document.querySelector('img[src="x"]')).toBeNull();
    });
  });
});
