import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { UserDetailPage } from '../pages/admin/UserDetailPage.jsx';
import * as authStorage from '../services/authStorage.js';

import userEventsFixture from '../../../docs/api-examples/admin-user-events.json';
import userRiskFixture from '../../../docs/api-examples/admin-user-risk-history.json';
import userDecisionsFixture from '../../../docs/api-examples/admin-user-decisions.json';
import userSessionsFixture from '../../../docs/api-examples/admin-user-sessions.json';
import userSequenceFixture from '../../../docs/api-examples/admin-user-sequence.json';

describe('Admin User Detail & Investigation (Module 12c-1)', () => {
  let queryClient;
  const originalFetch = global.fetch;
  const testUserId = 'usr_fixture_admin_demo_01';

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

  function setupFetchMock() {
    global.fetch = vi.fn().mockImplementation((url) => {
      if (url.includes(`/api/v1/admin/users/${testUserId}/events`)) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => userEventsFixture
        });
      }
      if (url.includes(`/api/v1/admin/users/${testUserId}/risk-history`)) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => userRiskFixture
        });
      }
      if (url.includes(`/api/v1/admin/users/${testUserId}/decisions`)) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => userDecisionsFixture
        });
      }
      if (url.includes(`/api/v1/admin/users/${testUserId}/sessions`)) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => userSessionsFixture
        });
      }
      if (url.includes(`/api/v1/admin/users/${testUserId}/sequence`)) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => userSequenceFixture
        });
      }
      return Promise.reject(new Error(`Unexpected URL: ${url}`));
    });
  }

  function renderUserDetail() {
    return render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={[`/admin/users/${testUserId}`]}>
          <Routes>
            <Route path="/admin/users/:id" element={<UserDetailPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    );
  }

  it('renders unified timeline merging events, risk, decisions, and active sequence steps', async () => {
    setupFetchMock();
    renderUserDetail();

    expect(screen.getByTestId('user-detail-title')).toHaveTextContent(testUserId);

    await waitFor(() => {
      expect(screen.getByTestId('timeline-list')).toBeInTheDocument();
    });

    const timelineItems = screen.getAllByTestId('timeline-item');
    // userEventsFixture has 5 events
    expect(timelineItems).toHaveLength(5);

    // Verify sequence step badges are rendered for events in active sequence
    expect(screen.getByText('Sequence Step 1/2')).toBeInTheDocument();
    expect(screen.getByText('Sequence Step 2/2')).toBeInTheDocument();

    // Verify active sequence indicator badge in header
    expect(screen.getByTestId('active-sequence-badge')).toBeInTheDocument();
  });

  it('switches between investigation tabs and renders corresponding tab views', async () => {
    setupFetchMock();
    renderUserDetail();

    await waitFor(() => {
      expect(screen.getByTestId('timeline-content')).toBeInTheDocument();
    });

    // Switch to Risk Tab
    fireEvent.click(screen.getByTestId('tab-risk'));
    await waitFor(() => {
      expect(screen.getByTestId('risk-content')).toBeInTheDocument();
      expect(screen.getByText('Risk Score Progression')).toBeInTheDocument();
    });

    // Switch to Decisions Tab
    fireEvent.click(screen.getByTestId('tab-decisions'));
    await waitFor(() => {
      expect(screen.getByTestId('decisions-content')).toBeInTheDocument();
      expect(screen.getAllByTestId('decision-row')).toHaveLength(2);
    });

    // Switch to Sessions Tab
    fireEvent.click(screen.getByTestId('tab-sessions'));
    await waitFor(() => {
      expect(screen.getByTestId('sessions-content')).toBeInTheDocument();
      expect(screen.getAllByTestId('session-row')).toHaveLength(2);
    });
  });

  it('provides explanation graph links for recorded decisions', async () => {
    setupFetchMock();
    renderUserDetail();

    fireEvent.click(screen.getByTestId('tab-decisions'));

    await waitFor(() => {
      expect(screen.getByTestId('view-graph-dec_fixture_02_contained')).toBeInTheDocument();
      expect(screen.getByTestId('view-graph-dec_fixture_01_allowed')).toBeInTheDocument();
    });

    const graphLink = screen.getByTestId('view-graph-dec_fixture_02_contained');
    expect(graphLink.getAttribute('href')).toBe(
      `/admin/users/${testUserId}/decisions/dec_fixture_02_contained`
    );
  });

  it('opens accessible EventDetailDrawer on timeline item click', async () => {
    setupFetchMock();
    renderUserDetail();

    await waitFor(() => {
      expect(screen.getByTestId('timeline-list')).toBeInTheDocument();
    });

    const firstItem = screen.getAllByTestId('timeline-item')[0];
    fireEvent.click(firstItem);

    const drawer = await screen.findByTestId('event-detail-drawer');
    expect(drawer).toBeInTheDocument();
    expect(screen.getByTestId('drawer-title')).toHaveTextContent('Event Details');

    // Close drawer via button
    fireEvent.click(screen.getByTestId('drawer-close-button'));
    await waitFor(() => {
      expect(screen.queryByTestId('event-detail-drawer')).not.toBeInTheDocument();
    });
  });
});
