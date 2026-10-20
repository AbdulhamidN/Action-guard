import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { OverviewPage } from '../pages/admin/OverviewPage.jsx';
import * as authStorage from '../services/authStorage.js';
import overview24hFixture from '../../../docs/api-examples/admin-overview-24h.json';
import overview7dFixture from '../../../docs/api-examples/admin-overview-7d.json';

describe('Admin Overview & Live Console (Module 12c-1)', () => {
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

  function renderOverview(events = []) {
    return render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <OverviewPage events={events} />
        </MemoryRouter>
      </QueryClientProvider>
    );
  }

  it('renders KPI summary cards loaded from authentic 24h overview fixture', async () => {
    global.fetch = vi.fn().mockImplementation((url) => {
      if (url.includes('/api/v1/admin/overview?window=24h')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => overview24hFixture
        });
      }
      return Promise.reject(new Error(`Unexpected URL: ${url}`));
    });

    renderOverview();

    expect(screen.getByTestId('overview-title')).toHaveTextContent('Security Telemetry & System Overview');

    await waitFor(() => {
      // Total decisions = 1+1+1+1+1+1 = 6
      expect(screen.getByTestId('kpi-total-decisions')).toHaveTextContent('6');
      // High (1) + Critical (1) = 2
      expect(screen.getByTestId('kpi-high-critical-alerts')).toHaveTextContent('2');
      // Active sessions = 2
      expect(screen.getByTestId('kpi-active-sessions')).toHaveTextContent('2');
      // Contained sessions = 1
      expect(screen.getByTestId('kpi-contained-sessions')).toHaveTextContent('1');
    });
  });

  it('switches time window toggle between 24h and 7d and fetches 7d metrics', async () => {
    global.fetch = vi.fn().mockImplementation((url) => {
      if (url.includes('/api/v1/admin/overview?window=7d')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => overview7dFixture
        });
      }
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => overview24hFixture
      });
    });

    renderOverview();

    await waitFor(() => {
      expect(screen.getByTestId('kpi-total-decisions')).toHaveTextContent('6');
    });

    const toggle7d = screen.getByTestId('window-toggle-7d');
    fireEvent.click(toggle7d);

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/admin/overview?window=7d'),
        expect.anything()
      );
    });
  });

  it('renders live activity console events and toggles pause/resume stream', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => overview24hFixture
    });

    const mockEvents = [
      {
        eventType: 'event:recorded',
        receivedAt: '2026-10-18T03:53:56.575Z',
        data: {
          event_id: 'evt_stream_01',
          event_type: 'password_change',
          user_id: 'usr_target_alice',
          risk_tier: 'critical',
          effective_decision: 'block'
        }
      },
      {
        eventType: 'event:recorded',
        receivedAt: '2026-10-18T03:50:00.000Z',
        data: {
          event_id: 'evt_stream_02',
          event_type: 'login_success',
          user_id: 'usr_target_bob',
          risk_tier: 'low',
          effective_decision: 'allow'
        }
      }
    ];

    renderOverview(mockEvents);

    const items = screen.getAllByTestId('live-feed-item');
    expect(items).toHaveLength(2);
    expect(screen.getByText('usr_target_alice')).toBeInTheDocument();
    expect(screen.getByText('usr_target_bob')).toBeInTheDocument();

    // Toggle Pause
    const pauseBtn = screen.getByTestId('feed-pause-toggle');
    expect(pauseBtn).toHaveTextContent('Pause Stream');
    fireEvent.click(pauseBtn);

    expect(pauseBtn).toHaveTextContent('Resume Stream');
    expect(screen.getByTestId('stream-paused-badge')).toBeInTheDocument();

    // Resume
    fireEvent.click(pauseBtn);
    expect(pauseBtn).toHaveTextContent('Pause Stream');
    expect(screen.queryByTestId('stream-paused-badge')).not.toBeInTheDocument();
  });

  it('filters live console items by risk tier, decision, and user ID substring', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => overview24hFixture
    });

    const mockEvents = [
      {
        eventType: 'event:recorded',
        receivedAt: '2026-10-18T03:53:56.575Z',
        data: {
          event_id: 'evt_01',
          event_type: 'password_change',
          user_id: 'usr_charlie_01',
          risk_tier: 'critical',
          effective_decision: 'block'
        }
      },
      {
        eventType: 'event:recorded',
        receivedAt: '2026-10-18T03:50:00.000Z',
        data: {
          event_id: 'evt_02',
          event_type: 'login',
          user_id: 'usr_david_02',
          risk_tier: 'low',
          effective_decision: 'allow'
        }
      }
    ];

    renderOverview(mockEvents);

    // Filter by tier: critical
    const tierSelect = screen.getByTestId('filter-tier');
    fireEvent.change(tierSelect, { target: { value: 'critical' } });

    expect(screen.getAllByTestId('live-feed-item')).toHaveLength(1);
    expect(screen.getByText('usr_charlie_01')).toBeInTheDocument();
    expect(screen.queryByText('usr_david_02')).not.toBeInTheDocument();

    // Reset tier filter, filter by user
    fireEvent.change(tierSelect, { target: { value: 'all' } });
    const userInput = screen.getByTestId('filter-user');
    fireEvent.change(userInput, { target: { value: 'david' } });

    expect(screen.getAllByTestId('live-feed-item')).toHaveLength(1);
    expect(screen.getByText('usr_david_02')).toBeInTheDocument();
  });

  it('opens accessible EventDetailDrawer on row click and closes on Escape with focus restoration', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => overview24hFixture
    });

    const mockEvent = {
      eventType: 'event:recorded',
      receivedAt: '2026-10-18T03:53:56.575Z',
      data: {
        event_id: 'evt_drawer_test_99',
        event_type: 'password_change',
        user_id: 'usr_drawer_target',
        risk_tier: 'high',
        risk_score: 75,
        effective_decision: 'delay',
        contributing_signals: [
          { signal: 'unrecognized_device', category: 'device', weight: 25 }
        ],
        explanation: {
          user_facing: 'Action paused pending verification.',
          admin_facing: 'Unrecognized hardware fingerprint triggered delay response.'
        }
      }
    };

    renderOverview([mockEvent]);

    const feedItem = screen.getByTestId('live-feed-item');
    feedItem.focus();
    expect(document.activeElement).toBe(feedItem);

    // Click to open drawer
    fireEvent.click(feedItem);

    const drawer = await screen.findByTestId('event-detail-drawer');
    expect(drawer).toBeInTheDocument();
    expect(screen.getByTestId('drawer-title')).toHaveTextContent('Event Details');
    expect(screen.getByText('evt_drawer_test_99')).toBeInTheDocument();
    expect(screen.getByText('Action paused pending verification.')).toBeInTheDocument();

    // Press Escape key to close drawer
    fireEvent.keyDown(window, { key: 'Escape', code: 'Escape' });

    await waitFor(() => {
      expect(screen.queryByTestId('event-detail-drawer')).not.toBeInTheDocument();
    });

    // Confirms focus restoration to triggering item
    expect(document.activeElement).toBe(feedItem);
  });
});
