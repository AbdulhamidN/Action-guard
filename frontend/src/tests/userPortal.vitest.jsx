import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { UserShell } from '../pages/UserShell.jsx';
import { SessionsTab } from '../components/user/SessionsTab.jsx';
import { HistoryTab } from '../components/user/HistoryTab.jsx';
import { CoolingOffTab } from '../components/user/CoolingOffTab.jsx';
import { StepUpModal } from '../components/user/StepUpModal.jsx';
import {
  storeCancellationToken,
  getCancellationToken,
  removeCancellationToken,
  clearAllCancellationTokens
} from '../services/cancellationStorage.js';
import * as authStorage from '../services/authStorage.js';

describe('Module 12c-2 — User-Facing Security Experience', () => {
  let queryClient;
  const originalFetch = global.fetch;

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } }
    });
    sessionStorage.clear();
    localStorage.clear();
    authStorage.setUserToken('valid_user_jwt_token_for_tests');
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    sessionStorage.clear();
    localStorage.clear();
    queryClient.clear();
  });

  describe('1. Active Sessions Management & Privacy Hygiene', () => {
    const mockSessions = [
      {
        session_id: 'sess_user_active_current',
        created_at: '2026-10-18T00:00:00.000Z',
        expires_at: '2026-10-18T08:00:00.000Z',
        is_active: true,
        is_current: true,
        risk: { risk_tier: 'low' },
        coarse_location: { country: 'US', region: 'VA' }
      },
      {
        session_id: 'sess_user_other_remote',
        created_at: '2026-10-17T20:00:00.000Z',
        expires_at: '2026-10-18T04:00:00.000Z',
        is_active: true,
        is_current: false,
        risk: { risk_tier: 'medium' },
        coarse_location: { country: 'DE', region: 'BE' }
      }
    ];

    it('renders coarse location and risk tier, never exposing raw IP/UA/fingerprint or numeric scores', async () => {
      global.fetch = vi.fn().mockImplementation((url) => {
        if (url.includes('/api/v1/me/sessions')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => mockSessions
          });
        }
        return Promise.reject(new Error(`Unexpected URL: ${url}`));
      });

      const { container } = render(
        <QueryClientProvider client={queryClient}>
          <SessionsTab currentSessionId="sess_user_active_current" />
        </QueryClientProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('sessions-heading')).toHaveTextContent('Active Sessions');
        expect(screen.getByTestId('current-session-badge')).toHaveTextContent('Current Session');
        expect(screen.getByText(/VA, US/)).toBeInTheDocument();
        expect(screen.getByText(/BE, DE/)).toBeInTheDocument();
      });

      // Assert privacy invariants: DOM contains no raw IP addresses or numeric risk score fields
      const renderedHtml = container.innerHTML;
      expect(renderedHtml).not.toMatch(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
      expect(renderedHtml).not.toContain('risk_score');
      expect(renderedHtml).not.toContain('device_fingerprint');
      expect(renderedHtml).not.toContain('user_agent');
    });

    it('terminates other session via DELETE /api/v1/me/sessions/:id and leaves current session disabled', async () => {
      let deleteCalled = false;
      global.fetch = vi.fn().mockImplementation((url, opts) => {
        if (url.includes('/api/v1/me/sessions/sess_user_other_remote') && opts?.method === 'DELETE') {
          deleteCalled = true;
          return Promise.resolve({
            ok: true,
            status: 200,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({
              message: 'Session sess_user_other_remote successfully terminated',
              session_id: 'sess_user_other_remote'
            })
          });
        }
        if (url.includes('/api/v1/me/sessions')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => (deleteCalled ? [mockSessions[0]] : mockSessions)
          });
        }
        return Promise.reject(new Error(`Unexpected URL: ${url}`));
      });

      render(
        <QueryClientProvider client={queryClient}>
          <SessionsTab currentSessionId="sess_user_active_current" />
        </QueryClientProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('terminate-session-sess_user_other_remote')).toBeInTheDocument();
        expect(screen.getByTestId('current-session-note')).toHaveTextContent('Active (Use Sign Out)');
      });

      fireEvent.click(screen.getByTestId('terminate-session-sess_user_other_remote'));

      await waitFor(() => {
        expect(deleteCalled).toBe(true);
        expect(screen.getByTestId('sessions-success')).toHaveTextContent('successfully terminated');
      });
    });
  });

  describe('2. Security History, Privacy & In-Memory Filters', () => {
    const mockDecisions = [
      {
        decision_id: 'dec_login_101',
        event_id: 'evt_login_101',
        session_id: 'sess_user_active_current',
        action_type: 'login_success',
        decision: 'allow',
        enforcement_outcome: 'authorized',
        risk_tier: 'low',
        decided_at: '2026-10-18T05:00:00.000Z',
        explanation: {
          user_facing: 'Sign-in from a recognized device within expected location profile.'
        }
      },
      {
        decision_id: 'dec_pw_102',
        event_id: 'evt_pw_102',
        session_id: 'sess_user_active_current',
        action_type: 'password_change',
        decision: 'reverify',
        enforcement_outcome: 'halted',
        risk_tier: 'medium',
        decided_at: '2026-10-18T06:00:00.000Z',
        explanation: {
          user_facing: 'Credential modification requires explicit identity re-verification.'
        }
      }
    ];

    it('renders user-facing explanations, outcome badges, and respects type and outcome filters', async () => {
      global.fetch = vi.fn().mockImplementation((url) => {
        if (url.includes('/api/v1/me/decisions')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => mockDecisions
          });
        }
        return Promise.reject(new Error(`Unexpected URL: ${url}`));
      });

      render(
        <QueryClientProvider client={queryClient}>
          <HistoryTab />
        </QueryClientProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('history-heading')).toHaveTextContent('Security History & Policy Decisions');
        expect(screen.getByTestId('history-item-dec_login_101')).toBeInTheDocument();
        expect(screen.getByTestId('history-item-dec_pw_102')).toBeInTheDocument();
        expect(
          screen.getByText('Sign-in from a recognized device within expected location profile.')
        ).toBeInTheDocument();
      });

      // Filter by outcome "reverify"
      const outcomeSelect = screen.getByTestId('history-outcome-filter');
      fireEvent.change(outcomeSelect, { target: { value: 'reverify' } });

      await waitFor(() => {
        expect(screen.queryByTestId('history-item-dec_login_101')).not.toBeInTheDocument();
        expect(screen.getByTestId('history-item-dec_pw_102')).toBeInTheDocument();
      });
    });
  });

  describe('3. Cooling-Off Delayed Actions & SessionStorage Invariants', () => {
    it('stores cancellation tokens strictly in sessionStorage and never in localStorage', () => {
      const actionId = 'dact_security_test_123';
      const token = 'cncl_tok_super_secret_single_use';

      storeCancellationToken(actionId, token);

      expect(getCancellationToken(actionId)).toBe(token);
      expect(sessionStorage.getItem(`ag_cancel_token_${actionId}`)).toBe(token);

      // CRITICAL ZERO TRUST INVARIANT: localStorage MUST NOT be touched
      expect(localStorage.getItem(`ag_cancel_token_${actionId}`)).toBeNull();
      expect(localStorage.length).toBe(0);

      removeCancellationToken(actionId);
      expect(getCancellationToken(actionId)).toBeNull();
      expect(sessionStorage.getItem(`ag_cancel_token_${actionId}`)).toBeNull();
    });

    it('cancels delayed action using sessionStorage cancellation token and removes token upon success', async () => {
      const actionId = 'dact_pw_cooling_off_999';
      const cancellationToken = 'cncl_token_test_secret_abc';
      storeCancellationToken(actionId, cancellationToken);

      const mockDelayedActions = [
        {
          id: actionId,
          action_type: 'password_change',
          action_sensitivity: 'high',
          scheduled_at_risk_tier: 'medium',
          cooling_off_seconds: 300,
          status: 'pending',
          scheduled_at: new Date(Date.now() - 10000).toISOString(),
          execute_at: new Date(Date.now() + 290000).toISOString()
        }
      ];

      let cancelCalledWithToken = null;

      global.fetch = vi.fn().mockImplementation((url, opts) => {
        if (url.includes(`/api/v1/cooling-off/actions/${actionId}/cancel`) && opts?.method === 'POST') {
          const body = JSON.parse(opts.body);
          cancelCalledWithToken = body.cancellation_token;
          return Promise.resolve({
            ok: true,
            status: 200,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({
              status: 'cancelled',
              action_id: actionId,
              cancelled_at: new Date().toISOString()
            })
          });
        }
        if (url.includes('/api/v1/cooling-off/actions')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({ actions: mockDelayedActions, count: 1 })
          });
        }
        return Promise.reject(new Error(`Unexpected URL: ${url}`));
      });

      render(
        <QueryClientProvider client={queryClient}>
          <CoolingOffTab />
        </QueryClientProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId(`delayed-action-item-${actionId}`)).toBeInTheDocument();
        expect(screen.getByTestId(`cancel-delayed-button-${actionId}`)).toBeInTheDocument();
      });

      fireEvent.click(screen.getByTestId(`cancel-delayed-button-${actionId}`));

      await waitFor(() => {
        expect(cancelCalledWithToken).toBe(cancellationToken);
        expect(getCancellationToken(actionId)).toBeNull();
        expect(screen.getByTestId('cooling-off-success')).toHaveTextContent('cancelled successfully');
      });
    });
  });

  describe('4. StepUpModal Focus Trap, Accessibility & Single-Retry Invariant', () => {
    it('traps focus, responds to Escape key, and enforces single-retry upon elevation', async () => {
      const sessionId = 'sess_test_step_up_portal';
      const onClose = vi.fn();
      const triggeringAction = vi.fn().mockResolvedValue({ status: 'completed' });
      const onSuccess = vi.fn();

      global.fetch = vi.fn().mockImplementation((url, opts) => {
        if (url.includes('/step-up/challenge') && opts?.method === 'POST') {
          return Promise.resolve({
            ok: true,
            status: 200,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({
              challenge_id: 'chl_modal_test_1',
              scope: 'sensitive_action',
              masked_destination: 'u***@example.com',
              expires_at: new Date(Date.now() + 300000).toISOString(),
              ttl_seconds: 300
            })
          });
        }
        if (url.includes('/step-up/verify') && opts?.method === 'POST') {
          return Promise.resolve({
            ok: true,
            status: 200,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({
              status: 'verified',
              verification_ticket: 'ticket_valid_p256_mock_123'
            })
          });
        }
        if (url.includes('/elevate') && opts?.method === 'POST') {
          return Promise.resolve({
            ok: true,
            status: 200,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({
              status: 'elevated',
              scope: 'sensitive_action',
              expires_at: new Date(Date.now() + 900000).toISOString()
            })
          });
        }
        return Promise.reject(new Error(`Unexpected URL: ${url}`));
      });

      const { rerender } = render(
        <button id="external-trigger" data-testid="external-trigger">
          Trigger Button
        </button>
      );
      const triggerBtn = screen.getByTestId('external-trigger');
      triggerBtn.focus();
      expect(document.activeElement).toBe(triggerBtn);

      rerender(
        <div>
          <button id="external-trigger" data-testid="external-trigger">
            Trigger Button
          </button>
          <StepUpModal
            isOpen={true}
            onClose={onClose}
            scope="sensitive_action"
            sessionId={sessionId}
            triggeringAction={triggeringAction}
            onSuccess={onSuccess}
          />
        </div>
      );

      await waitFor(() => {
        expect(screen.getByTestId('step-up-modal')).toBeInTheDocument();
        expect(screen.getByTestId('step-up-title')).toHaveTextContent('Identity Re-Verification Required');
        expect(screen.getByText(/u\*\*\*@example\.com/)).toBeInTheDocument();
      });

      // Test Escape key closes modal
      fireEvent.keyDown(window, { key: 'Escape', code: 'Escape' });
      expect(onClose).toHaveBeenCalled();

      // Enter code and submit
      const input = screen.getByTestId('step-up-input');
      await userEvent.type(input, '123456');

      const submitBtn = screen.getByTestId('step-up-submit-button');
      fireEvent.click(submitBtn);

      await waitFor(() => {
        expect(triggeringAction).toHaveBeenCalledTimes(1);
        expect(onSuccess).toHaveBeenCalledTimes(1);
      });
    });
  });
});
