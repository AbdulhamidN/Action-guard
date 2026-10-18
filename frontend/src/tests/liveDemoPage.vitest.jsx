import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { LiveDemoPage } from '../pages/admin/LiveDemoPage.jsx';
import * as authStorage from '../services/authStorage.js';

describe('LiveDemoPage (Module 13.2)', () => {
  const originalFetch = global.fetch;

  const mockScenarios = [
    {
      id: 'scenario_a',
      name: 'Scenario A: Normal User Activity',
      scenario_type: 'benign',
      description: 'Legitimate user establishes session from known workstation.',
      expected_interpretation: 'Legitimate user with consistent signals.'
    },
    {
      id: 'scenario_b',
      name: 'Scenario B: Simulated Account Takeover',
      scenario_type: 'simulated_takeover',
      description: 'Attacker accesses account from unrecognized foreign device.',
      expected_interpretation: 'Suspicious progression triggering seq_takeover_progression.'
    },
    {
      id: 'fp_benign_new_device',
      name: 'False-Positive Check: Benign New Device',
      scenario_type: 'false_positive',
      description: 'Legitimate user logs in from new phone.',
      expected_interpretation: 'New device alone should not be blocked.'
    }
  ];

  const mockScenarioBResult = {
    success: true,
    mode: 'scenario',
    result: {
      scenario_id: 'scenario_b',
      scenario_name: 'Scenario B: Simulated Account Takeover',
      scenario_type: 'simulated_takeover',
      run_id: 'run_test_takeover_001',
      user_id: 'usr_demo_takeover_001',
      user_email: 'demo-scenario_b-run_test_takeover_001@demo.actionguard.local',
      steps_executed: 3,
      final_outcome: {
        risk_score: 70,
        risk_tier: 'high',
        policy_decision: 'block',
        enforcement_outcome: 'contained_and_blocked',
        is_contained: true
      },
      steps: [
        {
          step_number: 1,
          step_name: 'Attacker login from foreign location',
          event_type: 'login_success',
          action_sensitivity: 'low',
          observed_pipeline: {
            risk_score: 25,
            risk_tier: 'low',
            policy_decision: 'allow',
            enforcement_outcome: 'allowed',
            contributing_signals: [
              { signal: 'unrecognized_device', weight: 10 },
              { signal: 'unrecognized_country', weight: 10 }
            ],
            user_facing_explanation: 'Action approved based on standard checks.',
            admin_facing_explanation: 'Low tier novelty login.'
          }
        },
        {
          step_number: 2,
          step_name: 'Recovery email modification',
          event_type: 'recovery_email_change',
          action_sensitivity: 'high',
          observed_pipeline: {
            risk_score: 41,
            risk_tier: 'medium',
            policy_decision: 'reverify',
            enforcement_outcome: 'step_up_challenged',
            contributing_signals: [
              { signal: 'unrecognized_device', weight: 10 },
              { signal: 'unrecognized_country', weight: 10 }
            ],
            user_facing_explanation: 'Identity verification required.',
            admin_facing_explanation: 'Escalated by esc_double_novelty.'
          }
        },
        {
          step_number: 3,
          step_name: 'High-impact action attempted',
          event_type: 'high_impact_action',
          action_sensitivity: 'critical',
          observed_pipeline: {
            risk_score: 70,
            risk_tier: 'high',
            policy_decision: 'block',
            enforcement_outcome: 'contained_and_blocked',
            contributing_signals: [
              { signal: 'seq_takeover_progression', weight: 25 },
              { signal: 'unrecognized_device', weight: 10 }
            ],
            user_facing_explanation: 'Action restricted for security reasons.',
            admin_facing_explanation: 'seq_takeover_progression pattern triggered critical block.'
          }
        }
      ]
    }
  };

  const mockFpResult = {
    success: true,
    mode: 'false_positive',
    result: {
      scenario_id: 'fp_benign_new_device',
      scenario_name: 'False-Positive Check: Benign New Device',
      expected_interpretation: 'New device alone should not be blocked.',
      expected_max_acceptable_decision: 'monitor',
      is_acceptable: true,
      observed_system_outcome: {
        risk_score: 15,
        risk_tier: 'low',
        policy_decision: 'allow',
        enforcement_outcome: 'allowed',
        contributing_signals: [{ signal: 'unrecognized_device', weight: 10 }],
        is_contained: false
      },
      summary: {
        run_id: 'run_fp_001',
        user_id: 'usr_fp_001',
        user_email: 'demo-fp-run_fp_001@demo.actionguard.local',
        final_outcome: {
          risk_score: 15,
          risk_tier: 'low',
          policy_decision: 'allow',
          enforcement_outcome: 'allowed',
          is_contained: false
        },
        steps: [
          {
            step_number: 1,
            step_name: 'Login from new tablet',
            event_type: 'login_success',
            action_sensitivity: 'low',
            observed_pipeline: {
              risk_score: 15,
              risk_tier: 'low',
              policy_decision: 'allow',
              enforcement_outcome: 'allowed',
              contributing_signals: [{ signal: 'unrecognized_device', weight: 10 }],
              user_facing_explanation: 'Standard login approved.',
              admin_facing_explanation: 'Benign single novelty.'
            }
          }
        ]
      }
    }
  };

  beforeEach(() => {
    authStorage.setAdminToken('agadm_valid_token_123');
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('loads and renders scenario selector with description', async () => {
    global.fetch = vi.fn().mockImplementation((url) => {
      if (url.includes('/api/v1/admin/demo/scenarios')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({ scenarios: mockScenarios })
        });
      }
      return Promise.reject(new Error(`Unexpected URL: ${url}`));
    });

    render(
      <MemoryRouter>
        <LiveDemoPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByTestId('live-demo-page')).toBeInTheDocument();
      expect(screen.getByTestId('scenario-select')).toBeInTheDocument();
    });

    expect(screen.getByText('Scenario A: Normal User Activity (benign)')).toBeInTheDocument();
    expect(screen.getByText('Scenario B: Simulated Account Takeover (simulated_takeover)')).toBeInTheDocument();
    expect(screen.getByTestId('run-scenario-btn')).toBeInTheDocument();
  });

  it('executes Scenario B, rendering real pipeline steps, score, decision, and containment', async () => {
    global.fetch = vi.fn().mockImplementation((url, opts) => {
      if (url.includes('/api/v1/admin/demo/scenarios')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({ scenarios: mockScenarios })
        });
      }
      if (url.includes('/api/v1/admin/demo/run') && opts?.method === 'POST') {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => mockScenarioBResult
        });
      }
      return Promise.reject(new Error(`Unexpected URL: ${url}`));
    });

    render(
      <MemoryRouter>
        <LiveDemoPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByTestId('scenario-select')).toBeInTheDocument();
    });

    // Select Scenario B
    fireEvent.change(screen.getByTestId('scenario-select'), {
      target: { value: 'scenario_b' }
    });

    // Run Scenario
    fireEvent.click(screen.getByTestId('run-scenario-btn'));

    await waitFor(() => {
      expect(screen.getByTestId('demo-results-section')).toBeInTheDocument();
    });

    // Check header & containment
    expect(screen.getAllByText('70').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('block').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('Session Locked')).toBeInTheDocument();

    // Check step 3 details
    expect(screen.getByText('High-impact action attempted')).toBeInTheDocument();
    expect(screen.getByText('seq_takeover_progression')).toBeInTheDocument();
    expect(screen.getByText('Reset Demo Data')).toBeInTheDocument();
  });

  it('executes a false-positive scenario and displays analysis badge', async () => {
    global.fetch = vi.fn().mockImplementation((url, opts) => {
      if (url.includes('/api/v1/admin/demo/scenarios')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({ scenarios: mockScenarios })
        });
      }
      if (url.includes('/api/v1/admin/demo/run') && opts?.method === 'POST') {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => mockFpResult
        });
      }
      return Promise.reject(new Error(`Unexpected URL: ${url}`));
    });

    render(
      <MemoryRouter>
        <LiveDemoPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByTestId('scenario-select')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByTestId('scenario-select'), {
      target: { value: 'fp_benign_new_device' }
    });

    fireEvent.click(screen.getByTestId('run-scenario-btn'));

    await waitFor(() => {
      expect(screen.getByText('False-Positive Analysis & Target Verification')).toBeInTheDocument();
      expect(screen.getByText('Non-False-Positive Confirmed (PASSED)')).toBeInTheDocument();
    });
  });

  it('resets demo data cleanly on clicking Reset Demo Data', async () => {
    let cleanupCalled = false;
    global.fetch = vi.fn().mockImplementation((url, opts) => {
      if (url.includes('/api/v1/admin/demo/scenarios')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({ scenarios: mockScenarios })
        });
      }
      if (url.includes('/api/v1/admin/demo/run') && opts?.method === 'POST') {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => mockScenarioBResult
        });
      }
      if (url.includes('/api/v1/admin/demo/cleanup') && opts?.method === 'POST') {
        cleanupCalled = true;
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({ success: true, removed: { events: 4, decisions: 3 } })
        });
      }
      return Promise.reject(new Error(`Unexpected URL: ${url}`));
    });

    render(
      <MemoryRouter>
        <LiveDemoPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByTestId('run-scenario-btn')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('run-scenario-btn'));

    await waitFor(() => {
      expect(screen.getByTestId('reset-demo-btn')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('reset-demo-btn'));

    await waitFor(() => {
      expect(cleanupCalled).toBe(true);
      expect(screen.getByText(/Demo data successfully cleaned up/i)).toBeInTheDocument();
    });
  });

  it('renders ErrorBanner on scenario execution failure', async () => {
    global.fetch = vi.fn().mockImplementation((url, opts) => {
      if (url.includes('/api/v1/admin/demo/scenarios')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({ scenarios: mockScenarios })
        });
      }
      if (url.includes('/api/v1/admin/demo/run')) {
        return Promise.resolve({
          ok: false,
          status: 500,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({ error: { message: 'Engine failure during evaluation' } })
        });
      }
      return Promise.reject(new Error(`Unexpected URL: ${url}`));
    });

    render(
      <MemoryRouter>
        <LiveDemoPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByTestId('run-scenario-btn')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('run-scenario-btn'));

    await waitFor(() => {
      expect(screen.getByText(/Engine failure during evaluation/i)).toBeInTheDocument();
    });
  });
});
