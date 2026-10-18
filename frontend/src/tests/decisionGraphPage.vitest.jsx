import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { DecisionGraphPage, buildDecisionGraph } from '../pages/admin/DecisionGraphPage.jsx';
import * as authStorage from '../services/authStorage.js';
import userDecisionsFixture from '../../../docs/api-examples/admin-user-decisions.json';

describe('Admin Decision Explanation Graph (Module 12c-1 & FR-35)', () => {
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
      if (url.includes(`/api/v1/admin/users/${testUserId}/decisions`)) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => userDecisionsFixture
        });
      }
      return Promise.reject(new Error(`Unexpected URL: ${url}`));
    });
  }

  function renderDecisionGraph(decisionId) {
    return render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={[`/admin/users/${testUserId}/decisions/${decisionId}`]}>
          <Routes>
            <Route
              path="/admin/users/:userId/decisions/:decisionId"
              element={<DecisionGraphPage />}
            />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    );
  }

  it('renders deterministic 5-column causal graph nodes from authentic decisions fixture', async () => {
    setupFetchMock();
    renderDecisionGraph('dec_fixture_02_contained');

    await waitFor(() => {
      expect(screen.getByTestId('decision-graph-title')).toHaveTextContent('dec_fixture_02_contained');
    });

    // Column 1: Signal nodes (present in graph)
    expect(screen.getAllByText('seq_rapid_credential_cascade').length).toBeGreaterThan(0);
    expect(screen.getAllByText('unrecognized_device').length).toBeGreaterThan(0);
    expect(screen.getAllByText('impossible_travel').length).toBeGreaterThan(0);

    // Column 2: Risk Assessment Node
    expect(screen.getByTestId('graph-node-risk-score')).toHaveTextContent('88');
    expect(screen.getByTestId('tier-badge-critical')).toBeInTheDocument();

    // Column 3: Policy Reasons Node
    expect(screen.getByText('critical_takeover_containment')).toBeInTheDocument();

    // Column 4: Effective Decision Node
    expect(screen.getByTestId('graph-node-effective-decision')).toHaveTextContent('block');

    // Column 5: Enforcement Outcome Node
    expect(screen.getByTestId('graph-node-outcome')).toHaveTextContent('contained_and_blocked');
  });

  it('displays explicit mitigating text label and negative weight styling for mitigating signals', async () => {
    setupFetchMock();
    // dec_fixture_01_allowed has known_device with weight -10
    renderDecisionGraph('dec_fixture_01_allowed');

    await waitFor(() => {
      expect(screen.getByTestId('decision-graph-title')).toHaveTextContent('dec_fixture_01_allowed');
    });

    expect(screen.getAllByText('known_device').length).toBeGreaterThan(0);
    // Must contain explicit text label "Mitigating signal" so accessibility does not rely on color alone
    expect(screen.getByText('Mitigating signal')).toBeInTheDocument();
    expect(screen.getAllByText('-10').length).toBeGreaterThan(0);
  });

  it('detects mathematical weight-to-score divergence and renders reconciliation warning banner', async () => {
    setupFetchMock();
    // dec_fixture_01_allowed: weight is -10, but risk_score is 15 -> sum != score
    renderDecisionGraph('dec_fixture_01_allowed');

    await waitFor(() => {
      expect(screen.getByTestId('reconciliation-warning')).toBeInTheDocument();
    });

    expect(screen.getByText(/Mathematical Weight-to-Score Divergence Detected/i)).toBeInTheDocument();
    expect(screen.getByText(/Sum of raw contributing signal weights \(-10\) does not equal final evaluated risk score \(15\)/i)).toBeInTheDocument();
  });

  it('omits reconciliation warning banner when weight sum matches evaluated risk score exactly', async () => {
    setupFetchMock();
    // dec_fixture_02_contained: weights are 35 + 25 + 28 = 88, score is 88 -> exact match
    renderDecisionGraph('dec_fixture_02_contained');

    await waitFor(() => {
      expect(screen.getByTestId('decision-graph-title')).toHaveTextContent('dec_fixture_02_contained');
    });

    expect(screen.queryByTestId('reconciliation-warning')).not.toBeInTheDocument();
  });

  it('renders accessible "Why this decision?" WCAG tabular breakdown with factor impacts', async () => {
    setupFetchMock();
    renderDecisionGraph('dec_fixture_02_contained');

    await waitFor(() => {
      expect(screen.getByTestId('why-this-decision-table')).toBeInTheDocument();
    });

    const table = screen.getByTestId('why-this-decision-table');
    expect(table).toHaveTextContent('seq_rapid_credential_cascade');
    expect(table).toHaveTextContent('unrecognized_device');
    expect(table).toHaveTextContent('impossible_travel');
    expect(screen.getAllByText('Aggravating').length).toBe(3);
    expect(screen.getAllByText('+35').length).toBeGreaterThan(0);
    expect(screen.getAllByText('+25').length).toBeGreaterThan(0);
    expect(screen.getAllByText('+28').length).toBeGreaterThan(0);
  });

  it('displays user-facing and administrator audit explanation cards', async () => {
    setupFetchMock();
    renderDecisionGraph('dec_fixture_02_contained');

    await waitFor(() => {
      expect(screen.getByTestId('explanation-user-facing')).toBeInTheDocument();
      expect(screen.getByTestId('explanation-admin-facing')).toBeInTheDocument();
    });

    expect(screen.getByTestId('explanation-user-facing')).toHaveTextContent(
      'Password modification halted. Session terminated due to critical risk escalation.'
    );
    expect(screen.getByTestId('explanation-admin-facing')).toHaveTextContent(
      'Escalation rule critical_takeover_containment triggered: contained_and_blocked outcome applied.'
    );
  });

  it('renders the same decision fixture twice and produces identical graph node coordinates and edge definitions', async () => {
    setupFetchMock();

    // First render of the decision graph page
    const { unmount: unmountFirst } = renderDecisionGraph('dec_fixture_02_contained');
    await waitFor(() => {
      expect(screen.getByTestId('decision-graph-title')).toHaveTextContent('dec_fixture_02_contained');
    });

    const targetDecision = userDecisionsFixture.find((d) => d.decision_id === 'dec_fixture_02_contained');
    const firstGraph = buildDecisionGraph(targetDecision);

    unmountFirst();

    // Second render of the decision graph page
    const { unmount: unmountSecond } = renderDecisionGraph('dec_fixture_02_contained');
    await waitFor(() => {
      expect(screen.getByTestId('decision-graph-title')).toHaveTextContent('dec_fixture_02_contained');
    });

    const secondGraph = buildDecisionGraph(targetDecision);

    // Verify node counts and exact positions { x, y }
    expect(firstGraph.nodes.length).toBe(7); // 3 signals + 1 assessment + 1 reasons + 1 decision + 1 outcome
    expect(firstGraph.nodes.length).toBe(secondGraph.nodes.length);
    expect(firstGraph.nodes.map((n) => ({ id: n.id, position: n.position }))).toEqual(
      secondGraph.nodes.map((n) => ({ id: n.id, position: n.position }))
    );

    // Verify edge counts and definitions { id, source, target }
    expect(firstGraph.edges.length).toBe(6); // 3 signal->assessment + assessment->reasons + reasons->decision + decision->outcome
    expect(firstGraph.edges.length).toBe(secondGraph.edges.length);
    expect(firstGraph.edges.map((e) => ({ id: e.id, source: e.source, target: e.target }))).toEqual(
      secondGraph.edges.map((e) => ({ id: e.id, source: e.source, target: e.target }))
    );

    unmountSecond();
  });
});

