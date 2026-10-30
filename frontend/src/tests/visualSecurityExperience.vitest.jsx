import React from 'react';
import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { PolicyInspector } from '../components/landing/PolicyInspector.jsx';

describe('Visual Security Experience & Interactive Pipeline', () => {
  const renderSimulator = () =>
    render(
      <MemoryRouter>
        <PolicyInspector />
      </MemoryRouter>
    );

  it('renders all five visual storytelling pipeline stages', () => {
    renderSimulator();

    // Stage 01: Context
    expect(screen.getByText(/01 — CONTEXT/i)).toBeInTheDocument();
    expect(screen.getByText(/Understand the session/i)).toBeInTheDocument();
    expect(screen.getByText(/Device:/i)).toBeInTheDocument();
    expect(screen.getByText(/Location:/i)).toBeInTheDocument();
    expect(screen.getByText(/Behavior:/i)).toBeInTheDocument();
    expect(screen.getByText(/Timing:/i)).toBeInTheDocument();

    // Stage 02: Risk Analysis
    expect(screen.getByText(/02 — RISK ANALYSIS/i)).toBeInTheDocument();
    expect(screen.getByText(/Evaluate changing signals/i)).toBeInTheDocument();

    // Stage 03: Policy Decision
    expect(screen.getByText(/03 — POLICY DECISION/i)).toBeInTheDocument();
    expect(screen.getByText(/Evaluate every action/i)).toBeInTheDocument();
    expect(screen.getByText(/Target Action:/i)).toBeInTheDocument();

    // Stage 04: Response
    expect(screen.getByText(/04 — RESPONSE/i)).toBeInTheDocument();
    expect(screen.getByText(/Proportional friction/i)).toBeInTheDocument();
    const responseCards = screen.getByTestId('pipeline-response-cards');
    expect(responseCards).toHaveTextContent(/allow/i);
    expect(responseCards).toHaveTextContent(/monitor/i);
    expect(responseCards).toHaveTextContent(/reverify/i);
    expect(responseCards).toHaveTextContent(/delay/i);
    expect(responseCards).toHaveTextContent(/block/i);

    // Stage 05: Continuous Trust
    expect(screen.getByText(/05 — CONTINUOUS TRUST/i)).toBeInTheDocument();
    expect(screen.getByText(/Trust never stops being evaluated/i)).toBeInTheDocument();
    expect(screen.getByText(/Live Continuous Monitoring Loop/i)).toBeInTheDocument();
  });

  it('highlights the active response verdict in Stage 04', () => {
    renderSimulator();

    // Default inputs: login_success, no anomalies => Decision is "allow"
    const responseCards = screen.getByTestId('pipeline-response-cards');
    expect(responseCards).toHaveTextContent('Active Verdict');
    expect(screen.getByTestId('inspector-decision')).toHaveTextContent(/allow/i);
  });

  it('reacts dynamically to preset selection (Impossible travel on password change -> delay)', () => {
    renderSimulator();

    const travelPreset = screen.getByTestId('preset-travel');
    fireEvent.click(travelPreset);

    // Should update Stage 04 active verdict and inspector decision
    expect(screen.getByTestId('inspector-decision')).toHaveTextContent(/delay/i);
    expect(screen.getByTestId('inspector-risk-tier')).toHaveTextContent(/high/i);

    // Context badge should reflect impossible travel
    expect(screen.getByText(/Location: Impossible Travel/i)).toBeInTheDocument();
  });

  it('escalates to block when selecting takeover sequence preset', () => {
    renderSimulator();

    const takeoverPreset = screen.getByTestId('preset-takeover');
    fireEvent.click(takeoverPreset);

    expect(screen.getByTestId('inspector-decision')).toHaveTextContent(/block/i);
    expect(screen.getByTestId('inspector-risk-tier')).toHaveTextContent(/critical/i);
  });

  it('updates risk score and badges when toggling individual signals', () => {
    renderSimulator();

    const newDeviceCheckbox = screen.getByTestId('input-new-device');
    expect(newDeviceCheckbox).not.toBeChecked();

    fireEvent.click(newDeviceCheckbox);
    expect(newDeviceCheckbox).toBeChecked();

    // Device badge in Stage 01 should update
    expect(screen.getByText(/Device: Unrecognized Device/i)).toBeInTheDocument();
    expect(screen.getAllByText(/\+25 Risk/i).length).toBeGreaterThan(0);
  });

  it('preserves all expandable technical details and test hooks', () => {
    renderSimulator();

    expect(screen.getByTestId('policy-inspector')).toBeInTheDocument();
    expect(screen.getByTestId('inspector-result')).toBeInTheDocument();
    expect(screen.getByTestId('inspector-score')).toBeInTheDocument();
    expect(screen.getByTestId('inspector-explanation')).toBeInTheDocument();
    expect(screen.getByTestId('inspector-signals')).toBeInTheDocument();
  });
});
