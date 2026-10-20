import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { UserSignupPage } from '../pages/UserSignupPage.jsx';
import { OverviewTab } from '../components/user/OverviewTab.jsx';
import * as authStorage from '../services/authStorage.js';

function jsonResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers({ 'content-type': 'application/json' }),
    json: async () => body,
    text: async () => JSON.stringify(body)
  };
}

function renderSignup() {
  return render(
    <MemoryRouter initialEntries={['/signup']}>
      <Routes>
        <Route path="/signup" element={<UserSignupPage />} />
        <Route path="/login" element={<div data-testid="login-stub">login</div>} />
      </Routes>
    </MemoryRouter>
  );
}

function fillForm(email, password, confirm) {
  fireEvent.change(screen.getByLabelText(/email address/i), { target: { value: email } });
  fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: password } });
  fireEvent.change(screen.getByLabelText(/confirm password/i), { target: { value: confirm } });
}

describe('Part A — signup page and overview tab', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    sessionStorage.clear();
    authStorage.setUserToken('valid_user_jwt_token_for_tests');
  });

  afterEach(() => {
    global.fetch = originalFetch;
    sessionStorage.clear();
  });

  it('rejects mismatched passwords without calling the API', async () => {
    global.fetch = vi.fn();
    renderSignup();
    fillForm('a@b.com', 'secret123', 'different');
    fireEvent.click(screen.getByRole('button', { name: /sign up/i }));
    expect(await screen.findByText(/passwords do not match/i)).toBeInTheDocument();
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('posts to /auth/signup and navigates to /login on success', async () => {
    global.fetch = vi.fn().mockResolvedValue(jsonResponse(201, { id: 'u1', email: 'a@b.com' }));
    renderSignup();
    fillForm('a@b.com', 'secret123', 'secret123');
    fireEvent.click(screen.getByRole('button', { name: /sign up/i }));
    await waitFor(() => expect(screen.getByTestId('login-stub')).toBeInTheDocument());
    expect(global.fetch.mock.calls[0][0]).toBe('/api/v1/auth/signup');
  });

  it('shows the server error for a duplicate email', async () => {
    global.fetch = vi.fn().mockResolvedValue(
      jsonResponse(400, { error: 'duplicate_email', message: 'A user with this email already exists' })
    );
    renderSignup();
    fillForm('a@b.com', 'secret123', 'secret123');
    fireEvent.click(screen.getByRole('button', { name: /sign up/i }));
    expect(await screen.findByText(/already exists/i)).toBeInTheDocument();
  });

  it('overview tab shows current tier and counts', async () => {
    global.fetch = vi.fn().mockResolvedValue(
      jsonResponse(200, [
        { session_id: 's1', is_active: true, is_current: true, risk: { risk_tier: 'low' } },
        { session_id: 's2', is_active: true, is_current: false, risk: { risk_tier: 'high' } }
      ])
    );
    render(<OverviewTab />);
    await waitFor(() => expect(screen.getByTestId('overview-active-count')).toHaveTextContent('2'));
    expect(screen.getByTestId('overview-elevated-count')).toHaveTextContent('1');
    expect(screen.getByTestId('overview-advice')).toHaveTextContent(/looks normal/i);
  });
});
