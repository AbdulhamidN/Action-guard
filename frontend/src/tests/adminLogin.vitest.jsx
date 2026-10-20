import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { AdminLoginPage } from '../pages/AdminLoginPage.jsx';
import * as authStorage from '../services/authStorage.js';

describe('Admin Operator Login Security Rules', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    authStorage.clearAllAuth();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('clears the admin key field immediately upon submit and never stores the key', async () => {
    const adminKeySecret = 'super_secret_admin_api_key_longer_than_32_characters';

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        admin_token: 'agadm_mock_token_123',
        expires_at: new Date(Date.now() + 1800000).toISOString()
      })
    });

    render(
      <MemoryRouter>
        <AdminLoginPage />
      </MemoryRouter>
    );

    const input = screen.getByTestId('admin-key-input');
    const submitBtn = screen.getByTestId('admin-submit-button');

    // Type the admin key
    fireEvent.change(input, { target: { value: adminKeySecret } });
    expect(input.value).toBe(adminKeySecret);

    // Submit the form
    fireEvent.click(submitBtn);

    // Immediately after submit, the input field must be cleared
    expect(input.value).toBe('');

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    // The key must never be stored anywhere in storage
    expect(localStorage.getItem('adminKey')).toBeNull();
    expect(sessionStorage.getItem('adminKey')).toBeNull();
    expect(localStorage.getItem(adminKeySecret)).toBeNull();
    expect(sessionStorage.getItem(adminKeySecret)).toBeNull();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);

    // Only the issued session token is held in memory
    expect(authStorage.getAdminToken()).toBe('agadm_mock_token_123');
  });
});
