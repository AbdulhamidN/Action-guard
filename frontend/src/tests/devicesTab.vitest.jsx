import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { DevicesTab } from '../components/user/DevicesTab.jsx';
import * as authStorage from '../services/authStorage.js';

describe('Module 12d-2 — Frontend DevicesTab Component', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    authStorage.setUserToken('valid_user_jwt_token_for_tests');
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    sessionStorage.clear();
    localStorage.clear();
  });

  const mockDevices = [
    {
      id: 'dev_mock_001_current',
      label: 'Primary Work Laptop',
      is_trusted: true,
      is_trust_active: true,
      trusted_at: '2026-10-18T10:00:00.000Z',
      expires_at: '2026-11-17T10:00:00.000Z',
      revoked_at: null,
      first_seen_at: '2026-09-01T08:00:00.000Z',
      last_used_at: '2026-10-18T12:00:00.000Z',
      is_current_device: true
    },
    {
      id: 'dev_mock_002_other',
      label: 'Old Tablet',
      is_trusted: false,
      is_trust_active: false,
      trusted_at: null,
      expires_at: null,
      revoked_at: null,
      first_seen_at: '2026-08-15T14:00:00.000Z',
      last_used_at: '2026-09-20T10:00:00.000Z',
      is_current_device: false
    }
  ];

  const jsonResponse = (data, status = 200, ok = true) => ({
    ok,
    status,
    headers: new Headers({ 'content-type': 'application/json' }),
    json: async () => data
  });

  it('renders loading spinner and then displays devices with badges', async () => {
    global.fetch = vi.fn().mockImplementation((url) => {
      if (url.includes('/api/v1/me/devices')) {
        return Promise.resolve(jsonResponse(mockDevices));
      }
      return Promise.reject(new Error(`Unexpected URL: ${url}`));
    });

    render(<DevicesTab />);

    await waitFor(() => {
      expect(screen.getByTestId('devices-heading')).toHaveTextContent('Trusted Devices');
      expect(screen.getByTestId('device-item-dev_mock_001_current')).toBeInTheDocument();
      expect(screen.getByTestId('device-item-dev_mock_002_other')).toBeInTheDocument();
      expect(screen.getByTestId('current-device-badge-dev_mock_001_current')).toHaveTextContent('Current Device');
      expect(screen.getByTestId('device-status-badge-dev_mock_001_current')).toHaveTextContent('Trusted');
      expect(screen.getByTestId('device-status-badge-dev_mock_002_other')).toHaveTextContent('Untrusted');
    });
  });

  it('renders empty state when user has no devices', async () => {
    global.fetch = vi.fn().mockImplementation((url) => {
      if (url.includes('/api/v1/me/devices')) {
        return Promise.resolve(jsonResponse([]));
      }
      return Promise.reject(new Error(`Unexpected URL: ${url}`));
    });

    render(<DevicesTab />);

    await waitFor(() => {
      expect(screen.getByTestId('empty-state')).toBeInTheDocument();
      expect(screen.getByText('No registered devices')).toBeInTheDocument();
    });
  });

  it('renders enrollment panel when current device is untrusted and allows enrollment', async () => {
    const untrustedCurrentDevices = [
      {
        id: 'dev_mock_current_untrusted',
        label: null,
        is_trusted: false,
        is_trust_active: false,
        trusted_at: null,
        expires_at: null,
        revoked_at: null,
        first_seen_at: '2026-10-18T00:00:00.000Z',
        last_used_at: '2026-10-18T12:00:00.000Z',
        is_current_device: true
      }
    ];

    let enrollCalled = false;
    global.fetch = vi.fn().mockImplementation((url, opts) => {
      if (url.includes('/api/v1/me/devices/enroll') && opts.method === 'POST') {
        enrollCalled = true;
        const body = JSON.parse(opts.body || '{}');
        expect(body.label).toBe('My MacBook Pro');
        return Promise.resolve(jsonResponse({
          message: 'Device trust enrolled successfully',
          device: {
            id: 'dev_mock_current_untrusted',
            label: 'My MacBook Pro',
            is_trusted: true
          },
          is_trust_active: true
        }));
      }

      if (url.includes('/api/v1/me/devices')) {
        return Promise.resolve(jsonResponse(
          enrollCalled
            ? [{ ...untrustedCurrentDevices[0], is_trusted: true, is_trust_active: true, label: 'My MacBook Pro' }]
            : untrustedCurrentDevices
        ));
      }

      return Promise.reject(new Error(`Unexpected URL: ${url}`));
    });

    render(<DevicesTab />);

    await waitFor(() => {
      expect(screen.getByTestId('enroll-device-panel')).toBeInTheDocument();
      expect(screen.getByTestId('trust-device-button')).toBeInTheDocument();
    });

    const labelInput = screen.getByTestId('device-label-input');
    fireEvent.change(labelInput, { target: { value: 'My MacBook Pro' } });

    const enrollBtn = screen.getByTestId('trust-device-button');
    fireEvent.click(enrollBtn);

    await waitFor(() => {
      expect(enrollCalled).toBe(true);
      expect(screen.getByTestId('devices-success-banner')).toHaveTextContent('Device trust enrolled successfully');
    });
  });

  it('allows revoking a trusted device and updates list', async () => {
    let revokeCalled = false;
    global.fetch = vi.fn().mockImplementation((url, opts) => {
      if (url.includes('/api/v1/me/devices/dev_mock_001_current') && opts.method === 'DELETE') {
        revokeCalled = true;
        return Promise.resolve(jsonResponse({
          message: 'Device trust revoked successfully',
          alreadyRevoked: false,
          is_trust_active: false
        }));
      }

      if (url.includes('/api/v1/me/devices')) {
        return Promise.resolve(jsonResponse(
          revokeCalled
            ? [{ ...mockDevices[0], is_trust_active: false, is_trusted: false, revoked_at: '2026-10-18T13:00:00.000Z' }]
            : mockDevices
        ));
      }

      return Promise.reject(new Error(`Unexpected URL: ${url}`));
    });

    render(<DevicesTab />);

    await waitFor(() => {
      expect(screen.getByTestId('revoke-device-button-dev_mock_001_current')).toBeInTheDocument();
    });

    const revokeBtn = screen.getByTestId('revoke-device-button-dev_mock_001_current');
    fireEvent.click(revokeBtn);

    await waitFor(() => {
      expect(revokeCalled).toBe(true);
      expect(screen.getByTestId('devices-success-banner')).toHaveTextContent('Device trust revoked successfully');
    });
  });

  it('displays error banner when loading devices fails', async () => {
    global.fetch = vi.fn().mockImplementation((url) => {
      if (url.includes('/api/v1/me/devices')) {
        return Promise.resolve(jsonResponse({
          error: {
            code: 'internal_error',
            message: 'Database connection failed',
            status: 500
          }
        }, 500, false));
      }
      return Promise.reject(new Error(`Unexpected URL: ${url}`));
    });

    render(<DevicesTab />);

    await waitFor(() => {
      expect(screen.getByTestId('devices-error-banner')).toHaveTextContent('Database connection failed');
    });
  });
});
