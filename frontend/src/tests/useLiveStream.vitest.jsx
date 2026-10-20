import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import React from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useLiveStream, setLiveStreamRedirectHandler } from '../hooks/useLiveStream.js';
import * as authStorage from '../services/authStorage.js';
import * as socketIoClient from 'socket.io-client';

// Mock socket.io-client
vi.mock('socket.io-client', () => {
  return {
    io: vi.fn()
  };
});

describe('useLiveStream Hook', () => {
  let mockSocket;
  let listeners;
  let authCallback;
  let queryClient;

  const createWrapper = () => {
    queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } }
    });
    return ({ children }) => (
      <QueryClientProvider client={queryClient}>
        {children}
      </QueryClientProvider>
    );
  };

  beforeEach(() => {
    sessionStorage.clear();
    authStorage.clearAllAuth();
    listeners = {};
    authCallback = null;

    mockSocket = {
      on: vi.fn((event, cb) => {
        listeners[event] = cb;
      }),
      emit: vi.fn(),
      disconnect: vi.fn()
    };

    vi.mocked(socketIoClient.io).mockImplementation((opts) => {
      authCallback = opts.auth;
      return mockSocket;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('connects in user mode sending strictly auth: { token } and never adminToken', () => {
    authStorage.setUserToken('jwt-user-active-token');

    const wrapper = createWrapper();
    const { result } = renderHook(() => useLiveStream('user'), { wrapper });

    expect(socketIoClient.io).toHaveBeenCalled();
    expect(authCallback).toBeTypeOf('function');

    let resolvedCreds;
    authCallback((creds) => {
      resolvedCreds = creds;
    });

    expect(resolvedCreds).toEqual({ token: 'jwt-user-active-token' });
    expect(resolvedCreds.adminToken).toBeUndefined();
    expect(result.current.status).toBe('connecting');
  });

  it('connects in admin mode sending strictly auth: { adminToken } and never user token', () => {
    authStorage.setAdminToken('agadm_operator_active_token');

    const wrapper = createWrapper();
    const { result } = renderHook(() => useLiveStream('admin'), { wrapper });

    expect(socketIoClient.io).toHaveBeenCalled();
    expect(authCallback).toBeTypeOf('function');

    let resolvedCreds;
    authCallback((creds) => {
      resolvedCreds = creds;
    });

    expect(resolvedCreds).toEqual({ adminToken: 'agadm_operator_active_token' });
    expect(resolvedCreds.token).toBeUndefined();
    expect(result.current.status).toBe('connecting');
  });

  it('updates connection status to live on connect, and offline on disconnect', () => {
    authStorage.setUserToken('jwt-user-active-token');

    const wrapper = createWrapper();
    const { result } = renderHook(() => useLiveStream('user'), { wrapper });

    expect(result.current.status).toBe('connecting');

    act(() => {
      listeners['connect']();
    });
    expect(result.current.status).toBe('live');

    act(() => {
      listeners['disconnect']();
    });
    expect(result.current.status).toBe('offline');
  });

  it('updates the bounded buffer on incoming telemetry events and caps at 200 items', () => {
    authStorage.setUserToken('jwt-user-active-token');

    const wrapper = createWrapper();
    const { result } = renderHook(() => useLiveStream('user'), { wrapper });

    act(() => {
      listeners['connect']();
    });

    // Send event:recorded
    act(() => {
      listeners['event:recorded']({
        event_id: 'evt_101',
        event_type: 'login_success'
      });
    });

    expect(result.current.events).toHaveLength(1);
    expect(result.current.events[0].eventType).toBe('event:recorded');
    expect(result.current.events[0].data.event_id).toBe('evt_101');

    // Send risk:updated
    act(() => {
      listeners['risk:updated']({
        event_id: 'evt_101',
        risk_tier: 'low'
      });
    });

    expect(result.current.events).toHaveLength(2);
    expect(result.current.events[0].eventType).toBe('risk:updated');

    // Send decision:recorded
    act(() => {
      listeners['decision:recorded']({
        decision_id: 'dec_202',
        decision: 'allow'
      });
    });

    expect(result.current.events).toHaveLength(3);

    // Verify bounded cap at 200 items
    act(() => {
      for (let i = 0; i < 250; i++) {
        listeners['event:recorded']({ event_id: `evt_bulk_${i}` });
      }
    });

    expect(result.current.events).toHaveLength(200);
  });

  it('invalidates matching React Query caches on telemetry events', () => {
    authStorage.setUserToken('jwt-user-active-token');

    const wrapper = createWrapper();
    renderHook(() => useLiveStream('user'), { wrapper });

    const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');

    act(() => {
      listeners['event:recorded']({ event_id: 'evt_1' });
    });
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['events'] });

    act(() => {
      listeners['risk:updated']({ event_id: 'evt_1', risk_tier: 'low' });
    });
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['risk'] });
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['sessions'] });

    act(() => {
      listeners['decision:recorded']({ decision_id: 'dec_1', decision: 'allow' });
    });
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['decisions'] });
  });

  it('logs out and sets notice when session:terminated is received', () => {
    authStorage.setUserToken('jwt-user-active-token');
    expect(authStorage.getUserToken()).toBe('jwt-user-active-token');

    const redirectSpy = vi.fn();
    setLiveStreamRedirectHandler(redirectSpy);

    const wrapper = createWrapper();
    const { result } = renderHook(() => useLiveStream('user'), { wrapper });

    act(() => {
      listeners['session:terminated']({
        session_id: 'sess_123',
        reason: 'administrative_revocation'
      });
    });

    expect(authStorage.getUserToken()).toBeNull();
    expect(result.current.terminationNotice).toContain('administrative_revocation');
    expect(redirectSpy).toHaveBeenCalledWith('/login');
  });

  it('logs out when connect_error with unauthorized error code is received', () => {
    authStorage.setUserToken('jwt-user-invalid-token');

    const redirectSpy = vi.fn();
    setLiveStreamRedirectHandler(redirectSpy);

    const wrapper = createWrapper();
    const { result } = renderHook(() => useLiveStream('user'), { wrapper });

    act(() => {
      listeners['connect_error'](new Error('unauthorized'));
    });

    expect(authStorage.getUserToken()).toBeNull();
    expect(result.current.status).toBe('offline');
    expect(result.current.terminationNotice).toContain('Authentication rejected');
    expect(redirectSpy).toHaveBeenCalledWith('/login');
  });
});
