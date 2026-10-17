import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { apiRequest, ApiError, setAuthExpiredHandler } from '../services/apiClient.js';
import * as authStorage from '../services/authStorage.js';

describe('API Client & Error Handling', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    sessionStorage.clear();
    authStorage.clearAllAuth();
    setAuthExpiredHandler(null);
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    setAuthExpiredHandler(null);
  });

  it('parses standard backend error envelope { error: { code, message, status } } into ApiError', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        error: {
          code: 'invalid_request',
          message: 'Malformed request envelope',
          status: 400
        }
      })
    });

    await expect(apiRequest('/test')).rejects.toThrow(ApiError);

    try {
      await apiRequest('/test');
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      expect(err.code).toBe('invalid_request');
      expect(err.message).toBe('Malformed request envelope');
      expect(err.status).toBe(400);
    }
  });

  it('parses flat error envelope { code, message } into ApiError', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        code: 'forbidden_action',
        message: 'Action prohibited by policy'
      })
    });

    try {
      await apiRequest('/test-flat');
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      expect(err.code).toBe('forbidden_action');
      expect(err.message).toBe('Action prohibited by policy');
      expect(err.status).toBe(403);
    }
  });

  it('surfaces 429 rate limit with retry_after_seconds from response body', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 429,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        error: {
          code: 'challenge_limited',
          message: 'Too many verification attempts',
          status: 429,
          retry_after_seconds: 30
        }
      })
    });

    try {
      await apiRequest('/sessions/123/step-up/challenge');
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      expect(err.status).toBe(429);
      expect(err.code).toBe('challenge_limited');
      expect(err.retryAfterSeconds).toBe(30);
    }
  });

  it('surfaces 429 rate limit with retry information from Retry-After HTTP header', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 429,
      headers: new Headers({
        'content-type': 'application/json',
        'Retry-After': '45'
      }),
      json: async () => ({
        error: {
          code: 'rate_limited',
          message: 'Rate limit exceeded'
        }
      })
    });

    try {
      await apiRequest('/events');
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      expect(err.status).toBe(429);
      expect(err.retryAfterSeconds).toBe(45);
    }
  });

  it('handles 401 token_expired by clearing user auth and redirecting to /login', async () => {
    authStorage.setUserToken('expired-user-jwt');
    expect(authStorage.getUserToken()).toBe('expired-user-jwt');

    const redirectSpy = vi.fn();
    setAuthExpiredHandler(redirectSpy);

    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        error: {
          code: 'token_expired',
          message: 'Session token has expired',
          status: 401
        }
      })
    });

    await expect(apiRequest('/me/sessions')).rejects.toThrow('Session token has expired');
    expect(authStorage.getUserToken()).toBeNull();
    expect(redirectSpy).toHaveBeenCalledWith('/login');
  });

  it('handles 401 invalid_session by clearing user auth and redirecting to /login', async () => {
    authStorage.setUserToken('revoked-user-jwt');
    const redirectSpy = vi.fn();
    setAuthExpiredHandler(redirectSpy);

    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        error: {
          code: 'invalid_session',
          message: 'Session has been invalidated',
          status: 401
        }
      })
    });

    await expect(apiRequest('/me/sessions')).rejects.toThrow('Session has been invalidated');
    expect(authStorage.getUserToken()).toBeNull();
    expect(redirectSpy).toHaveBeenCalledWith('/login');
  });

  it('handles 401 token_expired for admin request by clearing admin auth and redirecting to /admin/login', async () => {
    authStorage.setAdminToken('agadm_sample_admin_token');
    expect(authStorage.getAdminToken()).toBe('agadm_sample_admin_token');

    const redirectSpy = vi.fn();
    setAuthExpiredHandler(redirectSpy);

    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        error: {
          code: 'token_expired',
          message: 'Admin operator token expired',
          status: 401
        }
      })
    });

    await expect(apiRequest('/admin/users')).rejects.toThrow('Admin operator token expired');
    expect(authStorage.getAdminToken()).toBeNull();
    expect(redirectSpy).toHaveBeenCalledWith('/admin/login');
  });

  it('handles 401 invalid_session for admin request by clearing admin auth and redirecting to /admin/login', async () => {
    authStorage.setAdminToken('agadm_revoked_token');
    const redirectSpy = vi.fn();
    setAuthExpiredHandler(redirectSpy);

    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({
        error: {
          code: 'invalid_session',
          message: 'Admin session invalidated',
          status: 401
        }
      })
    });

    await expect(apiRequest('/admin/overview')).rejects.toThrow('Admin session invalidated');
    expect(authStorage.getAdminToken()).toBeNull();
    expect(redirectSpy).toHaveBeenCalledWith('/admin/login');
  });

  it('never logs tokens or request bodies across calls', async () => {
    const consoleLogSpy = vi.spyOn(console, 'log');
    const consoleWarnSpy = vi.spyOn(console, 'warn');
    const consoleErrorSpy = vi.spyOn(console, 'error');
    const consoleInfoSpy = vi.spyOn(console, 'info');

    authStorage.setUserToken('sensitive-user-token-secret');

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ success: true })
    });

    await apiRequest('/account/password', {
      method: 'POST',
      body: {
        current_password: 'super-secret-password-123',
        new_password: 'new-secret-password-456'
      }
    });

    const allLoggedArgs = [
      ...consoleLogSpy.mock.calls,
      ...consoleWarnSpy.mock.calls,
      ...consoleErrorSpy.mock.calls,
      ...consoleInfoSpy.mock.calls
    ].flat().map(String);

    for (const logItem of allLoggedArgs) {
      expect(logItem).not.toContain('sensitive-user-token-secret');
      expect(logItem).not.toContain('super-secret-password-123');
      expect(logItem).not.toContain('new-secret-password-456');
    }
  });
});
