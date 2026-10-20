/**
 * @fileoverview Central API client fetch wrapper targeting /api/v1.
 * Enforces Zero Trust communication requirements:
 * - Attaches Bearer authorization without URL parameters.
 * - Parses backend error envelopes { error: { code, message, status } } into ApiError.
 * - Handles 401 token_expired or invalid_session by clearing auth and redirecting to the proper login.
 * - Surfaces 429 with retry_after_seconds.
 * - Never logs credentials, tokens, or request bodies.
 */

import { getUserToken, clearUserToken, getAdminToken, clearAdminToken } from './authStorage.js';

export class ApiError extends Error {
  /**
   * @param {string} message
   * @param {string} code
   * @param {number} status
   * @param {number|null} [retryAfterSeconds=null]
   * @param {object|null} [details=null]
   */
  constructor(message, code, status, retryAfterSeconds = null, details = null) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.retryAfterSeconds = retryAfterSeconds;
    this.details = details;
  }
}

/** @type {((targetPath: string) => void)|null} */
let authExpiredRedirectHandler = null;

/**
 * Registers a custom redirect handler for testing or SPA routing.
 *
 * @param {((targetPath: string) => void)|null} handler
 */
export function setAuthExpiredHandler(handler) {
  authExpiredRedirectHandler = handler;
}

/**
 * Executes a redirect to the target login route.
 *
 * @param {string} targetPath
 */
function handleAuthRedirect(targetPath) {
  if (typeof authExpiredRedirectHandler === 'function') {
    authExpiredRedirectHandler(targetPath);
    return;
  }
  if (typeof window !== 'undefined' && window.location) {
    window.location.href = targetPath;
  }
}

/**
 * Performs an HTTP request against /api/v1 with error parsing and auth management.
 *
 * @param {string} endpoint - Path relative to /api/v1 (e.g. '/auth/login' or '/me/events')
 * @param {RequestInit & { authMode?: 'user'|'admin'|'none', headers?: Record<string, string> }} [options={}]
 * @returns {Promise<any>} Parsed response data
 */
export async function apiRequest(endpoint, options = {}) {
  const normalizedEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  const url = `/api/v1${normalizedEndpoint}`;

  const headers = new Headers(options.headers || {});
  if (!headers.has('Accept')) {
    headers.set('Accept', 'application/json');
  }

  // Determine auth mode
  const authMode = options.authMode || (normalizedEndpoint.startsWith('/admin') ? 'admin' : 'user');

  if (authMode === 'admin') {
    const adminToken = getAdminToken();
    if (adminToken && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${adminToken}`);
    }
  } else if (authMode === 'user') {
    const userToken = getUserToken();
    if (userToken && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${userToken}`);
    }
  }

  if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
    if (!headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
    options = {
      ...options,
      body: JSON.stringify(options.body)
    };
  }

  const response = await fetch(url, {
    ...options,
    headers
  });

  // Handle empty responses (204 No Content)
  if (response.status === 204) {
    return null;
  }

  const contentType = response.headers.get('content-type') || '';
  const isJson = contentType.includes('application/json');
  const data = isJson ? await response.json().catch(() => null) : await response.text().catch(() => null);

  if (!response.ok) {
    let errorCode = 'api_error';
    let errorMessage = response.statusText || 'API request failed';
    let retryAfter = null;
    let details = null;

    if (data && typeof data === 'object') {
      if (data.error && typeof data.error === 'object') {
        errorCode = data.error.code || errorCode;
        errorMessage = data.error.message || errorMessage;
        retryAfter = data.error.retry_after_seconds !== undefined ? data.error.retry_after_seconds : null;
        details = data.error;
      } else {
        errorCode = data.code || errorCode;
        errorMessage = data.message || errorMessage;
        retryAfter = data.retry_after_seconds !== undefined ? data.retry_after_seconds : null;
      }
    }

    // Check Retry-After header for rate limiting (429)
    if (response.status === 429) {
      errorCode = errorCode === 'api_error' ? 'rate_limited' : errorCode;
      const retryHeader = response.headers.get('Retry-After');
      if (retryHeader) {
        const parsedRetry = parseInt(retryHeader, 10);
        if (!Number.isNaN(parsedRetry)) {
          retryAfter = parsedRetry;
        }
      }
    }

    // 401 handling: on token_expired or invalid_session, clear auth and redirect
    if (response.status === 401 && (errorCode === 'token_expired' || errorCode === 'invalid_session')) {
      if (authMode === 'admin') {
        clearAdminToken();
        handleAuthRedirect('/admin/login');
      } else {
        clearUserToken();
        handleAuthRedirect('/login');
      }
    }

    throw new ApiError(errorMessage, errorCode, response.status, retryAfter, details);
  }

  return data;
}
