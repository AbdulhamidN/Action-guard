/**
 * @fileoverview Authentication credential storage service.
 * Enforces Zero Trust credential storage boundaries:
 * - User JWT is stored strictly in sessionStorage (cleared on tab/window close or logout).
 * - Admin token is stored strictly in memory (cleared on page reload or logout).
 * - localStorage is NEVER used for tokens.
 */

const USER_TOKEN_KEY = 'ag_user_token';

/** @type {string|null} */
let inMemoryAdminToken = null;

/**
 * Retrieves the current user session token.
 *
 * @returns {string|null}
 */
export function getUserToken() {
  try {
    return sessionStorage.getItem(USER_TOKEN_KEY);
  } catch {
    return null;
  }
}

/**
 * Stores the user session token in sessionStorage.
 *
 * @param {string} token
 */
export function setUserToken(token) {
  if (typeof token === 'string' && token.length > 0) {
    sessionStorage.setItem(USER_TOKEN_KEY, token);
  }
}

/**
 * Clears the user session token from sessionStorage.
 */
export function clearUserToken() {
  try {
    sessionStorage.removeItem(USER_TOKEN_KEY);
  } catch {
    // Ignore storage errors during teardown
  }
}

/**
 * Retrieves the current admin token from memory.
 *
 * @returns {string|null}
 */
export function getAdminToken() {
  return inMemoryAdminToken;
}

/**
 * Stores the admin token in memory only.
 *
 * @param {string} token
 */
export function setAdminToken(token) {
  if (typeof token === 'string' && token.length > 0) {
    inMemoryAdminToken = token;
  }
}

/**
 * Clears the admin token from memory.
 */
export function clearAdminToken() {
  inMemoryAdminToken = null;
}

/**
 * Clears all stored authentication credentials across both boundaries.
 */
export function clearAllAuth() {
  clearUserToken();
  clearAdminToken();
}
