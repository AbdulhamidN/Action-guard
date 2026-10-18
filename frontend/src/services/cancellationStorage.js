/**
 * @fileoverview Cooling-off delayed action cancellation token storage.
 * Enforces Zero Trust credential storage boundaries:
 * - Cancellation tokens are stored STRICTLY in sessionStorage.
 * - localStorage is NEVER touched or accessed.
 * - Tokens are cleared immediately when cancelled, executed, or upon window close.
 */

const PREFIX = 'ag_cancel_token_';

/**
 * Stores a cooling-off cancellation token in sessionStorage.
 *
 * @param {string} actionId
 * @param {string} cancellationToken
 */
export function storeCancellationToken(actionId, cancellationToken) {
  if (!actionId || typeof actionId !== 'string' || !cancellationToken || typeof cancellationToken !== 'string') {
    return;
  }
  try {
    sessionStorage.setItem(`${PREFIX}${actionId}`, cancellationToken);
  } catch {
    // Gracefully handle storage quota or privacy restrictions
  }
}

/**
 * Retrieves a stored cancellation token for a delayed action.
 *
 * @param {string} actionId
 * @returns {string|null}
 */
export function getCancellationToken(actionId) {
  if (!actionId || typeof actionId !== 'string') {
    return null;
  }
  try {
    return sessionStorage.getItem(`${PREFIX}${actionId}`);
  } catch {
    return null;
  }
}

/**
 * Removes a cancellation token from sessionStorage.
 *
 * @param {string} actionId
 */
export function removeCancellationToken(actionId) {
  if (!actionId || typeof actionId !== 'string') {
    return;
  }
  try {
    sessionStorage.removeItem(`${PREFIX}${actionId}`);
  } catch {
    // Ignore teardown errors
  }
}

/**
 * Clears all cooling-off cancellation tokens from sessionStorage.
 */
export function clearAllCancellationTokens() {
  try {
    const keysToRemove = [];
    for (let i = 0; i < sessionStorage.length; i += 1) {
      const key = sessionStorage.key(i);
      if (key && key.startsWith(PREFIX)) {
        keysToRemove.push(key);
      }
    }
    for (const key of keysToRemove) {
      sessionStorage.removeItem(key);
    }
  } catch {
    // Ignore storage errors
  }
}
