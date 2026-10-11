const crypto = require('crypto');
const { Session } = require('../database/models');
const redisStorage = require('../storage/redis');
const {
  IDLE_TIMEOUT_SECONDS,
  MAX_SESSION_LIFETIME_SECONDS,
  RENEWAL_THROTTLE_SECONDS
} = require('../config/sessionConfig');
const { revokeAllElevationsForSession } = require('./elevationService');
const eventBus = require('../events/eventBus');

// Backward-compatible export
const DEFAULT_SESSION_TTL_SECONDS = IDLE_TIMEOUT_SECONDS;

/**
 * Creates a persistent MySQL session record and an active Redis session.
 * Stores the absolute lifetime cap in MySQL expires_at and Redis max_expires_at,
 * and sets the initial Redis key TTL to the idle timeout window.
 *
 * @param {string} userId
 * @param {string} email
 * @param {number} [idleTtlSeconds=IDLE_TIMEOUT_SECONDS]
 * @param {object|null} [deviceData=null]
 * @param {number} [maxLifetimeSeconds=MAX_SESSION_LIFETIME_SECONDS]
 * @returns {Promise<{ sessionId: string, expiresAt: Date, ttlSeconds: number, maxExpiresAt: Date }>}
 */
async function createSession(
  userId,
  email,
  idleTtlSeconds = IDLE_TIMEOUT_SECONDS,
  deviceData = null,
  maxLifetimeSeconds = MAX_SESSION_LIFETIME_SECONDS
) {
  const sessionId = `sess_${crypto.randomUUID()}`;
  const now = new Date();
  const maxExpiresAt = new Date(now.getTime() + maxLifetimeSeconds * 1000);

  // Effective initial TTL bounded by max lifetime
  const effectiveIdleTtl = Math.min(idleTtlSeconds, maxLifetimeSeconds);
  const idleExpiresAt = new Date(now.getTime() + effectiveIdleTtl * 1000);

  // 1. Store persistent session in MySQL with absolute cap in expires_at
  await Session.create({
    id: sessionId,
    user_id: userId,
    created_at: now,
    expires_at: maxExpiresAt,
    is_active: true
  });

  // 2. Store active session in Redis with idle TTL and per-session idle_timeout_seconds
  const sessionData = {
    session_id: sessionId,
    user_id: userId,
    email: email,
    created_at: now.toISOString(),
    created_at_ms: now.getTime(),
    expires_at: idleExpiresAt.toISOString(),
    idle_timeout_seconds: effectiveIdleTtl,
    max_expires_at: maxExpiresAt.getTime(),
    last_renewed_at: now.getTime(),
    is_active: true
  };

  if (deviceData) {
    const deviceId = deviceData.device_id || deviceData.deviceId;
    const deviceFingerprint = deviceData.device_fingerprint || deviceData.deviceFingerprint || deviceData.fingerprint;
    if (deviceId) {
      sessionData.device_id = deviceId;
    }
    if (deviceFingerprint) {
      sessionData.device_fingerprint = deviceFingerprint;
    }
  }

  try {
    await redisStorage.storeSession(sessionId, sessionData, effectiveIdleTtl);
  } catch (redisErr) {
    // Compensating action: fail-closed if Redis write fails
    try {
      await Session.update({ is_active: false }, { where: { id: sessionId } });
    } catch {
      // Ignore compensation error
    }
    throw redisErr;
  }

  return {
    sessionId,
    expiresAt: idleExpiresAt,
    maxExpiresAt,
    ttlSeconds: effectiveIdleTtl
  };
}

/**
 * Validates active session state and conditionally refreshes the idle timeout window atomically.
 * Parses the session JSON returned directly by the Lua script, eliminating any race
 * condition between validation and a second GET round-trip.
 *
 * @param {string} sessionId
 * @param {object} [options={}]
 * @param {number} [options.nowMs]
 * @param {boolean} [options.touch=true]
 * @returns {Promise<object|null>}
 */
async function validateAndTouchSession(sessionId, options = {}) {
  if (!sessionId || typeof sessionId !== 'string') return null;

  const nowMs = options.nowMs || Date.now();
  const shouldTouch = options.touch !== false;
  const idleWindow = IDLE_TIMEOUT_SECONDS;
  const throttle = shouldTouch ? RENEWAL_THROTTLE_SECONDS : 999999999;

  let evalRes;
  try {
    evalRes = await redisStorage.executeValidateAndTouch(sessionId, nowMs, idleWindow, throttle);
  } catch (err) {
    // Fail-closed on Redis failure
    return null;
  }

  // evalRes is [code, status, newTtl, sessionJson]
  const code = Array.isArray(evalRes) ? Number(evalRes[0]) : Number(evalRes);
  if (code === -1 || code === -2) {
    if (code === -2) {
      Session.update({ is_active: false }, { where: { id: sessionId } }).catch(() => {});
    }
    return null;
  }

  const sessionJson = Array.isArray(evalRes) ? evalRes[3] : null;
  if (sessionJson && typeof sessionJson === 'string') {
    try {
      const parsed = JSON.parse(sessionJson);
      if (code === 1 && Number(evalRes[2]) > 0) {
        parsed.expires_at = new Date(nowMs + Number(evalRes[2]) * 1000).toISOString();
      }
      return parsed;
    } catch {
      return null;
    }
  }

  return redisStorage.getSession(sessionId);
}

/**
 * Validates whether a session is currently active in Redis.
 * Defaults to passive check (touch: false) unless touch: true is passed,
 * ensuring background WebSocket checks do not artificially renew idle timeouts.
 *
 * @param {string} sessionId
 * @param {object} [options={}]
 * @returns {Promise<object|null>}
 */
async function validateActiveSession(sessionId, options = {}) {
  const effectiveOptions = {
    ...options,
    touch: options.touch === true
  };
  return validateAndTouchSession(sessionId, effectiveOptions);
}

/**
 * Invalidates an active session in Redis and MySQL, and purges all associated elevation scopes.
 *
 * @param {string} sessionId
 * @param {string} [reason='session_invalidated']
 * @returns {Promise<boolean>}
 */
async function invalidateSession(sessionId, reason = 'session_invalidated') {
  if (!sessionId) return false;

  // 1. Purge all elevation scopes for this session
  await revokeAllElevationsForSession(sessionId);

  // 2. Remove/invalidate active session in Redis
  await redisStorage.deleteSession(sessionId);

  // 3. Mark session inactive in MySQL
  const [affectedRows] = await Session.update(
    { is_active: false },
    { where: { id: sessionId } }
  );

  const isSuccess = affectedRows > 0;
  if (isSuccess) {
    eventBus.safeEmit('session:terminated', {
      session_id: sessionId,
      reason,
      terminated_at: new Date().toISOString()
    });
  }

  return isSuccess;
}

/**
 * Terminates all active sessions and associated elevations for a specific user.
 * Used during password change, account reset, or critical security escalation.
 *
 * @param {string} userId
 * @param {string} [reason='user_sessions_terminated']
 * @returns {Promise<{ terminatedCount: number }>}
 */
async function terminateAllUserSessions(userId, reason = 'user_sessions_terminated') {
  if (!userId) return { terminatedCount: 0 };

  const sessions = await Session.findAll({
    where: {
      user_id: userId,
      is_active: true
    },
    attributes: ['id']
  });

  let count = 0;
  for (const s of sessions) {
    await invalidateSession(s.id, reason);
    count++;
  }

  // Ensure any orphaned sessions in MySQL are marked inactive
  await Session.update(
    { is_active: false },
    { where: { user_id: userId, is_active: true } }
  );

  return { terminatedCount: count };
}

/**
 * Bounded reconciliation utility: synchronizes MySQL is_active status
 * for sessions whose absolute lifetime has elapsed.
 *
 * @param {object} [options={}]
 * @param {Date} [options.now]
 * @returns {Promise<number>} Number of reconciled rows
 */
async function reconcileExpiredSessions(options = {}) {
  const { Op } = require('sequelize');
  const now = options.now || new Date();

  const [affectedCount] = await Session.update(
    { is_active: false },
    {
      where: {
        is_active: true,
        expires_at: { [Op.lte]: now }
      }
    }
  );

  return affectedCount;
}

module.exports = {
  createSession,
  invalidateSession,
  validateActiveSession,
  validateAndTouchSession,
  terminateAllUserSessions,
  reconcileExpiredSessions,
  getSessionTTL: redisStorage.getSessionTTL,
  DEFAULT_SESSION_TTL_SECONDS
};
