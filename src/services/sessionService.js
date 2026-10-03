const crypto = require('crypto');
const { Session } = require('../database/models');
const { storeSession, getSession, deleteSession, getSessionTTL } = require('../storage/redis');

// Default session expiration in seconds (15 minutes)
const DEFAULT_SESSION_TTL_SECONDS = parseInt(process.env.SESSION_TTL_SECONDS || '900', 10);

/**
 * Creates a persistent MySQL session record and an active Redis session.
 *
 * @param {string} userId
 * @param {string} email
 * @param {number} [ttlSeconds]
 * @param {object|null} [deviceData] - Optional device association { device_id, device_fingerprint }
 * @returns {Promise<{ sessionId: string, expiresAt: Date, ttlSeconds: number }>}
 */
async function createSession(userId, email, ttlSeconds = DEFAULT_SESSION_TTL_SECONDS, deviceData = null) {
  const sessionId = `sess_${crypto.randomUUID()}`;
  const now = new Date();
  const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);

  // 1. Store persistent session in MySQL
  await Session.create({
    id: sessionId,
    user_id: userId,
    created_at: now,
    expires_at: expiresAt,
    is_active: true
  });

  // 2. Store active session in Redis with matching TTL
  const sessionData = {
    session_id: sessionId,
    user_id: userId,
    email: email,
    created_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
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

  await storeSession(sessionId, sessionData, ttlSeconds);

  return {
    sessionId,
    expiresAt,
    ttlSeconds
  };
}

/**
 * Invalidates an active session in both Redis and MySQL.
 *
 * @param {string} sessionId
 * @returns {Promise<boolean>}
 */
async function invalidateSession(sessionId) {
  if (!sessionId) return false;

  // 1. Remove/invalidate active session in Redis
  await deleteSession(sessionId);

  // 2. Mark session inactive in MySQL
  const [affectedRows] = await Session.update(
    { is_active: false },
    { where: { id: sessionId } }
  );

  return affectedRows > 0;
}

/**
 * Validates whether a session is currently active in Redis.
 *
 * @param {string} sessionId
 * @returns {Promise<object|null>}
 */
async function validateActiveSession(sessionId) {
  if (!sessionId) return null;
  const activeSession = await getSession(sessionId);
  if (!activeSession || !activeSession.is_active) {
    return null;
  }
  return activeSession;
}

module.exports = {
  createSession,
  invalidateSession,
  validateActiveSession,
  getSessionTTL,
  DEFAULT_SESSION_TTL_SECONDS
};
