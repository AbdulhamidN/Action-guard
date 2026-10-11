'use strict';

const { User } = require('../database/models');
const redisStorage = require('../storage/redis');
const sessionService = require('./sessionService');
const { recordSecurityEvent } = require('./eventService');
const {
  ACCOUNT_LOCK_DURATION_SECONDS,
  REDIS_PREFIXES
} = require('../config/sessionConfig');

/**
 * Evaluates whether a policy decision + risk context qualifies for automatic
 * assume-breach session containment and protective account locking.
 *
 * Qualifying conditions:
 * 1. Effective decision is 'block' AND (risk_tier === 'critical' OR reasons includes 'esc_takeover_progression')
 *
 * @param {object} params
 * @param {string} params.effectiveDecision
 * @param {string} params.riskTier
 * @param {string[]} [params.reasons=[]]
 * @returns {{ qualifies: boolean, reason: string|null }}
 */
function shouldTriggerContainmentForDecision({ effectiveDecision, riskTier, reasons = [] }) {
  if (effectiveDecision !== 'block') {
    return { qualifies: false, reason: null };
  }
  const hasTakeoverProgression =
    Array.isArray(reasons) &&
    reasons.some(
      (r) =>
        (typeof r === 'string' && r.includes('esc_takeover_progression')) ||
        (r && typeof r === 'object' && typeof r.rule_id === 'string' && r.rule_id.includes('esc_takeover_progression'))
    );

  if (riskTier === 'critical') {
    return {
      qualifies: true,
      reason: hasTakeoverProgression ? 'critical_takeover_progression_blocked' : 'critical_risk_action_blocked'
    };
  }

  if (hasTakeoverProgression) {
    return {
      qualifies: true,
      reason: 'takeover_progression_blocked'
    };
  }

  return { qualifies: false, reason: null };
}

/**
 * Executes assume-breach session containment and applies a 15-minute protective account lock.
 *
 * Security invariant:
 * - Treats session containment and account locking as successful ONLY after the required
 *   Redis + MySQL invalidation and lock operations have actually succeeded.
 * - Throws if session invalidation or lock persistence fails so callers never report
 *   successful containment when invalidation failed.
 *
 * @param {object} params
 * @param {string} params.userId
 * @param {string|null} [params.sessionId=null]
 * @param {string} [params.reason='security_containment']
 * @param {string|null} [params.triggeringEventId=null]
 * @param {string|null} [params.triggeringDecisionId=null]
 * @param {object} [params.context={}]
 * @param {Date|number} [params.now=new Date()]
 * @param {number} [params.lockDurationSeconds=ACCOUNT_LOCK_DURATION_SECONDS]
 * @returns {Promise<{ session_contained: boolean, account_locked: boolean, locked_until: string, retry_after_seconds: number }>}
 */
async function containSessionAndLockAccount({
  userId,
  sessionId = null,
  reason = 'security_containment',
  triggeringEventId = null,
  triggeringDecisionId = null,
  context = {},
  now = new Date(),
  lockDurationSeconds = ACCOUNT_LOCK_DURATION_SECONDS
}) {
  if (!userId) {
    throw new Error('userId is required for session containment and account locking');
  }

  const nowDate = now instanceof Date ? now : new Date(now);
  const nowMs = nowDate.getTime();
  const effectiveDurationSec =
    typeof lockDurationSeconds === 'number' && lockDurationSeconds > 0
      ? lockDurationSeconds
      : ACCOUNT_LOCK_DURATION_SECONDS;
  const lockExpiresAt = new Date(nowMs + effectiveDurationSec * 1000);
  const lockExpiresAtIso = lockExpiresAt.toISOString();

  // 1. Verify target user exists and capture prior lock state for compensation if Redis fails
  const existingUser = await User.findByPk(userId, {
    attributes: ['id', 'locked_until']
  });
  if (!existingUser) {
    const err = new Error(`Account lock failed: user '${userId}' not found`);
    err.code = 'CONTAINMENT_USER_NOT_FOUND';
    throw err;
  }
  const previousLockedUntil = existingUser.locked_until || null;

  // 2. Invalidate the active session and all its elevations (strictly throwing on Redis/DB error or false return)
  let sessionContained = false;
  if (sessionId) {
    const invalidated = await sessionService.invalidateSession(
      sessionId,
      'security_containment',
      { throwOnError: true }
    );
    if (!invalidated) {
      const err = new Error(
        `Session containment failed: session '${sessionId}' could not be invalidated`
      );
      err.code = 'CONTAINMENT_INVALIDATION_FAILED';
      throw err;
    }
    sessionContained = true;
  }

  // 3. Persist protective account lock in MySQL and Redis with partial-failure compensation
  const [updatedRows] = await User.update(
    { locked_until: lockExpiresAt },
    { where: { id: userId } }
  );
  if (updatedRows === 0) {
    const verifyUser = await User.findByPk(userId, {
      attributes: ['id', 'locked_until']
    });
    const verifiedMs =
      verifyUser && verifyUser.locked_until ? new Date(verifyUser.locked_until).getTime() : 0;
    if (!verifyUser || verifiedMs < lockExpiresAt.getTime()) {
      const err = new Error(`Account lock failed: could not persist locked_until for user '${userId}'`);
      err.code = 'CONTAINMENT_LOCK_PERSISTENCE_FAILED';
      throw err;
    }
  }

  const client = redisStorage.getRedisClient();
  const lockKey = `${REDIS_PREFIXES.ACCOUNT_LOCK}${userId}`;
  const lockPayload = JSON.stringify({
    user_id: userId,
    session_id: sessionId || null,
    reason,
    locked_at: nowDate.toISOString(),
    locked_until: lockExpiresAtIso
  });

  try {
    await client.set(lockKey, lockPayload, 'EX', effectiveDurationSec);
  } catch (redisErr) {
    // Compensate MySQL lock update so a failed containment call does not leave contradictory lock state.
    // If compensation itself fails, checkAccountLock still reconciles from MySQL on next login attempt.
    await User.update(
      { locked_until: previousLockedUntil },
      { where: { id: userId } }
    ).catch((rollbackErr) => {
      console.error(
        '[ContainmentService] Failed to roll back locked_until after Redis lock error:',
        rollbackErr.message
      );
    });
    throw redisErr;
  }

  // 4. Record session_terminated security event for audit trail
  if (sessionId) {
    await recordSecurityEvent({
      userId,
      sessionId,
      eventType: 'session_terminated',
      timestamp: nowDate,
      context,
      metadata: {
        termination_reason: 'security_containment',
        containment_reason: reason,
        triggering_event_id: triggeringEventId,
        triggering_decision_id: triggeringDecisionId,
        account_locked_until: lockExpiresAtIso
      }
    });
  }

  return {
    session_contained: sessionContained,
    account_locked: true,
    locked_until: lockExpiresAtIso,
    retry_after_seconds: effectiveDurationSec
  };
}

/**
 * Checks whether a user account is currently under a protective lock.
 * Maintains strict consistency between MySQL `users.locked_until` and Redis `account_lock:<userId>`,
 * including recovery after Redis restarts and cleanup upon expiration.
 *
 * @param {object} user - User model instance or plain object with { id, locked_until }
 * @param {Date|number} [now=new Date()]
 * @returns {Promise<{ locked: boolean, lockedUntil: string|null, remainingSeconds: number }>}
 */
async function checkAccountLock(user, now = new Date()) {
  if (!user || !user.id) {
    return { locked: false, lockedUntil: null, remainingSeconds: 0 };
  }

  const nowMs = now instanceof Date ? now.getTime() : new Date(now).getTime();
  const lockKey = `${REDIS_PREFIXES.ACCOUNT_LOCK}${user.id}`;
  const client = redisStorage.getRedisClient();

  const dbLockedUntilMs = user.locked_until ? new Date(user.locked_until).getTime() : 0;

  // Case 1: MySQL has an active future lock timestamp
  if (Number.isFinite(dbLockedUntilMs) && dbLockedUntilMs > nowMs) {
    const remainingSeconds = Math.max(1, Math.ceil((dbLockedUntilMs - nowMs) / 1000));
    const lockedUntilIso = new Date(dbLockedUntilMs).toISOString();

    // Ensure Redis is warm (recovers automatically if Redis was flushed or restarted)
    try {
      const rawRedis = await client.get(lockKey);
      if (!rawRedis) {
        await client.set(
          lockKey,
          JSON.stringify({
            user_id: user.id,
            reason: 'security_containment',
            locked_until: lockedUntilIso
          }),
          'EX',
          remainingSeconds
        );
      }
    } catch {
      // MySQL authoritative lock still holds even if Redis is unreachable
    }

    return {
      locked: true,
      lockedUntil: lockedUntilIso,
      remainingSeconds
    };
  }

  // Case 2: MySQL had a lock timestamp that has now elapsed -> clean up both MySQL and Redis
  if (Number.isFinite(dbLockedUntilMs) && dbLockedUntilMs > 0 && dbLockedUntilMs <= nowMs) {
    try {
      await User.update({ locked_until: null }, { where: { id: user.id } });
    } catch {
      // Ignore best-effort cleanup failure
    }
    try {
      await client.del(lockKey);
    } catch {
      // Ignore best-effort cleanup failure
    }
    return { locked: false, lockedUntil: null, remainingSeconds: 0 };
  }

  // Case 3: Check Redis in case a lock exists there
  try {
    const rawRedis = await client.get(lockKey);
    if (rawRedis) {
      const parsed = JSON.parse(rawRedis);
      const redisUntilMs = parsed && parsed.locked_until ? new Date(parsed.locked_until).getTime() : 0;
      if (Number.isFinite(redisUntilMs) && redisUntilMs > nowMs) {
        const remainingSeconds = Math.max(1, Math.ceil((redisUntilMs - nowMs) / 1000));
        const lockedUntilIso = new Date(redisUntilMs).toISOString();
        await User.update({ locked_until: new Date(redisUntilMs) }, { where: { id: user.id } }).catch(() => {});
        return {
          locked: true,
          lockedUntil: lockedUntilIso,
          remainingSeconds
        };
      }
      await client.del(lockKey).catch(() => {});
    }
  } catch {
    // Ignore Redis read error when MySQL shows no active lock
  }

  return { locked: false, lockedUntil: null, remainingSeconds: 0 };
}

module.exports = {
  shouldTriggerContainmentForDecision,
  containSessionAndLockAccount,
  checkAccountLock
};
