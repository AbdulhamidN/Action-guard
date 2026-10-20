'use strict';

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const redisStorage = require('../storage/redis');
const { ElevationAuditLog, RiskAssessment } = require('../database/models');
const {
  DEFAULT_ELEVATION_DURATION_SECONDS,
  MAX_ELEVATION_DURATION_SECONDS,
  VERIFICATION_TICKET_TTL_SECONDS,
  ALLOWLISTED_ELEVATION_SCOPES,
  REDIS_PREFIXES
} = require('../config/sessionConfig');

const TEST_VERIFICATION_TICKET_SECRET =
  process.env.TEST_VERIFICATION_TICKET_SECRET || 'test_only_step_up_verification_ticket_secret';
const ALLOWED_TICKET_ALGORITHMS = Object.freeze(['HS256', 'RS256', 'ES256']);
const MAX_TICKET_CLOCK_SKEW_SECONDS = 5;

const TIER_RANKS = Object.freeze({
  low: 0,
  medium: 1,
  high: 2,
  critical: 3
});

/**
 * Best-effort persistence for elevation lifecycle audit events (granted, used, revoked, expired).
 * Never blocks Redis revocation or session teardown if the database write fails,
 * but explicitly logs an audit warning for operator visibility.
 *
 * @param {object} entry
 * @returns {Promise<object|null>}
 */
async function recordElevationAudit(entry) {
  try {
    if (!entry || !entry.user_id || !entry.scope || !entry.event_action) {
      return null;
    }
    return await ElevationAuditLog.create({
      user_id: entry.user_id,
      session_id: entry.session_id || null,
      scope: entry.scope,
      event_action: entry.event_action,
      reason: entry.reason || null,
      jti: entry.jti || null,
      granted_at_risk_tier: entry.granted_at_risk_tier || null,
      expires_at: entry.expires_at ? new Date(entry.expires_at) : null,
      metadata: entry.metadata || null,
      recorded_at: entry.recorded_at ? new Date(entry.recorded_at) : new Date()
    });
  } catch (err) {
    console.warn('[ElevationAudit] Best-effort audit persistence failed:', err.message);
    return null;
  }
}

/**
 * Resolves and validates the cryptographic verification key and its strictly compatible
 * signing algorithms.
 * - When overridePublicKey or STEP_UP_VERIFICATION_PUBLIC_KEY is provided, parses it explicitly
 *   as an asymmetric public KeyObject and restricts algorithms to match the key type
 *   (RS256 for RSA, ES256 for P-256 EC). Malformed or incompatible keys fail closed.
 * - HS256 symmetric secret verification is strictly restricted to NODE_ENV === 'test'
 *   when STEP_UP_VERIFICATION_PUBLIC_KEY is not configured.
 * - Never falls back to the general session JWT_SECRET.
 *
 * @param {string|object|null} [overridePublicKey=null]
 */
function resolveVerificationKeyContext(overridePublicKey = null) {
  const rawPublicKey =
    overridePublicKey !== null && overridePublicKey !== undefined
      ? overridePublicKey
      : process.env.STEP_UP_VERIFICATION_PUBLIC_KEY;

  if (rawPublicKey !== undefined && rawPublicKey !== null && String(rawPublicKey).trim() !== '') {
    let pubKeyObj;
    try {
      pubKeyObj =
        typeof rawPublicKey === 'object' && rawPublicKey.type === 'public'
          ? rawPublicKey
          : crypto.createPublicKey(rawPublicKey);
    } catch {
      return {
        ok: false,
        error: 'Configured step-up verification public key is malformed or invalid',
        code: 'INVALID_VERIFICATION_KEY'
      };
    }

    if (!pubKeyObj || pubKeyObj.type !== 'public') {
      return {
        ok: false,
        error: 'Configured step-up verification key must be an asymmetric public key',
        code: 'INVALID_VERIFICATION_KEY'
      };
    }

    if (pubKeyObj.asymmetricKeyType === 'rsa') {
      return {
        ok: true,
        keyObject: pubKeyObj,
        allowedAlgorithms: ['RS256']
      };
    }

    if (pubKeyObj.asymmetricKeyType === 'ec') {
      const namedCurve = pubKeyObj.asymmetricKeyDetails && pubKeyObj.asymmetricKeyDetails.namedCurve;
      if (namedCurve && namedCurve !== 'prime256v1' && namedCurve !== 'P-256') {
        return {
          ok: false,
          error: `Configured EC public key curve '${namedCurve}' is incompatible with ES256`,
          code: 'INVALID_VERIFICATION_KEY'
        };
      }
      return {
        ok: true,
        keyObject: pubKeyObj,
        allowedAlgorithms: ['ES256']
      };
    }

    return {
      ok: false,
      error: `Unsupported asymmetric key type '${pubKeyObj.asymmetricKeyType}' for step-up verification`,
      code: 'INVALID_VERIFICATION_KEY'
    };
  }

  if (process.env.NODE_ENV === 'test') {
    const secretKeyObj = crypto.createSecretKey(Buffer.from(TEST_VERIFICATION_TICKET_SECRET, 'utf8'));
    return {
      ok: true,
      keyObject: secretKeyObj,
      allowedAlgorithms: ['HS256']
    };
  }

  return {
    ok: false,
    error: 'Step-up verification provider is not configured',
    code: 'VERIFICATION_PROVIDER_UNAVAILABLE'
  };
}

/**
 * Creates a signed verification ticket for testing purposes.
 * Strictly restricted to NODE_ENV === 'test'.
 *
 * @param {object} params
 * @param {string} params.userId
 * @param {string} params.sessionId
 * @param {string} params.scope
 * @param {number|null} [params.expiresInSeconds=60]
 * @param {string|object} [params.secret=TEST_VERIFICATION_TICKET_SECRET]
 * @param {string} [params.algorithm='HS256']
 * @param {string|null} [params.jti]
 * @param {boolean} [params.noTimestamp=false]
 * @param {number} [params.iat]
 * @param {number} [params.exp]
 * @returns {string} Signed JWT ticket
 */
function createMockVerificationTicket({
  userId,
  sessionId,
  scope,
  expiresInSeconds = VERIFICATION_TICKET_TTL_SECONDS,
  secret = TEST_VERIFICATION_TICKET_SECRET,
  algorithm = 'HS256',
  jti = `tkt_${crypto.randomUUID()}`,
  noTimestamp = false,
  iat = undefined,
  exp = undefined
}) {
  if (process.env.NODE_ENV !== 'test') {
    throw new Error('createMockVerificationTicket is strictly forbidden outside test environment');
  }

  const payload = {
    sub: userId,
    session_id: sessionId,
    scope,
    purpose: 'step_up_verification'
  };

  if (iat !== undefined) {
    payload.iat = iat;
  }
  if (exp !== undefined) {
    payload.exp = exp;
  }

  const signOptions = {
    algorithm,
    noTimestamp
  };
  if (jti !== null) {
    signOptions.jwtid = jti;
  }
  if (exp === undefined && expiresInSeconds !== null) {
    signOptions.expiresIn = `${expiresInSeconds}s`;
  }

  return jwt.sign(payload, secret, signOptions);
}

/**
 * Validates a verification ticket.
 * Enforces key-type-specific algorithm allowlist, dedicated verification key,
 * iat/exp presence, future iat rejection, maximum 60s lifetime window,
 * and strict user/session/scope binding.
 *
 * @param {string} ticketString
 * @param {string} expectedUserId
 * @param {string} expectedSessionId
 * @param {string} expectedScope
 * @param {object} [options={}]
 * @param {number} [options.nowMs]
 * @param {number} [options.maxClockSkewSeconds=MAX_TICKET_CLOCK_SKEW_SECONDS]
 * @param {string|object|null} [options.publicKey=null]
 * @returns {Promise<{ valid: boolean, jti?: string, error?: string, code?: string }>}
 */
async function verifyVerificationTicket(
  ticketString,
  expectedUserId,
  expectedSessionId,
  expectedScope,
  options = {}
) {
  if (!ticketString || typeof ticketString !== 'string') {
    return { valid: false, error: 'Verification ticket is required', code: 'INVALID_TICKET' };
  }

  const keyCtx = resolveVerificationKeyContext(options.publicKey || null);
  if (!keyCtx.ok) {
    return {
      valid: false,
      error: keyCtx.error,
      code: keyCtx.code
    };
  }

  let decodedHeader;
  try {
    const completeDecoded = jwt.decode(ticketString, { complete: true });
    if (!completeDecoded || !completeDecoded.header) {
      return { valid: false, error: 'Malformed verification ticket', code: 'INVALID_TICKET' };
    }
    decodedHeader = completeDecoded.header;
  } catch {
    return { valid: false, error: 'Malformed verification ticket', code: 'INVALID_TICKET' };
  }

  if (!decodedHeader.alg || !keyCtx.allowedAlgorithms.includes(decodedHeader.alg)) {
    return {
      valid: false,
      error: 'Unsupported or disallowed ticket signing algorithm for configured key',
      code: 'INVALID_TICKET'
    };
  }

  const nowMs =
    typeof options.nowMs === 'number' && Number.isFinite(options.nowMs)
      ? options.nowMs
      : Date.now();
  const nowSec = Math.floor(nowMs / 1000);
  const maxClockSkewSeconds =
    typeof options.maxClockSkewSeconds === 'number' && Number.isFinite(options.maxClockSkewSeconds)
      ? options.maxClockSkewSeconds
      : MAX_TICKET_CLOCK_SKEW_SECONDS;

  let decoded;
  try {
    decoded = jwt.verify(ticketString, keyCtx.keyObject, {
      algorithms: [...keyCtx.allowedAlgorithms],
      clockTimestamp: nowSec
    });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return { valid: false, error: 'Verification ticket has expired', code: 'TICKET_EXPIRED' };
    }
    return { valid: false, error: 'Verification ticket is invalid or untrusted', code: 'INVALID_TICKET' };
  }

  // Require valid numeric iat and exp claims
  if (
    typeof decoded.iat !== 'number' ||
    !Number.isFinite(decoded.iat) ||
    typeof decoded.exp !== 'number' ||
    !Number.isFinite(decoded.exp)
  ) {
    return {
      valid: false,
      error: 'Verification ticket must include valid iat and exp claims',
      code: 'INVALID_TICKET'
    };
  }

  // Reject tickets with iat materially in the future
  if (decoded.iat > nowSec + maxClockSkewSeconds) {
    return {
      valid: false,
      error: 'Verification ticket iat claim cannot be in the future',
      code: 'INVALID_TICKET'
    };
  }

  const ticketLifetimeSec = decoded.exp - decoded.iat;
  if (ticketLifetimeSec <= 0 || ticketLifetimeSec > VERIFICATION_TICKET_TTL_SECONDS) {
    return {
      valid: false,
      error: `Verification ticket lifetime (${ticketLifetimeSec}s) exceeds maximum allowed (${VERIFICATION_TICKET_TTL_SECONDS}s)`,
      code: 'INVALID_TICKET'
    };
  }

  if (decoded.purpose !== 'step_up_verification') {
    return { valid: false, error: 'Invalid ticket purpose', code: 'INVALID_TICKET' };
  }

  if (decoded.sub !== expectedUserId) {
    return { valid: false, error: 'Ticket user does not match session user', code: 'TICKET_USER_MISMATCH' };
  }

  if (decoded.session_id !== expectedSessionId) {
    return { valid: false, error: 'Ticket session does not match active session', code: 'TICKET_SESSION_MISMATCH' };
  }

  if (decoded.scope !== expectedScope) {
    return { valid: false, error: 'Ticket scope does not match requested scope', code: 'TICKET_SCOPE_MISMATCH' };
  }

  if (!decoded.jti || typeof decoded.jti !== 'string' || decoded.jti.trim() === '') {
    return { valid: false, error: 'Ticket is missing unique identifier', code: 'INVALID_TICKET' };
  }

  return { valid: true, jti: decoded.jti };
}

/**
 * Resolves the current risk tier for a session at grant time.
 *
 * @param {string} userId
 * @param {string} sessionId
 * @param {string|null} [explicitTier=null]
 * @returns {Promise<'low'|'medium'|'high'|'critical'>}
 */
async function resolveGrantTimeRiskTier(userId, sessionId, explicitTier = null) {
  if (explicitTier && TIER_RANKS[explicitTier] !== undefined) {
    return explicitTier;
  }
  try {
    const latest = await RiskAssessment.findOne({
      where: {
        user_id: userId,
        session_id: sessionId
      },
      order: [
        ['evaluated_at', 'DESC'],
        ['id', 'DESC']
      ]
    });
    if (latest && TIER_RANKS[latest.risk_tier] !== undefined) {
      return latest.risk_tier;
    }
  } catch {
    // Fallback to 'low' if DB lookup fails
  }
  return 'low';
}

/**
 * Grants temporary, scoped elevation for an active session.
 * Uses an atomic Lua script to verify parent session existence and lifetime,
 * claim the single-use ticket, update the session elevation Set index with a bounded TTL,
 * and store the elevation record (including granted_at_risk_tier).
 *
 * @param {object} params
 * @param {string} params.sessionId
 * @param {string} params.userId
 * @param {string} params.scope
 * @param {string} params.verificationTicket
 * @param {number} [params.durationSeconds]
 * @param {number} [params.maxSessionExpiresAt]
 * @param {number} [params.nowMs]
 * @param {string|null} [params.grantedAtRiskTier]
 * @param {string|object|null} [params.publicKey]
 * @returns {Promise<{ elevated: boolean, scope: string, expiresAt: string, remainingSeconds: number, grantedAtRiskTier: string }>}
 */
async function grantElevation({
  sessionId,
  userId,
  scope,
  verificationTicket,
  durationSeconds = DEFAULT_ELEVATION_DURATION_SECONDS,
  maxSessionExpiresAt = null,
  nowMs = Date.now(),
  grantedAtRiskTier = null,
  publicKey = null
}) {
  if (!sessionId || !userId || !scope) {
    const error = new Error('Session ID, user ID, and scope are required');
    error.code = 'INVALID_REQUEST';
    throw error;
  }

  // 1. Scope allowlist check
  if (!ALLOWLISTED_ELEVATION_SCOPES.includes(scope)) {
    const error = new Error(`Elevation scope '${scope}' is not permitted`);
    error.code = 'INVALID_ELEVATION_SCOPE';
    throw error;
  }

  // 2. Ticket validation
  const ticketRes = await verifyVerificationTicket(verificationTicket, userId, sessionId, scope, {
    nowMs,
    publicKey
  });
  if (!ticketRes.valid) {
    const error = new Error(ticketRes.error);
    error.code = ticketRes.code;
    throw error;
  }

  // 3. Verify parent session in Redis and determine effective max lifetime
  const parentSession = await redisStorage.getSession(sessionId);
  if (!parentSession || !parentSession.is_active || parentSession.user_id !== userId) {
    const error = new Error('Active parent session not found or user mismatch');
    error.code = 'SESSION_EXPIRED';
    throw error;
  }

  const redisMaxExpiresAt = Number(parentSession.max_expires_at);
  const effectiveMaxSessionExpiresAt =
    maxSessionExpiresAt && Number.isFinite(Number(maxSessionExpiresAt))
      ? Math.min(redisMaxExpiresAt, Number(maxSessionExpiresAt))
      : redisMaxExpiresAt;

  // 4. Calculate clamped duration
  let effectiveDurationSec = Math.min(
    Math.max(1, durationSeconds),
    MAX_ELEVATION_DURATION_SECONDS
  );

  let remainingSessionSec = MAX_ELEVATION_DURATION_SECONDS;
  if (Number.isFinite(effectiveMaxSessionExpiresAt) && effectiveMaxSessionExpiresAt > 0) {
    remainingSessionSec = Math.floor((effectiveMaxSessionExpiresAt - nowMs) / 1000);
    if (remainingSessionSec <= 0) {
      const error = new Error('Parent session has reached its absolute maximum lifetime');
      error.code = 'SESSION_MAX_LIFETIME_EXCEEDED';
      throw error;
    }
    effectiveDurationSec = Math.min(effectiveDurationSec, remainingSessionSec);
  }

  const effectiveRiskTier = await resolveGrantTimeRiskTier(userId, sessionId, grantedAtRiskTier);

  const expiresAtMs = nowMs + effectiveDurationSec * 1000;
  const expiresAtIso = new Date(expiresAtMs).toISOString();

  const sessionKey = `${REDIS_PREFIXES.SESSION}${sessionId}`;
  const claimKey = `${REDIS_PREFIXES.TICKET_CLAIM}${ticketRes.jti}`;
  const indexKey = `${REDIS_PREFIXES.SESSION_ELEVATIONS_INDEX}${sessionId}`;
  const elevationKey = `${REDIS_PREFIXES.ELEVATION}${sessionId}:${scope}`;

  const payloadJson = JSON.stringify({
    session_id: sessionId,
    user_id: userId,
    scope,
    jti: ticketRes.jti,
    granted_at_risk_tier: effectiveRiskTier,
    granted_at: new Date(nowMs).toISOString(),
    expires_at: expiresAtIso
  });

  // 5. Atomic parent-session check + single-use claim + index update + elevation key write
  const evalRes = await redisStorage.executeGrantElevation({
    sessionKey,
    claimKey,
    indexKey,
    elevationKey,
    nowMs,
    userId,
    claimTtlSec: VERIFICATION_TICKET_TTL_SECONDS * 2,
    scope,
    payloadJson,
    elevationTtlSec: effectiveDurationSec,
    indexTtlSec: Math.max(effectiveDurationSec, remainingSessionSec)
  });

  const code = Array.isArray(evalRes) ? Number(evalRes[0]) : Number(evalRes);
  if (code === -1 || code === -3) {
    const error = new Error('Active parent session not found or invalidated');
    error.code = 'SESSION_EXPIRED';
    throw error;
  }
  if (code === -2) {
    const error = new Error('Parent session has reached its absolute maximum lifetime');
    error.code = 'SESSION_MAX_LIFETIME_EXCEEDED';
    throw error;
  }
  if (code !== 1) {
    const error = new Error('Verification ticket has already been used');
    error.code = 'VERIFICATION_TICKET_ALREADY_USED';
    throw error;
  }

  await recordElevationAudit({
    user_id: userId,
    session_id: sessionId,
    scope,
    event_action: 'granted',
    reason: 'step_up_verified',
    jti: ticketRes.jti,
    granted_at_risk_tier: effectiveRiskTier,
    expires_at: new Date(expiresAtMs),
    recorded_at: new Date(nowMs)
  });

  return {
    elevated: true,
    scope,
    expiresAt: expiresAtIso,
    remainingSeconds: effectiveDurationSec,
    grantedAtRiskTier: effectiveRiskTier
  };
}

/**
 * Checks whether a specific scope is currently elevated for a session.
 * Strictly validates parent session active status, absolute lifetime, ownership,
 * and optional risk-tier ceiling.
 * Fails closed (elevated: false) on any error or inconsistency unless throwOnRedisError is set.
 *
 * @param {object} params
 * @param {string} params.sessionId
 * @param {string} params.scope
 * @param {object|null} [params.parentSession] - Optional parent session object
 * @param {number} [params.nowMs] - Optional current timestamp override for deterministic tests
 * @param {string|null} [params.currentRiskTier] - Optional current risk tier to enforce ceiling
 * @param {boolean} [params.recordUse=false] - Whether to record an elevation 'used' audit entry
 * @param {string|null} [params.actionType=null] - Action type when recording 'used' audit entry
 * @param {boolean} [params.throwOnRedisError=false] - Whether to rethrow unexpected Redis errors
 * @returns {Promise<{ elevated: boolean, scope: string, expiresAt: string|null, remainingSeconds: number, grantedAtRiskTier?: string }>}
 */
async function checkElevation({
  sessionId,
  scope,
  parentSession = null,
  nowMs = Date.now(),
  currentRiskTier = null,
  recordUse = false,
  actionType = null,
  throwOnRedisError = false
}) {
  if (!sessionId || !scope) {
    return { elevated: false, scope, expiresAt: null, remainingSeconds: 0 };
  }

  if (!ALLOWLISTED_ELEVATION_SCOPES.includes(scope)) {
    return { elevated: false, scope, expiresAt: null, remainingSeconds: 0 };
  }

  try {
    const client = redisStorage.getRedisClient();

    // 1. Validate parent session thoroughly
    let validParent = parentSession;
    if (!validParent) {
      validParent = await redisStorage.getSession(sessionId);
    }

    if (
      !validParent ||
      validParent.session_id !== sessionId ||
      validParent.is_active !== true ||
      (validParent.max_expires_at && nowMs >= Number(validParent.max_expires_at))
    ) {
      return { elevated: false, scope, expiresAt: null, remainingSeconds: 0 };
    }

    // 2. Fetch elevation record
    const elevationKey = `${REDIS_PREFIXES.ELEVATION}${sessionId}:${scope}`;
    const raw = await client.get(elevationKey);
    if (!raw) {
      const indexKey = `${REDIS_PREFIXES.SESSION_ELEVATIONS_INDEX}${sessionId}`;
      await client.srem(indexKey, scope).catch(() => {});
      return { elevated: false, scope, expiresAt: null, remainingSeconds: 0 };
    }

    const data = JSON.parse(raw);

    // 3. Verify ownership and binding between elevation and parent session
    if (
      data.session_id !== sessionId ||
      data.user_id !== validParent.user_id ||
      data.scope !== scope
    ) {
      return { elevated: false, scope, expiresAt: null, remainingSeconds: 0 };
    }

    const expiresAtMs = new Date(data.expires_at).getTime();
    const remainingMs = expiresAtMs - nowMs;

    if (!Number.isFinite(remainingMs) || remainingMs <= 0) {
      await client.del(elevationKey).catch(() => {});
      await client.srem(`${REDIS_PREFIXES.SESSION_ELEVATIONS_INDEX}${sessionId}`, scope).catch(() => {});
      await recordElevationAudit({
        user_id: data.user_id,
        session_id: sessionId,
        scope,
        event_action: 'expired',
        reason: 'ttl_elapsed',
        jti: data.jti || null,
        granted_at_risk_tier: data.granted_at_risk_tier || null,
        expires_at: data.expires_at,
        recorded_at: new Date(nowMs)
      });
      return { elevated: false, scope, expiresAt: null, remainingSeconds: 0 };
    }

    // 4. Enforce risk-tier ceiling if currentRiskTier is provided
    const grantedTier = data.granted_at_risk_tier || 'low';
    if (
      currentRiskTier &&
      TIER_RANKS[currentRiskTier] !== undefined &&
      TIER_RANKS[grantedTier] !== undefined &&
      TIER_RANKS[currentRiskTier] > TIER_RANKS[grantedTier]
    ) {
      await revokeElevation(sessionId, scope, 'risk_tier_increased', data);
      return { elevated: false, scope, expiresAt: null, remainingSeconds: 0 };
    }

    // 5. Record usage if requested by PEP
    if (recordUse) {
      await recordElevationAudit({
        user_id: data.user_id,
        session_id: sessionId,
        scope,
        event_action: 'used',
        reason: actionType ? `reverify:${actionType}` : 'reverify_satisfied',
        jti: data.jti || null,
        granted_at_risk_tier: grantedTier,
        expires_at: data.expires_at,
        metadata: actionType ? { action_type: actionType } : null,
        recorded_at: new Date(nowMs)
      });
    }

    return {
      elevated: true,
      scope,
      expiresAt: data.expires_at,
      remainingSeconds: Math.ceil(remainingMs / 1000),
      grantedAtRiskTier: grantedTier
    };
  } catch (err) {
    if (throwOnRedisError) {
      throw err;
    }
    // Fail-closed on Redis failure or parse error
    return { elevated: false, scope, expiresAt: null, remainingSeconds: 0 };
  }
}

/**
 * Revokes a single elevation scope for a session and records a best-effort audit entry.
 *
 * @param {string} sessionId
 * @param {string} scope
 * @param {string} [reason='manual_revocation']
 * @param {object|null} [existingData=null]
 * @returns {Promise<boolean>}
 */
async function revokeElevation(sessionId, scope, reason = 'manual_revocation', existingData = null) {
  if (!sessionId || !scope) return false;
  try {
    const client = redisStorage.getRedisClient();
    const elevationKey = `${REDIS_PREFIXES.ELEVATION}${sessionId}:${scope}`;
    const indexKey = `${REDIS_PREFIXES.SESSION_ELEVATIONS_INDEX}${sessionId}`;

    let parsed = existingData;
    if (!parsed) {
      const raw = await client.get(elevationKey).catch(() => null);
      if (raw) {
        try {
          parsed = JSON.parse(raw);
        } catch {
          parsed = null;
        }
      }
    }

    const delCount = await client.del(elevationKey);
    await client.srem(indexKey, scope);

    if (parsed && parsed.user_id) {
      await recordElevationAudit({
        user_id: parsed.user_id,
        session_id: sessionId,
        scope,
        event_action: 'revoked',
        reason,
        jti: parsed.jti || null,
        granted_at_risk_tier: parsed.granted_at_risk_tier || null,
        expires_at: parsed.expires_at || null
      });
    }

    return delCount > 0 || Boolean(existingData);
  } catch {
    return false;
  }
}

/**
 * Revokes all elevation scopes for a specific session without wildcard scanning.
 * Records best-effort audit entries for each revoked scope.
 *
 * @param {string} sessionId
 * @param {string} [reason='session_invalidated']
 * @param {object} [options={}]
 * @param {boolean} [options.throwOnError=false]
 * @returns {Promise<number>} Number of revoked elevations
 */
async function revokeAllElevationsForSession(sessionId, reason = 'session_invalidated', options = {}) {
  if (!sessionId) return 0;
  try {
    const client = redisStorage.getRedisClient();
    const indexKey = `${REDIS_PREFIXES.SESSION_ELEVATIONS_INDEX}${sessionId}`;

    // Best-effort read of active scopes prior to Lua purge for audit logging
    const existingRecords = [];
    try {
      const scopes = await client.smembers(indexKey);
      if (Array.isArray(scopes)) {
        for (const scope of scopes) {
          const raw = await client.get(`${REDIS_PREFIXES.ELEVATION}${sessionId}:${scope}`);
          if (raw) {
            try {
              const parsed = JSON.parse(raw);
              if (parsed && parsed.user_id) {
                existingRecords.push({ scope, parsed });
              }
            } catch {
              // Ignore malformed record
            }
          }
        }
      }
    } catch {
      // Do not block Lua revocation if pre-read fails
    }

    const deletedCount = await redisStorage.executeRevokeSessionElevations(
      sessionId,
      REDIS_PREFIXES.ELEVATION,
      REDIS_PREFIXES.SESSION_ELEVATIONS_INDEX
    );

    for (const item of existingRecords) {
      await recordElevationAudit({
        user_id: item.parsed.user_id,
        session_id: sessionId,
        scope: item.scope,
        event_action: 'revoked',
        reason,
        jti: item.parsed.jti || null,
        granted_at_risk_tier: item.parsed.granted_at_risk_tier || null,
        expires_at: item.parsed.expires_at || null
      });
    }

    return deletedCount;
  } catch (err) {
    if (options.throwOnError) {
      throw err;
    }
    return 0;
  }
}

const REVOKE_ELEVATIONS_ON_RISK_INCREASE_LUA = `
-- ATOMIC_REVOKE_ELEVATIONS_ON_RISK_INCREASE
-- KEYS[1]: session_elevations:<sessionId>
-- ARGV[1]: elevationPrefix (elevation:session:)
-- ARGV[2]: sessionId
-- ARGV[3]: newRank (0=low, 1=medium, 2=high, 3=critical)

local indexKey = KEYS[1]
local elevationPrefix = ARGV[1]
local sessionId = ARGV[2]
local newRank = tonumber(ARGV[3]) or 0

local tierRanks = {
  low = 0,
  medium = 1,
  high = 2,
  critical = 3
}

local scopes = redis.call('SMEMBERS', indexKey)
local revokedList = {}

for _, scope in ipairs(scopes) do
  local elevationKey = elevationPrefix .. sessionId .. ':' .. scope
  local raw = redis.call('GET', elevationKey)
  if not raw then
    redis.call('SREM', indexKey, scope)
  else
    local ok, data = pcall(cjson.decode, raw)
    if ok and type(data) == 'table' then
      local grantedTier = tostring(data.granted_at_risk_tier or 'low')
      local grantedRank = tierRanks[grantedTier]
      if grantedRank == nil then
        grantedRank = 0
      end
      if newRank > grantedRank then
        redis.call('DEL', elevationKey)
        redis.call('SREM', indexKey, scope)
        table.insert(revokedList, raw)
      end
    end
  end
end

return revokedList
`;

/**
 * Revokes any active elevations on a session whose recorded granted_at_risk_tier
 * is strictly lower than newRiskTier using an atomic Redis Lua script.
 * Handles Redis failures safely without throwing.
 *
 * @param {string} sessionId
 * @param {'low'|'medium'|'high'|'critical'} newRiskTier
 * @returns {Promise<number>} Number of revoked elevations
 */
async function revokeElevationsOnRiskIncrease(sessionId, newRiskTier) {
  if (!sessionId || !newRiskTier || TIER_RANKS[newRiskTier] === undefined) {
    return 0;
  }

  try {
    const client = redisStorage.getRedisClient();
    const indexKey = `${REDIS_PREFIXES.SESSION_ELEVATIONS_INDEX}${sessionId}`;
    const newRank = TIER_RANKS[newRiskTier];

    const revokedRawList = await client.eval(
      REVOKE_ELEVATIONS_ON_RISK_INCREASE_LUA,
      1,
      indexKey,
      REDIS_PREFIXES.ELEVATION,
      String(sessionId),
      String(newRank)
    );

    if (!Array.isArray(revokedRawList) || revokedRawList.length === 0) {
      return 0;
    }

    for (const raw of revokedRawList) {
      let data;
      try {
        data = JSON.parse(raw);
      } catch {
        continue;
      }

      if (data && data.user_id && data.scope) {
        const grantedTier = data.granted_at_risk_tier || 'low';
        await recordElevationAudit({
          user_id: data.user_id,
          session_id: sessionId,
          scope: data.scope,
          event_action: 'revoked',
          reason: 'risk_tier_increased',
          jti: data.jti || null,
          granted_at_risk_tier: grantedTier,
          expires_at: data.expires_at || null,
          metadata: {
            previous_tier: grantedTier,
            new_tier: newRiskTier
          }
        });
      }
    }

    return revokedRawList.length;
  } catch (err) {
    console.warn('[ElevationService] Failed to evaluate risk-tier elevation revocation:', err.message);
    return 0;
  }
}

module.exports = {
  grantElevation,
  checkElevation,
  revokeElevation,
  revokeAllElevationsForSession,
  revokeElevationsOnRiskIncrease,
  recordElevationAudit,
  createMockVerificationTicket,
  verifyVerificationTicket,
  ALLOWLISTED_ELEVATION_SCOPES,
  TEST_VERIFICATION_TICKET_SECRET,
  TIER_RANKS
};
