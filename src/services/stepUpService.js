'use strict';

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { User, SecurityEvent } = require('../database/models');
const redisStorage = require('../storage/redis');
const { grantElevation } = require('./elevationService');
const { recordSecurityEvent } = require('./eventService');
const { containSessionAndLockAccount } = require('./containmentService');
const {
  DEFAULT_ELEVATION_DURATION_SECONDS,
  VERIFICATION_TICKET_TTL_SECONDS,
  STEP_UP_CHALLENGE_TTL_SECONDS,
  STEP_UP_MAX_ATTEMPTS,
  ALLOWLISTED_ELEVATION_SCOPES,
  REDIS_PREFIXES,
  STEP_UP_COOLDOWN_SECONDS,
  STEP_UP_WINDOW_SECONDS,
  STEP_UP_SESSION_SCOPE_MAX,
  STEP_UP_USER_MAX
} = require('../config/sessionConfig');
const { executeCheckStepUpChallengeLimits } = require('../storage/redis');
const mailService = require('./mailService');

let ephemeralDevTestKeyPair = null;
const testChallengeOutbox = new Map();

function resolveOtpSaltSecret() {
  const configuredSecret = process.env.STEP_UP_OTP_SECRET || process.env.JWT_SECRET;

  if (configuredSecret && String(configuredSecret).trim().length > 0) {
    return crypto.createHash('sha256').update(String(configuredSecret)).digest();
  }

  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'STEP_UP_OTP_SECRET or JWT_SECRET must be configured to keep step-up OTP verification stable across restarts.'
    );
  }

  return crypto.createHash('sha256').update('actionguard-dev-step-up-secret').digest();
}

const OTP_SALT_SECRET = resolveOtpSaltSecret();

const VERIFY_STEP_UP_CHALLENGE_LUA = `
-- ATOMIC_VERIFY_STEP_UP_CHALLENGE
-- KEYS[1]: challenge key (step_up_challenge:<challengeId>)
-- ARGV[1]: current timestamp in ms (nowMs)
-- ARGV[2]: expected userId
-- ARGV[3]: expected sessionId
-- ARGV[4]: JSON map of scope -> candidate HMAC hex digest

local challengeKey = KEYS[1]
local nowMs = tonumber(ARGV[1])
local expectedUserId = tostring(ARGV[2])
local expectedSessionId = tostring(ARGV[3])
local candidateHashesJson = ARGV[4]

local raw = redis.call('GET', challengeKey)
if not raw then
  return {-1, 'CHALLENGE_EXPIRED_OR_NOT_FOUND', 0, 0, '', ''}
end

local ok, challenge = pcall(cjson.decode, raw)
if not ok or type(challenge) ~= 'table' then
  redis.call('DEL', challengeKey)
  return {-1, 'CHALLENGE_EXPIRED_OR_NOT_FOUND', 0, 0, '', ''}
end

local expiresAtMs = tonumber(challenge.expires_at_ms)
if not expiresAtMs or nowMs >= expiresAtMs then
  redis.call('DEL', challengeKey)
  return {-1, 'CHALLENGE_EXPIRED_OR_NOT_FOUND', 0, 0, '', ''}
end

if tostring(challenge.user_id) ~= expectedUserId or tostring(challenge.session_id) ~= expectedSessionId then
  return {-2, 'CHALLENGE_BINDING_MISMATCH', 0, 0, tostring(challenge.scope or ''), ''}
end

local maxAttempts = tonumber(challenge.max_attempts) or 3
local currentAttempts = tonumber(challenge.attempts) or 0
if currentAttempts >= maxAttempts then
  redis.call('DEL', challengeKey)
  return {-3, 'CHALLENGE_MAX_ATTEMPTS_EXCEEDED', currentAttempts, maxAttempts, tostring(challenge.scope or ''), ''}
end

local okCandidates, candidateHashes = pcall(cjson.decode, candidateHashesJson)
if not okCandidates or type(candidateHashes) ~= 'table' then
  return {-1, 'CHALLENGE_EXPIRED_OR_NOT_FOUND', 0, 0, '', ''}
end

local scope = tostring(challenge.scope or '')
local expectedHash = tostring(challenge.code_hash or '')
local candidateHash = tostring(candidateHashes[scope] or '')

local isMatch = false
if #expectedHash > 0 and #expectedHash == #candidateHash then
  local diff = 0
  for i = 1, #expectedHash do
    if string.byte(expectedHash, i) ~= string.byte(candidateHash, i) then
      diff = diff + 1
    end
  end
  isMatch = (diff == 0)
end

if isMatch then
  redis.call('DEL', challengeKey)
  return {1, 'VERIFIED', currentAttempts + 1, maxAttempts, scope, expectedHash}
end

local nextAttempts = currentAttempts + 1
if nextAttempts >= maxAttempts then
  redis.call('DEL', challengeKey)
else
  challenge.attempts = nextAttempts
  local remainingTtlSec = math.max(1, math.ceil((expiresAtMs - nowMs) / 1000))
  redis.call('SET', challengeKey, cjson.encode(challenge), 'EX', remainingTtlSec)
end

return {0, 'INVALID_CODE', nextAttempts, maxAttempts, scope, expectedHash}
`;

/**
 * Derives a cryptographically strong per-challenge salt from the server-held
 * secret and the challenge binding tuple (challengeId, userId, sessionId).
 */
function deriveChallengeSalt(challengeId, userId, sessionId) {
  return crypto
    .createHmac('sha256', OTP_SALT_SECRET)
    .update(`${challengeId}:${userId}:${sessionId}`)
    .digest('hex');
}

/**
 * Prunes expired entries from the test-only challenge outbox.
 */
function pruneTestChallengeOutbox(nowMs = Date.now()) {
  if (process.env.NODE_ENV !== 'test' && process.env.ACTIONGUARD_DEMO_MODE !== 'true') {
    return;
  }
  for (const [id, entry] of testChallengeOutbox.entries()) {
    const expMs = entry && entry.expiresAt ? new Date(entry.expiresAt).getTime() : 0;
    if (!Number.isFinite(expMs) || nowMs >= expMs) {
      testChallengeOutbox.delete(id);
    }
  }
}

/**
 * Masks an email address for user-facing step-up challenge responses.
 * Example: "alice@example.com" -> "a***@example.com"
 *
 * @param {string} email
 * @returns {string}
 */
function maskEmail(email) {
  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return '***';
  }
  const [local, domain] = email.split('@');
  const firstChar = local.length > 0 ? local[0] : '*';
  return `${firstChar}***@${domain}`;
}

/**
 * Resolves and validates the ES256 keypair used by the local step-up verification provider.
 * - Never uses JWT_SECRET.
 * - In production (NODE_ENV === 'production'), requires both STEP_UP_VERIFICATION_PRIVATE_KEY
 *   and STEP_UP_VERIFICATION_PUBLIC_KEY to be configured, valid P-256 (prime256v1) EC keys,
 *   and mathematically matched.
 * - In test/development, if either env variable is set, validates them with the same strict rules;
 *   if neither is set, uses an in-memory ephemeral P-256 keypair without mutating process.env.
 *
 * @returns {{ ok: boolean, privateKeyObject?: crypto.KeyObject, publicKeyObject?: crypto.KeyObject, error?: string, code?: string }}
 */
function resolveLocalStepUpKeys() {
  const rawPriv = process.env.STEP_UP_VERIFICATION_PRIVATE_KEY;
  const rawPub = process.env.STEP_UP_VERIFICATION_PUBLIC_KEY;
  const hasPriv = rawPriv !== undefined && String(rawPriv).trim() !== '';
  const hasPub = rawPub !== undefined && String(rawPub).trim() !== '';

  if (process.env.NODE_ENV === 'production' || hasPriv || hasPub) {
    if (!hasPriv || !hasPub) {
      return {
        ok: false,
        error: 'Local step-up verification requires both STEP_UP_VERIFICATION_PRIVATE_KEY and STEP_UP_VERIFICATION_PUBLIC_KEY',
        code: 'VERIFICATION_PROVIDER_UNAVAILABLE'
      };
    }

    let privKeyObj;
    let pubKeyObj;
    try {
      privKeyObj = crypto.createPrivateKey(rawPriv);
      pubKeyObj = crypto.createPublicKey(rawPub);
    } catch {
      return {
        ok: false,
        error: 'Configured step-up verification ES256 keypair is malformed or invalid',
        code: 'INVALID_VERIFICATION_KEY'
      };
    }

    if (
      !privKeyObj ||
      privKeyObj.type !== 'private' ||
      privKeyObj.asymmetricKeyType !== 'ec' ||
      !pubKeyObj ||
      pubKeyObj.type !== 'public' ||
      pubKeyObj.asymmetricKeyType !== 'ec'
    ) {
      return {
        ok: false,
        error: 'Local step-up verification requires an asymmetric EC (P-256 / prime256v1) keypair',
        code: 'INVALID_VERIFICATION_KEY'
      };
    }

    const privCurve = privKeyObj.asymmetricKeyDetails && privKeyObj.asymmetricKeyDetails.namedCurve;
    const pubCurve = pubKeyObj.asymmetricKeyDetails && pubKeyObj.asymmetricKeyDetails.namedCurve;
    if (
      (privCurve && privCurve !== 'prime256v1' && privCurve !== 'P-256') ||
      (pubCurve && pubCurve !== 'prime256v1' && pubCurve !== 'P-256')
    ) {
      return {
        ok: false,
        error: 'Local step-up verification EC keypair must use curve prime256v1 (P-256) for ES256',
        code: 'INVALID_VERIFICATION_KEY'
      };
    }

    // Verify public key mathematically matches private key
    try {
      const derivedPubPem = crypto
        .createPublicKey(privKeyObj)
        .export({ type: 'spki', format: 'pem' });
      const configuredPubPem = pubKeyObj.export({ type: 'spki', format: 'pem' });
      if (derivedPubPem !== configuredPubPem) {
        return {
          ok: false,
          error: 'Configured STEP_UP_VERIFICATION_PUBLIC_KEY does not match STEP_UP_VERIFICATION_PRIVATE_KEY',
          code: 'INVALID_VERIFICATION_KEY'
        };
      }
    } catch {
      return {
        ok: false,
        error: 'Failed to verify step-up public/private keypair correspondence',
        code: 'INVALID_VERIFICATION_KEY'
      };
    }

    return {
      ok: true,
      privateKeyObject: privKeyObj,
      publicKeyObject: pubKeyObj
    };
  }

  // Ephemeral ES256 keypair for development / test when env keys are not set
  if (!ephemeralDevTestKeyPair) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });
    ephemeralDevTestKeyPair = {
      privateKeyObject: privateKey,
      publicKeyObject: publicKey
    };
  }

  return {
    ok: true,
    privateKeyObject: ephemeralDevTestKeyPair.privateKeyObject,
    publicKeyObject: ephemeralDevTestKeyPair.publicKeyObject
  };
}

/**
 * Computes HMAC-SHA256 digest of a step-up OTP bound to challengeId, sessionId, and scope.
 */
function hashChallengeCode({ salt, challengeId, sessionId, scope, code }) {
  return crypto
    .createHmac('sha256', salt)
    .update(`${challengeId}:${sessionId}:${scope}:${code}`)
    .digest('hex');
}

/**
 * Atomically evaluates and consumes step-up challenge rate limits across:
 * (a) 30s cooldown per session+scope
 * (b) <= 3 challenges per 10 minutes per session+scope
 * (c) <= 6 challenges per 10 minutes per user across sessions
 *
 * @param {object} params
 * @param {string} params.userId
 * @param {string} params.sessionId
 * @param {string} params.scope
 * @returns {Promise<{ allowed: boolean, reason: string, retryAfterSeconds: number, message?: string }>}
 */
async function checkStepUpLimits({ userId, sessionId, scope }) {
  const cooldownKey = `${REDIS_PREFIXES.STEP_UP_COOLDOWN}${sessionId}:${scope}`;
  const sessionScopeKey = `${REDIS_PREFIXES.STEP_UP_SESSION_SCOPE}${sessionId}:${scope}`;
  const userKey = `${REDIS_PREFIXES.STEP_UP_USER}${userId}`;

  const res = await executeCheckStepUpChallengeLimits({
    cooldownKey,
    sessionScopeKey,
    userKey,
    cooldownSec: STEP_UP_COOLDOWN_SECONDS,
    windowSec: STEP_UP_WINDOW_SECONDS,
    sessionScopeMax: STEP_UP_SESSION_SCOPE_MAX,
    userMax: STEP_UP_USER_MAX
  });

  const [allowedNum, reason, retryAfter] = res;
  const isAllowed = Number(allowedNum) === 1;
  const retryAfterSec = Number(retryAfter) || 1;

  if (!isAllowed) {
    let message = 'Step-up challenge limit exceeded. Please try again later.';
    if (reason === 'cooldown') {
      message = `Please wait ${retryAfterSec} second(s) before requesting another step-up challenge for this scope.`;
    } else if (reason === 'session_scope_limit') {
      message = `Too many step-up challenges requested for this session and scope. Please retry in ${retryAfterSec} second(s).`;
    } else if (reason === 'user_limit') {
      message = `Too many step-up challenges requested across your sessions. Please retry in ${retryAfterSec} second(s).`;
    }
    return {
      allowed: false,
      reason,
      retryAfterSeconds: retryAfterSec,
      message
    };
  }

  return {
    allowed: true,
    reason: 'ok',
    retryAfterSeconds: 0
  };
}

/**
 * Issues a single-use, session- and scope-bound step-up OTP challenge delivered
 * to the user's immutable registration email address.
 *
 * @param {object} params
 * @param {string} params.userId
 * @param {string} params.sessionId
 * @param {string} params.scope
 * @param {Date|number} [params.now=new Date()]
 * @returns {Promise<{ challenge_id: string, scope: string, delivery_channel: string, masked_destination: string, expires_at: string, ttl_seconds: number }>}
 */
async function issueStepUpChallenge({ userId, sessionId, scope, now = new Date() }) {
  if (process.env.ACTIONGUARD_DEMO_MODE === 'true' && process.env.NODE_ENV === 'production') {
    throw new Error('ACTIONGUARD_DEMO_MODE cannot be enabled in production environments');
  }

  if (!userId || !sessionId || !scope) {
    const err = new Error('userId, sessionId, and scope are required');
    err.code = 'INVALID_REQUEST';
    throw err;
  }

  const normalizedScope = String(scope).trim();
  if (!ALLOWLISTED_ELEVATION_SCOPES.includes(normalizedScope)) {
    const err = new Error(`Elevation scope '${normalizedScope}' is not permitted`);
    err.code = 'INVALID_ELEVATION_SCOPE';
    throw err;
  }

  const keyCtx = resolveLocalStepUpKeys();
  if (!keyCtx.ok) {
    const err = new Error(keyCtx.error);
    err.code = keyCtx.code;
    throw err;
  }

  const user = await User.findByPk(userId, {
    attributes: ['id', 'email']
  });
  if (!user || !user.email) {
    const err = new Error('User registration email not found');
    err.code = 'USER_NOT_FOUND';
    throw err;
  }

  const limitCheck = await checkStepUpLimits({
    userId,
    sessionId,
    scope: normalizedScope
  });
  if (!limitCheck.allowed) {
    const err = new Error(limitCheck.message);
    err.code = 'CHALLENGE_LIMITED';
    err.status = 429;
    err.retryAfterSeconds = limitCheck.retryAfterSeconds;
    err.reason = limitCheck.reason;
    throw err;
  }

  const nowDate = now instanceof Date ? now : new Date(now);
  const nowMs = nowDate.getTime();
  const expiresAtMs = nowMs + STEP_UP_CHALLENGE_TTL_SECONDS * 1000;
  const expiresAtIso = new Date(expiresAtMs).toISOString();

  const challengeId = `chl_${crypto.randomUUID()}`;
  const otp = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const salt = deriveChallengeSalt(challengeId, userId, sessionId);
  const codeHash = hashChallengeCode({
    salt,
    challengeId,
    sessionId,
    scope: normalizedScope,
    code: otp
  });

  const challengeRecord = {
    challenge_id: challengeId,
    user_id: userId,
    session_id: sessionId,
    scope: normalizedScope,
    salt,
    code_hash: codeHash,
    attempts: 0,
    max_attempts: STEP_UP_MAX_ATTEMPTS,
    created_at: nowDate.toISOString(),
    expires_at: expiresAtIso,
    expires_at_ms: expiresAtMs
  };

  const client = redisStorage.getRedisClient();
  const challengeKey = `${REDIS_PREFIXES.STEP_UP_CHALLENGE}${challengeId}`;
  await client.set(challengeKey, JSON.stringify(challengeRecord), 'EX', STEP_UP_CHALLENGE_TTL_SECONDS);

  const isTest = process.env.NODE_ENV === 'test';
  const isDemoMode = process.env.ACTIONGUARD_DEMO_MODE === 'true';

  if (isDemoMode && process.env.NODE_ENV === 'production') {
    throw new Error('ACTIONGUARD_DEMO_MODE cannot be enabled in production environments');
  }

  if (isTest || isDemoMode) {
    pruneTestChallengeOutbox(nowMs);
    testChallengeOutbox.set(challengeId, {
      otp,
      userId,
      sessionId,
      scope: normalizedScope,
      destination: user.email,
      expiresAt: expiresAtIso
    });

    if (isDemoMode) {
      console.log(`[DEMO OTP] Scope: ${normalizedScope} | Code: ${otp} | Expires: ${expiresAtIso}`);
      if (process.env.ACTIONGUARD_DEMO_OTP_FILE) {
        try {
          const fs = require('fs');
          fs.appendFileSync(
            process.env.ACTIONGUARD_DEMO_OTP_FILE,
            JSON.stringify({ challengeId, scope: normalizedScope, otp, expiresAt: expiresAtIso }) + '\n'
          );
        } catch (fileErr) {
          console.warn('[DEMO OTP] Failed to write demo OTP to file:', fileErr.message);
        }
      }
    }
  } else {
    try {
      await mailService.sendStepUpCode(user.email, otp, STEP_UP_CHALLENGE_TTL_SECONDS);
    } catch (mailErr) {
      try {
        await client.del(challengeKey);
      } catch (_) { /* best effort */ }
      console.error('[StepUp] OTP email delivery failed:', mailErr.message);
      const err = new Error('Verification code could not be delivered');
      err.code = 'STEP_UP_DELIVERY_FAILED';
      throw err;
    }
  }

  return {
    challenge_id: challengeId,
    scope: normalizedScope,
    delivery_channel: 'registration_email',
    masked_destination: maskEmail(user.email),
    expires_at: expiresAtIso,
    ttl_seconds: STEP_UP_CHALLENGE_TTL_SECONDS
  };
}

/**
 * Verifies a step-up challenge OTP in constant time and atomically via Redis Lua,
 * signs a short-lived ES256 verification ticket, and redeems it server-side through grantElevation.
 *
 * Records `verification_success` on match and `verification_failed` on mismatch.
 * Triggers session containment + 15-minute account lock when a session reaches
 * >= STEP_UP_MAX_ATTEMPTS (3) verification_failed events.
 *
 * @param {object} params
 * @param {string} params.userId
 * @param {string} params.sessionId
 * @param {string} params.challengeId
 * @param {string} params.code
 * @param {number} [params.durationSeconds]
 * @param {number|null} [params.maxSessionExpiresAt=null]
 * @param {object} [params.context={}]
 * @param {Date|number} [params.now=new Date()]
 * @returns {Promise<{ elevated: boolean, scope: string, expiresAt: string, remainingSeconds: number }>}
 */
async function verifyStepUpChallenge({
  userId,
  sessionId,
  challengeId,
  code,
  durationSeconds = DEFAULT_ELEVATION_DURATION_SECONDS,
  maxSessionExpiresAt = null,
  context = {},
  now = new Date()
}) {
  if (!userId || !sessionId || !challengeId || typeof challengeId !== 'string') {
    const err = new Error('challenge_id is required');
    err.code = 'INVALID_REQUEST';
    throw err;
  }

  if (typeof code !== 'string' || !/^\d{6}$/.test(code.trim())) {
    const err = new Error('A valid 6-digit verification code is required');
    err.code = 'INVALID_REQUEST';
    throw err;
  }

  const keyCtx = resolveLocalStepUpKeys();
  if (!keyCtx.ok) {
    const err = new Error(keyCtx.error);
    err.code = keyCtx.code;
    throw err;
  }

  const nowDate = now instanceof Date ? now : new Date(now);
  const nowMs = nowDate.getTime();
  const trimmedChallengeId = challengeId.trim();
  const trimmedCode = code.trim();

  const salt = deriveChallengeSalt(trimmedChallengeId, userId, sessionId);
  const candidateHashesByScope = {};
  for (const allowedScope of ALLOWLISTED_ELEVATION_SCOPES) {
    candidateHashesByScope[allowedScope] = hashChallengeCode({
      salt,
      challengeId: trimmedChallengeId,
      sessionId,
      scope: allowedScope,
      code: trimmedCode
    });
  }

  const client = redisStorage.getRedisClient();
  const challengeKey = `${REDIS_PREFIXES.STEP_UP_CHALLENGE}${trimmedChallengeId}`;
  const evalResult = await client.eval(
    VERIFY_STEP_UP_CHALLENGE_LUA,
    1,
    challengeKey,
    String(nowMs),
    String(userId),
    String(sessionId),
    JSON.stringify(candidateHashesByScope)
  );

  const statusCode = Number(evalResult && evalResult[0]);
  const statusReason = String((evalResult && evalResult[1]) || '');
  const nextAttempts = Number(evalResult && evalResult[2]) || 0;
  const maxAttempts = Number(evalResult && evalResult[3]) || STEP_UP_MAX_ATTEMPTS;
  const challengeScope = String((evalResult && evalResult[4]) || '');
  const expectedHash = String((evalResult && evalResult[5]) || '');

  if (statusCode === -1 || statusReason === 'CHALLENGE_EXPIRED_OR_NOT_FOUND') {
    if (process.env.NODE_ENV === 'test') {
      testChallengeOutbox.delete(trimmedChallengeId);
    }
    const err = new Error('Verification challenge has expired or does not exist');
    err.code = 'CHALLENGE_EXPIRED_OR_NOT_FOUND';
    throw err;
  }

  if (statusCode === -2 || statusReason === 'CHALLENGE_BINDING_MISMATCH') {
    await recordSecurityEvent({
      userId,
      sessionId,
      eventType: 'verification_failed',
      timestamp: nowDate,
      context,
      metadata: {
        challenge_id: trimmedChallengeId,
        reason: 'challenge_session_mismatch'
      }
    });
    const err = new Error('Verification challenge does not belong to the active session');
    err.code = 'CHALLENGE_BINDING_MISMATCH';
    throw err;
  }

  if (statusCode === -3 || statusReason === 'CHALLENGE_MAX_ATTEMPTS_EXCEEDED') {
    if (process.env.NODE_ENV === 'test') {
      testChallengeOutbox.delete(trimmedChallengeId);
    }
    const err = new Error('Maximum verification attempts exceeded for this challenge');
    err.code = 'CHALLENGE_MAX_ATTEMPTS_EXCEEDED';
    throw err;
  }

  if (statusCode === 0 || statusReason === 'INVALID_CODE') {
    if (nextAttempts >= maxAttempts && process.env.NODE_ENV === 'test') {
      testChallengeOutbox.delete(trimmedChallengeId);
    }

    const failedEvent = await recordSecurityEvent({
      userId,
      sessionId,
      eventType: 'verification_failed',
      timestamp: nowDate,
      context,
      metadata: {
        challenge_id: trimmedChallengeId,
        scope: challengeScope,
        attempt: nextAttempts,
        max_attempts: maxAttempts
      }
    });

    const allSessionFailedEvents = await SecurityEvent.findAll({
      where: {
        user_id: userId,
        session_id: sessionId,
        event_type: 'verification_failed'
      },
      attributes: ['event_id', 'metadata']
    });
    const priorChallengeFailures = allSessionFailedEvents.filter(
      (ev) => ev.metadata && ev.metadata.challenge_id !== trimmedChallengeId
    ).length;
    const effectiveSessionAttempts = priorChallengeFailures + nextAttempts;

    if (effectiveSessionAttempts >= STEP_UP_MAX_ATTEMPTS) {
      const containment = await containSessionAndLockAccount({
        userId,
        sessionId,
        reason: 'repeated_verification_failures',
        triggeringEventId: failedEvent ? failedEvent.event_id : null,
        context,
        now: nowDate
      });

      const err = new Error(
        'Maximum step-up verification attempts exceeded. Session has been terminated and account temporarily locked.'
      );
      err.code = 'VERIFICATION_FAILED_CONTAINED';
      err.sessionContained = containment.session_contained;
      err.accountLocked = containment.account_locked;
      err.lockedUntil = containment.locked_until;
      err.retryAfterSeconds = containment.retry_after_seconds;
      throw err;
    }

    const err = new Error('Invalid verification code');
    err.code = 'VERIFICATION_CODE_INVALID';
    err.remainingAttempts = Math.max(0, maxAttempts - nextAttempts);
    throw err;
  }

  const candidateHash = String(candidateHashesByScope[challengeScope] || '');
  const expectedBuf = Buffer.from(expectedHash, 'hex');
  const candidateBuf = Buffer.from(candidateHash, 'hex');
  if (
    statusCode !== 1 ||
    expectedBuf.length === 0 ||
    expectedBuf.length !== candidateBuf.length ||
    !crypto.timingSafeEqual(expectedBuf, candidateBuf)
  ) {
    const err = new Error('Verification challenge has expired or does not exist');
    err.code = 'CHALLENGE_EXPIRED_OR_NOT_FOUND';
    throw err;
  }

  if (process.env.NODE_ENV === 'test') {
    testChallengeOutbox.delete(trimmedChallengeId);
  }

  const challenge = { scope: challengeScope };

  await recordSecurityEvent({
    userId,
    sessionId,
    eventType: 'verification_success',
    timestamp: nowDate,
    context,
    metadata: {
      challenge_id: trimmedChallengeId,
      scope: challenge.scope,
      method: 'email_otp'
    }
  });

  const nowSec = Math.floor(nowMs / 1000);
  const jti = `tkt_${crypto.randomUUID()}`;
  const ticketString = jwt.sign(
    {
      sub: userId,
      session_id: sessionId,
      scope: challenge.scope,
      purpose: 'step_up_verification',
      iat: nowSec,
      exp: nowSec + VERIFICATION_TICKET_TTL_SECONDS
    },
    keyCtx.privateKeyObject,
    {
      algorithm: 'ES256',
      jwtid: jti
    }
  );

  const elevation = await grantElevation({
    sessionId,
    userId,
    scope: challenge.scope,
    verificationTicket: ticketString,
    durationSeconds,
    maxSessionExpiresAt,
    nowMs,
    publicKey: keyCtx.publicKeyObject
  });

  return {
    elevated: elevation.elevated,
    scope: elevation.scope,
    expiresAt: elevation.expiresAt,
    remainingSeconds: elevation.remainingSeconds
  };
}

function getTestChallengeOtp(challengeId) {
  if (process.env.NODE_ENV !== 'test') {
    throw new Error('getTestChallengeOtp is strictly restricted to NODE_ENV === "test"');
  }
  const entry = testChallengeOutbox.get(challengeId);
  return entry ? entry.otp : null;
}

function getTestChallengeRecord(challengeId) {
  if (process.env.NODE_ENV !== 'test') {
    throw new Error('getTestChallengeRecord is strictly restricted to NODE_ENV === "test"');
  }
  return testChallengeOutbox.get(challengeId) || null;
}

function getDemoChallengeRecord(challengeId) {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('getDemoChallengeRecord cannot be called in production environments');
  }
  if (process.env.NODE_ENV !== 'test' && process.env.ACTIONGUARD_DEMO_MODE !== 'true') {
    return null;
  }
  return testChallengeOutbox.get(challengeId) || null;
}

module.exports = {
  issueStepUpChallenge,
  verifyStepUpChallenge,
  checkStepUpLimits,
  resolveLocalStepUpKeys,
  getTestChallengeOtp,
  getTestChallengeRecord,
  getDemoChallengeRecord,
  testChallengeOutbox,
  maskEmail
};
