'use strict';

const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { Op } = require('sequelize');
const {
  User,
  Session,
  SecurityEvent,
  DelayedAction
} = require('../database/models');
const {
  REDIS_PREFIXES,
  ACTION_ELEVATION_SCOPE_MAP
} = require('../config/sessionConfig');
const redisStorage = require('../storage/redis');
const {
  validateActiveSession,
  terminateAllUserSessions
} = require('./sessionService');
const { checkElevation } = require('./elevationService');
const riskEngineService = require('./riskEngineService');
const policyLoader = require('./policyLoader');
const { decide } = require('../utils/policyDecision');
const { extractServerRequestContext } = require('../utils/requestContext');
const eventBus = require('../events/eventBus');

const RISK_TIER_ORDER = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3
};

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_REGEX = /^\+[1-9]\d{6,14}$/;

const ALLOWED_DELAYED_ACTION_TYPES = new Set([
  'password_change',
  'recovery_email_change',
  'phone_number_change',
  'mfa_change',
  'high_impact_action'
]);

const SENSITIVE_KEY_PATTERN =
  /^(password|current_password|new_password|password_hash|new_password_hash|token|cancellation_token|access_token|refresh_token|apikey|api_key|secret|client_secret|otp|code|pin|cvv|private_key)$/i;

const SENSITIVE_SUBSTRING_PATTERN = /(password|secret|token|api_?key|private_?key)/i;

const DEFAULT_STALE_EXECUTING_TIMEOUT_MS = 30000;

const customActionExecutors = new Map();

/**
 * Registers a custom executor function for a given action type.
 *
 * @param {string} actionType
 * @param {Function} executorFn - async (userId, payload, delayedAction) => result
 */
function registerActionExecutor(actionType, executorFn) {
  if (!actionType || typeof actionType !== 'string') {
    throw new TypeError('actionType must be a non-empty string');
  }
  if (typeof executorFn !== 'function') {
    throw new TypeError('executorFn must be a function');
  }
  customActionExecutors.set(actionType, executorFn);
}

/**
 * Resets registered custom action executors.
 */
function resetActionExecutors() {
  customActionExecutors.clear();
}

/**
 * Recursively sanitizes a payload object or array by removing any keys that match
 * credential, password, token, secret, or OTP patterns regardless of casing or nesting.
 *
 * @param {*} rawPayload
 * @param {number} [depth=0]
 * @returns {*}
 */
function sanitizePayload(rawPayload, depth = 0) {
  if (depth > 10 || rawPayload === null || rawPayload === undefined) {
    return {};
  }
  if (Array.isArray(rawPayload)) {
    return rawPayload.map((item) => {
      if (item && typeof item === 'object') {
        return sanitizePayload(item, depth + 1);
      }
      return item;
    });
  }
  if (typeof rawPayload !== 'object') {
    return {};
  }

  const sanitized = {};
  for (const [key, value] of Object.entries(rawPayload)) {
    if (key === 'password_change_requested' && typeof value === 'boolean') {
      sanitized[key] = value;
      continue;
    }
    if (SENSITIVE_KEY_PATTERN.test(key) || SENSITIVE_SUBSTRING_PATTERN.test(key)) {
      continue;
    }
    if (Array.isArray(value)) {
      sanitized[key] = sanitizePayload(value, depth + 1);
    } else if (value && typeof value === 'object') {
      sanitized[key] = sanitizePayload(value, depth + 1);
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

/**
 * Returns a safe public projection of a delayed action's payload suitable for
 * API responses, Redis caching, and event broadcasts.
 *
 * @param {object} payload
 * @returns {object}
 */
function sanitizePublicActionPayload(payload) {
  return sanitizePayload(payload || {});
}

/**
 * Returns a copy of a delayed action plain object with action_payload and
 * cancellation_token_hash sanitized for external/event consumption.
 *
 * @param {object} actionPlain
 * @returns {object}
 */
function toSafeActionObject(actionPlain) {
  if (!actionPlain || typeof actionPlain !== 'object') {
    return actionPlain;
  }
  return {
    ...actionPlain,
    action_payload: sanitizePublicActionPayload(actionPlain.action_payload)
  };
}

/**
 * Validates and builds an explicit, allowlisted payload for a delayed action.
 * Performs domain & credential verification before scheduling.
 *
 * @param {object} params
 * @param {string} params.actionType
 * @param {object} params.rawPayload
 * @param {string} params.userId
 * @returns {Promise<object>}
 */
async function validateAndBuildActionPayload({ actionType, rawPayload, userId }) {
  if (!actionType || typeof actionType !== 'string') {
    const err = new Error('A valid actionType string is required');
    err.status = 400;
    err.code = 'invalid_request';
    throw err;
  }

  const isBuiltIn = ALLOWED_DELAYED_ACTION_TYPES.has(actionType);
  const isCustom = customActionExecutors.has(actionType);
  if (!isBuiltIn && !isCustom) {
    const err = new Error(`Unsupported delayed action_type '${actionType}'`);
    err.status = 400;
    err.code = 'unsupported_action_type';
    throw err;
  }

  if (!rawPayload || typeof rawPayload !== 'object' || Array.isArray(rawPayload)) {
    const err = new Error('actionPayload must be a valid JSON object');
    err.status = 400;
    err.code = 'invalid_request';
    throw err;
  }

  // If a custom executor is registered for a custom action type, recursively strip secrets
  if (isCustom && !isBuiltIn) {
    return sanitizePayload(rawPayload);
  }

  switch (actionType) {
    case 'password_change': {
      const { current_password, new_password } = rawPayload;
      if (
        !current_password ||
        typeof current_password !== 'string' ||
        !new_password ||
        typeof new_password !== 'string' ||
        new_password.length < 8
      ) {
        const err = new Error('current_password and a new_password of at least 8 characters are required');
        err.status = 400;
        err.code = 'invalid_request';
        throw err;
      }
      if (new_password === current_password) {
        const err = new Error('new_password must be different from current_password');
        err.status = 400;
        err.code = 'invalid_request';
        throw err;
      }

      const user = await User.findByPk(userId);
      if (!user) {
        const err = new Error('User not found');
        err.status = 404;
        err.code = 'not_found';
        throw err;
      }

      const isCurrentValid = await bcrypt.compare(current_password, user.password_hash);
      if (!isCurrentValid) {
        const err = new Error('Current password is incorrect');
        err.status = 401;
        err.code = 'invalid_credentials';
        throw err;
      }

      const newPasswordHash = await bcrypt.hash(new_password, 10);
      return {
        password_change_requested: true,
        new_password_hash: newPasswordHash
      };
    }

    case 'recovery_email_change': {
      const { recovery_email } = rawPayload;
      if (
        !recovery_email ||
        typeof recovery_email !== 'string' ||
        recovery_email.trim().length > 255 ||
        !EMAIL_REGEX.test(recovery_email.trim())
      ) {
        const err = new Error('A valid recovery_email address is required');
        err.status = 400;
        err.code = 'invalid_request';
        throw err;
      }

      const normalizedEmail = recovery_email.trim().toLowerCase();
      const user = await User.findByPk(userId);
      if (!user) {
        const err = new Error('User not found');
        err.status = 404;
        err.code = 'not_found';
        throw err;
      }

      if (user.email && user.email.trim().toLowerCase() === normalizedEmail) {
        const err = new Error('recovery_email must be different from the primary registration email');
        err.status = 400;
        err.code = 'invalid_request';
        throw err;
      }

      return {
        recovery_email: normalizedEmail
      };
    }

    case 'phone_number_change': {
      const { phone_number } = rawPayload;
      if (
        !phone_number ||
        typeof phone_number !== 'string' ||
        !PHONE_REGEX.test(phone_number.trim())
      ) {
        const err = new Error('A valid E.164 phone_number (starting with +) is required');
        err.status = 400;
        err.code = 'invalid_request';
        throw err;
      }

      return {
        phone_number: phone_number.trim()
      };
    }

    case 'mfa_change': {
      const { mfa_enabled } = rawPayload;
      if (typeof mfa_enabled !== 'boolean') {
        const err = new Error('mfa_enabled boolean is required');
        err.status = 400;
        err.code = 'invalid_request';
        throw err;
      }

      return {
        mfa_enabled
      };
    }

    case 'high_impact_action': {
      const { operation, target } = rawPayload;
      if (
        !operation ||
        typeof operation !== 'string' ||
        operation.trim().length === 0 ||
        operation.trim().length > 128
      ) {
        const err = new Error('A valid operation string is required');
        err.status = 400;
        err.code = 'invalid_request';
        throw err;
      }
      if (target !== undefined && target !== null && (typeof target !== 'string' || target.trim().length > 255)) {
        const err = new Error('target must be a string of at most 255 characters');
        err.status = 400;
        err.code = 'invalid_request';
        throw err;
      }

      const allowlisted = {
        operation: operation.trim()
      };
      if (typeof target === 'string' && target.trim().length > 0) {
        allowlisted.target = target.trim();
      }
      return allowlisted;
    }

    default: {
      const err = new Error(`Unsupported delayed action_type '${actionType}'`);
      err.status = 400;
      err.code = 'unsupported_action_type';
      throw err;
    }
  }
}

/**
 * Computes constant-time hash comparison between two hex strings.
 */
function constantTimeHashEqual(hashA, hashB) {
  if (typeof hashA !== 'string' || typeof hashB !== 'string') {
    return false;
  }
  const bufA = Buffer.from(hashA, 'hex');
  const bufB = Buffer.from(hashB, 'hex');
  if (bufA.length !== bufB.length || bufA.length === 0) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Updates SecurityEvent metadata and cleans up Redis cooling-off keys when an action reaches a terminal state.
 */
async function cleanupTerminalActionState(action, extraMetadata = {}) {
  if (action && action.event_id) {
    try {
      const secEvent = await SecurityEvent.findByPk(action.event_id);
      if (secEvent) {
        await secEvent.update({
          metadata: {
            ...(secEvent.metadata || {}),
            delayed_action_id: action.id,
            ...extraMetadata
          }
        });
      }
    } catch {}
  }

  if (action && action.id) {
    try {
      const client = redisStorage.getRedisClient();
      if (action.cancellation_token_hash) {
        await client.del(`${REDIS_PREFIXES.COOLING_OFF_TOKEN_MAP}${action.cancellation_token_hash}`);
      }
      if (action.user_id) {
        await client.srem(`${REDIS_PREFIXES.COOLING_OFF_USER_INDEX}${action.user_id}`, action.id);
      }
      await client.del(`${REDIS_PREFIXES.COOLING_OFF_ACTION}${action.id}`);
    } catch {}
  }
}

/**
 * Schedules a delayed action for cooling-off enforcement.
 *
 * @param {object} params
 * @param {object} params.req - Express request
 * @param {object} params.decisionContext - Context from PEP
 * @param {string} [params.actionType]
 * @param {object} [params.actionPayload]
 * @param {number} [params.delaySeconds]
 * @param {number} [params.gracePeriodSeconds=3600]
 * @returns {Promise<{ delayedAction: object, cancellationToken: string }>}
 */
async function scheduleDelayedAction(params) {
  const {
    req,
    decisionContext = {},
    actionType: explicitActionType,
    actionPayload: explicitPayload,
    delaySeconds: explicitDelaySeconds,
    gracePeriodSeconds = 3600
  } = params;

  if (!req || typeof req !== 'object') {
    throw new TypeError('req is required to schedule a delayed action');
  }

  const userId = req.user ? req.user.id || req.user.user_id : null;
  if (!userId) {
    throw new Error('Authenticated user is required to schedule delayed action');
  }

  const sessionId =
    (req.session && (req.session.sessionId || req.session.session_id)) ||
    (req.user && req.user.session_id) ||
    null;

  const actionType =
    explicitActionType ||
    decisionContext.actionType ||
    (req.body && req.body.action) ||
    'high_impact_action';

  const routeSensitivity =
    decisionContext.routeSensitivity ||
    (decisionContext.decisionRecord && decisionContext.decisionRecord.action_sensitivity) ||
    'critical';

  const delaySeconds =
    typeof explicitDelaySeconds === 'number' && explicitDelaySeconds > 0
      ? explicitDelaySeconds
      : typeof decisionContext.delaySeconds === 'number' && decisionContext.delaySeconds > 0
        ? decisionContext.delaySeconds
        : 300;

  const decisionId =
    (decisionContext.decisionRecord && decisionContext.decisionRecord.id) || null;
  const eventId =
    (decisionContext.eventRecord && decisionContext.eventRecord.event_id) ||
    (decisionContext.decisionRecord && decisionContext.decisionRecord.event_id) ||
    null;

  const rawPayload = explicitPayload || req.body || {};
  let validatedPayload;
  try {
    validatedPayload = await validateAndBuildActionPayload({
      actionType,
      rawPayload,
      userId
    });
  } catch (validationErr) {
    if (eventId && validationErr.status && validationErr.status < 500) {
      try {
        const secEvent = await SecurityEvent.findByPk(eventId);
        if (secEvent) {
          await secEvent.update({
            metadata: {
              ...(secEvent.metadata || {}),
              action_status: 'rejected',
              rejection_reason: validationErr.code || 'invalid_delayed_action_payload'
            }
          });
        }
      } catch {}
    }
    throw validationErr;
  }

  // Generate cryptographically random cancellation token
  const cancellationToken = 'ctkn_' + crypto.randomBytes(32).toString('hex');
  const cancellationTokenHash = crypto
    .createHash('sha256')
    .update(cancellationToken)
    .digest('hex');

  const now = new Date();
  const executeAt = new Date(now.getTime() + delaySeconds * 1000);
  const expiresAt = new Date(executeAt.getTime() + gracePeriodSeconds * 1000);

  const riskTier = decisionContext.riskTier || 'high';
  const requestContext = await extractServerRequestContext(req);

  // Persist into MySQL
  const delayedAction = await DelayedAction.create({
    id: `cact_${crypto.randomUUID()}`,
    user_id: userId,
    session_id: sessionId,
    decision_id: decisionId,
    event_id: eventId,
    action_type: actionType,
    action_sensitivity: routeSensitivity,
    route_path: req.originalUrl || req.path || '/api/v1/account/high-impact',
    route_method: req.method || 'POST',
    action_payload: validatedPayload,
    request_context: requestContext,
    scheduled_at_risk_tier: riskTier,
    cooling_off_seconds: delaySeconds,
    status: 'pending',
    cancellation_token_hash: cancellationTokenHash,
    scheduled_at: now,
    execute_at: executeAt,
    expires_at: expiresAt
  });

  const plainAction =
    typeof delayedAction.get === 'function'
      ? delayedAction.get({ plain: true })
      : delayedAction;

  const safeAction = toSafeActionObject(plainAction);

  // Cache sanitized projection in Redis for fast query and concurrency locking
  try {
    const client = redisStorage.getRedisClient();
    const actionKey = `${REDIS_PREFIXES.COOLING_OFF_ACTION}${plainAction.id}`;
    const tokenKey = `${REDIS_PREFIXES.COOLING_OFF_TOKEN_MAP}${cancellationTokenHash}`;
    const userIndexKey = `${REDIS_PREFIXES.COOLING_OFF_USER_INDEX}${userId}`;
    const ttlSeconds = delaySeconds + gracePeriodSeconds;

    await client.set(actionKey, JSON.stringify(safeAction), 'EX', ttlSeconds);
    await client.set(tokenKey, plainAction.id, 'EX', ttlSeconds);
    await client.sadd(userIndexKey, plainAction.id);
    await client.expire(userIndexKey, ttlSeconds);
  } catch (redisErr) {
    console.warn('[CoolingOffService] Redis cache write failed; MySQL persisted safely:', redisErr.message);
  }

  if (eventId) {
    try {
      const secEvent = await SecurityEvent.findByPk(eventId);
      if (secEvent) {
        await secEvent.update({
          metadata: {
            ...(secEvent.metadata || {}),
            action_status: 'delayed',
            delayed_action_id: plainAction.id
          }
        });
      }
    } catch {}
  }

  eventBus.safeEmit('cooling_off:scheduled', {
    action_id: safeAction.id,
    delayed_action: safeAction
  });

  return {
    delayedAction: safeAction,
    cancellationToken
  };
}

/**
 * Retrieves a delayed action by ID with sanitized public payload.
 *
 * @param {string} actionId
 * @returns {Promise<object|null>}
 */
async function getDelayedAction(actionId) {
  if (!actionId || typeof actionId !== 'string') {
    return null;
  }
  const action = await DelayedAction.findByPk(actionId);
  if (!action) {
    return null;
  }
  const plain = typeof action.get === 'function' ? action.get({ plain: true }) : action;
  return toSafeActionObject(plain);
}

/**
 * Lists active pending delayed actions for a user.
 *
 * @param {string} userId
 * @returns {Promise<Array<object>>}
 */
async function listDelayedActionsForUser(userId) {
  if (!userId || typeof userId !== 'string') {
    return [];
  }
  const actions = await DelayedAction.findAll({
    where: {
      user_id: userId,
      status: 'pending'
    },
    order: [['execute_at', 'ASC']]
  });
  return actions.map((a) =>
    toSafeActionObject(typeof a.get === 'function' ? a.get({ plain: true }) : a)
  );
}

/**
 * Cancels a pending delayed action using its scoped cancellation token.
 * Enforces expires_at (returning 410 action_expired if already expired).
 *
 * @param {object} params
 * @param {string} params.actionId
 * @param {string} params.cancellationToken
 * @param {string} params.userId
 * @param {string} [params.reason='user_requested_cancellation']
 * @returns {Promise<object>}
 */
async function cancelDelayedAction(params) {
  const { actionId, cancellationToken, userId, reason = 'user_requested_cancellation' } = params;

  if (!actionId || typeof actionId !== 'string') {
    const err = new Error('actionId is required');
    err.status = 400;
    err.code = 'invalid_request';
    throw err;
  }

  if (!cancellationToken || typeof cancellationToken !== 'string') {
    const err = new Error('cancellation_token is required');
    err.status = 400;
    err.code = 'invalid_cancellation_token';
    throw err;
  }

  if (!userId || typeof userId !== 'string') {
    const err = new Error('userId is required');
    err.status = 401;
    err.code = 'unauthorized';
    throw err;
  }

  const action = await DelayedAction.findByPk(actionId);
  if (!action) {
    const err = new Error('Delayed action not found');
    err.status = 404;
    err.code = 'delayed_action_not_found';
    throw err;
  }

  // Scoped ownership verification
  if (action.user_id !== userId) {
    const err = new Error('Caller does not own this delayed action');
    err.status = 403;
    err.code = 'forbidden';
    throw err;
  }

  if (action.status === 'cancelled') {
    const err = new Error('Delayed action has already been cancelled');
    err.status = 409;
    err.code = 'action_already_cancelled';
    throw err;
  }

  if (action.status === 'expired') {
    const err = new Error('Delayed action has expired and can no longer be cancelled');
    err.status = 410;
    err.code = 'action_expired';
    throw err;
  }

  if (action.status !== 'pending') {
    const err = new Error(`Delayed action cannot be cancelled in status '${action.status}'`);
    err.status = 409;
    err.code = 'action_not_cancellable';
    throw err;
  }

  const now = new Date();

  // Enforce expires_at during cancellation (C-03)
  if (action.expires_at && now.getTime() >= new Date(action.expires_at).getTime()) {
    await DelayedAction.update(
      { status: 'expired', updated_at: now },
      { where: { id: actionId, status: 'pending' } }
    );
    await cleanupTerminalActionState(action, {
      action_status: 'expired',
      expired_at: now.toISOString()
    });
    eventBus.safeEmit('cooling_off:expired', { action_id: actionId });

    const err = new Error('Delayed action has expired and can no longer be cancelled');
    err.status = 410;
    err.code = 'action_expired';
    throw err;
  }

  // Verify cancellation token in constant time
  const providedHash = crypto
    .createHash('sha256')
    .update(cancellationToken.trim())
    .digest('hex');

  const matches = constantTimeHashEqual(providedHash, action.cancellation_token_hash);
  if (!matches) {
    const err = new Error('Invalid cancellation token');
    err.status = 403;
    err.code = 'invalid_cancellation_token';
    throw err;
  }

  // Atomic state transition from 'pending' to 'cancelled' while still un-expired
  const [affectedRows] = await DelayedAction.update(
    {
      status: 'cancelled',
      cancelled_at: now,
      cancelled_by: userId,
      cancellation_reason: reason.trim().slice(0, 255),
      updated_at: now
    },
    {
      where: {
        id: actionId,
        status: 'pending',
        expires_at: { [Op.gt]: now }
      }
    }
  );

  if (affectedRows === 0) {
    const latest = await DelayedAction.findByPk(actionId);
    if (latest && (latest.status === 'expired' || (latest.expires_at && now.getTime() >= new Date(latest.expires_at).getTime()))) {
      await DelayedAction.update(
        { status: 'expired', updated_at: now },
        { where: { id: actionId, status: 'pending' } }
      );
      await cleanupTerminalActionState(action, {
        action_status: 'expired',
        expired_at: now.toISOString()
      });
      eventBus.safeEmit('cooling_off:expired', { action_id: actionId });
      const err = new Error('Delayed action has expired and can no longer be cancelled');
      err.status = 410;
      err.code = 'action_expired';
      throw err;
    }

    const err = new Error('Concurrent state modification conflict during cancellation');
    err.status = 409;
    err.code = 'concurrent_state_conflict';
    throw err;
  }

  await cleanupTerminalActionState(action, {
    action_status: 'cancelled',
    cancelled_at: now.toISOString()
  });

  const updatedAction = await DelayedAction.findByPk(actionId);
  const plainUpdated = toSafeActionObject(
    typeof updatedAction.get === 'function'
      ? updatedAction.get({ plain: true })
      : updatedAction
  );

  eventBus.safeEmit('cooling_off:cancelled', {
    action_id: plainUpdated.id,
    delayed_action: plainUpdated
  });

  return plainUpdated;
}

/**
 * Executes state mutation for a delayed action based on its approved action_type.
 * Rejects unknown action types and malformed payloads without falling back to no-op success.
 */
async function executeActionMutation(delayedAction) {
  const { action_type: actionType, user_id: userId, action_payload: payload = {} } = delayedAction;

  // Check custom registered executor first
  if (customActionExecutors.has(actionType)) {
    const customFn = customActionExecutors.get(actionType);
    return await customFn(userId, payload, delayedAction);
  }

  switch (actionType) {
    case 'password_change': {
      if (
        !payload ||
        typeof payload.new_password_hash !== 'string' ||
        !payload.new_password_hash.startsWith('$2')
      ) {
        throw new Error('Invalid or missing pre-hashed password digest for delayed password_change');
      }

      const user = await User.findByPk(userId);
      if (!user) {
        throw new Error('User not found during delayed password_change execution');
      }

      await user.update({ password_hash: payload.new_password_hash });

      const { terminatedCount } = await terminateAllUserSessions(
        userId,
        'password_change',
        { throwOnError: true }
      );

      return {
        action: 'password_change',
        executed: true,
        sessions_terminated: terminatedCount,
        reauthentication_required: true
      };
    }

    case 'phone_number_change': {
      if (
        !payload ||
        typeof payload.phone_number !== 'string' ||
        !PHONE_REGEX.test(payload.phone_number.trim())
      ) {
        throw new Error('Invalid phone_number payload for delayed phone_number_change');
      }
      const normalizedPhone = payload.phone_number.trim();
      await User.update({ phone_number: normalizedPhone }, { where: { id: userId } });
      return { action: 'phone_number_change', phone_number: normalizedPhone, executed: true };
    }

    case 'recovery_email_change': {
      if (
        !payload ||
        typeof payload.recovery_email !== 'string' ||
        payload.recovery_email.trim().length > 255 ||
        !EMAIL_REGEX.test(payload.recovery_email.trim())
      ) {
        throw new Error('Invalid recovery_email payload for delayed recovery_email_change');
      }
      const normalizedEmail = payload.recovery_email.trim().toLowerCase();
      const user = await User.findByPk(userId);
      if (!user) {
        throw new Error('User not found during delayed recovery_email_change execution');
      }
      if (user.email && user.email.trim().toLowerCase() === normalizedEmail) {
        throw new Error('recovery_email must be different from the primary registration email');
      }
      await user.update({ recovery_email: normalizedEmail });
      return { action: 'recovery_email_change', recovery_email: normalizedEmail, executed: true };
    }

    case 'mfa_change': {
      if (!payload || typeof payload.mfa_enabled !== 'boolean') {
        throw new Error('Invalid mfa_enabled payload for delayed mfa_change');
      }
      await User.update({ mfa_enabled: payload.mfa_enabled }, { where: { id: userId } });
      return { action: 'mfa_change', mfa_enabled: payload.mfa_enabled, executed: true };
    }

    case 'high_impact_action': {
      if (
        !payload ||
        typeof payload.operation !== 'string' ||
        payload.operation.trim().length === 0 ||
        payload.operation.trim().length > 128
      ) {
        throw new Error('Invalid operation payload for delayed high_impact_action');
      }
      return {
        action: 'high_impact_action',
        operation: payload.operation.trim(),
        target: typeof payload.target === 'string' ? payload.target.trim() : null,
        executed: true
      };
    }

    default: {
      throw new Error(`Unsupported delayed action_type '${actionType}'`);
    }
  }
}

/**
 * Reconciles stale 'executing' actions whose worker crashed or timed out.
 * Transitions stuck rows to 'failed' with an explicit failure_reason without
 * blindly re-running a potentially completed sensitive state mutation.
 *
 * @param {number} [staleTimeoutMs=DEFAULT_STALE_EXECUTING_TIMEOUT_MS]
 * @returns {Promise<number>} Number of stale rows transitioned to 'failed'
 */
async function reconcileStaleExecutingActions(staleTimeoutMs = DEFAULT_STALE_EXECUTING_TIMEOUT_MS) {
  const cutoff = new Date(Date.now() - staleTimeoutMs);
  const staleRows = await DelayedAction.findAll({
    where: {
      status: 'executing',
      updated_at: { [Op.lte]: cutoff }
    },
    order: [['updated_at', 'ASC']],
    limit: 50
  });

  let reconciledCount = 0;
  const now = new Date();

  for (const row of staleRows) {
    const [updated] = await DelayedAction.update(
      {
        status: 'failed',
        failure_reason: 'worker_execution_timeout_or_crash',
        updated_at: now
      },
      {
        where: {
          id: row.id,
          status: 'executing'
        }
      }
    );

    if (updated > 0) {
      reconciledCount++;
      await cleanupTerminalActionState(row, {
        action_status: 'failed_execution',
        failure_reason: 'worker_execution_timeout_or_crash'
      });
      eventBus.safeEmit('cooling_off:failed', {
        action_id: row.id,
        error: 'worker_execution_timeout_or_crash'
      });
    }
  }

  return reconciledCount;
}

/**
 * Executes a delayed action once its cooling-off period has elapsed.
 *
 * Performs strict Zero Trust pre-execution rechecks:
 * 1. User account lock & status
 * 2. Bound session ownership, active state, and expiry across MySQL and Redis
 * 3. Fresh risk evaluation (failing closed on Risk Engine unavailability)
 * 4. Active policy re-evaluation (handling block, delay, and reverify with scoped elevation)
 *
 * @param {object} params
 * @param {string} params.actionId
 * @param {string} [params.triggeredBy='system']
 * @param {boolean} [params.force=false] - bypass cooling-off timer for testing
 * @returns {Promise<object>}
 */
async function executeDelayedAction(params) {
  const { actionId, triggeredBy = 'system', force = false } = params;

  if (!actionId || typeof actionId !== 'string') {
    const err = new Error('actionId is required');
    err.status = 400;
    err.code = 'invalid_request';
    throw err;
  }

  const action = await DelayedAction.findByPk(actionId);
  if (!action) {
    const err = new Error('Delayed action not found');
    err.status = 404;
    err.code = 'delayed_action_not_found';
    throw err;
  }

  if (action.status !== 'pending') {
    const err = new Error(`Delayed action is not pending (status: '${action.status}')`);
    err.status = 409;
    err.code = 'action_not_pending';
    throw err;
  }

  const now = new Date();

  // Enforce cooling-off duration
  if (now.getTime() < new Date(action.execute_at).getTime() && !force) {
    const remainingSeconds = Math.ceil((new Date(action.execute_at).getTime() - now.getTime()) / 1000);
    const err = new Error(`Action is still cooling off. Available for execution in ${remainingSeconds} seconds.`);
    err.status = 409;
    err.code = 'action_still_cooling_off';
    err.remaining_seconds = remainingSeconds;
    throw err;
  }

  // Check expiration
  if (now.getTime() >= new Date(action.expires_at).getTime()) {
    await DelayedAction.update(
      { status: 'expired', updated_at: now },
      { where: { id: actionId, status: 'pending' } }
    );
    await cleanupTerminalActionState(action, {
      action_status: 'expired',
      expired_at: now.toISOString()
    });
    eventBus.safeEmit('cooling_off:expired', { action_id: actionId });
    const err = new Error('Delayed action has expired and cannot be executed');
    err.status = 410;
    err.code = 'delayed_action_expired';
    throw err;
  }

  // Distributed per-action lock via Redis (owner-bound token + atomic Lua release)
  let lockAcquired = false;
  const client = redisStorage.getRedisClient();
  const lockKey = `${REDIS_PREFIXES.COOLING_OFF_LOCK}${actionId}`;
  const lockOwner = `exec_${crypto.randomUUID()}`;
  try {
    const lockRes = await client.set(lockKey, lockOwner, 'PX', 10000, 'NX');
    if (lockRes === 'OK') {
      lockAcquired = true;
    } else {
      const err = new Error('Action is already being executed or claimed by another worker');
      err.status = 409;
      err.code = 'concurrent_execution_conflict';
      throw err;
    }
  } catch (lockErr) {
    if (lockErr.code === 'concurrent_execution_conflict') {
      throw lockErr;
    }
    // If Redis is unreachable, fall back to atomic MySQL status claim below
  }

  // Atomic state claim in MySQL from 'pending' to 'executing'
  const [claimed] = await DelayedAction.update(
    {
      status: 'executing',
      updated_at: now
    },
    {
      where: {
        id: actionId,
        status: 'pending'
      }
    }
  );

  if (claimed === 0) {
    if (lockAcquired) {
      await redisStorage.executeReleaseLock(lockKey, lockOwner).catch(() => {});
    }
    const err = new Error('Action is already being executed or claimed by another worker');
    err.status = 409;
    err.code = 'concurrent_execution_conflict';
    throw err;
  }

  const rejectExecution = async (reason) => {
    const rejectedAt = new Date();
    await action.update({
      status: 'rejected',
      failure_reason: reason,
      updated_at: rejectedAt
    });
    await cleanupTerminalActionState(action, {
      action_status: 'rejected',
      rejection_reason: reason
    });
    eventBus.safeEmit('cooling_off:rejected', {
      action_id: actionId,
      reason
    });
    return { status: 'rejected', reason };
  };

  try {
    // -------------------------------------------------------------
    // ZERO TRUST PRE-EXECUTION RECHECKS
    // -------------------------------------------------------------
    try {
      // 1. User status & protective account lock check
      const user = await User.findByPk(action.user_id);
      if (!user) {
        return await rejectExecution('user_not_found');
      }

      const isUserLocked =
        (user.locked_until && new Date(user.locked_until).getTime() > Date.now()) ||
        Boolean(await client.get(`${REDIS_PREFIXES.ACCOUNT_LOCK}${action.user_id}`).catch(() => null));

      if (isUserLocked) {
        return await rejectExecution('user_account_locked');
      }

      // 2. Bound session validity, ownership, and expiry check across MySQL and Redis (C-05)
      if (!action.session_id || typeof action.session_id !== 'string') {
        return await rejectExecution('session_invalidated_or_expired');
      }

      const dbSession = await Session.findByPk(action.session_id);
      const nowMs = Date.now();
      const isDbSessionValid = Boolean(
        dbSession &&
          dbSession.is_active === true &&
          String(dbSession.user_id) === String(action.user_id) &&
          (!dbSession.expires_at || new Date(dbSession.expires_at).getTime() > nowMs)
      );

      const redisSession = await validateActiveSession(action.session_id, { touch: false });
      const isRedisSessionValid = Boolean(
        redisSession &&
          redisSession.is_active === true &&
          String(redisSession.user_id) === String(action.user_id)
      );

      if (!isDbSessionValid || !isRedisSessionValid) {
        return await rejectExecution('session_invalidated_or_expired');
      }

      // 3. Fresh Risk Engine evaluation — fail closed if unavailable (C-06)
      let currentRisk = null;
      try {
        currentRisk = await riskEngineService.evaluateRisk({
          user_id: action.user_id,
          session_id: action.session_id,
          event_type: action.action_type,
          timestamp: new Date(),
          context: action.request_context || {}
        });
      } catch (_riskErr) {
        currentRisk = { status: 'unavailable', risk_tier: null };
      }

      if (
        !currentRisk ||
        currentRisk.status !== 'ok' ||
        !currentRisk.risk_tier ||
        RISK_TIER_ORDER[currentRisk.risk_tier] === undefined
      ) {
        return await rejectExecution('risk_engine_unavailable');
      }

      const currentRiskTier = currentRisk.risk_tier;
      const scheduledRank =
        RISK_TIER_ORDER[action.scheduled_at_risk_tier] !== undefined
          ? RISK_TIER_ORDER[action.scheduled_at_risk_tier]
          : 0;
      const currentRank = RISK_TIER_ORDER[currentRiskTier];

      // 4. Active policy & scoped elevation recheck (C-06)
      const activePolicy = policyLoader.getActivePolicy();
      const signalNames = Array.isArray(currentRisk.contributing_signals)
        ? currentRisk.contributing_signals.map((s) => s.signal)
        : [];

      const pdpResult = decide(
        {
          risk: {
            risk_tier: currentRiskTier,
            status: currentRisk.status,
            signal_names: signalNames
          },
          action: {
            event_type: action.action_type,
            provided_sensitivity: action.action_sensitivity
          }
        },
        activePolicy
      );

      if (pdpResult.decision === 'block') {
        return await rejectExecution('policy_recheck_blocked');
      }

      if (currentRank > scheduledRank) {
        return await rejectExecution('risk_tier_increased');
      }

      if (pdpResult.decision === 'delay') {
        return await rejectExecution('policy_recheck_delayed');
      }

      if (pdpResult.decision === 'reverify') {
        const requiredScope =
          ACTION_ELEVATION_SCOPE_MAP[action.action_type] || 'sensitive_action';

        const elevStatus = await checkElevation({
          sessionId: action.session_id,
          scope: requiredScope,
          parentSession: redisSession,
          currentRiskTier,
          recordUse: true,
          actionType: action.action_type,
          throwOnRedisError: true
        });

        if (!elevStatus || !elevStatus.elevated) {
          return await rejectExecution('step_up_elevation_required');
        }
      }
    } catch (precheckErr) {
      await action.update({
        status: 'failed',
        failure_reason: precheckErr.message || 'precheck_execution_error',
        updated_at: new Date()
      });
      await cleanupTerminalActionState(action, {
        action_status: 'failed_execution',
        failure_reason: precheckErr.message || 'precheck_execution_error'
      });
      eventBus.safeEmit('cooling_off:failed', {
        action_id: actionId,
        error: precheckErr.message
      });
      throw precheckErr;
    }

    // -------------------------------------------------------------
    // EXECUTE STATE MUTATION
    // -------------------------------------------------------------
    let mutationResult = null;
    try {
      mutationResult = await executeActionMutation(action);
    } catch (mutErr) {
      await action.update({
        status: 'failed',
        failure_reason: mutErr.message || 'mutation_execution_failed',
        updated_at: new Date()
      });
      await cleanupTerminalActionState(action, {
        action_status: 'failed_execution',
        failure_reason: mutErr.message || 'mutation_execution_failed'
      });
      eventBus.safeEmit('cooling_off:failed', {
        action_id: actionId,
        error: mutErr.message
      });
      throw mutErr;
    }

    const executedAt = new Date();
    await action.update({
      status: 'completed',
      executed_at: executedAt,
      execution_result: mutationResult,
      updated_at: executedAt
    });

    await cleanupTerminalActionState(action, {
      action_status: 'completed',
      delayed_execution_completed_at: executedAt.toISOString(),
      triggered_by: triggeredBy
    });

    const completedPlain = toSafeActionObject(
      typeof action.get === 'function' ? action.get({ plain: true }) : action
    );

    eventBus.safeEmit('cooling_off:executed', {
      delayed_action: completedPlain,
      result: mutationResult
    });

    return {
      status: 'completed',
      action_id: actionId,
      result: mutationResult
    };
  } finally {
    if (lockAcquired) {
      await redisStorage.executeReleaseLock(lockKey, lockOwner).catch(() => {});
    }
  }
}

/**
 * Pluggable PEP delay handler registered via setDelayHandler().
 * Enqueues a cancellable cooling-off action and returns a contract-compliant HTTP response.
 */
function coolingOffDelayHandler(req, res, decisionContext = {}) {
  const {
    decisionRecord,
    riskTier,
    explanation,
    delaySeconds = 300
  } = decisionContext;

  scheduleDelayedAction({
    req,
    decisionContext,
    actionType: decisionContext.actionType,
    delaySeconds
  })
    .then(({ delayedAction, cancellationToken }) => {
      const status = req.headers['x-prefer-status'] === '202' ? 202 : 403;
      return res.status(status).json({
        error: {
          code: 'action_delayed',
          message:
            (explanation && explanation.user_facing) ||
            'This action is temporarily delayed pending security confirmation.',
          decision_id: decisionRecord ? decisionRecord.id : null,
          decision: 'delay',
          risk_tier: riskTier || 'high',
          retry_after_seconds: delaySeconds,
          cooling_off_seconds: delaySeconds,
          pending_action_id: delayedAction.id,
          cancellation_token: cancellationToken,
          cancel_endpoint: `/api/v1/cooling-off/actions/${delayedAction.id}/cancel`,
          status_endpoint: `/api/v1/cooling-off/actions/${delayedAction.id}`,
          execute_at: delayedAction.execute_at,
          expires_at: delayedAction.expires_at,
          explanation:
            (explanation && explanation.user_facing) ||
            'This action is temporarily delayed pending security confirmation.'
        }
      });
    })
    .catch((err) => {
      if (err && err.status && err.code && err.status < 500) {
        return res.status(err.status).json({
          error: {
            code: err.code,
            message: err.message
          }
        });
      }
      console.error('[CoolingOffService] Failed to schedule delayed action; failing closed:', err.message);
      return res.status(503).json({
        error: {
          code: 'policy_enforcement_unavailable',
          message: 'Policy enforcement failed closed: unable to schedule delayed cooling-off action'
        }
      });
    });
}

module.exports = {
  scheduleDelayedAction,
  getDelayedAction,
  listDelayedActionsForUser,
  cancelDelayedAction,
  executeDelayedAction,
  reconcileStaleExecutingActions,
  coolingOffDelayHandler,
  registerActionExecutor,
  resetActionExecutors,
  executeActionMutation,
  sanitizePayload,
  sanitizePublicActionPayload,
  ALLOWED_DELAYED_ACTION_TYPES,
  DEFAULT_STALE_EXECUTING_TIMEOUT_MS
};

