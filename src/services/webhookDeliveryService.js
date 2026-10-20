'use strict';

const crypto = require('crypto');
const { Op, Sequelize } = require('sequelize');
const {
  WebhookEndpoint,
  WebhookDeliveryLog,
  SecurityEvent,
  RiskAssessment,
  PolicyDecision
} = require('../database/models');
const {
  buildEventRecordedPayload,
  buildAdminRiskPayload,
  buildAdminDecisionPayload
} = require('../realtime/payloads');
const {
  decryptWebhookSecret,
  signWebhookPayload
} = require('../utils/webhookCrypto');
const {
  WebhookDeliveryError,
  sendPinnedWebhookRequest,
  DEFAULT_REQUEST_TIMEOUT_MS,
  DEFAULT_MAX_RESPONSE_BYTES
} = require('../utils/webhookHttpClient');
const { REDIS_PREFIXES } = require('../config/sessionConfig');
const riskConfig = require('../config/riskConfig');
const redisStorage = require('../storage/redis');

const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_BASE_BACKOFF_MS = 2000; // 2 seconds
const DEFAULT_MAX_BACKOFF_MS = 300000; // 5 minutes
const DEFAULT_MAX_RETRY_AFTER_MS = 300000; // 5 minutes cap on Retry-After
const DEFAULT_LEASE_TIMEOUT_MS = 30000; // 30 seconds in-flight worker lease
const DEFAULT_BATCH_SIZE = 25;
const DEFAULT_CONCURRENCY_LIMIT = 5;
const DEFAULT_RECONCILE_LOOKBACK_MS = 15 * 60 * 1000; // 15 minutes crash-recovery lookback
const MAX_RECONCILE_LOOKBACK_MS = 24 * 60 * 60 * 1000; // 24 hours maximum lookback bound
const DEFAULT_RECONCILE_BATCH_SIZE = 50;

const RETRY_AFTER_SUPPORTED_STATUSES = Object.freeze(new Set([429, 503]));
const RETRYABLE_4XX_STATUSES = Object.freeze(new Set([408, 429]));

/**
 * Derives a deterministic, collision-resistant `WebhookDeliveryLog` primary key
 * bound to `(webhook_id, event_type, source_event_id)`.
 *
 * Format: `whdel_<32 hex chars>` (38 chars total, fits `STRING(64)`).
 *
 * @param {string} webhookId
 * @param {string} eventType
 * @param {string} sourceEventId
 * @returns {string}
 */
function deriveDeterministicDeliveryId(webhookId, eventType, sourceEventId) {
  if (
    typeof webhookId !== 'string' ||
    webhookId.trim().length === 0 ||
    typeof eventType !== 'string' ||
    eventType.trim().length === 0 ||
    typeof sourceEventId !== 'string' ||
    sourceEventId.trim().length === 0
  ) {
    throw new TypeError(
      'webhookId, eventType, and sourceEventId must be non-empty strings'
    );
  }

  const canonicalTuple = `actionguard:webhook_delivery:${webhookId.trim()}:${eventType.trim()}:${sourceEventId.trim()}`;
  const digest = crypto
    .createHash('sha256')
    .update(canonicalTuple, 'utf8')
    .digest('hex');

  return `whdel_${digest.slice(0, 32)}`;
}

/**
 * Checks whether a Sequelize/MySQL error represents an expected primary-key or
 * unique-constraint duplicate violation.
 *
 * @param {Error} err
 * @returns {boolean}
 */
function isUniqueConstraintError(err) {
  if (!err || typeof err !== 'object') {
    return false;
  }
  if (err.name === 'SequelizeUniqueConstraintError') {
    return true;
  }
  if (
    err.parent &&
    (err.parent.code === 'ER_DUP_ENTRY' || err.parent.errno === 1062)
  ) {
    return true;
  }
  return false;
}

/**
 * Parses an HTTP `Retry-After` header value (delta-seconds or HTTP-date) and
 * clamps it to `[0, maxRetryAfterMs]`.
 *
 * @param {string|null|undefined} retryAfterHeader
 * @param {object} [options={}]
 * @param {number} [options.nowMs=Date.now()]
 * @param {number} [options.maxRetryAfterMs=DEFAULT_MAX_RETRY_AFTER_MS]
 * @returns {number|null} Clamped delay in milliseconds, or `null` if absent/invalid
 */
function parseRetryAfterMs(retryAfterHeader, options = {}) {
  if (typeof retryAfterHeader !== 'string') {
    return null;
  }
  const trimmed = retryAfterHeader.trim();
  if (!trimmed) {
    return null;
  }

  const nowMs =
    typeof options.nowMs === 'number' && Number.isFinite(options.nowMs)
      ? options.nowMs
      : Date.now();
  const maxRetryAfterMs =
    typeof options.maxRetryAfterMs === 'number' &&
    Number.isFinite(options.maxRetryAfterMs) &&
    options.maxRetryAfterMs > 0
      ? options.maxRetryAfterMs
      : DEFAULT_MAX_RETRY_AFTER_MS;

  // 1. Non-negative integer seconds
  if (/^\d+$/.test(trimmed)) {
    const seconds = Number.parseInt(trimmed, 10);
    if (!Number.isSafeInteger(seconds) || seconds < 0) {
      return null;
    }
    return Math.min(seconds * 1000, maxRetryAfterMs);
  }

  // Reject negative or fractional numeric values so V8 Date.parse('-5') does not treat them as dates
  if (/^[+-]?\d+(\.\d+)?$/.test(trimmed)) {
    return null;
  }

  // 2. HTTP-date timestamp
  const parsedDateMs = Date.parse(trimmed);
  if (!Number.isFinite(parsedDateMs)) {
    return null;
  }

  const deltaMs = Math.max(0, parsedDateMs - nowMs);
  return Math.min(deltaMs, maxRetryAfterMs);
}

/**
 * Computes bounded exponential backoff with uniform +/-20% jitter and combines
 * it with a clamped `Retry-After` header when supported (`429` or `503`).
 *
 * @param {object} params
 * @param {number} params.attemptCount - 1-based started attempt count
 * @param {number|null} [params.httpStatus=null]
 * @param {string|null} [params.retryAfterHeader=null]
 * @param {number} [params.nowMs=Date.now()]
 * @param {number} [params.baseBackoffMs=DEFAULT_BASE_BACKOFF_MS]
 * @param {number} [params.maxBackoffMs=DEFAULT_MAX_BACKOFF_MS]
 * @param {number} [params.maxRetryAfterMs=DEFAULT_MAX_RETRY_AFTER_MS]
 * @param {Function} [params.randomFn=Math.random]
 * @returns {number} Delay in milliseconds
 */
function computeRetryDelayMs(params = {}) {
  const {
    attemptCount = 1,
    httpStatus = null,
    retryAfterHeader = null,
    nowMs = Date.now(),
    baseBackoffMs = DEFAULT_BASE_BACKOFF_MS,
    maxBackoffMs = DEFAULT_MAX_BACKOFF_MS,
    maxRetryAfterMs = DEFAULT_MAX_RETRY_AFTER_MS,
    randomFn = Math.random
  } = params;

  const exponent = Math.max(0, (Number(attemptCount) || 1) - 1);
  const rawExponentialMs = Math.min(
    maxBackoffMs,
    baseBackoffMs * Math.pow(2, exponent)
  );

  const randVal = Math.min(1, Math.max(0, Number(randomFn()) || 0));
  const jitterMultiplier = 0.8 + randVal * 0.4; // [0.8, 1.2]
  const jitteredBackoffMs = Math.min(
    maxBackoffMs,
    Math.max(50, Math.round(rawExponentialMs * jitterMultiplier))
  );

  if (
    httpStatus !== null &&
    RETRY_AFTER_SUPPORTED_STATUSES.has(Number(httpStatus)) &&
    retryAfterHeader
  ) {
    const retryAfterMs = parseRetryAfterMs(retryAfterHeader, {
      nowMs,
      maxRetryAfterMs
    });
    if (retryAfterMs !== null) {
      const upperCap = Math.max(maxBackoffMs, maxRetryAfterMs);
      return Math.min(upperCap, Math.max(jitteredBackoffMs, retryAfterMs));
    }
  }

  return jitteredBackoffMs;
}

/**
 * Classifies an HTTP status code from a webhook receiver into delivered,
 * retryable failure, or permanent failure.
 *
 * @param {number} httpStatus
 * @returns {{ outcome: 'delivered'|'retry'|'permanent_failure', errorCode: string|null }}
 */
function classifyHttpResponseStatus(httpStatus) {
  const code = Number(httpStatus);
  if (code >= 200 && code < 300) {
    return {
      outcome: 'delivered',
      errorCode: null
    };
  }
  if (code >= 300 && code < 400) {
    return {
      outcome: 'permanent_failure',
      errorCode: 'HTTP_REDIRECT_REJECTED'
    };
  }
  if (RETRYABLE_4XX_STATUSES.has(code)) {
    return {
      outcome: 'retry',
      errorCode: `HTTP_${code}`
    };
  }
  if (code >= 400 && code < 500) {
    return {
      outcome: 'permanent_failure',
      errorCode: `HTTP_${code}`
    };
  }
  if (code >= 500 && code < 600) {
    return {
      outcome: 'retry',
      errorCode: `HTTP_${code}`
    };
  }
  return {
    outcome: 'permanent_failure',
    errorCode: 'HTTP_UNKNOWN_STATUS'
  };
}

/**
 * Reconstructs the sanitized webhook payload envelope for a delivery log
 * by querying the authoritative source record (`SecurityEvent` + `RiskAssessment`
 * for `event.processed`, or `PolicyDecision` for `decision.recorded`).
 *
 * Never invents missing records or substitutes another source ID.
 *
 * @param {object} deliveryLog
 * @returns {Promise<object>} Canonical webhook envelope object
 * @throws {WebhookDeliveryError} `SOURCE_EVENT_NOT_FOUND` or `UNSUPPORTED_WEBHOOK_EVENT`
 */
async function buildWebhookEventEnvelope(deliveryLog) {
  if (!deliveryLog || typeof deliveryLog !== 'object') {
    throw new WebhookDeliveryError(
      'SOURCE_EVENT_NOT_FOUND',
      'Delivery log record is required to build webhook envelope',
      { retryable: false }
    );
  }

  const {
    id: deliveryId,
    webhook_id: webhookId,
    event_type: webhookEventType,
    source_event_id: sourceEventId,
    created_at: createdAt
  } = deliveryLog;

  if (
    typeof sourceEventId !== 'string' ||
    sourceEventId.trim().length === 0
  ) {
    throw new WebhookDeliveryError(
      'SOURCE_EVENT_NOT_FOUND',
      'Delivery log is missing a valid source_event_id',
      { retryable: false }
    );
  }

  const trimmedSourceId = sourceEventId.trim();
  let sanitizedData = null;

  if (webhookEventType === 'event.processed') {
    const eventRecord = await SecurityEvent.findByPk(trimmedSourceId);
    if (!eventRecord) {
      throw new WebhookDeliveryError(
        'SOURCE_EVENT_NOT_FOUND',
        'Authoritative SecurityEvent record does not exist',
        { retryable: false }
      );
    }

    const assessmentRecord = await RiskAssessment.findOne({
      where: { event_id: eventRecord.event_id },
      order: [['evaluated_at', 'DESC']]
    });

    const plainEvent =
      typeof eventRecord.get === 'function'
        ? eventRecord.get({ plain: true })
        : { ...eventRecord };
    const plainAssessment = assessmentRecord
      ? typeof assessmentRecord.get === 'function'
        ? assessmentRecord.get({ plain: true })
        : { ...assessmentRecord }
      : null;

    const eventProjection = buildEventRecordedPayload(
      plainEvent,
      plainAssessment,
      { includeUserId: true }
    );
    const riskProjection = plainAssessment
      ? buildAdminRiskPayload(plainEvent, plainAssessment)
      : null;

    sanitizedData = {
      ...eventProjection,
      risk: riskProjection
        ? {
            risk_score: riskProjection.risk_score,
            risk_tier: riskProjection.risk_tier,
            contributing_signals: riskProjection.contributing_signals,
            evaluated_at: riskProjection.evaluated_at,
            explanation: riskProjection.explanation
          }
        : null
    };
  } else if (webhookEventType === 'decision.recorded') {
    const decisionRecord = await PolicyDecision.findByPk(trimmedSourceId);
    if (!decisionRecord) {
      throw new WebhookDeliveryError(
        'SOURCE_EVENT_NOT_FOUND',
        'Authoritative PolicyDecision record does not exist',
        { retryable: false }
      );
    }

    const plainDecision =
      typeof decisionRecord.get === 'function'
        ? decisionRecord.get({ plain: true })
        : { ...decisionRecord };

    sanitizedData = buildAdminDecisionPayload(plainDecision);
  } else {
    throw new WebhookDeliveryError(
      'UNSUPPORTED_WEBHOOK_EVENT',
      'Unsupported webhook event_type',
      { retryable: false }
    );
  }

  const createdIso =
    createdAt instanceof Date
      ? createdAt.toISOString()
      : createdAt
      ? new Date(createdAt).toISOString()
      : new Date().toISOString();

  return {
    id: deliveryId,
    webhook_id: webhookId,
    event_type: webhookEventType,
    source_event_id: trimmedSourceId,
    created_at: createdIso,
    data: sanitizedData
  };
}

/**
 * Enqueues pending delivery jobs for all active webhook endpoints subscribed
 * to `eventType`.
 *
 * Security & reliability invariants:
 * - Only active (`is_active: true`) endpoints subscribed to `eventType` receive jobs.
 * - Uses deterministic delivery IDs (`whdel_<sha256_32>`) and unique DB constraints
 *   to prevent duplicate job creation.
 * - New jobs start with `attempt_count: 0` (zero HTTP attempts started).
 * - Treats only `SequelizeUniqueConstraintError` / `ER_DUP_ENTRY` as an idempotent
 *   duplicate; rethrows any unexpected database failure.
 *
 * @param {object} params
 * @param {'event.processed'|'decision.recorded'} params.eventType
 * @param {string} params.sourceEventId
 * @param {Date|string|number|null} [params.occurredAt=null] - Optional timestamp of the source event/decision; endpoints created after this timestamp are skipped
 * @param {Date} [params.now=new Date()]
 * @returns {Promise<{ enqueued: Array<object>, duplicates: Array<object> }>}
 */
async function enqueueWebhooksForEvent(params = {}) {
  const {
    eventType,
    sourceEventId,
    occurredAt = null,
    now = new Date()
  } = params;

  if (
    typeof eventType !== 'string' ||
    !WebhookEndpoint.SUPPORTED_WEBHOOK_EVENTS.includes(eventType)
  ) {
    throw new Error(
      `Unsupported webhook eventType '${eventType}'. Must be one of: ${WebhookEndpoint.SUPPORTED_WEBHOOK_EVENTS.join(', ')}`
    );
  }

  if (typeof sourceEventId !== 'string' || sourceEventId.trim().length === 0) {
    throw new Error('sourceEventId must be a non-empty string');
  }

  const trimmedSourceId = sourceEventId.trim();
  const effectiveNow = now instanceof Date ? now : new Date(now);
  const occurredAtMs =
    occurredAt !== null && occurredAt !== undefined
      ? new Date(occurredAt).getTime()
      : null;

  const activeEndpoints = await WebhookEndpoint.findAll({
    where: { is_active: true },
    attributes: ['id', 'subscribed_events', 'is_active', 'created_at'],
    order: [
      ['created_at', 'ASC'],
      ['id', 'ASC']
    ]
  });

  const matchingEndpoints = activeEndpoints.filter((ep) => {
    if (
      ep.is_active !== true ||
      !Array.isArray(ep.subscribed_events) ||
      !ep.subscribed_events.includes(eventType)
    ) {
      return false;
    }

    if (
      occurredAtMs !== null &&
      Number.isFinite(occurredAtMs) &&
      ep.created_at
    ) {
      const epCreatedMs = new Date(ep.created_at).getTime();
      if (Number.isFinite(epCreatedMs) && epCreatedMs > occurredAtMs) {
        return false;
      }
    }

    return true;
  });

  const enqueued = [];
  const duplicates = [];

  for (const endpoint of matchingEndpoints) {
    const deliveryId = deriveDeterministicDeliveryId(
      endpoint.id,
      eventType,
      trimmedSourceId
    );

    try {
      const created = await WebhookDeliveryLog.create({
        id: deliveryId,
        webhook_id: endpoint.id,
        event_type: eventType,
        source_event_id: trimmedSourceId,
        status: 'pending',
        attempt_count: 0,
        http_status: null,
        error_code: null,
        next_attempt_at: effectiveNow,
        last_attempt_at: null,
        locked_at: null,
        locked_by: null,
        delivered_at: null,
        created_at: effectiveNow,
        updated_at: effectiveNow
      });
      enqueued.push(created);
    } catch (err) {
      if (isUniqueConstraintError(err)) {
        const existing = await WebhookDeliveryLog.findByPk(deliveryId);
        if (existing) {
          duplicates.push(existing);
        }
        continue;
      }
      throw err;
    }
  }

  return {
    enqueued,
    duplicates
  };
}

/**
 * Atomically claims a pending, due, and unlocked (or lease-expired) delivery job.
 *
 * Uses a conditional MySQL `UPDATE` as the authoritative claim operation, with
 * an optional Redis per-delivery lock for fast coordination.
 * Does NOT increment `attempt_count` on claim; `attempt_count` is incremented
 * atomically by `beginDeliveryAttempt` when an HTTP attempt actually begins.
 *
 * @param {string} deliveryId
 * @param {object} [options={}]
 * @param {string} [options.ownerToken]
 * @param {Date} [options.now=new Date()]
 * @param {number} [options.leaseTimeoutMs=DEFAULT_LEASE_TIMEOUT_MS]
 * @returns {Promise<{
 *   claimed: boolean,
 *   reason?: string,
 *   ownerToken: string|null,
 *   delivery: object|null,
 *   releaseRedisLock: () => Promise<void>
 * }>}
 */
async function claimDeliveryJob(deliveryId, options = {}) {
  const noopRelease = async () => {};

  if (typeof deliveryId !== 'string' || deliveryId.trim().length === 0) {
    return {
      claimed: false,
      reason: 'invalid_id',
      ownerToken: null,
      delivery: null,
      releaseRedisLock: noopRelease
    };
  }

  const trimmedId = deliveryId.trim();
  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  const leaseTimeoutMs =
    typeof options.leaseTimeoutMs === 'number' && options.leaseTimeoutMs > 0
      ? options.leaseTimeoutMs
      : DEFAULT_LEASE_TIMEOUT_MS;
  const maxAttempts =
    typeof options.maxAttempts === 'number' && options.maxAttempts >= 1
      ? Math.floor(options.maxAttempts)
      : DEFAULT_MAX_ATTEMPTS;
  const expiredCutoff = new Date(now.getTime() - leaseTimeoutMs);
  const ownerToken =
    typeof options.ownerToken === 'string' && options.ownerToken.trim().length > 0
      ? options.ownerToken.trim()
      : `whwrk_${crypto.randomUUID()}`;

  const redisKey = `${REDIS_PREFIXES.WEBHOOK_DELIVERY_LOCK}${trimmedId}`;
  let redisLockAcquired = false;

  try {
    const redisClient = redisStorage.getRedisClient();
    const lockRes = await redisClient.set(
      redisKey,
      ownerToken,
      'PX',
      leaseTimeoutMs,
      'NX'
    );
    if (lockRes === 'OK') {
      redisLockAcquired = true;
    } else {
      return {
        claimed: false,
        reason: 'redis_lock_held',
        ownerToken: null,
        delivery: null,
        releaseRedisLock: noopRelease
      };
    }
  } catch {
    // Proceed to authoritative MySQL conditional UPDATE if Redis is unavailable
  }

  const releaseRedisLock = async () => {
    if (redisLockAcquired) {
      redisLockAcquired = false;
      try {
        await redisStorage.executeReleaseLock(redisKey, ownerToken);
      } catch {}
    }
  };

  try {
    const [claimedRows] = await WebhookDeliveryLog.update(
      {
        locked_at: now,
        locked_by: ownerToken,
        updated_at: now
      },
      {
        where: {
          id: trimmedId,
          status: 'pending',
          attempt_count: { [Op.lt]: maxAttempts },
          [Op.and]: [
            {
              [Op.or]: [
                { next_attempt_at: null },
                { next_attempt_at: { [Op.lte]: now } }
              ]
            },
            {
              [Op.or]: [
                { locked_at: null },
                { locked_at: { [Op.lte]: expiredCutoff } }
              ]
            }
          ]
        }
      }
    );

    if (claimedRows === 0) {
      await releaseRedisLock();
      return {
        claimed: false,
        reason: 'not_claimable',
        ownerToken: null,
        delivery: null,
        releaseRedisLock: noopRelease
      };
    }

    const delivery = await WebhookDeliveryLog.findByPk(trimmedId);
    return {
      claimed: true,
      ownerToken,
      delivery,
      releaseRedisLock
    };
  } catch (err) {
    await releaseRedisLock();
    throw err;
  }
}

/**
 * Atomically increments `attempt_count` and sets `last_attempt_at` at the exact
 * moment a worker begins an outbound HTTP delivery attempt.
 *
 * Guarded by `locked_by: ownerToken`, `status: 'pending'`, and `attempt_count < maxAttempts`
 * so a stale worker or an exhausted job can never start an unauthorized attempt.
 *
 * @param {string} deliveryId
 * @param {string} ownerToken
 * @param {object} [options={}]
 * @param {Date} [options.now=new Date()]
 * @param {number} [options.maxAttempts=DEFAULT_MAX_ATTEMPTS]
 * @returns {Promise<{ started: boolean, attemptCount: number|null }>}
 */
async function beginDeliveryAttempt(deliveryId, ownerToken, options = {}) {
  if (
    typeof deliveryId !== 'string' ||
    !deliveryId.trim() ||
    typeof ownerToken !== 'string' ||
    !ownerToken.trim()
  ) {
    return { started: false, attemptCount: null };
  }

  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  const maxAttempts =
    typeof options.maxAttempts === 'number' && options.maxAttempts >= 1
      ? Math.floor(options.maxAttempts)
      : DEFAULT_MAX_ATTEMPTS;

  const [updatedCount] = await WebhookDeliveryLog.update(
    {
      attempt_count: Sequelize.literal('attempt_count + 1'),
      last_attempt_at: now,
      updated_at: now
    },
    {
      where: {
        id: deliveryId.trim(),
        status: 'pending',
        locked_by: ownerToken.trim(),
        attempt_count: { [Op.lt]: maxAttempts }
      }
    }
  );

  if (updatedCount === 0) {
    return { started: false, attemptCount: null };
  }

  const updated = await WebhookDeliveryLog.findByPk(deliveryId.trim(), {
    attributes: ['id', 'attempt_count']
  });

  return {
    started: true,
    attemptCount: updated ? Number(updated.attempt_count) : null
  };
}

/**
 * Transitions a claimed delivery to terminal `delivered` status, guarded by `locked_by: ownerToken`.
 *
 * @param {string} deliveryId
 * @param {string} ownerToken
 * @param {object} params
 * @param {number} params.httpStatus
 * @param {Date} [params.now=new Date()]
 * @returns {Promise<boolean>} `true` if updated, `false` if owner lease was lost
 */
async function completeDeliverySuccess(deliveryId, ownerToken, params = {}) {
  const now = params.now instanceof Date ? params.now : new Date(params.now || Date.now());
  const [updated] = await WebhookDeliveryLog.update(
    {
      status: 'delivered',
      http_status: params.httpStatus,
      error_code: null,
      delivered_at: now,
      next_attempt_at: null,
      locked_at: null,
      locked_by: null,
      updated_at: now
    },
    {
      where: {
        id: deliveryId,
        status: 'pending',
        locked_by: ownerToken
      }
    }
  );
  return updated > 0;
}

/**
 * Transitions a claimed delivery to terminal `failed` status, guarded by `locked_by: ownerToken`.
 *
 * @param {string} deliveryId
 * @param {string} ownerToken
 * @param {object} params
 * @param {string} params.errorCode
 * @param {number|null} [params.httpStatus=null]
 * @param {Date} [params.now=new Date()]
 * @returns {Promise<boolean>} `true` if updated, `false` if owner lease was lost
 */
async function failDeliveryPermanently(deliveryId, ownerToken, params = {}) {
  const now = params.now instanceof Date ? params.now : new Date(params.now || Date.now());
  const [updated] = await WebhookDeliveryLog.update(
    {
      status: 'failed',
      http_status: params.httpStatus !== undefined ? params.httpStatus : null,
      error_code: String(params.errorCode || 'DELIVERY_FAILED').slice(0, 128),
      delivered_at: null,
      next_attempt_at: null,
      locked_at: null,
      locked_by: null,
      updated_at: now
    },
    {
      where: {
        id: deliveryId,
        status: 'pending',
        locked_by: ownerToken
      }
    }
  );
  return updated > 0;
}

/**
 * Schedules a retry for a claimed delivery (or marks it `failed` if `attemptCount >= maxAttempts`),
 * guarded by `locked_by: ownerToken`.
 *
 * @param {string} deliveryId
 * @param {string} ownerToken
 * @param {object} params
 * @param {number} params.attemptCount
 * @param {number} [params.maxAttempts=DEFAULT_MAX_ATTEMPTS]
 * @param {string} params.errorCode
 * @param {number|null} [params.httpStatus=null]
 * @param {string|null} [params.retryAfterHeader=null]
 * @param {Date} [params.now=new Date()]
 * @param {number} [params.baseBackoffMs=DEFAULT_BASE_BACKOFF_MS]
 * @param {number} [params.maxBackoffMs=DEFAULT_MAX_BACKOFF_MS]
 * @param {number} [params.maxRetryAfterMs=DEFAULT_MAX_RETRY_AFTER_MS]
 * @param {Function} [params.randomFn=Math.random]
 * @returns {Promise<{ updated: boolean, status: 'pending'|'failed'|'stale_owner', nextAttemptAt: Date|null, delayMs: number|null }>}
 */
async function scheduleDeliveryRetry(deliveryId, ownerToken, params = {}) {
  const {
    attemptCount,
    maxAttempts = DEFAULT_MAX_ATTEMPTS,
    errorCode = 'DELIVERY_RETRY_SCHEDULED',
    httpStatus = null,
    retryAfterHeader = null,
    now = new Date(),
    baseBackoffMs = DEFAULT_BASE_BACKOFF_MS,
    maxBackoffMs = DEFAULT_MAX_BACKOFF_MS,
    maxRetryAfterMs = DEFAULT_MAX_RETRY_AFTER_MS,
    randomFn = Math.random
  } = params;

  const effectiveNow = now instanceof Date ? now : new Date(now);

  if (Number(attemptCount) >= Number(maxAttempts)) {
    const failedOk = await failDeliveryPermanently(deliveryId, ownerToken, {
      errorCode,
      httpStatus,
      now: effectiveNow
    });
    return {
      updated: failedOk,
      status: failedOk ? 'failed' : 'stale_owner',
      nextAttemptAt: null,
      delayMs: null
    };
  }

  const delayMs = computeRetryDelayMs({
    attemptCount,
    httpStatus,
    retryAfterHeader,
    nowMs: effectiveNow.getTime(),
    baseBackoffMs,
    maxBackoffMs,
    maxRetryAfterMs,
    randomFn
  });

  const nextAttemptAt = new Date(effectiveNow.getTime() + delayMs);

  const [updated] = await WebhookDeliveryLog.update(
    {
      status: 'pending',
      http_status: httpStatus !== undefined ? httpStatus : null,
      error_code: String(errorCode).slice(0, 128),
      next_attempt_at: nextAttemptAt,
      locked_at: null,
      locked_by: null,
      updated_at: effectiveNow
    },
    {
      where: {
        id: deliveryId,
        status: 'pending',
        locked_by: ownerToken
      }
    }
  );

  return {
    updated: updated > 0,
    status: updated > 0 ? 'pending' : 'stale_owner',
    nextAttemptAt: updated > 0 ? nextAttemptAt : null,
    delayMs: updated > 0 ? delayMs : null
  };
}

/**
 * Executes a single webhook delivery lifecycle:
 * 1. Atomically claims the job (or verifies the caller's existing claim `ownerToken`).
 * 2. Verifies the endpoint exists and is active, and reconstructs the authoritative
 *    sanitized payload envelope before starting an HTTP attempt.
 * 3. Atomically increments `attempt_count` (`beginDeliveryAttempt`) guarded by
 *    `locked_by: ownerToken` and `attempt_count < maxAttempts`.
 * 4. Rechecks endpoint active state, decrypts `signing_secret` in-memory, signs
 *    the exact UTF-8 payload buffer with HMAC-SHA256, and transmits via the
 *    SSRF-pinned HTTP client.
 * 5. Updates the delivery row (`delivered`, scheduled `pending` retry, or terminal `failed`)
 *    strictly guarded by `locked_by: ownerToken`.
 *
 * @param {string} deliveryId
 * @param {object} [options={}]
 * @param {string} [options.ownerToken]
 * @param {boolean} [options.alreadyClaimed=false]
 * @param {Date} [options.now]
 * @param {number} [options.leaseTimeoutMs=DEFAULT_LEASE_TIMEOUT_MS]
 * @param {number} [options.maxAttempts=DEFAULT_MAX_ATTEMPTS]
 * @param {number} [options.baseBackoffMs=DEFAULT_BASE_BACKOFF_MS]
 * @param {number} [options.maxBackoffMs=DEFAULT_MAX_BACKOFF_MS]
 * @param {number} [options.maxRetryAfterMs=DEFAULT_MAX_RETRY_AFTER_MS]
 * @param {number} [options.timeoutMs=DEFAULT_REQUEST_TIMEOUT_MS]
 * @param {number} [options.maxResponseBytes=DEFAULT_MAX_RESPONSE_BYTES]
 * @param {Function} [options.lookupFn]
 * @param {Function} [options.sendRequestFn=sendPinnedWebhookRequest]
 * @param {Function} [options.randomFn=Math.random]
 * @param {NodeJS.ProcessEnv} [options.env=process.env]
 * @param {boolean} [options.allowLocalTargets=false]
 * @param {boolean} [options.allowInsecureHttp=false]
 * @param {object} [options.tlsOptions]
 * @returns {Promise<object>} Execution summary
 */
async function executeWebhookDelivery(deliveryId, options = {}) {
  const env = options.env || process.env;
  const maxAttempts =
    typeof options.maxAttempts === 'number' && options.maxAttempts >= 1
      ? Math.floor(options.maxAttempts)
      : DEFAULT_MAX_ATTEMPTS;
  const sendRequestFn =
    typeof options.sendRequestFn === 'function'
      ? options.sendRequestFn
      : sendPinnedWebhookRequest;

  let ownerToken = options.ownerToken || null;
  let delivery = null;
  let releaseRedisLock = async () => {};

  if (options.alreadyClaimed === true && ownerToken) {
    delivery = await WebhookDeliveryLog.findByPk(deliveryId);
    if (
      !delivery ||
      delivery.status !== 'pending' ||
      delivery.locked_by !== ownerToken
    ) {
      return {
        executed: false,
        reason: 'stale_owner_or_not_pending',
        status: delivery ? delivery.status : null
      };
    }
  } else {
    const claimRes = await claimDeliveryJob(deliveryId, {
      ownerToken: options.ownerToken,
      now: options.now,
      leaseTimeoutMs: options.leaseTimeoutMs,
      maxAttempts
    });
    if (!claimRes.claimed || !claimRes.delivery) {
      return {
        executed: false,
        reason: claimRes.reason || 'not_claimable',
        status: null
      };
    }
    ownerToken = claimRes.ownerToken;
    delivery = claimRes.delivery;
    releaseRedisLock = claimRes.releaseRedisLock;
  }

  try {
    const checkNow =
      options.now instanceof Date ? options.now : new Date(options.now || Date.now());

    // 1. Enforce attempt budget before starting an attempt
    if (Number(delivery.attempt_count) >= maxAttempts) {
      const updated = await failDeliveryPermanently(delivery.id, ownerToken, {
        errorCode: 'MAX_ATTEMPTS_EXHAUSTED',
        httpStatus: delivery.http_status,
        now: checkNow
      });
      return {
        executed: false,
        status: updated ? 'failed' : 'stale_owner',
        error_code: 'MAX_ATTEMPTS_EXHAUSTED',
        attempt_count: Number(delivery.attempt_count)
      };
    }

    // 2. Verify parent endpoint exists and is active BEFORE decrypting secret or starting attempt
    const endpoint = await WebhookEndpoint.findByPk(delivery.webhook_id);
    if (!endpoint) {
      const updated = await failDeliveryPermanently(delivery.id, ownerToken, {
        errorCode: 'ENDPOINT_NOT_FOUND',
        httpStatus: null,
        now: checkNow
      }).catch(() => false);
      if (!updated) {
        const stillExists = await WebhookDeliveryLog.findByPk(delivery.id, {
          attributes: ['id']
        }).catch(() => null);
        return {
          executed: false,
          status: stillExists ? 'stale_owner' : 'deleted',
          error_code: 'ENDPOINT_NOT_FOUND',
          attempt_count: Number(delivery.attempt_count)
        };
      }
      return {
        executed: false,
        status: 'failed',
        error_code: 'ENDPOINT_NOT_FOUND',
        attempt_count: Number(delivery.attempt_count)
      };
    }

    if (!endpoint.is_active) {
      const updated = await failDeliveryPermanently(delivery.id, ownerToken, {
        errorCode: 'ENDPOINT_INACTIVE',
        httpStatus: null,
        now: checkNow
      });
      return {
        executed: false,
        status: updated ? 'failed' : 'stale_owner',
        error_code: 'ENDPOINT_INACTIVE',
        attempt_count: Number(delivery.attempt_count)
      };
    }

    // 3. Reconstruct authoritative sanitized event/decision payload envelope
    let envelope;
    try {
      envelope = await buildWebhookEventEnvelope(delivery);
    } catch (envErr) {
      const errCode =
        (envErr && envErr.code) || 'SOURCE_EVENT_NOT_FOUND';
      const updated = await failDeliveryPermanently(delivery.id, ownerToken, {
        errorCode: errCode,
        httpStatus: null,
        now: checkNow
      });
      return {
        executed: false,
        status: updated ? 'failed' : 'stale_owner',
        error_code: errCode,
        attempt_count: Number(delivery.attempt_count)
      };
    }

    // 4. Recheck endpoint exists and remains active immediately before starting the attempt and decrypting secret
    const freshEndpoint = await WebhookEndpoint.findByPk(delivery.webhook_id);
    if (!freshEndpoint) {
      const updated = await failDeliveryPermanently(delivery.id, ownerToken, {
        errorCode: 'ENDPOINT_NOT_FOUND',
        httpStatus: null,
        now: checkNow
      }).catch(() => false);
      if (!updated) {
        const stillExists = await WebhookDeliveryLog.findByPk(delivery.id, {
          attributes: ['id']
        }).catch(() => null);
        return {
          executed: false,
          status: stillExists ? 'stale_owner' : 'deleted',
          error_code: 'ENDPOINT_NOT_FOUND',
          attempt_count: Number(delivery.attempt_count)
        };
      }
      return {
        executed: false,
        status: 'failed',
        error_code: 'ENDPOINT_NOT_FOUND',
        attempt_count: Number(delivery.attempt_count)
      };
    }

    if (!freshEndpoint.is_active) {
      const updated = await failDeliveryPermanently(delivery.id, ownerToken, {
        errorCode: 'ENDPOINT_INACTIVE',
        httpStatus: null,
        now: checkNow
      });
      return {
        executed: false,
        status: updated ? 'failed' : 'stale_owner',
        error_code: 'ENDPOINT_INACTIVE',
        attempt_count: Number(delivery.attempt_count)
      };
    }

    // 5. Atomically increment attempt_count as the delivery attempt begins
    const attemptNow =
      options.now instanceof Date ? options.now : new Date(options.now || Date.now());
    const attemptStart = await beginDeliveryAttempt(delivery.id, ownerToken, {
      now: attemptNow,
      maxAttempts
    });

    if (!attemptStart.started) {
      return {
        executed: false,
        reason: 'stale_owner_or_budget_exhausted',
        status: 'stale_owner',
        attempt_count: Number(delivery.attempt_count)
      };
    }

    const currentAttemptCount = attemptStart.attemptCount;

    // 6. Decrypt endpoint signing secret in-memory only for this active delivery attempt
    let plaintextSecret;
    try {
      plaintextSecret = decryptWebhookSecret(freshEndpoint, env);
    } catch (cryptoErr) {
      const isKeyUnconfigured = Boolean(
        cryptoErr && cryptoErr.reason === 'key_unconfigured'
      );
      if (isKeyUnconfigured) {
        const retryRes = await scheduleDeliveryRetry(delivery.id, ownerToken, {
          attemptCount: currentAttemptCount,
          maxAttempts,
          errorCode: 'SECRET_DECRYPTION_UNAVAILABLE',
          httpStatus: null,
          now: attemptNow,
          baseBackoffMs: options.baseBackoffMs,
          maxBackoffMs: options.maxBackoffMs,
          maxRetryAfterMs: options.maxRetryAfterMs,
          randomFn: options.randomFn
        });
        return {
          executed: true,
          status: retryRes.status,
          error_code: 'SECRET_DECRYPTION_UNAVAILABLE',
          attempt_count: currentAttemptCount,
          next_attempt_at: retryRes.nextAttemptAt
        };
      }

      const failedOk = await failDeliveryPermanently(delivery.id, ownerToken, {
        errorCode: 'SECRET_DECRYPTION_FAILED',
        httpStatus: null,
        now: attemptNow
      });
      return {
        executed: true,
        status: failedOk ? 'failed' : 'stale_owner',
        error_code: 'SECRET_DECRYPTION_FAILED',
        attempt_count: currentAttemptCount
      };
    }

    // 7. Serialize envelope once to a UTF-8 Buffer and sign that exact buffer
    const rawBodyBuffer = Buffer.from(JSON.stringify(envelope), 'utf8');
    const timestampSeconds = Math.max(1, Math.floor(attemptNow.getTime() / 1000));
    const signatureHeader = signWebhookPayload(
      rawBodyBuffer,
      plaintextSecret,
      timestampSeconds
    );
    // Clear local secret reference immediately after HMAC computation
    plaintextSecret = null;

    const requestHeaders = {
      'X-ActionGuard-Webhook-Id': delivery.id,
      'X-ActionGuard-Webhook-Event': delivery.event_type,
      'X-ActionGuard-Webhook-Timestamp': String(timestampSeconds),
      'X-ActionGuard-Webhook-Signature': signatureHeader
    };

    // 8. Execute SSRF-pinned HTTP delivery
    let httpResult;
    try {
      httpResult = await sendRequestFn(freshEndpoint.url, {
        headers: requestHeaders,
        bodyBuffer: rawBodyBuffer,
        timeoutMs: options.timeoutMs,
        maxResponseBytes: options.maxResponseBytes,
        lookupFn: options.lookupFn,
        env,
        allowLocalTargets: options.allowLocalTargets,
        allowInsecureHttp: options.allowInsecureHttp,
        tlsOptions: options.tlsOptions
      });
    } catch (netErr) {
      const finishNow =
        options.now instanceof Date ? options.now : new Date(Date.now());
      const errCode =
        netErr instanceof WebhookDeliveryError && netErr.code
          ? netErr.code
          : 'NETWORK_ERROR';
      const isRetryable =
        netErr instanceof WebhookDeliveryError ? netErr.retryable : true;
      const errHttpStatus =
        netErr instanceof WebhookDeliveryError ? netErr.httpStatus : null;

      if (isRetryable) {
        const retryRes = await scheduleDeliveryRetry(delivery.id, ownerToken, {
          attemptCount: currentAttemptCount,
          maxAttempts,
          errorCode: errCode,
          httpStatus: errHttpStatus,
          now: finishNow,
          baseBackoffMs: options.baseBackoffMs,
          maxBackoffMs: options.maxBackoffMs,
          maxRetryAfterMs: options.maxRetryAfterMs,
          randomFn: options.randomFn
        });
        return {
          executed: true,
          status: retryRes.status,
          error_code: errCode,
          http_status: errHttpStatus,
          attempt_count: currentAttemptCount,
          next_attempt_at: retryRes.nextAttemptAt
        };
      }

      const failedOk = await failDeliveryPermanently(delivery.id, ownerToken, {
        errorCode: errCode,
        httpStatus: errHttpStatus,
        now: finishNow
      });
      return {
        executed: true,
        status: failedOk ? 'failed' : 'stale_owner',
        error_code: errCode,
        http_status: errHttpStatus,
        attempt_count: currentAttemptCount
      };
    }

    // 9. Classify HTTP response status and update delivery record guarded by ownerToken
    const finishNow =
      options.now instanceof Date ? options.now : new Date(Date.now());
    const classification = classifyHttpResponseStatus(httpResult.httpStatus);

    if (classification.outcome === 'delivered') {
      const completedOk = await completeDeliverySuccess(
        delivery.id,
        ownerToken,
        {
          httpStatus: httpResult.httpStatus,
          now: finishNow
        }
      );
      return {
        executed: true,
        status: completedOk ? 'delivered' : 'stale_owner',
        http_status: httpResult.httpStatus,
        error_code: null,
        attempt_count: currentAttemptCount
      };
    }

    if (classification.outcome === 'retry') {
      const retryRes = await scheduleDeliveryRetry(delivery.id, ownerToken, {
        attemptCount: currentAttemptCount,
        maxAttempts,
        errorCode: classification.errorCode,
        httpStatus: httpResult.httpStatus,
        retryAfterHeader: httpResult.retryAfterHeader,
        now: finishNow,
        baseBackoffMs: options.baseBackoffMs,
        maxBackoffMs: options.maxBackoffMs,
        maxRetryAfterMs: options.maxRetryAfterMs,
        randomFn: options.randomFn
      });
      return {
        executed: true,
        status: retryRes.status,
        http_status: httpResult.httpStatus,
        error_code: classification.errorCode,
        attempt_count: currentAttemptCount,
        next_attempt_at: retryRes.nextAttemptAt
      };
    }

    const failedOk = await failDeliveryPermanently(delivery.id, ownerToken, {
      errorCode: classification.errorCode,
      httpStatus: httpResult.httpStatus,
      now: finishNow
    });
    return {
      executed: true,
      status: failedOk ? 'failed' : 'stale_owner',
      http_status: httpResult.httpStatus,
      error_code: classification.errorCode,
      attempt_count: currentAttemptCount
    };
  } finally {
    await releaseRedisLock();
  }
}

/**
 * Reconciles stale in-flight delivery leases (`status = 'pending'` with expired `locked_at`)
 * left behind by crashed or timed-out workers.
 *
 * Security & reliability invariants:
 * - At-least-once delivery semantics: a remote receiver may or may not have received
 *   the HTTP request before the worker crashed; receivers deduplicate via `X-ActionGuard-Webhook-Id`.
 * - Does NOT increment `attempt_count` a second time, because `beginDeliveryAttempt`
 *   already incremented `attempt_count` when the crashed attempt started.
 * - Uses conditional updates verifying `locked_by` and `locked_at` so a stale recovery
 *   sweep never overwrites a job completed or reclaimed by another worker.
 * - If `attempt_count >= maxAttempts`, transitions the row to terminal `failed`
 *   (`error_code: 'WORKER_LEASE_EXPIRED'`). Otherwise releases the lock and schedules
 *   `next_attempt_at` with backoff.
 *
 * @param {object} [options={}]
 * @param {Date} [options.now=new Date()]
 * @param {number} [options.leaseTimeoutMs=DEFAULT_LEASE_TIMEOUT_MS]
 * @param {number} [options.maxAttempts=DEFAULT_MAX_ATTEMPTS]
 * @param {number} [options.baseBackoffMs=DEFAULT_BASE_BACKOFF_MS]
 * @param {number} [options.maxBackoffMs=DEFAULT_MAX_BACKOFF_MS]
 * @param {Function} [options.randomFn=Math.random]
 * @returns {Promise<{ reconciledCount: number, rescheduledCount: number, failedCount: number }>}
 */
async function reconcileStaleLockedDeliveries(options = {}) {
  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  const leaseTimeoutMs =
    typeof options.leaseTimeoutMs === 'number' && options.leaseTimeoutMs > 0
      ? options.leaseTimeoutMs
      : DEFAULT_LEASE_TIMEOUT_MS;
  const maxAttempts =
    typeof options.maxAttempts === 'number' && options.maxAttempts >= 1
      ? Math.floor(options.maxAttempts)
      : DEFAULT_MAX_ATTEMPTS;

  const cutoff = new Date(now.getTime() - leaseTimeoutMs);

  const staleRows = await WebhookDeliveryLog.findAll({
    where: {
      status: 'pending',
      locked_at: { [Op.lte]: cutoff }
    },
    order: [['locked_at', 'ASC']],
    limit: 50
  });

  let reconciledCount = 0;
  let rescheduledCount = 0;
  let failedCount = 0;

  for (const row of staleRows) {
    const currentAttempts = Number(row.attempt_count) || 0;

    if (currentAttempts >= maxAttempts) {
      const [updated] = await WebhookDeliveryLog.update(
        {
          status: 'failed',
          error_code: 'WORKER_LEASE_EXPIRED',
          next_attempt_at: null,
          locked_at: null,
          locked_by: null,
          updated_at: now
        },
        {
          where: {
            id: row.id,
            status: 'pending',
            locked_by: row.locked_by,
            locked_at: row.locked_at
          }
        }
      );

      if (updated > 0) {
        reconciledCount++;
        failedCount++;
      }
    } else {
      const delayMs = computeRetryDelayMs({
        attemptCount: Math.max(1, currentAttempts),
        nowMs: now.getTime(),
        baseBackoffMs: options.baseBackoffMs,
        maxBackoffMs: options.maxBackoffMs,
        randomFn: options.randomFn
      });
      const nextAttemptAt = new Date(now.getTime() + delayMs);

      const [updated] = await WebhookDeliveryLog.update(
        {
          status: 'pending',
          error_code: 'WORKER_LEASE_EXPIRED',
          next_attempt_at: nextAttemptAt,
          locked_at: null,
          locked_by: null,
          updated_at: now
        },
        {
          where: {
            id: row.id,
            status: 'pending',
            locked_by: row.locked_by,
            locked_at: row.locked_at
          }
        }
      );

      if (updated > 0) {
        reconciledCount++;
        rescheduledCount++;
      }
    }
  }

  return {
    reconciledCount,
    rescheduledCount,
    failedCount
  };
}

/**
 * Processes a batch of due pending webhook deliveries with bounded concurrency.
 *
 * @param {object} [options={}]
 * @param {Date} [options.now=new Date()]
 * @param {number} [options.batchSize=DEFAULT_BATCH_SIZE]
 * @param {number} [options.concurrency=DEFAULT_CONCURRENCY_LIMIT]
 * @param {number} [options.leaseTimeoutMs=DEFAULT_LEASE_TIMEOUT_MS]
 * @param {number} [options.maxAttempts=DEFAULT_MAX_ATTEMPTS]
 * @returns {Promise<{
 *   reconciled: { reconciledCount: number, rescheduledCount: number, failedCount: number },
 *   processed: number,
 *   deliveredCount: number,
 *   retriedCount: number,
 *   failedCount: number
 * }>}
 */
async function processPendingWebhookDeliveries(options = {}) {
  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  const batchSize =
    typeof options.batchSize === 'number' && options.batchSize >= 1
      ? Math.min(100, Math.floor(options.batchSize))
      : DEFAULT_BATCH_SIZE;
  const concurrency =
    typeof options.concurrency === 'number' && options.concurrency >= 1
      ? Math.min(20, Math.floor(options.concurrency))
      : DEFAULT_CONCURRENCY_LIMIT;
  const leaseTimeoutMs =
    typeof options.leaseTimeoutMs === 'number' && options.leaseTimeoutMs > 0
      ? options.leaseTimeoutMs
      : DEFAULT_LEASE_TIMEOUT_MS;
  const maxAttempts =
    typeof options.maxAttempts === 'number' && options.maxAttempts >= 1
      ? Math.floor(options.maxAttempts)
      : DEFAULT_MAX_ATTEMPTS;

  const reconciled = await reconcileStaleLockedDeliveries({
    ...options,
    now,
    leaseTimeoutMs,
    maxAttempts
  });

  const expiredCutoff = new Date(now.getTime() - leaseTimeoutMs);
  const candidates = await WebhookDeliveryLog.findAll({
    where: {
      status: 'pending',
      attempt_count: { [Op.lt]: maxAttempts },
      [Op.and]: [
        {
          [Op.or]: [
            { next_attempt_at: null },
            { next_attempt_at: { [Op.lte]: now } }
          ]
        },
        {
          [Op.or]: [
            { locked_at: null },
            { locked_at: { [Op.lte]: expiredCutoff } }
          ]
        }
      ]
    },
    attributes: ['id'],
    order: [
      ['next_attempt_at', 'ASC'],
      ['created_at', 'ASC']
    ],
    limit: batchSize
  });

  let processed = 0;
  let deliveredCount = 0;
  let retriedCount = 0;
  let failedCount = 0;

  let index = 0;
  const workerCount = Math.min(concurrency, candidates.length);

  const runSlot = async () => {
    while (index < candidates.length) {
      const currentIdx = index++;
      const candidate = candidates[currentIdx];
      const result = await executeWebhookDelivery(candidate.id, options);
      if (result.executed || result.error_code) {
        processed++;
        if (result.status === 'delivered') {
          deliveredCount++;
        } else if (result.status === 'pending') {
          retriedCount++;
        } else if (result.status === 'failed') {
          failedCount++;
        }
      }
    }
  };

  const slots = [];
  for (let i = 0; i < workerCount; i += 1) {
    slots.push(runSlot());
  }
  await Promise.all(slots);

  return {
    reconciled,
    processed,
    deliveredCount,
    retriedCount,
    failedCount
  };
}

/**
 * Reconciles missing webhook delivery jobs for authoritative `SecurityEvent` and
 * `PolicyDecision` records created within a bounded lookback window.
 *
 * Architectural context & limitation:
 * - ActionGuard commits `SecurityEvent` (+ `RiskAssessment`) and `PolicyDecision`
 *   rows to MySQL before emitting `pipeline:event_processed` or `policy:decision_recorded`
 *   on the in-process eventBus.
 * - If a process crashes or restarts in that post-commit window before the async
 *   listener inserts the `webhook_delivery_logs` rows, this bounded reconciliation
 *   sweep recovers any missing jobs within `lookbackMs` (default 15 minutes, max 24 hours).
 * - This is a bounded lookback reconciliation mechanism (not a transactional outbox);
 *   events older than `lookbackMs` are outside the recovery window.
 *
 * Security & eligibility invariants:
 * - Respects event eligibility: scored event types require a persisted `RiskAssessment`
 *   row (matching `requireAssessmentForEmit`), whereas unscored housekeeping events
 *   (`riskConfig.UNSCORED_EVENT_TYPES`) are eligible once persisted with a `user_id`.
 *   `PolicyDecision` rows whose linked event has `containment_status: 'pending' | 'failed'`
 *   are excluded because `policy:decision_recorded` is never emitted for failed/incomplete containment.
 * - Respects endpoint subscription rules (`is_active: true` and `subscribed_events`).
 * - Respects endpoint creation time: never enqueues a historical event or decision
 *   for a `WebhookEndpoint` created after that source record occurred (`ep.created_at <= occurredAt`).
 * - Idempotent and concurrency-safe via deterministic delivery IDs (`whdel_<sha256_32>`)
 *   and `uq_webhook_delivery_logs_endpoint_event`.
 *
 * @param {object} [options={}]
 * @param {Date} [options.now=new Date()]
 * @param {number} [options.lookbackMs=DEFAULT_RECONCILE_LOOKBACK_MS]
 * @param {number} [options.batchSize=DEFAULT_RECONCILE_BATCH_SIZE]
 * @returns {Promise<{
 *   scannedEvents: number,
 *   eligibleEvents: number,
 *   scannedDecisions: number,
 *   eligibleDecisions: number,
 *   enqueuedCount: number,
 *   duplicateCount: number
 * }>}
 */
async function reconcileMissingWebhookEnqueues(options = {}) {
  const effectiveNow =
    options.now instanceof Date ? options.now : new Date(options.now || Date.now());

  const envLookback = Number.parseInt(
    process.env.WEBHOOK_RECONCILE_LOOKBACK_MS || '',
    10
  );
  const rawLookbackMs =
    typeof options.lookbackMs === 'number' && Number.isFinite(options.lookbackMs)
      ? options.lookbackMs
      : Number.isFinite(envLookback) && envLookback > 0
      ? envLookback
      : DEFAULT_RECONCILE_LOOKBACK_MS;
  const lookbackMs = Math.min(
    MAX_RECONCILE_LOOKBACK_MS,
    Math.max(1000, Math.floor(rawLookbackMs))
  );

  const envBatchSize = Number.parseInt(
    process.env.WEBHOOK_RECONCILE_BATCH_SIZE || '',
    10
  );
  const rawBatchSize =
    typeof options.batchSize === 'number' && Number.isFinite(options.batchSize)
      ? options.batchSize
      : Number.isFinite(envBatchSize) && envBatchSize > 0
      ? envBatchSize
      : DEFAULT_RECONCILE_BATCH_SIZE;
  const batchSize = Math.min(200, Math.max(1, Math.floor(rawBatchSize)));

  const lookbackCutoff = new Date(effectiveNow.getTime() - lookbackMs);

  const activeEndpoints = await WebhookEndpoint.findAll({
    where: { is_active: true },
    attributes: ['id', 'subscribed_events', 'is_active', 'created_at'],
    order: [
      ['created_at', 'ASC'],
      ['id', 'ASC']
    ]
  });

  if (activeEndpoints.length === 0) {
    return {
      scannedEvents: 0,
      eligibleEvents: 0,
      scannedDecisions: 0,
      eligibleDecisions: 0,
      enqueuedCount: 0,
      duplicateCount: 0
    };
  }

  const eventEndpoints = activeEndpoints.filter(
    (ep) =>
      ep.is_active === true &&
      Array.isArray(ep.subscribed_events) &&
      ep.subscribed_events.includes('event.processed')
  );
  const decisionEndpoints = activeEndpoints.filter(
    (ep) =>
      ep.is_active === true &&
      Array.isArray(ep.subscribed_events) &&
      ep.subscribed_events.includes('decision.recorded')
  );

  let scannedEvents = 0;
  let eligibleEvents = 0;
  let scannedDecisions = 0;
  let eligibleDecisions = 0;
  let enqueuedCount = 0;
  let duplicateCount = 0;

  const unscoredTypes = Array.isArray(riskConfig.UNSCORED_EVENT_TYPES)
    ? riskConfig.UNSCORED_EVENT_TYPES
    : [];

  // 1. Reconcile missing `event.processed` jobs
  if (eventEndpoints.length > 0) {
    const candidateEvents = await SecurityEvent.findAll({
      where: {
        timestamp: {
          [Op.gte]: lookbackCutoff,
          [Op.lte]: effectiveNow
        }
      },
      attributes: ['event_id', 'user_id', 'event_type', 'timestamp'],
      order: [
        ['timestamp', 'DESC'],
        ['event_id', 'DESC']
      ],
      limit: batchSize
    });

    scannedEvents = candidateEvents.length;

    const eventsWithUser = candidateEvents.filter(
      (ev) => typeof ev.user_id === 'string' && ev.user_id.trim().length > 0
    );

    const scoredCandidateIds = eventsWithUser
      .filter((ev) => !unscoredTypes.includes(ev.event_type))
      .map((ev) => ev.event_id);

    const assessedEventIdSet = new Set();
    if (scoredCandidateIds.length > 0) {
      const assessments = await RiskAssessment.findAll({
        where: {
          event_id: { [Op.in]: scoredCandidateIds }
        },
        attributes: ['event_id']
      });
      for (const a of assessments) {
        if (a.event_id) {
          assessedEventIdSet.add(a.event_id);
        }
      }
    }

    const qualifiedEvents = eventsWithUser.filter(
      (ev) =>
        unscoredTypes.includes(ev.event_type) ||
        assessedEventIdSet.has(ev.event_id)
    );
    eligibleEvents = qualifiedEvents.length;

    if (qualifiedEvents.length > 0) {
      const qualifiedEventIds = qualifiedEvents.map((ev) => ev.event_id);
      const existingLogs = await WebhookDeliveryLog.findAll({
        where: {
          event_type: 'event.processed',
          source_event_id: { [Op.in]: qualifiedEventIds }
        },
        attributes: ['webhook_id', 'source_event_id']
      });

      const existingKeys = new Set(
        existingLogs.map((row) => `${row.webhook_id}:${row.source_event_id}`)
      );

      for (const ev of qualifiedEvents) {
        const evTimeMs = new Date(ev.timestamp).getTime();
        const needsEnqueue = eventEndpoints.some((ep) => {
          const epCreatedMs = ep.created_at ? new Date(ep.created_at).getTime() : 0;
          if (Number.isFinite(epCreatedMs) && Number.isFinite(evTimeMs) && epCreatedMs > evTimeMs) {
            return false;
          }
          return !existingKeys.has(`${ep.id}:${ev.event_id}`);
        });

        if (needsEnqueue) {
          const res = await enqueueWebhooksForEvent({
            eventType: 'event.processed',
            sourceEventId: ev.event_id,
            occurredAt: ev.timestamp,
            now: effectiveNow
          });
          enqueuedCount += res.enqueued.length;
          duplicateCount += res.duplicates.length;
        }
      }
    }
  }

  // 2. Reconcile missing `decision.recorded` jobs
  if (decisionEndpoints.length > 0) {
    const candidateDecisions = await PolicyDecision.findAll({
      where: {
        decided_at: {
          [Op.gte]: lookbackCutoff,
          [Op.lte]: effectiveNow
        }
      },
      attributes: ['id', 'user_id', 'event_id', 'decided_at'],
      order: [
        ['decided_at', 'DESC'],
        ['id', 'DESC']
      ],
      limit: batchSize
    });

    scannedDecisions = candidateDecisions.length;

    const decisionsWithUser = candidateDecisions.filter(
      (dec) =>
        typeof dec.id === 'string' &&
        dec.id.trim().length > 0 &&
        typeof dec.user_id === 'string' &&
        dec.user_id.trim().length > 0
    );

    const linkedEventIds = Array.from(
      new Set(
        decisionsWithUser
          .map((dec) => dec.event_id)
          .filter((id) => typeof id === 'string' && id.trim().length > 0)
      )
    );

    const excludedEventIds = new Set();
    if (linkedEventIds.length > 0) {
      const linkedEvents = await SecurityEvent.findAll({
        where: {
          event_id: { [Op.in]: linkedEventIds }
        },
        attributes: ['event_id', 'metadata']
      });
      for (const ev of linkedEvents) {
        const containmentStatus =
          ev.metadata && typeof ev.metadata === 'object'
            ? ev.metadata.containment_status
            : undefined;
        if (containmentStatus === 'pending' || containmentStatus === 'failed') {
          excludedEventIds.add(ev.event_id);
        }
      }
    }

    const qualifiedDecisions = decisionsWithUser.filter(
      (dec) => !dec.event_id || !excludedEventIds.has(dec.event_id)
    );
    eligibleDecisions = qualifiedDecisions.length;

    if (qualifiedDecisions.length > 0) {
      const qualifiedDecisionIds = qualifiedDecisions.map((dec) => dec.id);
      const existingLogs = await WebhookDeliveryLog.findAll({
        where: {
          event_type: 'decision.recorded',
          source_event_id: { [Op.in]: qualifiedDecisionIds }
        },
        attributes: ['webhook_id', 'source_event_id']
      });

      const existingKeys = new Set(
        existingLogs.map((row) => `${row.webhook_id}:${row.source_event_id}`)
      );

      for (const dec of qualifiedDecisions) {
        const decTimeMs = new Date(dec.decided_at).getTime();
        const needsEnqueue = decisionEndpoints.some((ep) => {
          const epCreatedMs = ep.created_at ? new Date(ep.created_at).getTime() : 0;
          if (Number.isFinite(epCreatedMs) && Number.isFinite(decTimeMs) && epCreatedMs > decTimeMs) {
            return false;
          }
          return !existingKeys.has(`${ep.id}:${dec.id}`);
        });

        if (needsEnqueue) {
          const res = await enqueueWebhooksForEvent({
            eventType: 'decision.recorded',
            sourceEventId: dec.id,
            occurredAt: dec.decided_at,
            now: effectiveNow
          });
          enqueuedCount += res.enqueued.length;
          duplicateCount += res.duplicates.length;
        }
      }
    }
  }

  return {
    scannedEvents,
    eligibleEvents,
    scannedDecisions,
    eligibleDecisions,
    enqueuedCount,
    duplicateCount
  };
}

module.exports = {
  DEFAULT_MAX_ATTEMPTS,
  DEFAULT_BASE_BACKOFF_MS,
  DEFAULT_MAX_BACKOFF_MS,
  DEFAULT_MAX_RETRY_AFTER_MS,
  DEFAULT_LEASE_TIMEOUT_MS,
  DEFAULT_BATCH_SIZE,
  DEFAULT_CONCURRENCY_LIMIT,
  DEFAULT_RECONCILE_LOOKBACK_MS,
  MAX_RECONCILE_LOOKBACK_MS,
  DEFAULT_RECONCILE_BATCH_SIZE,
  deriveDeterministicDeliveryId,
  parseRetryAfterMs,
  computeRetryDelayMs,
  classifyHttpResponseStatus,
  buildWebhookEventEnvelope,
  enqueueWebhooksForEvent,
  claimDeliveryJob,
  beginDeliveryAttempt,
  scheduleDeliveryRetry,
  executeWebhookDelivery,
  reconcileStaleLockedDeliveries,
  reconcileMissingWebhookEnqueues,
  processPendingWebhookDeliveries
};
