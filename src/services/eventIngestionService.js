'use strict';

const crypto = require('crypto');
const {
  sequelize,
  User,
  Session,
  SecurityEvent,
  RiskAssessment,
  ActionSequence,
  SequenceEvent
} = require('../database/models');
const eventService = require('./eventService');
const riskEngineService = require('./riskEngineService');
const {
  correlateEventIntoSequence,
  invalidateSequenceCache
} = require('./sequenceGroupingService');
const policyLoader = require('./policyLoader');
const { decide, SENSITIVITY_RANKS } = require('../utils/policyDecision');
const riskConfig = require('../config/riskConfig');
const { REDIS_PREFIXES } = require('../config/sessionConfig');
const redisStorage = require('../storage/redis');
const { normalizeIp } = require('../utils/ip');
const { validateDeviceFingerprint, getOrCreateDevice } = require('./deviceService');
const geoService = require('./geoService');
const { collectTravelAnomalySignal } = require('../collectors/travelCollector');
const { constantTimeKeyMatch } = require('../middleware/auth');
const { isPlainObject, isBoundedString } = require('../middleware/validation');
const eventBus = require('../events/eventBus');

const DEFAULT_MAX_FUTURE_SKEW_MS = 5 * 60 * 1000; // 5 minutes
const DEFAULT_MAX_PAST_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const DEFAULT_IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60; // 24 hours
const DEFAULT_IDEMPOTENCY_LEASE_SECONDS = 30; // 30-second processing lease
const DEFAULT_COOLING_OFF_SECONDS = 300;

const SAFE_IDENTIFIER_REGEX = /^[a-zA-Z0-9_.:-]+$/;
const SAFE_DETAIL_KEY_REGEX = /^[a-zA-Z0-9_]{1,64}$/;
const CONTROL_CHAR_REGEX = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/;

const ISO_8601_STRICT_REGEX =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/;

const ALLOWED_TOP_LEVEL_FIELDS = Object.freeze(
  new Set([
    'user_id',
    'session_id',
    'event_type',
    'timestamp',
    'context',
    'metadata',
    'idempotency_key'
  ])
);

const ALLOWED_CONTEXT_FIELDS = Object.freeze(
  new Set(['ip_address', 'device_fingerprint', 'user_agent'])
);

const ALLOWED_METADATA_FIELDS = Object.freeze(
  new Set([
    'action_sensitivity',
    'operation',
    'target',
    'resource',
    'reason',
    'correlation_id',
    'external_ref',
    'details'
  ])
);

const FORBIDDEN_AUTHORITATIVE_KEYS = Object.freeze(
  new Set([
    'id',
    'event_id',
    'risk_score',
    'risk_tier',
    'decision',
    'policy_decision',
    'enforcement_mode',
    'is_trusted_device',
    'trusted_device',
    'trust_status',
    'device_trust',
    'is_new_device',
    'is_new_country',
    'action_status',
    'source',
    'ingested_via',
    'api_key_fingerprint',
    'idempotency_payload_hash',
    'travel_anomaly',
    'bot_detection',
    'behavioral_deviation',
    'contributing_signals',
    'signals',
    'explanation',
    'cooling_off_seconds',
    'evaluated_at',
    'created_at',
    'updated_at'
  ])
);

const SENSITIVE_KEY_PATTERN =
  /^(password|current_password|new_password|password_hash|new_password_hash|token|cancellation_token|access_token|refresh_token|apikey|api_key|secret|client_secret|otp|code|pin|cvv|private_key|authorization|cookie|credential|credentials)$/i;

const SENSITIVE_SUBSTRING_PATTERN =
  /(password|secret|token|api_?key|private_?key|authorization|credential)/i;

const SECRET_VALUE_PATTERNS = [
  /\bBearer\s+[A-Za-z0-9._~+/=-]{6,}/gi,
  /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
  /\$2[aby]\$\d{2}\$[./A-Za-z0-9]{20,}/g,
  /\b(?:whsec|ctkn)_[A-Za-z0-9_-]{6,}/gi,
  /\b(?:password|secret|token|api_?key|private_?key|client_secret)\s*[:=]\s*\S+/gi
];

function parsePositiveIntEnv(rawVal, fallbackVal) {
  if (rawVal === undefined || rawVal === null || rawVal === '') {
    return fallbackVal;
  }
  const num = Number.parseInt(String(rawVal).trim(), 10);
  if (!Number.isSafeInteger(num) || num <= 0) {
    return fallbackVal;
  }
  return num;
}

/**
 * Computes a one-way, domain-separated SHA-256 fingerprint of the authenticated API key.
 * Never exposes or stores the raw API key.
 *
 * @param {string} apiKey
 * @returns {string}
 */
function computeApiKeyFingerprint(apiKey) {
  const digest = crypto
    .createHash('sha256')
    .update(`actionguard:external_api_key_fp:${String(apiKey || '')}`, 'utf8')
    .digest('hex');
  return `akfp_${digest.slice(0, 32)}`;
}

/**
 * Derives a deterministic SecurityEvent primary key bound to `(apiKeyFingerprint, idempotencyKey)`
 * so database-level primary key constraints prevent duplicate event creation across retries or crashes.
 *
 * @param {string} apiKeyFingerprint
 * @param {string} idempotencyKey
 * @returns {string}
 */
function deriveDeterministicEventId(apiKeyFingerprint, idempotencyKey) {
  const digest = crypto
    .createHash('sha256')
    .update(`actionguard:ext_event_id:${apiKeyFingerprint}:${idempotencyKey}`, 'utf8')
    .digest('hex');
  return `evt_idem_${digest.slice(0, 32)}`;
}

/**
 * Deterministic recursive JSON canonicalizer for computing stable request payload hashes.
 *
 * @param {unknown} value
 * @returns {string}
 */
function canonicalizeValue(value) {
  if (value === null || value === undefined) {
    return 'null';
  }
  if (typeof value === 'boolean' || typeof value === 'number') {
    return JSON.stringify(value);
  }
  if (typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeValue(item)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    const entries = keys
      .filter((k) => value[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${canonicalizeValue(value[k])}`);
    return `{${entries.join(',')}}`;
  }
  return 'null';
}

/**
 * Computes a SHA-256 hex digest of the canonical request representation.
 *
 * @param {object} canonicalPayload
 * @returns {string}
 */
function computeCanonicalPayloadHash(canonicalPayload) {
  const serialized = canonicalizeValue(canonicalPayload);
  return crypto.createHash('sha256').update(serialized, 'utf8').digest('hex');
}

/**
 * Redacts secret-bearing patterns and any occurrence of the raw API key from a string value.
 *
 * @param {string} str
 * @param {string} [rawApiKey]
 * @returns {string}
 */
function redactSecretsFromString(str, rawApiKey = '') {
  let sanitized = str;
  if (typeof rawApiKey === 'string' && rawApiKey.length >= 4 && sanitized.includes(rawApiKey)) {
    sanitized = sanitized.split(rawApiKey).join('[REDACTED]');
  }
  for (const pattern of SECRET_VALUE_PATTERNS) {
    sanitized = sanitized.replace(pattern, '[REDACTED]');
  }
  return sanitized;
}

/**
 * Validates an ISO-8601 timestamp string and checks that it falls within the allowed
 * future skew (default 5 minutes) and past age (default 30 days) windows.
 *
 * @param {unknown} rawTimestamp
 * @param {number} [nowMs=Date.now()]
 * @returns {{ valid: boolean, date?: Date, message?: string }}
 */
function validateEventTimestamp(rawTimestamp, nowMs = Date.now()) {
  if (typeof rawTimestamp !== 'string' || rawTimestamp.trim().length === 0) {
    return {
      valid: false,
      message: 'timestamp is required and must be a valid ISO-8601 string'
    };
  }

  const trimmed = rawTimestamp.trim();
  const match = ISO_8601_STRICT_REGEX.exec(trimmed);
  if (!match) {
    return {
      valid: false,
      message: 'timestamp must be a valid ISO-8601 date-time string with timezone (e.g. 2026-10-12T14:00:00Z)'
    };
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);

  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > 31 ||
    hour < 0 ||
    hour > 23 ||
    minute < 0 ||
    minute > 59 ||
    second < 0 ||
    second > 59
  ) {
    return {
      valid: false,
      message: 'timestamp contains out-of-range date or time components'
    };
  }

  if (match[9]) {
    const tzHour = Number(match[10]);
    const tzMin = Number(match[11]);
    if (tzHour > 23 || tzMin > 59) {
      return {
        valid: false,
        message: 'timestamp contains an invalid timezone offset'
      };
    }
  }

  // Prevent calendar date rollover (e.g. Feb 30 -> Mar 2)
  const utcCalendarCheck = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  if (
    utcCalendarCheck.getUTCFullYear() !== year ||
    utcCalendarCheck.getUTCMonth() + 1 !== month ||
    utcCalendarCheck.getUTCDate() !== day
  ) {
    return {
      valid: false,
      message: 'timestamp is not a valid calendar date'
    };
  }

  const parsedDate = new Date(trimmed);
  const tsMs = parsedDate.getTime();
  if (!Number.isFinite(tsMs)) {
    return {
      valid: false,
      message: 'timestamp must be a valid ISO-8601 date'
    };
  }

  const maxFutureSkewMs = parsePositiveIntEnv(
    process.env.EXTERNAL_EVENT_MAX_FUTURE_SKEW_MS,
    DEFAULT_MAX_FUTURE_SKEW_MS
  );
  const maxPastAgeMs = parsePositiveIntEnv(
    process.env.EXTERNAL_EVENT_MAX_PAST_AGE_MS,
    DEFAULT_MAX_PAST_AGE_MS
  );

  if (tsMs > nowMs + maxFutureSkewMs) {
    return {
      valid: false,
      message: 'timestamp cannot be more than 5 minutes in the future'
    };
  }

  if (tsMs < nowMs - maxPastAgeMs) {
    return {
      valid: false,
      message: 'timestamp exceeds maximum allowed past age of 30 days'
    };
  }

  return {
    valid: true,
    date: parsedDate
  };
}

/**
 * Validates and normalizes the `context` object against a strict allowlist.
 * Rejects unknown fields, client-supplied geolocation/coordinates, and malformed values.
 *
 * @param {unknown} rawContext
 * @param {string} [rawApiKey]
 * @returns {{ valid: boolean, context?: object, message?: string }}
 */
function validateAndNormalizeContext(rawContext, rawApiKey = '') {
  if (rawContext === undefined) {
    return { valid: true, context: {} };
  }

  if (!isPlainObject(rawContext)) {
    return {
      valid: false,
      message: 'context must be a plain JSON object'
    };
  }

  const keys = Object.keys(rawContext);
  for (const key of keys) {
    if (
      FORBIDDEN_AUTHORITATIVE_KEYS.has(key) ||
      FORBIDDEN_AUTHORITATIVE_KEYS.has(String(key).toLowerCase())
    ) {
      return {
        valid: false,
        message: `Field 'context.${key}' is reserved and cannot be supplied by external callers`
      };
    }
    if (!ALLOWED_CONTEXT_FIELDS.has(key)) {
      if (
        key === 'latitude' ||
        key === 'longitude' ||
        key === 'coordinates' ||
        key === 'geo_country' ||
        key === 'geo_region'
      ) {
        return {
          valid: false,
          message: `Client-supplied geolocation or coordinate field 'context.${key}' is not permitted`
        };
      }
      return {
        valid: false,
        message: `Unknown or forbidden field 'context.${key}'`
      };
    }
  }

  const normalizedContext = {};

  if (rawContext.ip_address !== undefined && rawContext.ip_address !== null) {
    if (
      typeof rawContext.ip_address !== 'string' ||
      rawContext.ip_address.length > 64
    ) {
      return {
        valid: false,
        message: 'context.ip_address must be a valid IP address string'
      };
    }
    const normalizedIp = normalizeIp(rawContext.ip_address);
    if (!normalizedIp) {
      return {
        valid: false,
        message: 'context.ip_address must be a valid IPv4 or IPv6 address'
      };
    }
    normalizedContext.ip_address = normalizedIp;
  }

  if (rawContext.device_fingerprint !== undefined && rawContext.device_fingerprint !== null) {
    if (typeof rawContext.device_fingerprint !== 'string') {
      return {
        valid: false,
        message: 'context.device_fingerprint must be a string'
      };
    }
    if (!validateDeviceFingerprint(rawContext.device_fingerprint)) {
      return {
        valid: false,
        message: 'context.device_fingerprint must be 4-255 valid identifier characters'
      };
    }
    const trimmedFp = rawContext.device_fingerprint.trim();
    if (rawApiKey && trimmedFp.includes(rawApiKey)) {
      return {
        valid: false,
        message: 'context.device_fingerprint must not contain authentication credentials'
      };
    }
    normalizedContext.device_fingerprint = trimmedFp;
  }

  if (rawContext.user_agent !== undefined && rawContext.user_agent !== null) {
    if (
      !isBoundedString(rawContext.user_agent, { minLength: 1, maxLength: 512, trim: true }) ||
      CONTROL_CHAR_REGEX.test(rawContext.user_agent)
    ) {
      return {
        valid: false,
        message: 'context.user_agent must be a valid string between 1 and 512 characters'
      };
    }
    normalizedContext.user_agent = redactSecretsFromString(rawContext.user_agent.trim(), rawApiKey);
  }

  return {
    valid: true,
    context: normalizedContext
  };
}

/**
 * Validates, sanitizes, and normalizes the `metadata` object against a strict allowlist.
 * Enforces policy-defined minimum action_sensitivity and strips/redacts secret-bearing values.
 *
 * @param {unknown} rawMetadata
 * @param {string} eventType
 * @param {object} activePolicy
 * @param {string} [rawApiKey]
 * @returns {{ valid: boolean, clientMetadata?: object, effectiveSensitivity?: string, message?: string }}
 */
function validateAndSanitizeMetadata(rawMetadata, eventType, activePolicy, rawApiKey = '') {
  if (rawMetadata !== undefined && !isPlainObject(rawMetadata)) {
    return {
      valid: false,
      message: 'metadata must be a plain JSON object'
    };
  }

  const inputMeta = rawMetadata || {};
  const keys = Object.keys(inputMeta);

  if (keys.length > 8) {
    return {
      valid: false,
      message: 'metadata exceeds maximum allowed number of keys (8)'
    };
  }

  for (const key of keys) {
    if (
      FORBIDDEN_AUTHORITATIVE_KEYS.has(key) ||
      FORBIDDEN_AUTHORITATIVE_KEYS.has(String(key).toLowerCase())
    ) {
      return {
        valid: false,
        message: `Field 'metadata.${key}' is reserved and cannot be supplied by external callers`
      };
    }
    if (SENSITIVE_KEY_PATTERN.test(key) || SENSITIVE_SUBSTRING_PATTERN.test(key)) {
      return {
        valid: false,
        message: `Secret or credential field 'metadata.${key}' is not permitted`
      };
    }
    if (!ALLOWED_METADATA_FIELDS.has(key)) {
      return {
        valid: false,
        message: `Unknown field 'metadata.${key}' is not permitted`
      };
    }
  }

  const policyMinSensitivity =
    (activePolicy &&
      activePolicy.DEFAULT_ACTION_SENSITIVITY &&
      activePolicy.DEFAULT_ACTION_SENSITIVITY[eventType]) ||
    'low';

  let providedSensitivity = null;
  if (inputMeta.action_sensitivity !== undefined && inputMeta.action_sensitivity !== null) {
    if (
      typeof inputMeta.action_sensitivity !== 'string' ||
      !SecurityEvent.ACTION_SENSITIVITY_LEVELS.includes(inputMeta.action_sensitivity)
    ) {
      return {
        valid: false,
        message: `Invalid action_sensitivity '${inputMeta.action_sensitivity}'. Must be one of: ${SecurityEvent.ACTION_SENSITIVITY_LEVELS.join(', ')}`
      };
    }
    providedSensitivity = inputMeta.action_sensitivity;
  }

  const effectiveSensitivity =
    providedSensitivity &&
    SENSITIVITY_RANKS[providedSensitivity] > SENSITIVITY_RANKS[policyMinSensitivity]
      ? providedSensitivity
      : policyMinSensitivity;

  const sanitizedMeta = {
    action_sensitivity: effectiveSensitivity
  };

  const boundedStringRules = [
    { field: 'operation', maxLength: 128 },
    { field: 'target', maxLength: 255 },
    { field: 'resource', maxLength: 255 },
    { field: 'reason', maxLength: 128 }
  ];

  for (const { field, maxLength } of boundedStringRules) {
    if (inputMeta[field] !== undefined && inputMeta[field] !== null) {
      if (
        !isBoundedString(inputMeta[field], { minLength: 1, maxLength, trim: true }) ||
        CONTROL_CHAR_REGEX.test(inputMeta[field])
      ) {
        return {
          valid: false,
          message: `metadata.${field} must be a non-empty string of at most ${maxLength} characters`
        };
      }
      sanitizedMeta[field] = redactSecretsFromString(inputMeta[field].trim(), rawApiKey);
    }
  }

  const safeIdFields = ['correlation_id', 'external_ref'];
  for (const field of safeIdFields) {
    if (inputMeta[field] !== undefined && inputMeta[field] !== null) {
      if (
        typeof inputMeta[field] !== 'string' ||
        inputMeta[field].trim().length === 0 ||
        inputMeta[field].trim().length > 128 ||
        !SAFE_IDENTIFIER_REGEX.test(inputMeta[field].trim())
      ) {
        return {
          valid: false,
          message: `metadata.${field} must be a valid identifier string (1-128 characters)`
        };
      }
      const trimmedVal = inputMeta[field].trim();
      if (rawApiKey && trimmedVal.includes(rawApiKey)) {
        return {
          valid: false,
          message: `metadata.${field} must not contain authentication credentials`
        };
      }
      sanitizedMeta[field] = trimmedVal;
    }
  }

  if (inputMeta.details !== undefined && inputMeta.details !== null) {
    if (!isPlainObject(inputMeta.details)) {
      return {
        valid: false,
        message: 'metadata.details must be a plain JSON object'
      };
    }

    const detailKeys = Object.keys(inputMeta.details);
    if (detailKeys.length > 10) {
      return {
        valid: false,
        message: 'metadata.details exceeds maximum allowed number of keys (10)'
      };
    }

    const sanitizedDetails = {};
    for (const dKey of detailKeys) {
      if (!SAFE_DETAIL_KEY_REGEX.test(dKey)) {
        return {
          valid: false,
          message: `Invalid key 'metadata.details.${dKey}'`
        };
      }
      if (
        FORBIDDEN_AUTHORITATIVE_KEYS.has(dKey) ||
        FORBIDDEN_AUTHORITATIVE_KEYS.has(String(dKey).toLowerCase())
      ) {
        return {
          valid: false,
          message: `Reserved key 'metadata.details.${dKey}' is not permitted`
        };
      }
      if (SENSITIVE_KEY_PATTERN.test(dKey) || SENSITIVE_SUBSTRING_PATTERN.test(dKey)) {
        // Strip secret-bearing keys from details so they are never persisted
        continue;
      }

      const dVal = inputMeta.details[dKey];
      if (dVal === null || typeof dVal === 'boolean') {
        sanitizedDetails[dKey] = dVal;
      } else if (typeof dVal === 'number') {
        if (!Number.isFinite(dVal)) {
          return {
            valid: false,
            message: `metadata.details.${dKey} must be a finite number`
          };
        }
        sanitizedDetails[dKey] = dVal;
      } else if (typeof dVal === 'string') {
        if (dVal.length > 256 || CONTROL_CHAR_REGEX.test(dVal)) {
          return {
            valid: false,
            message: `metadata.details.${dKey} must be a valid string of at most 256 characters`
          };
        }
        sanitizedDetails[dKey] = redactSecretsFromString(dVal, rawApiKey);
      } else {
        return {
          valid: false,
          message: `metadata.details.${dKey} must be a string, number, boolean, or null`
        };
      }
    }

    sanitizedMeta.details = sanitizedDetails;
  }

  return {
    valid: true,
    clientMetadata: sanitizedMeta,
    providedSensitivity,
    effectiveSensitivity
  };
}

/**
 * Validates and resolves the optional idempotency key from the `Idempotency-Key` header
 * and/or `req.body.idempotency_key`. Requires them to match if both are supplied.
 *
 * @param {import('express').Request} req
 * @returns {{ valid: boolean, idempotencyKey: string|null, message?: string }}
 */
function resolveIdempotencyKey(req) {
  const rawHeader = req.headers ? req.headers['idempotency-key'] : undefined;
  const rawBody = req.body ? req.body.idempotency_key : undefined;

  let headerKey = null;
  if (rawHeader !== undefined) {
    if (
      typeof rawHeader !== 'string' ||
      rawHeader.trim().length === 0 ||
      rawHeader.trim().length > 128 ||
      !SAFE_IDENTIFIER_REGEX.test(rawHeader.trim())
    ) {
      return {
        valid: false,
        idempotencyKey: null,
        message: 'Idempotency-Key header must be a valid identifier string (1-128 characters)'
      };
    }
    headerKey = rawHeader.trim();
  }

  let bodyKey = null;
  if (rawBody !== undefined && rawBody !== null) {
    if (
      typeof rawBody !== 'string' ||
      rawBody.trim().length === 0 ||
      rawBody.trim().length > 128 ||
      !SAFE_IDENTIFIER_REGEX.test(rawBody.trim())
    ) {
      return {
        valid: false,
        idempotencyKey: null,
        message: 'idempotency_key must be a valid identifier string (1-128 characters)'
      };
    }
    bodyKey = rawBody.trim();
  }

  if (headerKey !== null && bodyKey !== null && headerKey !== bodyKey) {
    return {
      valid: false,
      idempotencyKey: null,
      message: 'Idempotency-Key header and body idempotency_key must match'
    };
  }

  return {
    valid: true,
    idempotencyKey: headerKey || bodyKey || null
  };
}

/**
 * Builds the deterministic API response payload for a persisted SecurityEvent
 * and its evaluated RiskAssessment.
 *
 * @param {object} event
 * @param {object|null} assessment
 * @param {object} activePolicy
 * @param {string} effectiveSensitivity
 * @returns {object}
 */
function buildEventIngestionResponse(event, assessment, activePolicy, effectiveSensitivity) {
  const isUnscored =
    Array.isArray(riskConfig.UNSCORED_EVENT_TYPES) &&
    riskConfig.UNSCORED_EVENT_TYPES.includes(event.event_type);

  const riskScore = isUnscored ? 0 : assessment.risk_score;
  const riskTier = isUnscored ? 'low' : assessment.risk_tier;
  const contributingSignals = isUnscored
    ? []
    : Array.isArray(assessment.contributing_signals)
    ? assessment.contributing_signals
    : [];

  const signalNames = contributingSignals.map((s) => s.signal);

  const policyResult = decide(
    {
      risk: {
        status: 'ok',
        risk_tier: riskTier,
        signal_names: signalNames
      },
      action: {
        event_type: event.event_type,
        provided_sensitivity: effectiveSensitivity
      }
    },
    activePolicy
  );

  const explanation =
    (!isUnscored && assessment && assessment.explanation) || policyResult.explanation;

  const isoTimestamp =
    event.timestamp instanceof Date
      ? event.timestamp.toISOString()
      : new Date(event.timestamp).toISOString();

  return {
    event_id: event.event_id,
    user_id: event.user_id,
    session_id: event.session_id,
    event_type: event.event_type,
    timestamp: isoTimestamp,
    decision: policyResult.decision,
    risk_score: riskScore,
    risk_tier: riskTier,
    contributing_signals: contributingSignals,
    explanation,
    cooling_off_seconds:
      policyResult.decision === 'delay' ? DEFAULT_COOLING_OFF_SECONDS : 0
  };
}

const RELEASE_LOCK_LUA = `
-- ATOMIC_RELEASE_LOCK
-- KEYS[1]: lock_key
-- ARGV[1]: expected_owner_token
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
else
    return 0
end
`;

const COMPLETE_IDEMPOTENCY_LEASE_LUA = `
-- ATOMIC_COMPLETE_IDEMPOTENCY_LEASE
-- KEYS[1]: idempotency_key
-- ARGV[1]: expected_raw_lease
-- ARGV[2]: completed_record_json
-- ARGV[3]: ttl_seconds
if redis.call("GET", KEYS[1]) == ARGV[1] then
    local ttl = tonumber(ARGV[3])
    if ttl and ttl > 0 then
        redis.call("SET", KEYS[1], ARGV[2], "EX", ttl)
    else
        redis.call("SET", KEYS[1], ARGV[2])
    end
    return 1
else
    return 0
end
`;

/**
 * Atomically releases an in-progress Redis idempotency lease ONLY if the stored value
 * still matches this request's exact lease payload (including its unique owner_token).
 * Uses the Redis atomic compare-and-delete Lua script supported by both InMemoryRedisClient
 * and real ioredis. Never falls back to non-atomic GET-then-DEL; fails safely (returning 0)
 * if atomic eval is unavailable so an expired worker can never delete a replacement lease.
 *
 * @param {object} redisClient
 * @param {string|null} redisKey
 * @param {string|null} expectedRawLease
 * @returns {Promise<number>} 1 if the lease was atomically released, 0 otherwise
 */
async function releaseInProgressLease(redisClient, redisKey, expectedRawLease) {
  if (!redisClient || !redisKey || !expectedRawLease) {
    return 0;
  }
  if (typeof redisClient.eval !== 'function') {
    return 0;
  }
  try {
    const deleted = await redisClient.eval(
      RELEASE_LOCK_LUA,
      1,
      String(redisKey),
      String(expectedRawLease)
    );
    return Number(deleted) === 1 ? 1 : 0;
  } catch {
    // Best-effort atomic cleanup; bounded EX lease guarantees automatic recovery
    return 0;
  }
}

/**
 * Atomically transitions an in-progress Redis idempotency lease to a completed record
 * ONLY if the stored value still matches this request's exact lease payload
 * (including its unique owner_token).
 * Uses the Redis atomic compare-and-set Lua script supported by both InMemoryRedisClient
 * and real ioredis. Never falls back to non-atomic GET-then-SET; fails safely (returning 0)
 * if atomic eval is unavailable or if the lease expired or changed ownership.
 *
 * @param {object} redisClient
 * @param {string|null} redisKey
 * @param {string|null} expectedRawLease
 * @param {string} completedRecordJson
 * @param {number} ttlSeconds
 * @returns {Promise<number>} 1 if the lease was atomically completed, 0 otherwise
 */
async function completeInProgressLease(
  redisClient,
  redisKey,
  expectedRawLease,
  completedRecordJson,
  ttlSeconds
) {
  if (!redisClient || !redisKey || !expectedRawLease || !completedRecordJson) {
    return 0;
  }
  if (typeof redisClient.eval !== 'function') {
    return 0;
  }
  try {
    const completed = await redisClient.eval(
      COMPLETE_IDEMPOTENCY_LEASE_LUA,
      1,
      String(redisKey),
      String(expectedRawLease),
      String(completedRecordJson),
      String(ttlSeconds)
    );
    return Number(completed) === 1 ? 1 : 0;
  } catch {
    // Durable MySQL record with deterministicEventId and idempotency_payload_hash is already committed
    return 0;
  }
}

/**
 * Concurrency-safely rolls back a scored SecurityEvent whose required risk assessment
 * failed to persist, restoring ActionSequence/SequenceEvent state inside a row-locked
 * database transaction and invalidating the user's Redis active sequence cache so
 * subsequent reads fall back to authoritative MySQL state without risking stale cache overwrites.
 *
 * @param {string} eventId
 * @param {string} userId
 */
async function rollbackFailedScoredEvent(eventId, userId) {
  if (!eventId) {
    return;
  }

  await sequelize.transaction(async (t) => {
    const seqLink = await SequenceEvent.findOne({
      where: { event_id: eventId },
      transaction: t,
      lock: t.LOCK.UPDATE
    });

    if (seqLink) {
      const parentSeq = await ActionSequence.findByPk(seqLink.sequence_id, {
        transaction: t,
        lock: t.LOCK.UPDATE
      });

      await seqLink.destroy({ transaction: t });

      if (parentSeq) {
        const remainingLinks = await SequenceEvent.findAll({
          where: { sequence_id: parentSeq.id },
          include: [
            {
              model: SecurityEvent,
              as: 'securityEvent'
            }
          ],
          order: [
            ['step_order', 'ASC'],
            ['id', 'ASC']
          ],
          transaction: t,
          lock: t.LOCK.UPDATE
        });

        if (remainingLinks.length === 0) {
          await parentSeq.destroy({ transaction: t });
        } else {
          for (let idx = 0; idx < remainingLinks.length; idx += 1) {
            const expectedStep = idx + 1;
            if (remainingLinks[idx].step_order !== expectedStep) {
              await remainingLinks[idx].update(
                { step_order: expectedStep },
                { transaction: t }
              );
            }
          }

          let restoredLastEventAt =
            parentSeq.started_at instanceof Date
              ? parentSeq.started_at
              : new Date(parentSeq.started_at);

          for (let idx = 0; idx < remainingLinks.length; idx += 1) {
            const link = remainingLinks[idx];
            const evTimeRaw = link.securityEvent && link.securityEvent.timestamp;
            if (evTimeRaw) {
              const evTime = evTimeRaw instanceof Date ? evTimeRaw : new Date(evTimeRaw);
              if (idx === 0 || evTime > restoredLastEventAt) {
                restoredLastEventAt = evTime;
              }
            }
          }

          await parentSeq.update(
            {
              event_count: remainingLinks.length,
              last_event_at: restoredLastEventAt
            },
            { transaction: t }
          );
        }
      }
    }

    await SecurityEvent.destroy({
      where: { event_id: eventId },
      transaction: t
    });
  });

  if (userId) {
    try {
      await invalidateSequenceCache(userId);
    } catch {
      // Cache invalidation is best-effort; MySQL authoritative sequence state is committed
    }
  }
}

/**
 * Validates, deduplicates, persists, and evaluates an external security event submitted via POST /api/v1/events.
 *
 * @param {import('express').Request} req
 * @returns {Promise<{ httpStatus: number, body: object }>}
 */
async function ingestExternalSecurityEvent(req) {
  const body = req.body;
  if (!isPlainObject(body)) {
    return {
      httpStatus: 400,
      body: {
        error: {
          code: 'invalid_request',
          message: 'Request body must be a valid JSON object',
          status: 400
        }
      }
    };
  }

  // 1. Strict top-level field allowlist check
  const topKeys = Object.keys(body);
  for (const key of topKeys) {
    if (
      FORBIDDEN_AUTHORITATIVE_KEYS.has(key) ||
      FORBIDDEN_AUTHORITATIVE_KEYS.has(String(key).toLowerCase())
    ) {
      return {
        httpStatus: 400,
        body: {
          error: {
            code: 'invalid_request',
            message: `Field '${key}' is computed by ActionGuard and cannot be supplied by external callers`,
            status: 400
          }
        }
      };
    }
    if (!ALLOWED_TOP_LEVEL_FIELDS.has(key)) {
      return {
        httpStatus: 400,
        body: {
          error: {
            code: 'invalid_request',
            message: `Unknown top-level field '${key}' is not permitted`,
            status: 400
          }
        }
      };
    }
  }

  // 2. Validate idempotency key (header and/or body)
  const idemResolution = resolveIdempotencyKey(req);
  if (!idemResolution.valid) {
    return {
      httpStatus: 400,
      body: {
        error: {
          code: 'invalid_request',
          message: idemResolution.message,
          status: 400
        }
      }
    };
  }
  const idempotencyKey = idemResolution.idempotencyKey;

  // 3. Validate user_id syntax
  const rawUserId = body.user_id;
  if (
    typeof rawUserId !== 'string' ||
    rawUserId.trim().length === 0 ||
    rawUserId.trim().length > 128 ||
    !SAFE_IDENTIFIER_REGEX.test(rawUserId.trim())
  ) {
    return {
      httpStatus: 400,
      body: {
        error: {
          code: 'invalid_request',
          message: 'user_id is required and must be a valid identifier string',
          status: 400
        }
      }
    };
  }
  const resolvedUserId = rawUserId.trim();

  // 4. Validate session_id syntax (if provided)
  let resolvedSessionId = null;
  if (body.session_id !== undefined && body.session_id !== null) {
    if (
      typeof body.session_id !== 'string' ||
      body.session_id.trim().length === 0 ||
      body.session_id.trim().length > 128 ||
      !SAFE_IDENTIFIER_REGEX.test(body.session_id.trim())
    ) {
      return {
        httpStatus: 400,
        body: {
          error: {
            code: 'invalid_request',
            message: 'session_id must be a valid identifier string when provided',
            status: 400
          }
        }
      };
    }
    resolvedSessionId = body.session_id.trim();
  }

  // 5. Validate event_type against SecurityEvent.SUPPORTED_EVENT_TYPES
  const rawEventType = body.event_type;
  if (typeof rawEventType !== 'string' || rawEventType.trim().length === 0) {
    return {
      httpStatus: 400,
      body: {
        error: {
          code: 'invalid_request',
          message: 'event_type is required and must be a non-empty string',
          status: 400
        }
      }
    };
  }
  if (!SecurityEvent.SUPPORTED_EVENT_TYPES.includes(rawEventType)) {
    return {
      httpStatus: 400,
      body: {
        error: {
          code: 'invalid_event_type',
          message: `The event_type '${rawEventType}' is not a recognized event type.`,
          status: 400
        }
      }
    };
  }
  const resolvedEventType = rawEventType;

  // 6. Validate timestamp format and acceptable window (max 5m future, max 30d past)
  const timestampCheck = validateEventTimestamp(body.timestamp);
  if (!timestampCheck.valid) {
    return {
      httpStatus: 400,
      body: {
        error: {
          code: 'invalid_request',
          message: timestampCheck.message,
          status: 400
        }
      }
    };
  }
  const resolvedTimestamp = timestampCheck.date;

  // 7. Validate context against allowlist
  const rawApiKey = typeof req.apiKey === 'string' ? req.apiKey : '';
  const contextCheck = validateAndNormalizeContext(body.context, rawApiKey);
  if (!contextCheck.valid) {
    return {
      httpStatus: 400,
      body: {
        error: {
          code: 'invalid_request',
          message: contextCheck.message,
          status: 400
        }
      }
    };
  }
  const clientContext = contextCheck.context;

  // 8. Load active policy and validate metadata against allowlist + sensitivity floor
  let activePolicy;
  try {
    activePolicy = policyLoader.loadActivePolicy();
  } catch {
    return {
      httpStatus: 503,
      body: {
        error: {
          code: 'pipeline_unavailable',
          message: 'Policy configuration is temporarily unavailable',
          status: 503
        }
      }
    };
  }

  const metadataCheck = validateAndSanitizeMetadata(
    body.metadata,
    resolvedEventType,
    activePolicy,
    rawApiKey
  );
  if (!metadataCheck.valid) {
    return {
      httpStatus: 400,
      body: {
        error: {
          code: 'invalid_request',
          message: metadataCheck.message,
          status: 400
        }
      }
    };
  }

  // 9. Compute API key fingerprint & canonical payload hash for idempotency
  const apiKeyFingerprint = computeApiKeyFingerprint(rawApiKey);
  const canonicalPayload = {
    user_id: resolvedUserId,
    session_id: resolvedSessionId,
    event_type: resolvedEventType,
    timestamp: resolvedTimestamp.toISOString(),
    context: clientContext,
    metadata: {
      ...metadataCheck.clientMetadata,
      provided_action_sensitivity: metadataCheck.providedSensitivity
    }
  };
  const payloadHash = computeCanonicalPayloadHash(canonicalPayload);

  // 10. Idempotency check & atomic lease acquisition in Redis (if idempotencyKey supplied)
  const redisClient = redisStorage.getRedisClient();
  let redisIdemKey = null;
  let inProgressLeaseRaw = null;
  let deterministicEventId = null;

  const idemTtlSeconds = parsePositiveIntEnv(
    process.env.EXTERNAL_EVENT_IDEMPOTENCY_TTL_SECONDS,
    DEFAULT_IDEMPOTENCY_TTL_SECONDS
  );
  const leaseSeconds = parsePositiveIntEnv(
    process.env.EXTERNAL_EVENT_IDEMPOTENCY_LEASE_SECONDS,
    DEFAULT_IDEMPOTENCY_LEASE_SECONDS
  );

  if (idempotencyKey) {
    redisIdemKey = `${REDIS_PREFIXES.EXTERNAL_EVENT_IDEMPOTENCY}${apiKeyFingerprint}:${idempotencyKey}`;
    deterministicEventId = deriveDeterministicEventId(apiKeyFingerprint, idempotencyKey);

    const nowMs = Date.now();
    const leasePayload = {
      status: 'in_progress',
      payload_hash: payloadHash,
      owner_token: crypto.randomUUID(),
      started_at_ms: nowMs,
      lease_expires_at_ms: nowMs + leaseSeconds * 1000
    };
    inProgressLeaseRaw = JSON.stringify(leasePayload);

    try {
      const acquired = await redisClient.set(
        redisIdemKey,
        inProgressLeaseRaw,
        'EX',
        leaseSeconds,
        'NX'
      );

      if (!acquired) {
        const existingRaw = await redisClient.get(redisIdemKey);
        if (existingRaw) {
          let existingState = null;
          try {
            existingState = JSON.parse(existingRaw);
          } catch {
            existingState = null;
          }

          if (existingState && typeof existingState === 'object') {
            const hashesMatch = constantTimeKeyMatch(
              existingState.payload_hash,
              payloadHash
            );
            if (!hashesMatch) {
              return {
                httpStatus: 409,
                body: {
                  error: {
                    code: 'idempotency_conflict',
                    message:
                      'Idempotency key has already been used with a different request payload',
                    status: 409
                  }
                }
              };
            }

            if (existingState.status === 'completed' && existingState.response) {
              return {
                httpStatus: 200,
                body: existingState.response
              };
            }

            if (
              existingState.status === 'in_progress' &&
              (!existingState.lease_expires_at_ms ||
                Date.now() < Number(existingState.lease_expires_at_ms))
            ) {
              return {
                httpStatus: 409,
                body: {
                  error: {
                    code: 'idempotency_in_progress',
                    message: 'A request with this idempotency key is currently being processed',
                    status: 409
                  }
                }
              };
            }
          }
        }

        // Stale or just-released key: attempt one atomic re-claim
        const retryAcquired = await redisClient.set(
          redisIdemKey,
          inProgressLeaseRaw,
          'EX',
          leaseSeconds,
          'NX'
        );
        if (!retryAcquired) {
          return {
            httpStatus: 409,
            body: {
              error: {
                code: 'idempotency_in_progress',
                message: 'A request with this idempotency key is currently being processed',
                status: 409
              }
            }
          };
        }
      }
    } catch {
      return {
        httpStatus: 503,
        body: {
          error: {
            code: 'service_unavailable',
            message: 'Idempotency service is temporarily unavailable',
            status: 503
          }
        }
      };
    }
  }

  try {
    // 11. Verify user exists in database
    const userRecord = await User.findByPk(resolvedUserId);
    if (!userRecord) {
      await releaseInProgressLease(redisClient, redisIdemKey, inProgressLeaseRaw);
      return {
        httpStatus: 400,
        body: {
          error: {
            code: 'invalid_request',
            message: 'user_id does not identify an existing user',
            status: 400
          }
        }
      };
    }

    // 12. Verify session exists and belongs to user_id (if session_id supplied)
    if (resolvedSessionId !== null) {
      const sessionRecord = await Session.findOne({
        where: {
          id: resolvedSessionId,
          user_id: resolvedUserId
        }
      });
      if (!sessionRecord) {
        await releaseInProgressLease(redisClient, redisIdemKey, inProgressLeaseRaw);
        return {
          httpStatus: 400,
          body: {
            error: {
              code: 'invalid_request',
              message: 'session_id does not exist or does not belong to the specified user',
              status: 400
            }
          }
        };
      }
    }

    const isUnscoredEvent =
      Array.isArray(riskConfig.UNSCORED_EVENT_TYPES) &&
      riskConfig.UNSCORED_EVENT_TYPES.includes(resolvedEventType);

    // 13. Durable database idempotency check (handles Redis eviction or prior partial failure)
    if (deterministicEventId) {
      const existingEvent = await SecurityEvent.findByPk(deterministicEventId);
      if (existingEvent) {
        const storedHash =
          existingEvent.metadata && existingEvent.metadata.idempotency_payload_hash;
        if (storedHash && !constantTimeKeyMatch(storedHash, payloadHash)) {
          await releaseInProgressLease(redisClient, redisIdemKey, inProgressLeaseRaw);
          return {
            httpStatus: 409,
            body: {
              error: {
                code: 'idempotency_conflict',
                message:
                  'Idempotency key has already been used with a different request payload',
                status: 409
              }
            }
          };
        }

        let existingAssessment = null;
        let recoveredFromPartial = false;

        if (!isUnscoredEvent) {
          existingAssessment = await RiskAssessment.findOne({
            where: { event_id: existingEvent.event_id }
          });

          if (!existingAssessment) {
            // Previous attempt crashed after SecurityEvent.create but before RiskAssessment was saved
            recoveredFromPartial = true;
            const existingSeqLink = await SequenceEvent.findOne({
              where: { event_id: existingEvent.event_id }
            });
            if (!existingSeqLink) {
              await correlateEventIntoSequence(existingEvent);
            }
            existingAssessment =
              await riskEngineService.evaluateAndStoreRiskForEvent(existingEvent);
            if (!existingAssessment) {
              try {
                await rollbackFailedScoredEvent(existingEvent.event_id, resolvedUserId);
              } catch {
                // Best-effort cleanup on recovery failure
              }
              await releaseInProgressLease(redisClient, redisIdemKey, inProgressLeaseRaw);
              return {
                httpStatus: 503,
                body: {
                  error: {
                    code: 'pipeline_unavailable',
                    message: 'Security event risk evaluation pipeline is temporarily unavailable',
                    status: 503
                  }
                }
              };
            }

            try {
              const plainEvent =
                typeof existingEvent.get === 'function'
                  ? existingEvent.get({ plain: true })
                  : { ...existingEvent };
              const plainAssessment =
                typeof existingAssessment.get === 'function'
                  ? existingAssessment.get({ plain: true })
                  : { ...existingAssessment };
              eventBus.safeEmit('pipeline:event_processed', {
                event: plainEvent,
                assessment: plainAssessment
              });
            } catch {
              // Ignore broadcast errors after durable persistence
            }
          }
        }

        const recoveredResponse = buildEventIngestionResponse(
          existingEvent,
          existingAssessment,
          activePolicy,
          metadataCheck.effectiveSensitivity
        );

        await completeInProgressLease(
          redisClient,
          redisIdemKey,
          inProgressLeaseRaw,
          JSON.stringify({
            status: 'completed',
            payload_hash: payloadHash,
            response: recoveredResponse,
            completed_at: new Date().toISOString()
          }),
          idemTtlSeconds
        );

        return {
          httpStatus: recoveredFromPartial ? 201 : 200,
          body: recoveredResponse
        };
      }
    }

    // 14. Server-side context enrichment (resolve approximate geo_country / geo_region from IP)
    const enrichedContext = { ...clientContext };
    if (enrichedContext.ip_address) {
      try {
        const geo = await geoService.resolveGeoLocation(enrichedContext.ip_address);
        if (geo && geo.geo_country) {
          enrichedContext.geo_country = geo.geo_country;
        }
        if (geo && geo.geo_region) {
          enrichedContext.geo_region = geo.geo_region;
        }
      } catch {
        // Safe fallback if GeoIP is unavailable
      }
    }

    // Associate untrusted device record if fingerprint is present on login_success or new_device
    if (
      enrichedContext.device_fingerprint &&
      (resolvedEventType === 'login_success' || resolvedEventType === 'new_device')
    ) {
      try {
        await getOrCreateDevice(resolvedUserId, enrichedContext.device_fingerprint);
      } catch {
        // Safe fallback
      }
    }

    // 15. Build server-stamped metadata with source attribution and API key fingerprint
    const enrichedMetadata = {
      ...metadataCheck.clientMetadata,
      source: 'external_api',
      api_key_fingerprint: apiKeyFingerprint
    };

    if (idempotencyKey) {
      enrichedMetadata.idempotency_payload_hash = payloadHash;
    }

    if (resolvedEventType === 'login_success' && enrichedContext.ip_address) {
      try {
        const travelAnomaly = await collectTravelAnomalySignal(
          resolvedUserId,
          enrichedContext.ip_address,
          resolvedTimestamp
        );
        if (travelAnomaly) {
          enrichedMetadata.travel_anomaly = travelAnomaly;
        }
      } catch {
        // Safe fallback if travel collector fails
      }
    }

    // 16. Persist and process event through the existing eventService pipeline.
    // Pass per-call requireAssessmentForEmit for scored events so pipeline:event_processed
    // is not emitted if risk evaluation fails and the event is rolled back.
    const targetEventId = deterministicEventId || `evt_${crypto.randomUUID()}`;
    const createdEvent = await eventService.recordSecurityEvent(
      {
        eventId: targetEventId,
        userId: resolvedUserId,
        sessionId: resolvedSessionId,
        eventType: resolvedEventType,
        timestamp: resolvedTimestamp,
        context: enrichedContext,
        metadata: enrichedMetadata,
        requireAssessmentForEmit: !isUnscoredEvent
      },
      {
        requireAssessmentForEmit: !isUnscoredEvent
      }
    );

    if (!createdEvent) {
      await releaseInProgressLease(redisClient, redisIdemKey, inProgressLeaseRaw);
      return {
        httpStatus: 503,
        body: {
          error: {
            code: 'pipeline_unavailable',
            message: 'Security event persistence failed',
            status: 503
          }
        }
      };
    }

    // 17. Verify risk assessment succeeded for scored event types
    const assessmentRecord = createdEvent._assessment || null;
    if (!isUnscoredEvent && !assessmentRecord) {
      // Concurrency-safely roll back the incomplete event and restore sequence state
      try {
        await rollbackFailedScoredEvent(createdEvent.event_id, resolvedUserId);
      } catch {
        // If cleanup fails, deterministicEventId recovery path handles retry safely
      }
      await releaseInProgressLease(redisClient, redisIdemKey, inProgressLeaseRaw);
      return {
        httpStatus: 503,
        body: {
          error: {
            code: 'pipeline_unavailable',
            message: 'Security event risk evaluation pipeline is temporarily unavailable',
            status: 503
          }
        }
      };
    }

    const responsePayload = buildEventIngestionResponse(
      createdEvent,
      assessmentRecord,
      activePolicy,
      metadataCheck.effectiveSensitivity
    );

    // 18. Atomically transition owned in-progress lease to completed response in Redis with 24h TTL
    if (redisIdemKey) {
      await completeInProgressLease(
        redisClient,
        redisIdemKey,
        inProgressLeaseRaw,
        JSON.stringify({
          status: 'completed',
          payload_hash: payloadHash,
          response: responsePayload,
          completed_at: new Date().toISOString()
        }),
        idemTtlSeconds
      );
    }

    return {
      httpStatus: 201,
      body: responsePayload
    };
  } catch (_err) {
    await releaseInProgressLease(redisClient, redisIdemKey, inProgressLeaseRaw);
    return {
      httpStatus: 503,
      body: {
        error: {
          code: 'pipeline_unavailable',
          message: 'Security event ingestion service is temporarily unavailable',
          status: 503
        }
      }
    };
  }
}

module.exports = {
  ingestExternalSecurityEvent,
  validateEventTimestamp,
  validateAndNormalizeContext,
  validateAndSanitizeMetadata,
  resolveIdempotencyKey,
  computeApiKeyFingerprint,
  deriveDeterministicEventId,
  computeCanonicalPayloadHash,
  redactSecretsFromString,
  releaseInProgressLease,
  completeInProgressLease,
  rollbackFailedScoredEvent,
  DEFAULT_MAX_FUTURE_SKEW_MS,
  DEFAULT_MAX_PAST_AGE_MS,
  DEFAULT_IDEMPOTENCY_TTL_SECONDS,
  DEFAULT_IDEMPOTENCY_LEASE_SECONDS
};
