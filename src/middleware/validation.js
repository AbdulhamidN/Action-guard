'use strict';

const { sendError } = require('../utils/errors');

const VALIDATION_LIMITS = Object.freeze({
  MAX_EMAIL_LENGTH: 254,
  MAX_PASSWORD_LENGTH: 256,
  MIN_SIGNUP_PASSWORD_LENGTH: 6,
  MIN_CHANGE_PASSWORD_LENGTH: 8,
  MAX_ID_PARAM_LENGTH: 128,
  MAX_SCOPE_LENGTH: 64,
  MAX_CHALLENGE_ID_LENGTH: 128,
  MAX_OTP_CODE_LENGTH: 16,
  MAX_TICKET_LENGTH: 4096,
  MAX_TOKEN_LENGTH: 512,
  MAX_STRING_FIELD_LENGTH: 1024,
  MAX_OBJECT_DEPTH: 20
});

const FORBIDDEN_PROTOTYPE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const SAFE_ID_REGEX = /^[a-zA-Z0-9_.:-]+$/;

/**
 * Checks whether a value is a plain JavaScript object (not null, not an array).
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function isPlainObject(value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Recursively scans an object or array for prototype-pollution keys
 * (`__proto__`, `constructor`, `prototype`) or excessive nesting depth.
 * Uses `Object.getOwnPropertyNames` so own `__proto__` properties created by
 * `JSON.parse` are reliably detected at any nesting level.
 *
 * @param {unknown} value
 * @param {number} [depth=0]
 * @returns {{ forbidden: boolean, reason?: string }}
 */
function inspectPayloadSafety(value, depth = 0) {
  if (depth > VALIDATION_LIMITS.MAX_OBJECT_DEPTH) {
    return { forbidden: true, reason: 'exceeds_max_depth' };
  }

  if (value === null || value === undefined || typeof value !== 'object') {
    return { forbidden: false };
  }

  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      const nested = inspectPayloadSafety(value[i], depth + 1);
      if (nested.forbidden) {
        return nested;
      }
    }
    return { forbidden: false };
  }

  if (!isPlainObject(value)) {
    return { forbidden: true, reason: 'prototype_pollution_key' };
  }

  const ownKeys = Object.getOwnPropertyNames(value);
  for (let i = 0; i < ownKeys.length; i += 1) {
    const key = ownKeys[i];
    if (FORBIDDEN_PROTOTYPE_KEYS.has(key)) {
      return { forbidden: true, reason: 'prototype_pollution_key' };
    }
    const nested = inspectPayloadSafety(value[key], depth + 1);
    if (nested.forbidden) {
      return nested;
    }
  }

  return { forbidden: false };
}

/**
 * Boolean convenience wrapper checking whether an object/array contains
 * any prototype-pollution keys or exceeds maximum nesting depth.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function hasForbiddenKeys(value) {
  return inspectPayloadSafety(value).forbidden;
}

/**
 * Inspects the raw request URL query string for forbidden prototype-pollution
 * tokens (`__proto__`, `constructor`, `prototype`), catching cases where the
 * query parser may strip or transform bracketed keys.
 *
 * @param {string} originalUrl
 * @returns {boolean}
 */
function hasForbiddenQueryTokens(originalUrl) {
  if (typeof originalUrl !== 'string') {
    return false;
  }
  const qIndex = originalUrl.indexOf('?');
  if (qIndex === -1) {
    return false;
  }
  let rawQuery = originalUrl.slice(qIndex + 1);
  try {
    rawQuery = decodeURIComponent(rawQuery);
  } catch {
    // Keep raw string if malformed percent-encoding is present
  }
  return /(?:^|[&?[\].=])(?:__proto__|constructor|prototype)(?:$|[&[\].=])/i.test(rawQuery);
}

/**
 * Global request-envelope validation middleware executed immediately after `express.json()`.
 * - Rejects non-plain-object JSON bodies (arrays, primitives, null) with 400 `invalid_request`.
 * - Rejects prototype-pollution keys (`__proto__`, `constructor`, `prototype`) in body or query.
 * - Rejects excessively nested payloads (> 20 levels).
 * - Normalizes undefined `req.body` on POST/PUT/PATCH to `{}` so downstream destructuring is safe.
 * - Never logs sensitive rejected payloads.
 */
function validateRequestEnvelope(req, res, next) {
  if (hasForbiddenQueryTokens(req.originalUrl) || (req.query && hasForbiddenKeys(req.query))) {
    return sendError(
      res,
      400,
      'invalid_request',
      'Query parameters contain forbidden keys'
    );
  }

  if (req.body !== undefined) {
    if (!isPlainObject(req.body)) {
      return sendError(
        res,
        400,
        'invalid_request',
        'Request body must be a valid JSON object'
      );
    }

    const safety = inspectPayloadSafety(req.body);
    if (safety.forbidden) {
      const msg =
        safety.reason === 'exceeds_max_depth'
          ? 'Request body exceeds maximum allowed nesting depth'
          : 'Request body contains forbidden keys';
      return sendError(res, 400, 'invalid_request', msg);
    }
  } else if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
    // Reject explicitly sent non-empty JSON bodies that evaluated to undefined only if applicable;
    // otherwise normalize omitted body to empty plain object.
    req.body = {};
  }

  return next();
}

/**
 * Express error-handling middleware for `express.json()` body-parser errors.
 * Converts 413 PayloadTooLargeError and 400 SyntaxError into ActionGuard's
 * standard JSON error envelope without leaking stack traces or raw payloads.
 */
function jsonBodyErrorHandler(err, _req, res, next) {
  if (!err) {
    return next();
  }

  if (
    err.type === 'entity.too.large' ||
    err.status === 413 ||
    err.statusCode === 413
  ) {
    return sendError(
      res,
      413,
      'payload_too_large',
      'Request payload exceeds maximum allowed size'
    );
  }

  if (
    err instanceof SyntaxError &&
    (err.status === 400 || err.statusCode === 400 || 'body' in err)
  ) {
    return sendError(
      res,
      400,
      'invalid_request',
      'Malformed JSON request body'
    );
  }

  if (err.type === 'entity.parse.failed') {
    return sendError(
      res,
      400,
      'invalid_request',
      'Malformed JSON request body'
    );
  }

  return next(err);
}

/**
 * Validates a route parameter (default `:id`) to ensure it is a bounded,
 * safe identifier string before hitting Redis or database queries.
 *
 * @param {string} [paramName='id']
 */
function validateIdParam(paramName = 'id') {
  return function validateIdParamMiddleware(req, res, next) {
    const val = req.params ? req.params[paramName] : undefined;
    if (
      typeof val !== 'string' ||
      val.trim().length === 0 ||
      val.length > VALIDATION_LIMITS.MAX_ID_PARAM_LENGTH ||
      !SAFE_ID_REGEX.test(val)
    ) {
      return sendError(
        res,
        400,
        'invalid_request',
        `Route parameter '${paramName}' must be a valid identifier (1-${VALIDATION_LIMITS.MAX_ID_PARAM_LENGTH} characters)`
      );
    }
    return next();
  };
}

/**
 * Validates bounded string constraints without logging the value.
 *
 * @param {unknown} value
 * @param {object} [options={}]
 * @param {number} [options.minLength=1]
 * @param {number} [options.maxLength=VALIDATION_LIMITS.MAX_STRING_FIELD_LENGTH]
 * @param {boolean} [options.trim=false]
 * @returns {boolean}
 */
function isBoundedString(value, options = {}) {
  if (typeof value !== 'string') {
    return false;
  }
  const minLength = options.minLength !== undefined ? options.minLength : 1;
  const maxLength =
    options.maxLength !== undefined
      ? options.maxLength
      : VALIDATION_LIMITS.MAX_STRING_FIELD_LENGTH;
  const target = options.trim ? value.trim() : value;
  return target.length >= minLength && value.length <= maxLength;
}

module.exports = {
  VALIDATION_LIMITS,
  FORBIDDEN_PROTOTYPE_KEYS,
  isPlainObject,
  inspectPayloadSafety,
  hasForbiddenKeys,
  hasForbiddenQueryTokens,
  validateRequestEnvelope,
  jsonBodyErrorHandler,
  validateIdParam,
  isBoundedString
};
