'use strict';

const crypto = require('crypto');
const { sequelize, WebhookEndpoint } = require('../database/models');
const { isPlainObject } = require('../middleware/validation');
const { ApiError } = require('../utils/errors');
const {
  generateWebhookSecret,
  encryptWebhookSecret
} = require('../utils/webhookCrypto');
const { validateWebhookDestinationUrl } = require('../utils/webhookUrlValidator');
const eventBus = require('../events/eventBus');

const WEBHOOK_ID_REGEX = /^whk_[a-zA-Z0-9_-]{1,60}$/;
const CONTROL_CHAR_REGEX = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/;
const MAX_DESCRIPTION_LENGTH = 255;
const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 100;

const SECRET_VALUE_PATTERNS = [
  /\bBearer\s+[A-Za-z0-9._~+/=-]{6,}/i,
  /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/,
  /\$2[aby]\$\d{2}\$[./A-Za-z0-9]{20,}/,
  /\b(?:whsec|ctkn)_[A-Za-z0-9_-]{6,}/i,
  /\b(?:password|secret|token|api_?key|private_?key|client_secret)\s*[:=]\s*\S+/i
];

const ALLOWED_CREATE_FIELDS = Object.freeze(
  new Set(['url', 'subscribed_events', 'description', 'is_active'])
);

const ALLOWED_UPDATE_FIELDS = Object.freeze(
  new Set(['url', 'subscribed_events', 'description', 'is_active'])
);

const ALLOWED_LIST_QUERY_FIELDS = Object.freeze(
  new Set(['is_active', 'limit', 'offset'])
);

const SAFE_WEBHOOK_ATTRIBUTES = Object.freeze([
  'id',
  'url',
  'subscribed_events',
  'description',
  'secret_prefix',
  'is_active',
  'created_at',
  'updated_at'
]);

/**
 * Validates that a webhook endpoint ID matches the server-issued `whk_<id>` format
 * and fits within the `STRING(64)` column limit.
 *
 * @param {unknown} rawId
 * @returns {string}
 * @throws {ApiError} 400 `invalid_request`
 */
function validateWebhookEndpointId(rawId) {
  if (
    typeof rawId !== 'string' ||
    rawId.trim().length === 0 ||
    rawId.length > 64 ||
    !WEBHOOK_ID_REGEX.test(rawId)
  ) {
    throw new ApiError(
      400,
      'invalid_request',
      'Invalid webhook endpoint ID format (expected whk_<identifier>)'
    );
  }
  return rawId;
}

/**
 * Validates `subscribed_events` against `WebhookEndpoint.SUPPORTED_WEBHOOK_EVENTS`.
 * Rejects non-arrays, empty arrays, unsupported event names, and duplicate entries.
 *
 * @param {unknown} rawEvents
 * @returns {string[]}
 * @throws {ApiError} 400 `invalid_subscribed_events`
 */
function validateSubscribedEvents(rawEvents) {
  if (!Array.isArray(rawEvents) || rawEvents.length === 0) {
    throw new ApiError(
      400,
      'invalid_subscribed_events',
      'subscribed_events must be a non-empty array of supported event types'
    );
  }

  const supported = WebhookEndpoint.SUPPORTED_WEBHOOK_EVENTS;
  if (rawEvents.length > supported.length) {
    throw new ApiError(
      400,
      'invalid_subscribed_events',
      `subscribed_events cannot contain more than ${supported.length} event types`
    );
  }

  const seen = new Set();
  const normalized = [];

  for (const item of rawEvents) {
    if (typeof item !== 'string' || !supported.includes(item)) {
      throw new ApiError(
        400,
        'invalid_subscribed_events',
        `Unsupported webhook event type '${String(item)}'. Supported events: ${supported.join(', ')}`
      );
    }
    if (seen.has(item)) {
      throw new ApiError(
        400,
        'invalid_subscribed_events',
        `Duplicate webhook event type '${item}' in subscribed_events`
      );
    }
    seen.add(item);
    normalized.push(item);
  }

  return normalized;
}

/**
 * Validates and normalizes the optional `description` field.
 * Rejects non-strings, strings > 255 chars, control characters, and secret-bearing values.
 *
 * @param {unknown} rawDescription
 * @returns {string|null}
 * @throws {ApiError} 400 `invalid_request`
 */
function validateWebhookDescription(rawDescription) {
  if (rawDescription === undefined || rawDescription === null) {
    return null;
  }

  if (typeof rawDescription !== 'string') {
    throw new ApiError(400, 'invalid_request', 'description must be a string or null');
  }

  if (rawDescription.length > MAX_DESCRIPTION_LENGTH) {
    throw new ApiError(
      400,
      'invalid_request',
      `description must not exceed ${MAX_DESCRIPTION_LENGTH} characters`
    );
  }

  if (CONTROL_CHAR_REGEX.test(rawDescription)) {
    throw new ApiError(
      400,
      'invalid_request',
      'description must not contain control characters'
    );
  }

  for (const pattern of SECRET_VALUE_PATTERNS) {
    if (pattern.test(rawDescription)) {
      throw new ApiError(
        400,
        'invalid_request',
        'description must not contain credentials, tokens, or secret material'
      );
    }
  }

  const trimmed = rawDescription.trim();
  return trimmed.length === 0 ? null : trimmed;
}

/**
 * Validates that an object only contains keys from `allowedSet`.
 *
 * @param {object} obj
 * @param {Set<string>} allowedSet
 * @param {string} contextLabel
 * @throws {ApiError} 400 `invalid_request`
 */
function assertOnlyAllowedKeys(obj, allowedSet, contextLabel = 'Request body') {
  if (!isPlainObject(obj)) {
    throw new ApiError(400, 'invalid_request', `${contextLabel} must be a JSON object`);
  }

  const keys = Object.keys(obj);
  for (const key of keys) {
    if (!allowedSet.has(key)) {
      throw new ApiError(
        400,
        'invalid_request',
        `${contextLabel} contains unknown or non-writable field '${key}'`
      );
    }
  }
}

/**
 * Serializes a WebhookEndpoint record into a public, secret-free response object.
 * Explicitly allowlists safe metadata attributes and never includes plaintext secrets,
 * encrypted_secret, secret_iv, or secret_auth_tag.
 *
 * @param {object} endpoint
 * @returns {object}
 */
function serializeWebhookEndpoint(endpoint) {
  const plain =
    endpoint && typeof endpoint.toJSON === 'function' ? endpoint.toJSON() : endpoint || {};

  const createdAt =
    plain.created_at instanceof Date
      ? plain.created_at.toISOString()
      : new Date(plain.created_at).toISOString();
  const updatedAt =
    plain.updated_at instanceof Date
      ? plain.updated_at.toISOString()
      : new Date(plain.updated_at).toISOString();

  return {
    id: plain.id,
    url: plain.url,
    subscribed_events: Array.isArray(plain.subscribed_events)
      ? [...plain.subscribed_events]
      : [],
    description: plain.description !== undefined ? plain.description : null,
    secret_prefix: plain.secret_prefix,
    is_active: Boolean(plain.is_active),
    created_at: createdAt,
    updated_at: updatedAt
  };
}

/**
 * Emits a secret-free administrative audit notification on the internal event bus.
 *
 * @param {string} action
 * @param {object} serializedWebhook
 */
function emitWebhookAdminAudit(action, serializedWebhook) {
  eventBus.safeEmit('webhook:endpoint_audit', {
    action,
    webhook_id: serializedWebhook.id,
    url: serializedWebhook.url || null,
    subscribed_events: serializedWebhook.subscribed_events || null,
    is_active:
      serializedWebhook.is_active !== undefined ? serializedWebhook.is_active : null,
    secret_prefix: serializedWebhook.secret_prefix || null,
    timestamp: new Date().toISOString()
  });
}

/**
 * Registers a new outbound webhook endpoint with a server-generated ID and
 * AES-256-GCM encrypted signing secret.
 *
 * Security contract (one-time secret disclosure):
 * - The full `signing_secret` (`whsec_<64 hex chars>`) is returned ONLY ONCE in the
 *   successful creation response after the encrypted record has been persisted.
 * - Subsequent list, retrieve, update, activate, deactivate, and delete operations
 *   never return `signing_secret`.
 * - Audit events, logs, and database rows never contain the plaintext `signing_secret`.
 *
 * @param {object} payload
 * @returns {Promise<object>} Safe serialized webhook metadata plus one-time `signing_secret`
 */
async function registerWebhookEndpoint(payload) {
  assertOnlyAllowedKeys(payload, ALLOWED_CREATE_FIELDS, 'Request body');

  if (payload.url === undefined || payload.url === null) {
    throw new ApiError(400, 'invalid_request', 'url is required');
  }

  const validatedUrl = validateWebhookDestinationUrl(payload.url);

  const subscribedEvents =
    payload.subscribed_events !== undefined
      ? validateSubscribedEvents(payload.subscribed_events)
      : [...WebhookEndpoint.SUPPORTED_WEBHOOK_EVENTS];

  const description = validateWebhookDescription(payload.description);

  let isActive = true;
  if (payload.is_active !== undefined) {
    if (typeof payload.is_active !== 'boolean') {
      throw new ApiError(400, 'invalid_request', 'is_active must be a boolean');
    }
    isActive = payload.is_active;
  }

  const { secret, secret_prefix } = generateWebhookSecret();
  const { encrypted_secret, secret_iv, secret_auth_tag } = encryptWebhookSecret(secret);

  const now = new Date();
  const endpointId = `whk_${crypto.randomUUID()}`;

  const created = await WebhookEndpoint.create({
    id: endpointId,
    url: validatedUrl,
    subscribed_events: subscribedEvents,
    description,
    encrypted_secret,
    secret_iv,
    secret_auth_tag,
    secret_prefix,
    is_active: isActive,
    created_at: now,
    updated_at: now
  });

  const serialized = serializeWebhookEndpoint(created);
  emitWebhookAdminAudit('registered', serialized);

  return {
    ...serialized,
    signing_secret: secret
  };
}

/**
 * Lists registered webhook endpoints with safe metadata only.
 *
 * @param {object} [query={}]
 * @returns {Promise<{ webhooks: object[], count: number, total: number }>}
 */
async function listWebhookEndpoints(query = {}) {
  assertOnlyAllowedKeys(query, ALLOWED_LIST_QUERY_FIELDS, 'Query parameters');

  const where = {};
  if (query.is_active !== undefined) {
    if (query.is_active === 'true' || query.is_active === true) {
      where.is_active = true;
    } else if (query.is_active === 'false' || query.is_active === false) {
      where.is_active = false;
    } else {
      throw new ApiError(
        400,
        'invalid_request',
        "Query parameter 'is_active' must be 'true' or 'false'"
      );
    }
  }

  let limit = DEFAULT_LIST_LIMIT;
  if (query.limit !== undefined) {
    const limitStr = String(query.limit).trim();
    if (!/^\d+$/.test(limitStr)) {
      throw new ApiError(400, 'invalid_request', 'limit must be a positive integer');
    }
    const parsedLimit = Number.parseInt(limitStr, 10);
    if (!Number.isSafeInteger(parsedLimit) || parsedLimit < 1 || parsedLimit > MAX_LIST_LIMIT) {
      throw new ApiError(
        400,
        'invalid_request',
        `limit must be an integer between 1 and ${MAX_LIST_LIMIT}`
      );
    }
    limit = parsedLimit;
  }

  let offset = 0;
  if (query.offset !== undefined) {
    const offsetStr = String(query.offset).trim();
    if (!/^\d+$/.test(offsetStr)) {
      throw new ApiError(400, 'invalid_request', 'offset must be a non-negative integer');
    }
    const parsedOffset = Number.parseInt(offsetStr, 10);
    if (!Number.isSafeInteger(parsedOffset) || parsedOffset < 0) {
      throw new ApiError(400, 'invalid_request', 'offset must be a non-negative integer');
    }
    offset = parsedOffset;
  }

  const { rows, count } = await WebhookEndpoint.findAndCountAll({
    where,
    attributes: SAFE_WEBHOOK_ATTRIBUTES,
    order: [
      ['created_at', 'DESC'],
      ['id', 'ASC']
    ],
    limit,
    offset
  });

  const webhooks = rows.map((row) => serializeWebhookEndpoint(row));
  return {
    webhooks,
    count: webhooks.length,
    total: count
  };
}

/**
 * Retrieves a single webhook endpoint by ID with safe metadata only.
 *
 * @param {string} rawId
 * @param {object} [query={}]
 * @returns {Promise<object>}
 */
async function getWebhookEndpointById(rawId, query = {}) {
  const id = validateWebhookEndpointId(rawId);
  assertOnlyAllowedKeys(query, new Set(), 'Query parameters');

  const endpoint = await WebhookEndpoint.findByPk(id, {
    attributes: SAFE_WEBHOOK_ATTRIBUTES
  });

  if (!endpoint) {
    throw new ApiError(404, 'webhook_not_found', 'Webhook endpoint not found');
  }

  return serializeWebhookEndpoint(endpoint);
}

/**
 * Updates permitted settings (`url`, `subscribed_events`, `description`, `is_active`)
 * on an existing webhook endpoint.
 *
 * @param {string} rawId
 * @param {object} payload
 * @param {object} [query={}]
 * @returns {Promise<object>}
 */
async function updateWebhookEndpoint(rawId, payload, query = {}) {
  const id = validateWebhookEndpointId(rawId);
  assertOnlyAllowedKeys(query, new Set(), 'Query parameters');
  assertOnlyAllowedKeys(payload, ALLOWED_UPDATE_FIELDS, 'Request body');

  const providedKeys = Object.keys(payload);
  if (providedKeys.length === 0) {
    throw new ApiError(
      400,
      'invalid_request',
      'Update request must specify at least one updatable field (url, subscribed_events, description, is_active)'
    );
  }

  const updates = {};

  if (Object.prototype.hasOwnProperty.call(payload, 'url')) {
    updates.url = validateWebhookDestinationUrl(payload.url);
  }

  if (Object.prototype.hasOwnProperty.call(payload, 'subscribed_events')) {
    updates.subscribed_events = validateSubscribedEvents(payload.subscribed_events);
  }

  if (Object.prototype.hasOwnProperty.call(payload, 'description')) {
    updates.description = validateWebhookDescription(payload.description);
  }

  if (Object.prototype.hasOwnProperty.call(payload, 'is_active')) {
    if (typeof payload.is_active !== 'boolean') {
      throw new ApiError(400, 'invalid_request', 'is_active must be a boolean');
    }
    updates.is_active = payload.is_active;
  }

  const serialized = await sequelize.transaction(async (t) => {
    const endpoint = await WebhookEndpoint.findByPk(id, {
      attributes: SAFE_WEBHOOK_ATTRIBUTES,
      transaction: t,
      lock: t.LOCK.UPDATE
    });

    if (!endpoint) {
      throw new ApiError(404, 'webhook_not_found', 'Webhook endpoint not found');
    }

    updates.updated_at = new Date();
    await endpoint.update(updates, { transaction: t });
    return serializeWebhookEndpoint(endpoint);
  });

  emitWebhookAdminAudit('updated', serialized);
  return serialized;
}

/**
 * Explicitly activates or deactivates a webhook endpoint by ID.
 *
 * @param {string} rawId
 * @param {boolean} isActive
 * @param {object} [body={}]
 * @param {object} [query={}]
 * @returns {Promise<object>}
 */
async function setWebhookEndpointActiveState(rawId, isActive, body = {}, query = {}) {
  const id = validateWebhookEndpointId(rawId);
  assertOnlyAllowedKeys(query, new Set(), 'Query parameters');
  assertOnlyAllowedKeys(body, new Set(), 'Request body');

  const serialized = await sequelize.transaction(async (t) => {
    const endpoint = await WebhookEndpoint.findByPk(id, {
      attributes: SAFE_WEBHOOK_ATTRIBUTES,
      transaction: t,
      lock: t.LOCK.UPDATE
    });

    if (!endpoint) {
      throw new ApiError(404, 'webhook_not_found', 'Webhook endpoint not found');
    }

    await endpoint.update(
      {
        is_active: Boolean(isActive),
        updated_at: new Date()
      },
      { transaction: t }
    );

    return serializeWebhookEndpoint(endpoint);
  });

  emitWebhookAdminAudit(isActive ? 'activated' : 'deactivated', serialized);
  return serialized;
}

/**
 * Deletes a webhook endpoint by ID using the established CASCADE deletion policy.
 *
 * @param {string} rawId
 * @param {object} [query={}]
 * @returns {Promise<{ deleted: boolean, id: string }>}
 */
async function deleteWebhookEndpoint(rawId, query = {}) {
  const id = validateWebhookEndpointId(rawId);
  assertOnlyAllowedKeys(query, new Set(), 'Query parameters');

  const deletedSnapshot = await sequelize.transaction(async (t) => {
    const endpoint = await WebhookEndpoint.findByPk(id, {
      attributes: SAFE_WEBHOOK_ATTRIBUTES,
      transaction: t,
      lock: t.LOCK.UPDATE
    });

    if (!endpoint) {
      throw new ApiError(404, 'webhook_not_found', 'Webhook endpoint not found');
    }

    const snapshot = serializeWebhookEndpoint(endpoint);
    await endpoint.destroy({ transaction: t });
    return snapshot;
  });

  emitWebhookAdminAudit('deleted', deletedSnapshot);
  return {
    deleted: true,
    id: deletedSnapshot.id
  };
}

module.exports = {
  SAFE_WEBHOOK_ATTRIBUTES,
  ALLOWED_CREATE_FIELDS,
  ALLOWED_UPDATE_FIELDS,
  ALLOWED_LIST_QUERY_FIELDS,
  validateWebhookEndpointId,
  validateSubscribedEvents,
  validateWebhookDescription,
  serializeWebhookEndpoint,
  registerWebhookEndpoint,
  listWebhookEndpoints,
  getWebhookEndpointById,
  updateWebhookEndpoint,
  setWebhookEndpointActiveState,
  deleteWebhookEndpoint
};
