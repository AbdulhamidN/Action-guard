'use strict';

const express = require('express');
const authMiddleware = require('../middleware/auth');
const {
  authenticateAdminApiKey,
  constantTimeKeyMatch,
  MIN_ADMIN_API_KEY_LENGTH
} = authMiddleware;
const { validateIdParam } = require('../middleware/validation');
const { ApiError, sendError } = require('../utils/errors');
const {
  registerWebhookEndpoint,
  listWebhookEndpoints,
  getWebhookEndpointById,
  updateWebhookEndpoint,
  setWebhookEndpointActiveState,
  deleteWebhookEndpoint,
  listWebhookEndpointDeliveries
} = require('../services/webhookEndpointService');

const router = express.Router();

/**
 * Enforces strict administrator authorization for webhook endpoint management.
 *
 * Security ordering:
 * 1. Rejects query-parameter credentials (`apiKey`, `api_key`, `adminApiKey`, `admin_api_key`,
 *    `token`, `access_token`) with 401 `unauthorized`.
 * 2. Rejects missing, malformed, or conflicting (`Authorization` + `X-Admin-Api-Key`) headers
 *    with 401 `unauthorized`.
 * 3. Validates administrator configuration (`ACTIONGUARD_ADMIN_API_KEY` present, >= 32 chars,
 *    and distinct from `API_KEY` / `ACTIONGUARD_API_KEY`) BEFORE inspecting whether the caller
 *    supplied a normal user JWT or service API key. Fails closed with 401 `unauthorized`
 *    when admin configuration is missing or invalid.
 * 4. Verifies administrator credential in constant time (`constantTimeKeyMatch`).
 * 5. When administrator configuration is valid and the supplied credential does not match,
 *    rejects authenticated non-administrator identities (valid service API key or active
 *    user session JWT) consistently across both header forms with 403 `forbidden`, and
 *    rejects invalid credentials with 401 `unauthorized`.
 */
async function requireWebhookAdmin(req, res, next) {
  if (
    req.query &&
    (req.query.apiKey !== undefined ||
      req.query.api_key !== undefined ||
      req.query.adminApiKey !== undefined ||
      req.query.admin_api_key !== undefined ||
      req.query.token !== undefined ||
      req.query.access_token !== undefined)
  ) {
    return sendError(
      res,
      401,
      'unauthorized',
      'Credentials in query parameters are not permitted'
    );
  }

  const authHeader = req.headers['authorization'];
  const headerAdminKey = req.headers['x-admin-api-key'];

  if (authHeader !== undefined && headerAdminKey !== undefined) {
    return sendError(
      res,
      401,
      'unauthorized',
      'Conflicting admin authentication headers'
    );
  }

  let candidateCredential = null;
  if (headerAdminKey !== undefined) {
    if (
      typeof headerAdminKey !== 'string' ||
      headerAdminKey.trim().length === 0 ||
      /\s/.test(headerAdminKey)
    ) {
      return sendError(
        res,
        401,
        'unauthorized',
        'Missing or malformed admin API key'
      );
    }
    candidateCredential = headerAdminKey;
  } else if (authHeader !== undefined) {
    if (typeof authHeader !== 'string' || !authHeader.startsWith('Bearer ')) {
      return sendError(
        res,
        401,
        'unauthorized',
        'Missing or malformed Authorization header'
      );
    }
    const parts = authHeader.split(' ');
    if (
      parts.length !== 2 ||
      parts[0] !== 'Bearer' ||
      !parts[1] ||
      parts[1].trim().length === 0 ||
      parts[1].trim() !== parts[1]
    ) {
      return sendError(
        res,
        401,
        'unauthorized',
        'Missing or malformed Authorization header'
      );
    }
    candidateCredential = parts[1];
  } else {
    return authenticateAdminApiKey(req, res, next);
  }

  const configuredAdminKey = process.env.ACTIONGUARD_ADMIN_API_KEY;
  const configuredServiceKeys = [
    process.env.API_KEY,
    process.env.ACTIONGUARD_API_KEY
  ].filter((key) => typeof key === 'string' && key.trim().length > 0);

  const isAdminKeyWellFormed =
    typeof configuredAdminKey === 'string' &&
    configuredAdminKey.trim().length >= MIN_ADMIN_API_KEY_LENGTH &&
    configuredAdminKey.length >= MIN_ADMIN_API_KEY_LENGTH;

  const adminConflictsWithServiceKey =
    isAdminKeyWellFormed &&
    configuredServiceKeys.some((serviceKey) =>
      constantTimeKeyMatch(configuredAdminKey, serviceKey)
    );

  if (!isAdminKeyWellFormed || adminConflictsWithServiceKey) {
    return sendError(
      res,
      401,
      'unauthorized',
      'Invalid or unconfigured admin API key'
    );
  }

  if (constantTimeKeyMatch(candidateCredential, configuredAdminKey)) {
    return authenticateAdminApiKey(req, res, next);
  }

  // Admin configuration is valid, and the credential did not match the admin key.
  // Check whether the caller presented a valid non-admin credential -> 403 forbidden.
  if (
    configuredServiceKeys.some((serviceKey) =>
      constantTimeKeyMatch(candidateCredential, serviceKey)
    )
  ) {
    return sendError(
      res,
      403,
      'forbidden',
      'Forbidden: administrator privileges required to manage webhook endpoints'
    );
  }

  if (candidateCredential.split('.').length === 3) {
    try {
      const verified = await authMiddleware.verifyUserAndSessionToken(
        candidateCredential,
        {
          skipTouch: true
        }
      );
      if (verified && verified.user) {
        return sendError(
          res,
          403,
          'forbidden',
          'Forbidden: administrator privileges required to manage webhook endpoints'
        );
      }
    } catch {
      // Expired or invalid JWT falls through to 401 unauthorized
    }
  }

  return authenticateAdminApiKey(req, res, next);
}

/**
 * Centralized error handler for webhook management routes.
 * Maps known ApiError instances to standard error envelopes and masks all
 * unexpected database or runtime errors behind a generic 500 response.
 *
 * @param {unknown} err
 * @param {import('express').Response} res
 */
function handleWebhookRouteError(err, res) {
  if (
    err instanceof ApiError ||
    (err &&
      typeof err === 'object' &&
      typeof err.status === 'number' &&
      typeof err.code === 'string' &&
      typeof err.message === 'string')
  ) {
    return sendError(res, err.status, err.code, err.message);
  }

  return sendError(
    res,
    500,
    'internal_error',
    'An unexpected error occurred while managing webhook endpoints'
  );
}

router.use(requireWebhookAdmin);

/**
 * POST /api/v1/webhooks
 * Register a new outbound webhook endpoint.
 */
router.post('/', async (req, res) => {
  try {
    const webhook = await registerWebhookEndpoint(req.body || {});
    return res.status(201).json({ webhook });
  } catch (err) {
    return handleWebhookRouteError(err, res);
  }
});

/**
 * GET /api/v1/webhooks
 * List registered webhook endpoints with safe metadata only.
 */
router.get('/', async (req, res) => {
  try {
    const result = await listWebhookEndpoints(req.query || {});
    return res.status(200).json(result);
  } catch (err) {
    return handleWebhookRouteError(err, res);
  }
});

/**
 * GET /api/v1/webhooks/:id/deliveries
 * List safe delivery history metadata for a specific webhook endpoint.
 */
router.get('/:id/deliveries', validateIdParam('id'), async (req, res) => {
  try {
    const result = await listWebhookEndpointDeliveries(
      req.params.id,
      req.query || {}
    );
    return res.status(200).json(result);
  } catch (err) {
    return handleWebhookRouteError(err, res);
  }
});

/**
 * GET /api/v1/webhooks/:id
 * Retrieve a single webhook endpoint by ID with safe metadata only.
 */
router.get('/:id', validateIdParam('id'), async (req, res) => {
  try {
    const webhook = await getWebhookEndpointById(req.params.id, req.query || {});
    return res.status(200).json({ webhook });
  } catch (err) {
    return handleWebhookRouteError(err, res);
  }
});

/**
 * PATCH /api/v1/webhooks/:id
 * Update a webhook endpoint's URL, subscribed_events, description, or is_active state.
 */
router.patch('/:id', validateIdParam('id'), async (req, res) => {
  try {
    const webhook = await updateWebhookEndpoint(
      req.params.id,
      req.body || {},
      req.query || {}
    );
    return res.status(200).json({ webhook });
  } catch (err) {
    return handleWebhookRouteError(err, res);
  }
});

/**
 * POST /api/v1/webhooks/:id/activate
 * Explicitly activate a webhook endpoint.
 */
router.post('/:id/activate', validateIdParam('id'), async (req, res) => {
  try {
    const webhook = await setWebhookEndpointActiveState(
      req.params.id,
      true,
      req.body || {},
      req.query || {}
    );
    return res.status(200).json({ webhook });
  } catch (err) {
    return handleWebhookRouteError(err, res);
  }
});

/**
 * POST /api/v1/webhooks/:id/deactivate
 * Explicitly deactivate a webhook endpoint.
 */
router.post('/:id/deactivate', validateIdParam('id'), async (req, res) => {
  try {
    const webhook = await setWebhookEndpointActiveState(
      req.params.id,
      false,
      req.body || {},
      req.query || {}
    );
    return res.status(200).json({ webhook });
  } catch (err) {
    return handleWebhookRouteError(err, res);
  }
});

/**
 * DELETE /api/v1/webhooks/:id
 * Delete a webhook endpoint and cascade-delete its delivery logs.
 */
router.delete('/:id', validateIdParam('id'), async (req, res) => {
  try {
    const result = await deleteWebhookEndpoint(req.params.id, req.query || {});
    return res.status(200).json(result);
  } catch (err) {
    return handleWebhookRouteError(err, res);
  }
});

module.exports = router;
