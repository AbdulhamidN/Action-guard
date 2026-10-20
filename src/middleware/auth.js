const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { sendError } = require('../utils/errors');
const { validateAndTouchSession } = require('../services/sessionService');
const { checkElevation } = require('../services/elevationService');
const adminTokenService = require('../services/adminTokenService');

const TEST_JWT_SECRET_FALLBACK = 'test-jwt-secret-actionguard-automated-tests-32char';
const JWT_SECRET =
  process.env.NODE_ENV === 'test'
    ? (process.env.JWT_SECRET || TEST_JWT_SECRET_FALLBACK)
    : process.env.JWT_SECRET;

/**
 * Returns the active JWT signing/verification secret.
 * Outside automated test mode (NODE_ENV !== 'test'), requires process.env.JWT_SECRET
 * with no hardcoded fallback.
 */
function getJwtSecret() {
  if (process.env.JWT_SECRET) {
    return process.env.JWT_SECRET;
  }
  if (process.env.NODE_ENV === 'test') {
    return TEST_JWT_SECRET_FALLBACK;
  }
  return JWT_SECRET;
}

/**
 * Validates that required application secrets are present and meet minimum
 * entropy / length requirements. Invoked strictly at process startup (index.js).
 * Never prints secret values in error messages.
 *
 * @param {object} [env=process.env]
 */
function assertRequiredSecrets(env = process.env) {
  if (env.ACTIONGUARD_DEMO_MODE === 'true' && env.NODE_ENV === 'production') {
    throw new Error('ACTIONGUARD_DEMO_MODE must not be enabled in production environments.');
  }
  if (env.NODE_ENV === 'test') {
    return;
  }
  const secret = env.JWT_SECRET;
  if (!secret || typeof secret !== 'string' || secret.trim().length === 0) {
    throw new Error('JWT_SECRET environment variable is required and must not be empty.');
  }
  if (secret.length < 32) {
    throw new Error(`JWT_SECRET must be at least 32 characters in length (received ${secret.length} characters).`);
  }
}

const MIN_ADMIN_API_KEY_LENGTH = 32;

/**
 * Performs a constant-time cryptographic comparison of two API key strings
 * by hashing both values with SHA-256 (32-byte fixed digest) and comparing
 * via crypto.timingSafeEqual. Safely handles unequal lengths without leaking
 * key length through early-return byte comparison.
 *
 * @param {unknown} providedKey
 * @param {unknown} configuredKey
 * @returns {boolean}
 */
function constantTimeKeyMatch(providedKey, configuredKey) {
  const isProvidedValid = typeof providedKey === 'string' && providedKey.length > 0;
  const isConfiguredValid =
    typeof configuredKey === 'string' && configuredKey.trim().length > 0;

  const safeProvided = isProvidedValid ? providedKey : '';
  const safeConfigured = isConfiguredValid ? configuredKey : '';

  const providedHash = crypto.createHash('sha256').update(safeProvided, 'utf8').digest();
  const configuredHash = crypto.createHash('sha256').update(safeConfigured, 'utf8').digest();

  const hashesEqual = crypto.timingSafeEqual(providedHash, configuredHash);
  return isProvidedValid && isConfiguredValid && hashesEqual;
}

/**
 * Verifies a JWT token and its active session state in Redis.
 * Performs atomic validation and sliding idle renewal.
 *
 * @param {string} token - Raw JWT token
 * @param {object} [options={}] - Options for session touch
 * @returns {Promise<{ user: object, session: object|null }>}
 * @throws {Error} Error with err.code set to 'unauthorized', 'token_expired', or 'invalid_session'
 */
async function verifyUserAndSessionToken(token, options = {}) {
  if (!token || typeof token !== 'string') {
    const err = new Error('Missing authorization token');
    err.code = 'unauthorized';
    throw err;
  }

  let decoded;
  try {
    decoded = jwt.verify(token, getJwtSecret());
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      const error = new Error('Authorization token has expired');
      error.code = 'token_expired';
      throw error;
    }
    const error = new Error('Invalid authorization token');
    error.code = 'unauthorized';
    throw error;
  }

  let activeSession = null;
  // If session_id is present, validate active session state in Redis and conditionally touch idle TTL
  if (decoded.session_id) {
    activeSession = await validateAndTouchSession(decoded.session_id, options);
    if (!activeSession) {
      const error = new Error('Session is invalid, expired, or logged out');
      error.code = 'invalid_session';
      throw error;
    }
  }

  return {
    user: decoded,
    session: activeSession
  };
}

/**
 * Reusable JWT and active session verification middleware.
 * Verifies Bearer token, checks expiration/validity,
 * verifies session is active in Redis, slides idle timeout,
 * and attaches decoded user and session context.
 */
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || typeof authHeader !== 'string') {
    return sendError(res, 401, 'unauthorized', 'Missing authorization token');
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer' || !parts[1]) {
    return sendError(res, 401, 'unauthorized', 'Malformed authorization token. Expected Bearer <token>');
  }

  const token = parts[1];

  try {
    const { user, session } = await verifyUserAndSessionToken(token);
    if (session) {
      req.session = session;
    }
    req.user = user;
    next();
  } catch (err) {
    const code = err.code || 'unauthorized';
    return sendError(res, 401, code, err.message);
  }
}

/**
 * Helper middleware generator requiring verified scoped temporary elevation.
 * Fails closed if session is not elevated for the requested scope.
 *
 * @param {string} scope - Required elevation scope
 */
function requireElevation(scope) {
  return async function (req, res, next) {
    const sessionId = req.session?.session_id || req.user?.session_id;
    if (!sessionId) {
      return sendError(res, 401, 'unauthorized', 'Active session required for privilege elevation check');
    }

    const elevationStatus = await checkElevation({
      sessionId,
      scope,
      parentSession: req.session || null
    });

    if (!elevationStatus.elevated) {
      return sendError(
        res,
        403,
        'elevation_required',
        `Action requires elevated privileges for scope '${scope}'`
      );
    }

    req.elevation = elevationStatus;
    next();
  };
}

/**
 * Verifies service-level API key for external integrating application requests.
 * Uses constant-time SHA-256 digest comparison and rejects unconfigured,
 * missing, malformed, or mismatched keys without logging secret material.
 */
function authenticateApiKey(req, res, next) {
  if (
    req.query &&
    (req.query.apiKey !== undefined ||
      req.query.api_key !== undefined ||
      req.query.token !== undefined)
  ) {
    return sendError(res, 401, 'unauthorized', 'Credentials in query parameters are not permitted');
  }

  const authHeader = req.headers['authorization'];
  if (!authHeader || typeof authHeader !== 'string') {
    return sendError(res, 401, 'unauthorized', 'Missing authorization token');
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer' || !parts[1]) {
    return sendError(
      res,
      401,
      'unauthorized',
      'Malformed authorization token. Expected Bearer <api_key>'
    );
  }

  const providedKey = parts[1];
  const configuredKey = process.env.API_KEY || process.env.ACTIONGUARD_API_KEY;

  if (!constantTimeKeyMatch(providedKey, configuredKey)) {
    return sendError(res, 401, 'unauthorized', 'Invalid or unconfigured API key');
  }

  req.apiKey = providedKey;
  next();
}

/**
 * Verifies dedicated administrator API key (`ACTIONGUARD_ADMIN_API_KEY`).
 * Enforces minimum key length (>= 32 chars) in alignment with Socket.IO admin
 * handshake validation, fails closed when missing/invalid, rejects query-string
 * credentials, and compares keys using constant-time SHA-256 digest comparison.
 */
function authenticateAdminApiKey(req, res, next) {
  if (
    req.query &&
    (req.query.apiKey !== undefined ||
      req.query.api_key !== undefined ||
      req.query.admin_api_key !== undefined ||
      req.query.token !== undefined)
  ) {
    return sendError(res, 401, 'unauthorized', 'Credentials in query parameters are not permitted');
  }

  const authHeader = req.headers['authorization'];
  const headerAdminKey = req.headers['x-admin-api-key'];

  let providedKey = null;

  if (authHeader !== undefined) {
    if (typeof authHeader !== 'string') {
      return sendError(res, 401, 'unauthorized', 'Malformed authorization header');
    }
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer' || !parts[1]) {
      return sendError(
        res,
        401,
        'unauthorized',
        'Malformed authorization token. Expected Bearer <admin_api_key>'
      );
    }
    providedKey = parts[1];
  }

  if (headerAdminKey !== undefined) {
    if (typeof headerAdminKey !== 'string' || headerAdminKey.length === 0) {
      return sendError(res, 401, 'unauthorized', 'Malformed X-Admin-Api-Key header');
    }
    if (providedKey !== null && !constantTimeKeyMatch(providedKey, headerAdminKey)) {
      return sendError(res, 401, 'unauthorized', 'Conflicting admin authentication headers');
    }
    providedKey = headerAdminKey;
  }

  if (!providedKey) {
    return sendError(res, 401, 'unauthorized', 'Missing admin authorization key');
  }

  const configuredAdminKey = process.env.ACTIONGUARD_ADMIN_API_KEY;
  const isConfigValid =
    typeof configuredAdminKey === 'string' &&
    configuredAdminKey.trim().length >= MIN_ADMIN_API_KEY_LENGTH &&
    configuredAdminKey.length >= MIN_ADMIN_API_KEY_LENGTH;

  const matched = constantTimeKeyMatch(providedKey, isConfigValid ? configuredAdminKey : '');
  if (!isConfigValid || !matched) {
    return sendError(res, 401, 'unauthorized', 'Invalid or unconfigured admin API key');
  }

  req.isAdmin = true;
  req.authType = 'adminApiKey';
  next();
}

/**
 * Verifies short-lived opaque admin session token (`agadm_...`).
 * Strictly rejects:
 * - Credentials in query parameters
 * - Raw ACTIONGUARD_ADMIN_API_KEY (Bearer or X-Admin-Api-Key)
 * - User JWTs
 * - Expired or revoked tokens
 * Slides idle TTL upon valid read request.
 */
async function requireAdminToken(req, res, next) {
  if (
    req.query &&
    (req.query.apiKey !== undefined ||
      req.query.api_key !== undefined ||
      req.query.admin_key !== undefined ||
      req.query.adminToken !== undefined ||
      req.query.admin_token !== undefined ||
      req.query.token !== undefined)
  ) {
    return sendError(res, 401, 'unauthorized', 'Credentials in query parameters are not permitted');
  }

  // Reject X-Admin-Api-Key on admin token read routes
  if (req.headers['x-admin-api-key'] !== undefined) {
    return sendError(res, 401, 'unauthorized', 'Raw admin API key is not permitted on this endpoint');
  }

  const authHeader = req.headers['authorization'];
  if (!authHeader || typeof authHeader !== 'string') {
    return sendError(res, 401, 'unauthorized', 'Missing authorization token');
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer' || !parts[1]) {
    return sendError(
      res,
      401,
      'unauthorized',
      'Malformed authorization token. Expected Bearer <admin_token>'
    );
  }

  const provided = parts[1];

  // 1. Check if provided matches the raw ACTIONGUARD_ADMIN_API_KEY
  const configuredAdminKey = process.env.ACTIONGUARD_ADMIN_API_KEY;
  if (constantTimeKeyMatch(provided, configuredAdminKey)) {
    return sendError(res, 401, 'unauthorized', 'Raw admin API key is not permitted on this endpoint');
  }

  // 2. Reject user JWTs
  if (provided.startsWith('ey') || provided.split('.').length === 3) {
    return sendError(res, 401, 'unauthorized', 'User tokens are not permitted on admin endpoints');
  }

  // 3. Must have admin token prefix
  if (!provided.startsWith(adminTokenService.TOKEN_PREFIX)) {
    return sendError(res, 401, 'unauthorized', 'Invalid admin token');
  }

  // 4. Validate token against Redis with sliding idle TTL
  try {
    const record = await adminTokenService.validateAdminToken(provided, { touch: true });
    if (!record) {
      return sendError(res, 401, 'unauthorized', 'Invalid or expired admin token');
    }

    req.admin = {
      isAdmin: true,
      tokenHash: record.token_hash,
      expires_at: record.expires_at
    };
    req.adminToken = provided;
    next();
  } catch (err) {
    console.error('[AuthMiddleware] Error validating admin token:', err.message);
    return sendError(res, 503, 'service_unavailable', 'Authentication service temporarily unavailable');
  }
}

module.exports = {
  authenticateToken,
  authenticateApiKey,
  authenticateAdminApiKey,
  requireAdminToken,
  constantTimeKeyMatch,
  requireElevation,
  verifyUserAndSessionToken,
  assertRequiredSecrets,
  getJwtSecret,
  JWT_SECRET: getJwtSecret(),
  MIN_ADMIN_API_KEY_LENGTH
};

Object.defineProperty(module.exports, 'JWT_SECRET', {
  get: () => getJwtSecret(),
  enumerable: true,
  configurable: true
});
