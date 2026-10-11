const jwt = require('jsonwebtoken');
const { sendError } = require('../utils/errors');
const { validateAndTouchSession } = require('../services/sessionService');
const { checkElevation } = require('../services/elevationService');

const JWT_SECRET = process.env.JWT_SECRET || 'dev_fallback_secret_for_actionguard_local';

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
    decoded = jwt.verify(token, JWT_SECRET);
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
  if (!authHeader) {
    return sendError(res, 401, 'unauthorized', 'Missing authorization token');
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
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
 * Rejects requests if API key is unconfigured, missing, or mismatched.
 */
function authenticateApiKey(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return sendError(res, 401, 'unauthorized', 'Missing authorization token');
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return sendError(
      res,
      401,
      'unauthorized',
      'Malformed authorization token. Expected Bearer <api_key>'
    );
  }

  const providedKey = parts[1];
  const configuredKey = process.env.API_KEY || process.env.ACTIONGUARD_API_KEY;

  if (!configuredKey || providedKey !== configuredKey) {
    return sendError(res, 401, 'unauthorized', 'Invalid or unconfigured API key');
  }

  req.apiKey = providedKey;
  next();
}

module.exports = {
  authenticateToken,
  authenticateApiKey,
  requireElevation,
  verifyUserAndSessionToken,
  JWT_SECRET
};
