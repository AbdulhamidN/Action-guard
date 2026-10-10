const jwt = require('jsonwebtoken');
const { sendError } = require('../utils/errors');
const { validateActiveSession } = require('../services/sessionService');

const JWT_SECRET = process.env.JWT_SECRET || 'dev_fallback_secret_for_actionguard_local';

/**
 * Verifies a JWT token and its active session state in Redis.
 * Shared helper used by both Express HTTP middleware and Socket.IO handshake auth.
 *
 * @param {string} token - Raw JWT token
 * @returns {Promise<{ user: object, session: object|null }>}
 * @throws {Error} Error with err.code set to 'unauthorized', 'token_expired', or 'invalid_session'
 */
async function verifyUserAndSessionToken(token) {
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
  // If session_id is present, validate active session state in Redis
  if (decoded.session_id) {
    activeSession = await validateActiveSession(decoded.session_id);
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
 * verifies session is active in Redis,
 * and attaches decoded user identity to req.user.
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
  verifyUserAndSessionToken,
  JWT_SECRET
};
