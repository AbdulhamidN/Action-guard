const jwt = require('jsonwebtoken');
const { sendError } = require('../utils/errors');
const { validateActiveSession } = require('../services/sessionService');

const JWT_SECRET = process.env.JWT_SECRET || 'dev_fallback_secret_for_actionguard_local';

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

  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return sendError(res, 401, 'token_expired', 'Authorization token has expired');
    }
    return sendError(res, 401, 'unauthorized', 'Invalid authorization token');
  }

  // If session_id is present, validate active session state in Redis
  if (decoded.session_id) {
    const activeSession = await validateActiveSession(decoded.session_id);
    if (!activeSession) {
      return sendError(
        res,
        401,
        'invalid_session',
        'Session is invalid, expired, or logged out'
      );
    }
    req.session = activeSession;
  }

  req.user = decoded;
  next();
}

module.exports = {
  authenticateToken,
  JWT_SECRET
};
