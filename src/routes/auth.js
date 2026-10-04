const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { User } = require('../database/models');
const { sendError } = require('../utils/errors');
const { JWT_SECRET, authenticateToken } = require('../middleware/auth');
const {
  createSession,
  invalidateSession,
  DEFAULT_SESSION_TTL_SECONDS
} = require('../services/sessionService');
const { recordSecurityEvent } = require('../services/eventService');
const {
  validateDeviceFingerprint,
  getOrCreateDevice
} = require('../services/deviceService');
const { normalizeIp } = require('../utils/ip');
const geoService = require('../services/geoService');
const { collectTravelAnomalySignal } = require('../collectors/travelCollector');
const { collectBotSignal } = require('../collectors/botCollector');

const router = express.Router();
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || `${DEFAULT_SESSION_TTL_SECONDS}s`;

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function extractRequestContext(req, explicitFingerprint = null) {
  const rawIp = req.ip || req.socket?.remoteAddress || null;
  const ip = normalizeIp(rawIp) || (typeof rawIp === 'string' ? rawIp.trim() : null);

  const context = {
    ip_address: ip,
    user_agent: req.headers['user-agent'] || null
  };

  const fingerprint = explicitFingerprint || (req.session && req.session.device_fingerprint) || null;
  if (fingerprint) {
    context.device_fingerprint = fingerprint;
  }

  return context;
}

async function extractLoginRequestContext(req, explicitFingerprint = null) {
  const context = extractRequestContext(req, explicitFingerprint);
  if (context.ip_address) {
    const geo = await geoService.resolveGeoLocation(context.ip_address);
    if (geo.geo_country) {
      context.geo_country = geo.geo_country;
    }
    if (geo.geo_region) {
      context.geo_region = geo.geo_region;
    }
  }
  return context;
}

/**
 * POST /api/v1/auth/signup
 */
router.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || typeof email !== 'string' || !EMAIL_REGEX.test(email)) {
      return sendError(res, 400, 'invalid_request', 'A valid email address is required');
    }

    if (!password || typeof password !== 'string' || password.length < 6) {
      return sendError(
        res,
        400,
        'invalid_request',
        'Password must be at least 6 characters long'
      );
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Check for existing user
    const existingUser = await User.findOne({ where: { email: normalizedEmail } });
    if (existingUser) {
      return sendError(res, 400, 'duplicate_email', 'A user with this email already exists');
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create user
    const newUser = await User.create({
      email: normalizedEmail,
      password_hash: passwordHash
    });

    return res.status(201).json({
      id: newUser.id,
      email: newUser.email
    });
  } catch (error) {
    console.error('Signup error:', error);
    return sendError(res, 500, 'internal_error', 'An unexpected error occurred during signup');
  }
});

/**
 * POST /api/v1/auth/login
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
      return sendError(res, 400, 'invalid_request', 'Email and password are required');
    }

    // Single request arrival timestamp and canonical source identity for the request
    const currentTimestamp = new Date();
    const rawIp = req.ip || req.socket?.remoteAddress || null;
    const canonicalIp = normalizeIp(rawIp) || (typeof rawIp === 'string' ? rawIp.trim() : null);

    let botSignal = null;
    try {
      botSignal = await collectBotSignal(canonicalIp, currentTimestamp);
    } catch (botErr) {
      // Safe fallback: never disrupt authentication on bot signal collection failure
      console.warn('[Auth] Bot signal collection failed:', botErr.message);
    }

    const rawFingerprint = req.headers['x-device-fingerprint'];
    const validFingerprint = validateDeviceFingerprint(rawFingerprint) ? rawFingerprint.trim() : null;

    const normalizedEmail = email.toLowerCase().trim();

    const user = await User.findOne({ where: { email: normalizedEmail } });
    if (!user) {
      // Generic error - do not reveal if email exists
      return sendError(res, 401, 'authentication_failed', 'Invalid email or password');
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      const loginContext = await extractLoginRequestContext(req, validFingerprint);
      const failedMetadata = {};
      if (botSignal) {
        failedMetadata.bot_detection = botSignal;
      }
      await recordSecurityEvent({
        userId: user.id,
        eventType: 'login_failed',
        timestamp: currentTimestamp,
        context: loginContext,
        metadata: failedMetadata
      });
      // Generic error - do not reveal password was wrong
      return sendError(res, 401, 'authentication_failed', 'Invalid email or password');
    }

    let deviceData = null;
    if (validFingerprint) {
      const { device } = await getOrCreateDevice(user.id, validFingerprint);
      deviceData = {
        device_id: device.id,
        device_fingerprint: validFingerprint
      };
    }

    // Create session in MySQL & Redis
    const session = await createSession(user.id, user.email, DEFAULT_SESSION_TTL_SECONDS, deviceData);

    const loginContext = await extractLoginRequestContext(req, validFingerprint);

    let travelAnomaly = null;
    try {
      travelAnomaly = await collectTravelAnomalySignal(
        user.id,
        loginContext.ip_address,
        currentTimestamp
      );
    } catch (travelErr) {
      // Safe fallback: never disrupt authentication on travel calculation failure
      console.warn('[Auth] Impossible travel check failed:', travelErr.message);
    }

    const loginMetadata = {};
    if (travelAnomaly) {
      loginMetadata.travel_anomaly = travelAnomaly;
    }
    if (botSignal) {
      loginMetadata.bot_detection = botSignal;
    }

    // Record login_success
    await recordSecurityEvent({
      userId: user.id,
      sessionId: session.sessionId,
      eventType: 'login_success',
      timestamp: currentTimestamp,
      context: loginContext,
      metadata: loginMetadata
    });

    // Record session_created
    await recordSecurityEvent({
      userId: user.id,
      sessionId: session.sessionId,
      eventType: 'session_created',
      timestamp: currentTimestamp,
      context: extractRequestContext(req, validFingerprint)
    });

    // Issue short-lived JWT containing user id, email, and session_id
    const tokenPayload = {
      id: user.id,
      email: user.email,
      session_id: session.sessionId
    };

    const token = jwt.sign(tokenPayload, JWT_SECRET, {
      expiresIn: JWT_EXPIRES_IN
    });

    return res.status(200).json({
      token,
      session_id: session.sessionId,
      user: {
        id: user.id,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    return sendError(res, 500, 'internal_error', 'An unexpected error occurred during login');
  }
});

/**
 * POST /api/v1/auth/logout
 */
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    const sessionId = req.user && req.user.session_id;
    const userId = req.user && req.user.id;

    if (sessionId) {
      const sessionFingerprint = req.session?.device_fingerprint || null;
      const rawFingerprint = req.headers['x-device-fingerprint'];
      const validHeaderFingerprint = validateDeviceFingerprint(rawFingerprint) ? rawFingerprint.trim() : null;
      const deviceFingerprint = sessionFingerprint || validHeaderFingerprint;

      await invalidateSession(sessionId);

      await recordSecurityEvent({
        userId,
        sessionId,
        eventType: 'session_terminated',
        context: extractRequestContext(req, deviceFingerprint)
      });
    }

    return res.status(200).json({
      message: 'Successfully logged out'
    });
  } catch (error) {
    console.error('Logout error:', error);
    return sendError(res, 500, 'internal_error', 'An unexpected error occurred during logout');
  }
});

module.exports = router;
