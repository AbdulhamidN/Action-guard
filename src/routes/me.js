const express = require('express');
const { Op } = require('sequelize');
const { authenticateToken } = require('../middleware/auth');
const { Session, SecurityEvent, RiskAssessment, PolicyDecision } = require('../database/models');
const { invalidateSession } = require('../services/sessionService');
const { recordSecurityEvent } = require('../services/eventService');
const {
  buildUserSessionPayload,
  buildEventRecordedPayload,
  buildUserRiskHistoryItem,
  buildUserDecisionPayload
} = require('../realtime/payloads');
const { sendError } = require('../utils/errors');
const {
  listUserDevices,
  enrollTrustedDevice,
  revokeDeviceTrust,
  validateDeviceLabel
} = require('../services/deviceService');

const router = express.Router();

/**
 * Validates limit and before pagination query params.
 * @param {object} query
 * @param {string} timeField
 * @returns {{ limit: number, timeFilter?: object } | { error: string, message: string }}
 */
function parsePagination(query, timeField) {
  let limit = 50;
  if (query.limit !== undefined) {
    const parsed = Number(query.limit);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > 200) {
      return {
        error: 'invalid_request',
        message: 'limit must be a positive integer <= 200'
      };
    }
    limit = parsed;
  }

  const result = { limit };

  if (query.before !== undefined) {
    if (typeof query.before !== 'string') {
      return {
        error: 'invalid_request',
        message: 'before must be a valid ISO 8601 timestamp'
      };
    }
    const beforeDate = new Date(query.before);
    if (isNaN(beforeDate.getTime())) {
      return {
        error: 'invalid_request',
        message: 'before must be a valid ISO 8601 timestamp'
      };
    }
    result.timeFilter = { [timeField]: { [Op.lt]: beforeDate } };
  }

  return result;
}

/**
 * GET /api/v1/me
 * Protected endpoint returning authenticated user identity.
 */
router.get('/', authenticateToken, (req, res) => {
  return res.status(200).json({
    id: req.user.id,
    email: req.user.email
  });
});

/**
 * GET /api/v1/me/sessions
 * Returns user sessions with latest risk tier and coarse location.
 */
router.get('/sessions', authenticateToken, async (req, res) => {
  try {
    const sessions = await Session.findAll({
      where: { user_id: req.user.id },
      order: [
        ['created_at', 'DESC'],
        ['id', 'DESC']
      ]
    });

    if (sessions.length === 0) {
      return res.status(200).json([]);
    }

    const sessionIds = sessions.map((s) => s.id);
    const [assessments, events] = await Promise.all([
      RiskAssessment.findAll({
        where: {
          session_id: { [Op.in]: sessionIds }
        },
        order: [
          ['evaluated_at', 'DESC'],
          ['id', 'DESC']
        ]
      }),
      SecurityEvent.findAll({
        where: {
          session_id: { [Op.in]: sessionIds }
        },
        order: [
          ['timestamp', 'DESC'],
          ['event_id', 'DESC']
        ]
      })
    ]);

    const latestBySession = new Map();
    for (const a of assessments) {
      if (!latestBySession.has(a.session_id)) {
        latestBySession.set(a.session_id, a);
      }
    }

    const latestEventBySession = new Map();
    for (const e of events) {
      if (!latestEventBySession.has(e.session_id)) {
        latestEventBySession.set(e.session_id, e);
      }
    }

    const payloads = sessions.map((s) => {
      const isCurrent = Boolean(req.user.session_id && s.id === req.user.session_id);
      const latest = latestBySession.get(s.id) || null;
      const latestEv = latestEventBySession.get(s.id) || null;
      return buildUserSessionPayload(s, isCurrent, latest, latestEv);
    });

    return res.status(200).json(payloads);
  } catch (err) {
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to retrieve sessions'
    });
  }
});

/**
 * DELETE /api/v1/me/sessions/:id
 * Terminates another active session owned by the authenticated caller.
 */
router.delete('/sessions/:id', authenticateToken, async (req, res) => {
  try {
    const targetSessionId = req.params.id;
    if (!targetSessionId || typeof targetSessionId !== 'string') {
      return res.status(404).json({
        error: {
          code: 'not_found',
          message: 'Session not found'
        }
      });
    }

    // Disallow terminating current active session via generic other-session endpoint
    if (req.user.session_id && targetSessionId === req.user.session_id) {
      return res.status(400).json({
        error: {
          code: 'invalid_request',
          message: 'Cannot terminate the active session via this endpoint; use POST /api/v1/auth/logout'
        }
      });
    }

    const session = await Session.findOne({
      where: {
        id: targetSessionId,
        user_id: req.user.id
      }
    });

    if (!session) {
      return res.status(404).json({
        error: {
          code: 'not_found',
          message: 'Session not found'
        }
      });
    }

    await invalidateSession(session.id);

    await recordSecurityEvent({
      userId: req.user.id,
      sessionId: session.id,
      eventType: 'session_terminated',
      metadata: {
        terminated_by: 'user',
        reason: 'user_terminated_other_session',
        caller_session_id: req.user.session_id || null
      }
    });

    return res.status(200).json({
      message: 'Session successfully terminated',
      session_id: session.id
    });
  } catch (err) {
    return res.status(500).json({
      error: {
        code: 'internal_error',
        message: 'Failed to terminate session'
      }
    });
  }
});

/**
 * GET /api/v1/me/events?limit&before
 * Returns user security events without user_id.
 */
router.get('/events', authenticateToken, async (req, res) => {
  try {
    const pagination = parsePagination(req.query, 'timestamp');
    if (pagination.error) {
      return res.status(400).json({
        error: pagination.error,
        message: pagination.message
      });
    }

    const where = {
      user_id: req.user.id,
      ...(pagination.timeFilter || {})
    };

    const events = await SecurityEvent.findAll({
      where,
      order: [
        ['timestamp', 'DESC'],
        ['event_id', 'DESC']
      ],
      limit: pagination.limit
    });

    const payloads = events.map((e) => buildEventRecordedPayload(e, null, { includeUserId: false }));
    return res.status(200).json(payloads);
  } catch (err) {
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to retrieve events'
    });
  }
});

/**
 * GET /api/v1/me/risk-history?session_id&limit&before
 * Returns user risk assessments history.
 */
router.get('/risk-history', authenticateToken, async (req, res) => {
  try {
    if (req.query.session_id) {
      const session = await Session.findByPk(req.query.session_id);
      if (!session || session.user_id !== req.user.id) {
        return res.status(404).json({
          error: 'not_found',
          message: 'Session not found'
        });
      }
    }

    const pagination = parsePagination(req.query, 'evaluated_at');
    if (pagination.error) {
      return res.status(400).json({
        error: pagination.error,
        message: pagination.message
      });
    }

    const where = {
      user_id: req.user.id,
      ...(req.query.session_id ? { session_id: req.query.session_id } : {}),
      ...(pagination.timeFilter || {})
    };

    const assessments = await RiskAssessment.findAll({
      where,
      order: [
        ['evaluated_at', 'DESC'],
        ['id', 'DESC']
      ],
      limit: pagination.limit
    });

    const payloads = assessments.map((a) => buildUserRiskHistoryItem(a));
    return res.status(200).json(payloads);
  } catch (err) {
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to retrieve risk history'
    });
  }
});

/**
 * GET /api/v1/me/decisions?limit&before
 * Returns user policy decisions.
 */
router.get('/decisions', authenticateToken, async (req, res) => {
  try {
    const pagination = parsePagination(req.query, 'decided_at');
    if (pagination.error) {
      return res.status(400).json({
        error: pagination.error,
        message: pagination.message
      });
    }

    const where = {
      user_id: req.user.id,
      ...(pagination.timeFilter || {})
    };

    const decisions = await PolicyDecision.findAll({
      where,
      order: [
        ['decided_at', 'DESC'],
        ['id', 'DESC']
      ],
      limit: pagination.limit
    });

    const payloads = decisions.map((d) => buildUserDecisionPayload(d));
    return res.status(200).json(payloads);
  } catch (err) {
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to retrieve decisions'
    });
  }
});

/**
 * GET /api/v1/me/devices
 * Returns all devices registered to the authenticated user with live trust status and current session indicator.
 * Strictly redacts raw fingerprints.
 */
router.get('/devices', authenticateToken, async (req, res) => {
  try {
    const callerId = req.user.id || req.user.user_id;
    const activeDeviceId = req.session?.device_id || null;

    const devices = await listUserDevices(callerId);

    const payloads = devices.map((d) => ({
      id: d.id,
      label: d.label || null,
      is_trusted: Boolean(d.is_trusted),
      is_trust_active: Boolean(d.is_trust_active),
      trusted_at: d.trusted_at ? (d.trusted_at instanceof Date ? d.trusted_at.toISOString() : new Date(d.trusted_at).toISOString()) : null,
      expires_at: d.expires_at ? (d.expires_at instanceof Date ? d.expires_at.toISOString() : new Date(d.expires_at).toISOString()) : null,
      revoked_at: d.revoked_at ? (d.revoked_at instanceof Date ? d.revoked_at.toISOString() : new Date(d.revoked_at).toISOString()) : null,
      first_seen_at: d.first_seen_at ? (d.first_seen_at instanceof Date ? d.first_seen_at.toISOString() : new Date(d.first_seen_at).toISOString()) : null,
      last_used_at: d.last_used_at ? (d.last_used_at instanceof Date ? d.last_used_at.toISOString() : new Date(d.last_used_at).toISOString()) : null,
      is_current_device: Boolean(activeDeviceId && d.id === activeDeviceId)
    }));

    return res.status(200).json(payloads);
  } catch (err) {
    return sendError(res, 500, 'internal_error', 'Failed to retrieve devices');
  }
});

/**
 * POST /api/v1/me/devices/enroll
 * Enrolls the device associated with the active authenticated session as trusted.
 * MANDATORY: Bound strictly to req.session.device_id. Rejects client-controlled overrides.
 */
router.post('/devices/enroll', authenticateToken, async (req, res) => {
  try {
    const callerId = req.user.id || req.user.user_id;
    const activeDeviceId = req.session?.device_id;

    if (!activeDeviceId || typeof activeDeviceId !== 'string' || activeDeviceId.trim().length === 0) {
      return sendError(
        res,
        403,
        'device_session_mismatch',
        'No verified device identity is bound to the active session'
      );
    }

    const { deviceId, label } = req.body || {};

    // Prevent client-controlled deviceId from overriding session identity
    if (deviceId !== undefined && deviceId !== null && deviceId !== activeDeviceId) {
      return sendError(
        res,
        403,
        'device_session_mismatch',
        'Cannot enroll a device that does not match the active session device'
      );
    }

    if (label !== undefined && label !== null && !validateDeviceLabel(label)) {
      return sendError(
        res,
        400,
        'invalid_request',
        'Invalid device label: must be between 1 and 100 characters without control characters'
      );
    }

    const result = await enrollTrustedDevice({
      userId: callerId,
      deviceId: activeDeviceId,
      currentDeviceId: activeDeviceId,
      label: label !== undefined ? label : null
    });

    return res.status(200).json({
      message: 'Device trust enrolled successfully',
      device: {
        id: result.device.id,
        label: result.device.label || null,
        is_trusted: Boolean(result.device.is_trusted),
        trusted_at: result.device.trusted_at ? new Date(result.device.trusted_at).toISOString() : null,
        expires_at: result.device.expires_at ? new Date(result.device.expires_at).toISOString() : null,
        revoked_at: result.device.revoked_at ? new Date(result.device.revoked_at).toISOString() : null,
        first_seen_at: result.device.first_seen_at ? new Date(result.device.first_seen_at).toISOString() : null,
        last_used_at: result.device.last_used_at ? new Date(result.device.last_used_at).toISOString() : null
      },
      is_trust_active: Boolean(result.is_trust_active)
    });
  } catch (err) {
    if (err.status && err.status < 500) {
      return sendError(res, err.status, err.code ? err.code.toLowerCase() : 'invalid_request', err.message);
    }
    return sendError(res, 500, 'internal_error', 'Failed to enroll trusted device');
  }
});

/**
 * POST /api/v1/me/devices/:id/trust
 * Alternative REST endpoint to enroll a specific device by ID.
 * Strictly enforces that :id matches the authenticated session's device.
 */
router.post('/devices/:id/trust', authenticateToken, async (req, res) => {
  try {
    const callerId = req.user.id || req.user.user_id;
    const targetDeviceId = req.params.id;
    const activeDeviceId = req.session?.device_id;

    if (!activeDeviceId || typeof activeDeviceId !== 'string' || activeDeviceId.trim().length === 0) {
      return sendError(
        res,
        403,
        'device_session_mismatch',
        'No verified device identity is bound to the active session'
      );
    }

    if (!targetDeviceId || targetDeviceId !== activeDeviceId) {
      return sendError(
        res,
        403,
        'device_session_mismatch',
        'Cannot enroll a device that does not match the active session device'
      );
    }

    const { label } = req.body || {};
    if (label !== undefined && label !== null && !validateDeviceLabel(label)) {
      return sendError(
        res,
        400,
        'invalid_request',
        'Invalid device label: must be between 1 and 100 characters without control characters'
      );
    }

    const result = await enrollTrustedDevice({
      userId: callerId,
      deviceId: targetDeviceId,
      currentDeviceId: activeDeviceId,
      label: label !== undefined ? label : null
    });

    return res.status(200).json({
      message: 'Device trust enrolled successfully',
      device: {
        id: result.device.id,
        label: result.device.label || null,
        is_trusted: Boolean(result.device.is_trusted),
        trusted_at: result.device.trusted_at ? new Date(result.device.trusted_at).toISOString() : null,
        expires_at: result.device.expires_at ? new Date(result.device.expires_at).toISOString() : null,
        revoked_at: result.device.revoked_at ? new Date(result.device.revoked_at).toISOString() : null,
        first_seen_at: result.device.first_seen_at ? new Date(result.device.first_seen_at).toISOString() : null,
        last_used_at: result.device.last_used_at ? new Date(result.device.last_used_at).toISOString() : null
      },
      is_trust_active: Boolean(result.is_trust_active)
    });
  } catch (err) {
    if (err.status && err.status < 500) {
      return sendError(res, err.status, err.code ? err.code.toLowerCase() : 'invalid_request', err.message);
    }
    return sendError(res, 500, 'internal_error', 'Failed to enroll trusted device');
  }
});

/**
 * DELETE /api/v1/me/devices/:id
 * Revokes trust for a device owned by the authenticated user. Idempotent.
 */
router.delete('/devices/:id', authenticateToken, async (req, res) => {
  try {
    const callerId = req.user.id || req.user.user_id;
    const targetDeviceId = req.params.id;

    if (!targetDeviceId || typeof targetDeviceId !== 'string' || targetDeviceId.trim().length === 0) {
      return sendError(res, 400, 'invalid_request', 'deviceId parameter is required');
    }

    const result = await revokeDeviceTrust({
      userId: callerId,
      deviceId: targetDeviceId.trim()
    });

    return res.status(200).json({
      message: 'Device trust revoked successfully',
      device: {
        id: result.device.id,
        label: result.device.label || null,
        is_trusted: Boolean(result.device.is_trusted),
        trusted_at: result.device.trusted_at ? new Date(result.device.trusted_at).toISOString() : null,
        expires_at: result.device.expires_at ? new Date(result.device.expires_at).toISOString() : null,
        revoked_at: result.device.revoked_at ? new Date(result.device.revoked_at).toISOString() : null,
        first_seen_at: result.device.first_seen_at ? new Date(result.device.first_seen_at).toISOString() : null,
        last_used_at: result.device.last_used_at ? new Date(result.device.last_used_at).toISOString() : null
      },
      alreadyRevoked: Boolean(result.alreadyRevoked),
      is_trust_active: Boolean(result.is_trust_active)
    });
  } catch (err) {
    if (err.status && err.status < 500) {
      return sendError(res, err.status, err.code ? err.code.toLowerCase() : 'invalid_request', err.message);
    }
    return sendError(res, 500, 'internal_error', 'Failed to revoke device trust');
  }
});

/**
 * POST /api/v1/me/devices/:id/revoke
 * Alternative REST endpoint to revoke device trust. Idempotent.
 */
router.post('/devices/:id/revoke', authenticateToken, async (req, res) => {
  try {
    const callerId = req.user.id || req.user.user_id;
    const targetDeviceId = req.params.id;

    if (!targetDeviceId || typeof targetDeviceId !== 'string' || targetDeviceId.trim().length === 0) {
      return sendError(res, 400, 'invalid_request', 'deviceId parameter is required');
    }

    const result = await revokeDeviceTrust({
      userId: callerId,
      deviceId: targetDeviceId.trim()
    });

    return res.status(200).json({
      message: 'Device trust revoked successfully',
      device: {
        id: result.device.id,
        label: result.device.label || null,
        is_trusted: Boolean(result.device.is_trusted),
        trusted_at: result.device.trusted_at ? new Date(result.device.trusted_at).toISOString() : null,
        expires_at: result.device.expires_at ? new Date(result.device.expires_at).toISOString() : null,
        revoked_at: result.device.revoked_at ? new Date(result.device.revoked_at).toISOString() : null,
        first_seen_at: result.device.first_seen_at ? new Date(result.device.first_seen_at).toISOString() : null,
        last_used_at: result.device.last_used_at ? new Date(result.device.last_used_at).toISOString() : null
      },
      alreadyRevoked: Boolean(result.alreadyRevoked),
      is_trust_active: Boolean(result.is_trust_active)
    });
  } catch (err) {
    if (err.status && err.status < 500) {
      return sendError(res, err.status, err.code ? err.code.toLowerCase() : 'invalid_request', err.message);
    }
    return sendError(res, 500, 'internal_error', 'Failed to revoke device trust');
  }
});

module.exports = router;
