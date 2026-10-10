const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const { Session, SecurityEvent } = require('../database/models');
const riskEngineService = require('../services/riskEngineService');
const { validateDeviceFingerprint } = require('../services/deviceService');
const { normalizeIp } = require('../utils/ip');
const { sendError } = require('../utils/errors');

const router = express.Router();

/**
 * POST /api/v1/risk/evaluate
 *
 * Advisory endpoint evaluating risk for a proposed security event without mutating persistent state.
 * Advisory only: results are never persisted, affect no sequence tables or Redis caches,
 * and Module 10 must never trust them as authorization or audit truth.
 *
 * Scoped strictly to the authenticated caller identity.
 * Validates event_type, session ownership, context, and action_sensitivity.
 */
router.post('/evaluate', authenticateToken, async (req, res) => {
  try {
    const callerId = req.user.id || req.user.user_id;

    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
      return sendError(res, 400, 'invalid_request', 'Request body must be a JSON object');
    }

    const { user_id, event_type, session_id, context, metadata } = req.body;

    // 1. user_id validation & ownership check
    if (!user_id || typeof user_id !== 'string') {
      return sendError(res, 400, 'invalid_request', 'user_id is required');
    }

    if (user_id !== callerId) {
      return sendError(res, 403, 'forbidden', 'Forbidden: caller is not authorized for this user');
    }

    // 2. event_type validation
    if (!event_type || typeof event_type !== 'string') {
      return sendError(res, 400, 'invalid_request', 'event_type is required');
    }

    if (!SecurityEvent.SUPPORTED_EVENT_TYPES.includes(event_type)) {
      return sendError(
        res,
        400,
        'invalid_event_type',
        `The event_type '${event_type}' is not a recognized event type.`
      );
    }

    // 3. session_id validation & caller ownership check
    let resolvedSessionId = null;
    if (session_id !== undefined && session_id !== null) {
      if (typeof session_id !== 'string' || session_id.trim() === '') {
        return sendError(res, 400, 'invalid_request', 'session_id must be a string');
      }

      resolvedSessionId = session_id.trim();
      const sessionRecord = await Session.findOne({
        where: {
          id: resolvedSessionId,
          user_id: callerId
        }
      });

      if (!sessionRecord) {
        return sendError(res, 404, 'not_found', 'Session not found');
      }
    }

    // 4. context validation (optional { ip_address, device_fingerprint })
    const resolvedContext = {};
    if (context !== undefined && context !== null) {
      if (typeof context !== 'object' || Array.isArray(context)) {
        return sendError(res, 400, 'invalid_request', 'context must be an object');
      }

      if (context.ip_address !== undefined && context.ip_address !== null) {
        if (typeof context.ip_address !== 'string') {
          return sendError(res, 400, 'invalid_request', 'context.ip_address must be a string');
        }
        resolvedContext.ip_address = normalizeIp(context.ip_address) || context.ip_address.trim();
      }

      if (context.device_fingerprint !== undefined && context.device_fingerprint !== null) {
        if (typeof context.device_fingerprint !== 'string') {
          return sendError(res, 400, 'invalid_request', 'context.device_fingerprint must be a string');
        }
        if (!validateDeviceFingerprint(context.device_fingerprint)) {
          return sendError(res, 400, 'invalid_request', 'Invalid device fingerprint in context');
        }
        resolvedContext.device_fingerprint = context.device_fingerprint.trim();
      }
    }

    // 5. metadata validation (optional { action_sensitivity })
    const resolvedMetadata = {};
    if (metadata !== undefined && metadata !== null) {
      if (typeof metadata !== 'object' || Array.isArray(metadata)) {
        return sendError(res, 400, 'invalid_request', 'metadata must be an object');
      }

      if (metadata.action_sensitivity !== undefined && metadata.action_sensitivity !== null) {
        if (
          typeof metadata.action_sensitivity !== 'string' ||
          !SecurityEvent.ACTION_SENSITIVITY_LEVELS.includes(metadata.action_sensitivity)
        ) {
          return sendError(
            res,
            400,
            'invalid_request',
            `Invalid action_sensitivity: '${metadata.action_sensitivity}'. Must be one of: ${SecurityEvent.ACTION_SENSITIVITY_LEVELS.join(', ')}`
          );
        }
        resolvedMetadata.action_sensitivity = metadata.action_sensitivity;
      }
    }

    // Server generates deterministic arrival timestamp; client timestamps are ignored
    const serverTimestamp = new Date();

    const proposedEvent = {
      user_id: callerId,
      session_id: resolvedSessionId,
      event_type,
      timestamp: serverTimestamp,
      context: resolvedContext,
      metadata: resolvedMetadata
    };

    // Advisory evaluation through riskEngineService with proposedEvent
    const result = await riskEngineService.evaluateRisk(proposedEvent, { proposedEvent });

    if (!result || result.status === 'unavailable') {
      return res.status(503).json({
        status: 'unavailable',
        risk_score: null,
        risk_tier: null,
        contributing_signals: [],
        error_code: 'risk_evaluation_failed',
        explanation: result?.explanation || {
          user_facing: 'Security risk evaluation is temporarily unavailable.',
          admin_facing: 'Risk engine failed to evaluate context: risk_evaluation_failed.'
        }
      });
    }

    return res.status(200).json({
      risk_score: result.risk_score,
      risk_tier: result.risk_tier,
      contributing_signals: result.contributing_signals,
      explanation: result.explanation,
      evaluated_at: serverTimestamp.toISOString()
    });
  } catch (error) {
    console.error('[Risk API] Error evaluating proposed event risk:', error);
    return res.status(503).json({
      status: 'unavailable',
      risk_score: null,
      risk_tier: null,
      contributing_signals: [],
      error_code: 'risk_evaluation_failed',
      explanation: {
        user_facing: 'Security risk evaluation is temporarily unavailable.',
        admin_facing: 'Risk engine failed to evaluate context: risk_evaluation_failed.'
      }
    });
  }
});

module.exports = router;
