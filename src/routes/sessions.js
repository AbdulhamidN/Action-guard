const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const { Session } = require('../database/models');
const { getLatestRiskAssessment } = require('../services/riskEngineService');
const { sendError } = require('../utils/errors');
const { grantElevation, checkElevation } = require('../services/elevationService');

const router = express.Router();

/**
 * POST /api/v1/sessions/:id/elevate
 *
 * Requests temporary, scoped privilege elevation for the active session.
 * Requires a valid, cryptographically verified single-use verification ticket.
 */
router.post('/:id/elevate', authenticateToken, async (req, res) => {
  try {
    const callerId = req.user.id || req.user.user_id;
    const requestedSessionId = req.params.id;
    const activeSessionId = req.session?.session_id || req.user?.session_id;

    if (requestedSessionId !== activeSessionId) {
      return sendError(res, 403, 'forbidden', 'Cannot elevate a session other than the active session');
    }

    const { scope, verification_ticket, duration_seconds } = req.body || {};
    if (!scope || typeof scope !== 'string') {
      return sendError(res, 400, 'invalid_request', 'Elevation scope is required');
    }

    if (!verification_ticket || typeof verification_ticket !== 'string') {
      return sendError(res, 400, 'invalid_request', 'Verification ticket is required');
    }

    const maxSessionExpiresAt = req.session?.max_expires_at
      ? Number(req.session.max_expires_at)
      : null;

    try {
      const elevation = await grantElevation({
        sessionId: activeSessionId,
        userId: callerId,
        scope: scope.trim(),
        verificationTicket: verification_ticket.trim(),
        durationSeconds: typeof duration_seconds === 'number' ? duration_seconds : undefined,
        maxSessionExpiresAt
      });

      return res.status(200).json(elevation);
    } catch (grantErr) {
      if (
        grantErr.code === 'VERIFICATION_PROVIDER_UNAVAILABLE' ||
        grantErr.code === 'INVALID_VERIFICATION_KEY'
      ) {
        return sendError(res, 501, 'verification_provider_unavailable', grantErr.message);
      }
      if (grantErr.code === 'VERIFICATION_TICKET_ALREADY_USED') {
        return sendError(res, 409, 'ticket_already_used', grantErr.message);
      }
      if (grantErr.code === 'INVALID_ELEVATION_SCOPE') {
        return sendError(res, 400, 'invalid_scope', grantErr.message);
      }
      if (
        grantErr.code === 'TICKET_EXPIRED' ||
        grantErr.code === 'INVALID_TICKET' ||
        grantErr.code === 'TICKET_USER_MISMATCH' ||
        grantErr.code === 'TICKET_SESSION_MISMATCH' ||
        grantErr.code === 'TICKET_SCOPE_MISMATCH'
      ) {
        return sendError(res, 401, 'invalid_ticket', grantErr.message);
      }
      if (
        grantErr.code === 'SESSION_MAX_LIFETIME_EXCEEDED' ||
        grantErr.code === 'SESSION_EXPIRED'
      ) {
        return sendError(res, 403, 'session_expired', grantErr.message);
      }
      throw grantErr;
    }
  } catch (error) {
    console.error('[Sessions API] Error elevating session:', error);
    return sendError(res, 500, 'internal_error', 'An unexpected error occurred while elevating session');
  }
});

/**
 * GET /api/v1/sessions/:id/elevate/:scope
 *
 * Checks elevation status for a specific scope on the active session.
 */
router.get('/:id/elevate/:scope', authenticateToken, async (req, res) => {
  try {
    const callerId = req.user.id || req.user.user_id;
    const requestedSessionId = req.params.id;
    const activeSessionId = req.session?.session_id || req.user?.session_id;

    if (requestedSessionId !== activeSessionId) {
      return sendError(res, 403, 'forbidden', 'Cannot inspect elevation for another session');
    }

    const requestedScope = req.params.scope;
    const elevationStatus = await checkElevation({
      sessionId: activeSessionId,
      scope: requestedScope,
      parentSession: req.session || null
    });

    return res.status(200).json(elevationStatus);
  } catch (error) {
    console.error('[Sessions API] Error checking elevation:', error);
    return sendError(res, 500, 'internal_error', 'An unexpected error occurred while checking elevation');
  }
});

/**
 * GET /api/v1/sessions/:id
 *
 * Retrieves metadata and current evaluated risk state for an active or historical session.
 * Strictly scoped to the authenticated caller identity.
 *
 * Missing session or session belonging to another user returns identical 404 not_found.
 * Omissions (per Module 6.4 api contract):
 * - trusted_device and active_restrictions are omitted (scheduled for Module 11 and Module 8).
 * - Sensitive raw attributes (IP, device fingerprint, coordinates, user_id) are never returned.
 */
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const callerId = req.user.id || req.user.user_id;
    const requestedSessionId = req.params.id;

    if (!requestedSessionId || typeof requestedSessionId !== 'string') {
      return sendError(res, 404, 'not_found', 'Session not found');
    }

    const sessionRecord = await Session.findOne({
      where: {
        id: requestedSessionId.trim(),
        user_id: callerId
      }
    });

    if (!sessionRecord) {
      return sendError(res, 404, 'not_found', 'Session not found');
    }

    // Retrieve latest risk assessment for this user and session
    const latestAssessment = await getLatestRiskAssessment(callerId, sessionRecord.id);

    const risk = latestAssessment
      ? {
          current_risk_score: latestAssessment.risk_score,
          risk_tier: latestAssessment.risk_tier,
          contributing_signals: latestAssessment.contributing_signals || [],
          evaluated_at:
            latestAssessment.evaluated_at instanceof Date
              ? latestAssessment.evaluated_at.toISOString()
              : new Date(latestAssessment.evaluated_at).toISOString()
        }
      : {
          current_risk_score: null,
          risk_tier: null,
          contributing_signals: null,
          evaluated_at: null
        };

    return res.status(200).json({
      session_id: sessionRecord.id,
      created_at:
        sessionRecord.created_at instanceof Date
          ? sessionRecord.created_at.toISOString()
          : new Date(sessionRecord.created_at).toISOString(),
      expires_at:
        sessionRecord.expires_at instanceof Date
          ? sessionRecord.expires_at.toISOString()
          : new Date(sessionRecord.expires_at).toISOString(),
      is_active: Boolean(sessionRecord.is_active),
      risk
    });
  } catch (error) {
    console.error('[Sessions API] Error retrieving session:', error);
    return sendError(res, 500, 'internal_error', 'An unexpected error occurred while retrieving session');
  }
});

module.exports = router;
