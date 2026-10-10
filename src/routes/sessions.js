const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const { Session } = require('../database/models');
const { getLatestRiskAssessment } = require('../services/riskEngineService');
const { sendError } = require('../utils/errors');

const router = express.Router();

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
