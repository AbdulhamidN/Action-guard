const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const { stepUpRateLimiter, apiRateLimiter } = require('../middleware/rateLimiter');
const { VALIDATION_LIMITS, validateIdParam } = require('../middleware/validation');
const { Session } = require('../database/models');
const { getLatestRiskAssessment } = require('../services/riskEngineService');
const { sendError } = require('../utils/errors');
const { grantElevation, checkElevation } = require('../services/elevationService');
const { issueStepUpChallenge, verifyStepUpChallenge } = require('../services/stepUpService');
const { extractServerRequestContext } = require('../utils/requestContext');

const router = express.Router();

/**
 * POST /api/v1/sessions/:id/step-up/challenge
 *
 * Issues a session- and scope-bound step-up OTP challenge delivered to the user's
 * immutable registration email address.
 */
router.post(
  '/:id/step-up/challenge',
  stepUpRateLimiter,
  validateIdParam('id'),
  authenticateToken,
  async (req, res) => {
    try {
      const callerId = req.user.id || req.user.user_id;
      const requestedSessionId = req.params.id;
      const activeSessionId = req.session?.session_id || req.user?.session_id;

      if (requestedSessionId !== activeSessionId) {
        return sendError(res, 403, 'forbidden', 'Cannot request a step-up challenge for another session');
      }

      const { scope } = req.body || {};
      if (
        !scope ||
        typeof scope !== 'string' ||
        scope.trim().length === 0 ||
        scope.length > VALIDATION_LIMITS.MAX_SCOPE_LENGTH
      ) {
        return sendError(res, 400, 'invalid_request', 'Elevation scope is required');
      }

      try {
        const challenge = await issueStepUpChallenge({
          userId: callerId,
          sessionId: activeSessionId,
          scope: scope.trim()
        });
        return res.status(200).json(challenge);
      } catch (challengeErr) {
        if (
          challengeErr.code === 'VERIFICATION_PROVIDER_UNAVAILABLE' ||
          challengeErr.code === 'INVALID_VERIFICATION_KEY'
        ) {
          return sendError(res, 501, 'verification_provider_unavailable', challengeErr.message);
        }
        if (challengeErr.code === 'CHALLENGE_LIMITED') {
          res.set('Retry-After', String(challengeErr.retryAfterSeconds || 30));
          return res.status(429).json({
            error: {
              code: 'challenge_limited',
              message: challengeErr.message,
              retry_after_seconds: challengeErr.retryAfterSeconds
            }
          });
        }
        if (challengeErr.code === 'INVALID_ELEVATION_SCOPE') {
          return sendError(res, 400, 'invalid_scope', challengeErr.message);
        }
        if (challengeErr.code === 'INVALID_REQUEST') {
          return sendError(res, 400, 'invalid_request', challengeErr.message);
        }
        throw challengeErr;
      }
    } catch (error) {
      console.error('[Sessions API] Error issuing step-up challenge:', error);
      return sendError(res, 500, 'internal_error', 'An unexpected error occurred while issuing step-up challenge');
    }
  }
);

/**
 * POST /api/v1/sessions/:id/step-up/verify
 *
 * Verifies a step-up OTP code, signs a short-lived ES256 verification ticket,
 * and redeems it server-side to elevate the active session for the bound scope.
 */
router.post(
  '/:id/step-up/verify',
  stepUpRateLimiter,
  validateIdParam('id'),
  authenticateToken,
  async (req, res) => {
    try {
      const callerId = req.user.id || req.user.user_id;
      const requestedSessionId = req.params.id;
      const activeSessionId = req.session?.session_id || req.user?.session_id;

      if (requestedSessionId !== activeSessionId) {
        return sendError(res, 403, 'forbidden', 'Cannot verify a step-up challenge for another session');
      }

      const { challenge_id, code, duration_seconds } = req.body || {};
      if (
        !challenge_id ||
        typeof challenge_id !== 'string' ||
        challenge_id.trim().length === 0 ||
        challenge_id.length > VALIDATION_LIMITS.MAX_CHALLENGE_ID_LENGTH
      ) {
        return sendError(res, 400, 'invalid_request', 'challenge_id is required');
      }
      if (
        !code ||
        typeof code !== 'string' ||
        code.trim().length === 0 ||
        code.length > VALIDATION_LIMITS.MAX_OTP_CODE_LENGTH
      ) {
        return sendError(res, 400, 'invalid_request', 'Verification code is required');
      }

      const context = await extractServerRequestContext(req);
      const maxSessionExpiresAt = req.session?.max_expires_at
        ? Number(req.session.max_expires_at)
        : null;

      try {
        const elevation = await verifyStepUpChallenge({
          userId: callerId,
          sessionId: activeSessionId,
          challengeId: challenge_id,
          code,
          durationSeconds: typeof duration_seconds === 'number' ? duration_seconds : undefined,
          maxSessionExpiresAt,
          context
        });
        return res.status(200).json(elevation);
      } catch (verifyErr) {
        if (
          verifyErr.code === 'VERIFICATION_PROVIDER_UNAVAILABLE' ||
          verifyErr.code === 'INVALID_VERIFICATION_KEY'
        ) {
          return sendError(res, 501, 'verification_provider_unavailable', verifyErr.message);
        }
        if (verifyErr.code === 'INVALID_REQUEST') {
          return sendError(res, 400, 'invalid_request', verifyErr.message);
        }
        if (verifyErr.code === 'CHALLENGE_BINDING_MISMATCH') {
          return sendError(res, 403, 'challenge_mismatch', verifyErr.message);
        }
        if (verifyErr.code === 'CHALLENGE_EXPIRED_OR_NOT_FOUND') {
          return sendError(res, 401, 'challenge_expired', verifyErr.message);
        }
        if (verifyErr.code === 'VERIFICATION_FAILED_CONTAINED') {
          return res.status(403).json({
            error: {
              code: 'session_contained',
              message: verifyErr.message,
              session_contained: Boolean(verifyErr.sessionContained),
              account_locked: Boolean(verifyErr.accountLocked),
              locked_until: verifyErr.lockedUntil || null,
              retry_after_seconds: verifyErr.retryAfterSeconds || null
            }
          });
        }
        if (
          verifyErr.code === 'VERIFICATION_CODE_INVALID' ||
          verifyErr.code === 'CHALLENGE_MAX_ATTEMPTS_EXCEEDED'
        ) {
          return res.status(401).json({
            error: {
              code: 'verification_failed',
              message: verifyErr.message,
              remaining_attempts:
                typeof verifyErr.remainingAttempts === 'number' ? verifyErr.remainingAttempts : 0
            }
          });
        }
        if (
          verifyErr.code === 'SESSION_MAX_LIFETIME_EXCEEDED' ||
          verifyErr.code === 'SESSION_EXPIRED'
        ) {
          return sendError(res, 403, 'session_expired', verifyErr.message);
        }
        throw verifyErr;
      }
    } catch (error) {
      console.error('[Sessions API] Error verifying step-up challenge:', error);
      return sendError(res, 500, 'internal_error', 'An unexpected error occurred while verifying step-up challenge');
    }
  }
);

/**
 * POST /api/v1/sessions/:id/elevate
 *
 * Requests temporary, scoped privilege elevation for the active session.
 * Requires a valid, cryptographically verified single-use verification ticket.
 */
router.post(
  '/:id/elevate',
  stepUpRateLimiter,
  validateIdParam('id'),
  authenticateToken,
  async (req, res) => {
    try {
      const callerId = req.user.id || req.user.user_id;
      const requestedSessionId = req.params.id;
      const activeSessionId = req.session?.session_id || req.user?.session_id;

      if (requestedSessionId !== activeSessionId) {
        return sendError(res, 403, 'forbidden', 'Cannot elevate a session other than the active session');
      }

      const { scope, verification_ticket, duration_seconds } = req.body || {};
      if (
        !scope ||
        typeof scope !== 'string' ||
        scope.trim().length === 0 ||
        scope.length > VALIDATION_LIMITS.MAX_SCOPE_LENGTH
      ) {
        return sendError(res, 400, 'invalid_request', 'Elevation scope is required');
      }

      if (
        !verification_ticket ||
        typeof verification_ticket !== 'string' ||
        verification_ticket.trim().length === 0 ||
        verification_ticket.length > VALIDATION_LIMITS.MAX_TICKET_LENGTH
      ) {
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
router.get(
  '/:id/elevate/:scope',
  apiRateLimiter,
  validateIdParam('id'),
  authenticateToken,
  async (req, res) => {
    try {
      const callerId = req.user.id || req.user.user_id;
      const requestedSessionId = req.params.id;
      const activeSessionId = req.session?.session_id || req.user?.session_id;

      if (requestedSessionId !== activeSessionId) {
        return sendError(res, 403, 'forbidden', 'Cannot inspect elevation for another session');
      }

      const requestedScope = req.params.scope;
      if (
        !requestedScope ||
        typeof requestedScope !== 'string' ||
        requestedScope.length > VALIDATION_LIMITS.MAX_SCOPE_LENGTH
      ) {
        return sendError(res, 400, 'invalid_request', 'Invalid elevation scope parameter');
      }

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
  }
);

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
router.get(
  '/:id',
  apiRateLimiter,
  validateIdParam('id'),
  authenticateToken,
  async (req, res) => {
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
          risk_tier: latestAssessment.risk_tier,
          evaluated_at:
            latestAssessment.evaluated_at instanceof Date
              ? latestAssessment.evaluated_at.toISOString()
              : new Date(latestAssessment.evaluated_at).toISOString(),
          explanation: {
            user_facing:
              latestAssessment.explanation && typeof latestAssessment.explanation.user_facing === 'string'
                ? latestAssessment.explanation.user_facing
                : ''
          }
        }
      : {
          risk_tier: null,
          evaluated_at: null,
          explanation: {
            user_facing: ''
          }
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

/**
 * GET /api/v1/sessions/:id/step-up/demo-code?challenge_id=...
 * Development and demo only endpoint returning latest demo OTP code for a challenge.
 * Returns 404 in production or when ACTIONGUARD_DEMO_MODE is not true.
 */
router.get(
  '/:id/step-up/demo-code',
  apiRateLimiter,
  validateIdParam('id'),
  authenticateToken,
  async (req, res) => {
    try {
      if (process.env.NODE_ENV === 'production' || process.env.ACTIONGUARD_DEMO_MODE !== 'true') {
        return sendError(res, 404, 'not_found', 'Demo code endpoint is not available');
      }

      const requestedSessionId = req.params.id;
      const activeSessionId = req.session?.session_id || req.user?.session_id;

      if (requestedSessionId !== activeSessionId) {
        return sendError(res, 403, 'forbidden', 'Cannot retrieve demo code for another session');
      }

      const challengeId = req.query.challenge_id;
      if (!challengeId || typeof challengeId !== 'string') {
        return sendError(res, 400, 'invalid_request', 'challenge_id query parameter is required');
      }

      const { getDemoChallengeRecord } = require('../services/stepUpService');
      const challenge = getDemoChallengeRecord(challengeId);
      if (!challenge || challenge.sessionId !== activeSessionId) {
        return sendError(res, 404, 'not_found', 'Demo challenge not found or expired');
      }

      return res.status(200).json({
        challenge_id: challengeId,
        scope: challenge.scope,
        demo_code: challenge.otp,
        expires_at: challenge.expiresAt
      });
    } catch (error) {
      console.error('[Sessions API] Error retrieving demo code:', error);
      return sendError(res, 500, 'internal_error', 'An unexpected error occurred while retrieving demo code');
    }
  }
);

module.exports = router;
