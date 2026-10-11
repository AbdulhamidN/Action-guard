'use strict';

const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const {
  getDelayedAction,
  listDelayedActionsForUser,
  cancelDelayedAction,
  executeDelayedAction,
  sanitizePublicActionPayload
} = require('../services/coolingOffService');
const { sendError } = require('../utils/errors');

const router = express.Router();

/**
 * GET /api/v1/cooling-off/actions
 *
 * Lists all active pending delayed actions for the authenticated user.
 */
router.get('/actions', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id || req.user.user_id;
    const actions = await listDelayedActionsForUser(userId);

    const sanitized = actions.map((a) => ({
      id: a.id,
      action_type: a.action_type,
      action_sensitivity: a.action_sensitivity,
      scheduled_at_risk_tier: a.scheduled_at_risk_tier,
      cooling_off_seconds: a.cooling_off_seconds,
      status: a.status,
      scheduled_at: a.scheduled_at,
      execute_at: a.execute_at,
      expires_at: a.expires_at,
      decision_id: a.decision_id
    }));

    return res.status(200).json({
      actions: sanitized,
      count: sanitized.length
    });
  } catch (error) {
    console.error('[CoolingOffRoutes] Error listing delayed actions:', error);
    return sendError(res, 500, 'internal_error', 'An error occurred while listing delayed actions');
  }
});

/**
 * GET /api/v1/cooling-off/actions/:id
 *
 * Retrieves details of a specific delayed action.
 */
router.get('/actions/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id || req.user.user_id;
    const action = await getDelayedAction(req.params.id);

    if (!action) {
      return sendError(res, 404, 'delayed_action_not_found', 'Delayed action not found');
    }

    if (action.user_id !== userId) {
      return sendError(res, 403, 'forbidden', 'Caller does not own this delayed action');
    }

    return res.status(200).json({
      action: {
        id: action.id,
        action_type: action.action_type,
        action_sensitivity: action.action_sensitivity,
        action_payload: sanitizePublicActionPayload(action.action_payload),
        scheduled_at_risk_tier: action.scheduled_at_risk_tier,
        cooling_off_seconds: action.cooling_off_seconds,
        status: action.status,
        scheduled_at: action.scheduled_at,
        execute_at: action.execute_at,
        expires_at: action.expires_at,
        cancelled_at: action.cancelled_at,
        executed_at: action.executed_at,
        cancellation_reason: action.cancellation_reason,
        failure_reason: action.failure_reason,
        execution_result: action.execution_result,
        decision_id: action.decision_id
      }
    });
  } catch (error) {
    console.error('[CoolingOffRoutes] Error retrieving delayed action:', error);
    return sendError(res, 500, 'internal_error', 'An error occurred while retrieving delayed action');
  }
});

/**
 * POST /api/v1/cooling-off/actions/:id/cancel
 *
 * Cancels a pending delayed action during its cooling-off period.
 * Requires cancellation_token in request body or X-Cancellation-Token header.
 */
router.post('/actions/:id/cancel', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id || req.user.user_id;
    const token =
      (req.body && req.body.cancellation_token) ||
      req.headers['x-cancellation-token'] ||
      '';

    const reason = (req.body && req.body.reason) || 'user_requested_cancellation';

    const cancelledAction = await cancelDelayedAction({
      actionId: req.params.id,
      cancellationToken: token,
      userId,
      reason
    });

    return res.status(200).json({
      status: 'cancelled',
      action_id: cancelledAction.id,
      cancelled_at: cancelledAction.cancelled_at,
      reason: cancelledAction.cancellation_reason
    });
  } catch (error) {
    if (error.status && error.code) {
      return sendError(res, error.status, error.code, error.message);
    }
    console.error('[CoolingOffRoutes] Error cancelling delayed action:', error);
    return sendError(res, 500, 'internal_error', 'An error occurred while cancelling delayed action');
  }
});

/**
 * POST /api/v1/cooling-off/actions/:id/execute
 *
 * Manually triggers execution of an eligible delayed action whose cooling-off period has expired.
 */
router.post('/actions/:id/execute', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id || req.user.user_id;
    const action = await getDelayedAction(req.params.id);

    if (!action) {
      return sendError(res, 404, 'delayed_action_not_found', 'Delayed action not found');
    }

    if (action.user_id !== userId) {
      return sendError(res, 403, 'forbidden', 'Caller does not own this delayed action');
    }

    const result = await executeDelayedAction({
      actionId: req.params.id,
      triggeredBy: 'user'
    });

    if (result.status === 'rejected') {
      return res.status(403).json({
        error: {
          code: 'action_rejected',
          message: `Delayed action was rejected at recheck: ${result.reason}`,
          reason: result.reason
        }
      });
    }

    return res.status(200).json({
      status: 'completed',
      action_id: req.params.id,
      result: result.result,
      execution_result: result.result
    });
  } catch (error) {
    if (error.status && error.code) {
      return res.status(error.status).json({
        error: {
          code: error.code,
          message: error.message,
          ...(error.remaining_seconds !== undefined ? { remaining_seconds: error.remaining_seconds } : {})
        }
      });
    }
    console.error('[CoolingOffRoutes] Error executing delayed action:', error);
    return sendError(res, 500, 'internal_error', 'An error occurred while executing delayed action');
  }
});

module.exports = router;
