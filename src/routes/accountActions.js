'use strict';

const express = require('express');
const bcrypt = require('bcrypt');
const { User } = require('../database/models');
const { authenticateToken } = require('../middleware/auth');
const { enforce } = require('../middleware/pep');
const { terminateAllUserSessions } = require('../services/sessionService');
const { sendError } = require('../utils/errors');

const router = express.Router();

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_REGEX = /^\+[1-9]\d{6,14}$/;

/**
 * Authoritative registry of protected sensitive-action routes for PEP audit & test verification.
 */
const SENSITIVE_ROUTE_REGISTRY = Object.freeze([
  Object.freeze({
    method: 'POST',
    path: '/password',
    fullPath: '/api/v1/account/password',
    actionType: 'password_change',
    sensitivity: 'high',
    scope: 'credential_change'
  }),
  Object.freeze({
    method: 'POST',
    path: '/recovery-email',
    fullPath: '/api/v1/account/recovery-email',
    actionType: 'recovery_email_change',
    sensitivity: 'high',
    scope: 'account_recovery'
  }),
  Object.freeze({
    method: 'POST',
    path: '/phone',
    fullPath: '/api/v1/account/phone',
    actionType: 'phone_number_change',
    sensitivity: 'medium',
    scope: 'account_recovery'
  }),
  Object.freeze({
    method: 'POST',
    path: '/mfa',
    fullPath: '/api/v1/account/mfa',
    actionType: 'mfa_change',
    sensitivity: 'high',
    scope: 'credential_change'
  }),
  Object.freeze({
    method: 'POST',
    path: '/high-impact',
    fullPath: '/api/v1/account/high-impact',
    actionType: 'high_impact_action',
    sensitivity: 'critical',
    scope: 'sensitive_action'
  })
]);

function validatePasswordPayload(req) {
  const { current_password, new_password } = req.body || {};
  if (
    !current_password ||
    typeof current_password !== 'string' ||
    !new_password ||
    typeof new_password !== 'string' ||
    new_password.length < 8
  ) {
    return {
      valid: false,
      status: 400,
      code: 'invalid_request',
      message: 'current_password and a new_password of at least 8 characters are required'
    };
  }
  if (new_password === current_password) {
    return {
      valid: false,
      status: 400,
      code: 'invalid_request',
      message: 'new_password must be different from current_password'
    };
  }
  return { valid: true };
}

function validateRecoveryEmailPayload(req) {
  const { recovery_email } = req.body || {};
  if (
    !recovery_email ||
    typeof recovery_email !== 'string' ||
    recovery_email.trim().length > 255 ||
    !EMAIL_REGEX.test(recovery_email.trim())
  ) {
    return {
      valid: false,
      status: 400,
      code: 'invalid_request',
      message: 'A valid recovery_email address is required'
    };
  }
  return { valid: true };
}

function validatePhonePayload(req) {
  const { phone_number } = req.body || {};
  if (
    !phone_number ||
    typeof phone_number !== 'string' ||
    !PHONE_REGEX.test(phone_number.trim())
  ) {
    return {
      valid: false,
      status: 400,
      code: 'invalid_request',
      message: 'A valid E.164 phone_number (starting with +) is required'
    };
  }
  return { valid: true };
}

function validateMfaPayload(req) {
  const { mfa_enabled } = req.body || {};
  if (typeof mfa_enabled !== 'boolean') {
    return {
      valid: false,
      status: 400,
      code: 'invalid_request',
      message: 'mfa_enabled boolean is required'
    };
  }
  return { valid: true };
}

function validateHighImpactPayload(req) {
  const { operation } = req.body || {};
  if (
    !operation ||
    typeof operation !== 'string' ||
    operation.trim().length === 0 ||
    operation.trim().length > 128
  ) {
    return {
      valid: false,
      status: 400,
      code: 'invalid_request',
      message: 'A valid operation string is required'
    };
  }
  return { valid: true };
}

/**
 * POST /api/v1/account/password
 *
 * Protected by PEP ('password_change', sensitivity: 'high', scope: 'credential_change').
 * Validates current_password, updates password_hash, and terminates all active sessions
 * and elevations for the user (including the current session), requiring a fresh login.
 */
router.post(
  '/password',
  authenticateToken,
  enforce('password_change', {
    sensitivity: 'high',
    scope: 'credential_change',
    validateRequest: validatePasswordPayload
  }),
  async (req, res) => {
    try {
      const userId = req.user.id || req.user.user_id;
      const { current_password, new_password } = req.body || {};

      const user = await User.findByPk(userId);
      if (!user) {
        if (req.rejectProtectedAction) {
          await req.rejectProtectedAction('user_not_found');
        }
        return sendError(res, 404, 'not_found', 'User not found');
      }

      const isCurrentValid = await bcrypt.compare(current_password, user.password_hash);
      if (!isCurrentValid) {
        if (req.rejectProtectedAction) {
          await req.rejectProtectedAction('invalid_current_password');
        }
        return sendError(res, 401, 'invalid_credentials', 'Current password is incorrect');
      }

      const newPasswordHash = await bcrypt.hash(new_password, 10);
      await user.update({ password_hash: newPasswordHash });

      // Approved Decision #4: Invalidate all sessions and elevations for the user, including current session
      const { terminatedCount } = await terminateAllUserSessions(
        userId,
        'password_change',
        { throwOnError: true }
      );

      if (req.completeProtectedAction) {
        await req.completeProtectedAction({
          sessions_terminated: terminatedCount
        });
      }

      return res.status(200).json({
        status: 'completed',
        action: 'password_change',
        decision_id: req.policyDecision ? req.policyDecision.id : null,
        sessions_terminated: terminatedCount,
        reauthentication_required: true
      });
    } catch (error) {
      if (req.failProtectedAction) {
        await req.failProtectedAction(error);
      }
      console.error('[AccountActions] Error changing password:', error);
      return sendError(res, 500, 'internal_error', 'An unexpected error occurred while changing password');
    }
  }
);

/**
 * POST /api/v1/account/recovery-email
 *
 * Protected by PEP ('recovery_email_change', sensitivity: 'high', scope: 'account_recovery').
 */
router.post(
  '/recovery-email',
  authenticateToken,
  enforce('recovery_email_change', {
    sensitivity: 'high',
    scope: 'account_recovery',
    validateRequest: validateRecoveryEmailPayload
  }),
  async (req, res) => {
    try {
      const userId = req.user.id || req.user.user_id;
      const { recovery_email } = req.body || {};
      const normalizedEmail = recovery_email.trim().toLowerCase();

      const user = await User.findByPk(userId);
      if (!user) {
        if (req.rejectProtectedAction) {
          await req.rejectProtectedAction('user_not_found');
        }
        return sendError(res, 404, 'not_found', 'User not found');
      }

      if (user.email && user.email.trim().toLowerCase() === normalizedEmail) {
        if (req.rejectProtectedAction) {
          await req.rejectProtectedAction('recovery_email_matches_primary');
        }
        return sendError(
          res,
          400,
          'invalid_request',
          'recovery_email must be different from the primary registration email'
        );
      }

      await user.update({ recovery_email: normalizedEmail });

      if (req.completeProtectedAction) {
        await req.completeProtectedAction({
          recovery_email: normalizedEmail
        });
      }

      return res.status(200).json({
        status: 'completed',
        action: 'recovery_email_change',
        recovery_email: normalizedEmail,
        decision_id: req.policyDecision ? req.policyDecision.id : null
      });
    } catch (error) {
      if (req.failProtectedAction) {
        await req.failProtectedAction(error);
      }
      console.error('[AccountActions] Error changing recovery email:', error);
      return sendError(res, 500, 'internal_error', 'An unexpected error occurred while updating recovery email');
    }
  }
);

/**
 * POST /api/v1/account/phone
 *
 * Protected by PEP ('phone_number_change', sensitivity: 'medium', scope: 'account_recovery').
 */
router.post(
  '/phone',
  authenticateToken,
  enforce('phone_number_change', {
    sensitivity: 'medium',
    scope: 'account_recovery',
    validateRequest: validatePhonePayload
  }),
  async (req, res) => {
    try {
      const userId = req.user.id || req.user.user_id;
      const { phone_number } = req.body || {};
      const normalizedPhone = phone_number.trim();

      const user = await User.findByPk(userId);
      if (!user) {
        if (req.rejectProtectedAction) {
          await req.rejectProtectedAction('user_not_found');
        }
        return sendError(res, 404, 'not_found', 'User not found');
      }

      await user.update({ phone_number: normalizedPhone });

      if (req.completeProtectedAction) {
        await req.completeProtectedAction({
          phone_number: normalizedPhone
        });
      }

      return res.status(200).json({
        status: 'completed',
        action: 'phone_number_change',
        phone_number: normalizedPhone,
        decision_id: req.policyDecision ? req.policyDecision.id : null
      });
    } catch (error) {
      if (req.failProtectedAction) {
        await req.failProtectedAction(error);
      }
      console.error('[AccountActions] Error changing phone number:', error);
      return sendError(res, 500, 'internal_error', 'An unexpected error occurred while updating phone number');
    }
  }
);

/**
 * POST /api/v1/account/mfa
 *
 * Protected by PEP ('mfa_change', sensitivity: 'high', scope: 'credential_change').
 */
router.post(
  '/mfa',
  authenticateToken,
  enforce('mfa_change', {
    sensitivity: 'high',
    scope: 'credential_change',
    validateRequest: validateMfaPayload
  }),
  async (req, res) => {
    try {
      const userId = req.user.id || req.user.user_id;
      const { mfa_enabled } = req.body || {};

      const user = await User.findByPk(userId);
      if (!user) {
        if (req.rejectProtectedAction) {
          await req.rejectProtectedAction('user_not_found');
        }
        return sendError(res, 404, 'not_found', 'User not found');
      }

      await user.update({ mfa_enabled });

      if (req.completeProtectedAction) {
        await req.completeProtectedAction({
          mfa_enabled
        });
      }

      return res.status(200).json({
        status: 'completed',
        action: 'mfa_change',
        mfa_enabled,
        decision_id: req.policyDecision ? req.policyDecision.id : null
      });
    } catch (error) {
      if (req.failProtectedAction) {
        await req.failProtectedAction(error);
      }
      console.error('[AccountActions] Error updating MFA settings:', error);
      return sendError(res, 500, 'internal_error', 'An unexpected error occurred while updating MFA settings');
    }
  }
);

/**
 * POST /api/v1/account/high-impact
 *
 * Protected by PEP ('high_impact_action', sensitivity: 'critical', scope: 'sensitive_action').
 */
router.post(
  '/high-impact',
  authenticateToken,
  enforce('high_impact_action', {
    sensitivity: 'critical',
    scope: 'sensitive_action',
    validateRequest: validateHighImpactPayload
  }),
  async (req, res) => {
    try {
      const { operation, target } = req.body || {};
      const trimmedOperation = operation.trim();
      const sanitizedTarget =
        typeof target === 'string' && target.trim().length <= 255 ? target.trim() : null;

      if (req.completeProtectedAction) {
        await req.completeProtectedAction({
          operation: trimmedOperation,
          ...(sanitizedTarget ? { target: sanitizedTarget } : {})
        });
      }

      return res.status(200).json({
        status: 'completed',
        action: 'high_impact_action',
        operation: trimmedOperation,
        ...(sanitizedTarget ? { target: sanitizedTarget } : {}),
        decision_id: req.policyDecision ? req.policyDecision.id : null
      });
    } catch (error) {
      if (req.failProtectedAction) {
        await req.failProtectedAction(error);
      }
      console.error('[AccountActions] Error executing high-impact action:', error);
      return sendError(res, 500, 'internal_error', 'An unexpected error occurred while executing high-impact action');
    }
  }
);

router.SENSITIVE_ROUTE_REGISTRY = SENSITIVE_ROUTE_REGISTRY;

module.exports = router;

