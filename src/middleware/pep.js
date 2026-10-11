'use strict';

const { PolicyDecision } = require('../database/models');
const policyLoader = require('../services/policyLoader');
const { decide, SENSITIVITY_RANKS } = require('../utils/policyDecision');
const { recordSecurityEvent } = require('../services/eventService');
const { checkElevation } = require('../services/elevationService');
const {
  shouldTriggerContainmentForDecision,
  containSessionAndLockAccount
} = require('../services/containmentService');
const { extractServerRequestContext } = require('../utils/requestContext');
const { ACTION_ELEVATION_SCOPE_MAP } = require('../config/sessionConfig');
const eventBus = require('../events/eventBus');
const { sendError } = require('../utils/errors');

const DEFAULT_DELAY_SECONDS = 300;

/**
 * Default synchronous delay enforcement handler for Module 10b.
 * Can be replaced in Module 10c via setDelayHandler() to enqueue a cancellable cooling-off record.
 */
function defaultDelayHandler(req, res, decisionContext) {
  const { decisionRecord, riskTier, explanation, delaySeconds = DEFAULT_DELAY_SECONDS } = decisionContext;
  return res.status(403).json({
    error: {
      code: 'action_delayed',
      message:
        (explanation && explanation.user_facing) ||
        'This action is temporarily delayed pending security confirmation.',
      decision_id: decisionRecord.id,
      decision: 'delay',
      risk_tier: riskTier,
      retry_after_seconds: delaySeconds,
      explanation:
        (explanation && explanation.user_facing) ||
        'This action is temporarily delayed pending security confirmation.'
    }
  });
}

let activeDelayHandler = defaultDelayHandler;

function setDelayHandler(handler) {
  if (typeof handler !== 'function') {
    throw new TypeError('delayHandler must be a function');
  }
  activeDelayHandler = handler;
}

function resetDelayHandler() {
  activeDelayHandler = defaultDelayHandler;
}

/**
 * Transitions the request's SecurityEvent metadata to action_status: 'completed'.
 * Must be called explicitly by the route handler ONLY after state mutation succeeds.
 */
async function completeProtectedAction(req, extraMetadata = {}) {
  if (req && req.securityEvent && typeof req.securityEvent.update === 'function') {
    await req.securityEvent.update({
      metadata: {
        ...(req.securityEvent.metadata || {}),
        ...extraMetadata,
        action_status: 'completed',
        completed_at: new Date().toISOString()
      }
    });
  }
}

/**
 * Transitions the request's SecurityEvent metadata to action_status: 'rejected'
 * when post-PEP domain or credential checks fail (e.g. invalid current_password).
 */
async function rejectProtectedAction(req, reason, extraMetadata = {}) {
  if (req && req.securityEvent && typeof req.securityEvent.update === 'function') {
    try {
      await req.securityEvent.update({
        metadata: {
          ...(req.securityEvent.metadata || {}),
          ...extraMetadata,
          action_status: 'rejected',
          rejection_reason: reason
        }
      });
    } catch {
      // Ignore metadata update error on rejected request
    }
  }
}

/**
 * Transitions the request's SecurityEvent metadata to action_status: 'failed_execution'
 * when a downstream database mutation or post-mutation operation throws.
 */
async function failProtectedAction(req, error, extraMetadata = {}) {
  if (req && req.securityEvent && typeof req.securityEvent.update === 'function') {
    try {
      await req.securityEvent.update({
        metadata: {
          ...(req.securityEvent.metadata || {}),
          ...extraMetadata,
          action_status: 'failed_execution',
          failure_reason: (error && error.message) || 'execution_failed'
        }
      });
    } catch {
      // Ignore metadata update error on failed execution
    }
  }
}

/**
 * Policy Enforcement Point (PEP) Middleware Factory.
 *
 * Security invariants:
 * 1. Never trusts client-supplied context, timestamp, or action sensitivity.
 * 2. Uses a single immutable activePolicy snapshot per decision and records policy_id@schema_version.
 * 3. Elevation may satisfy 'reverify' only; it never bypasses 'delay' or 'block'.
 * 4. Fails closed (503 policy_enforcement_unavailable) on unexpected policy, Redis, or decision-audit
 *    persistence errors. Never calls next() unless a PolicyDecision record has been durably persisted.
 * 5. Distinguishes attempted, authorized, halted, rejected, failed_execution, and completed states in
 *    security_events.metadata. Never marks an action 'completed' before downstream mutation succeeds.
 * 6. Never records or broadcasts 'contained_and_blocked' unless session invalidation and account locking
 *    have both succeeded.
 *
 * @param {string} actionType - Canonical event_type for the protected action
 * @param {object} [options={}]
 * @param {'low'|'medium'|'high'|'critical'} [options.sensitivity] - Route-defined sensitivity
 * @param {string} [options.scope] - Required elevation scope for step-up re-verification
 * @param {number} [options.delaySeconds=DEFAULT_DELAY_SECONDS] - Cooling-off retry window for 'delay'
 * @param {Function} [options.validateRequest] - Optional pre-event request schema validator
 * @returns {import('express').RequestHandler}
 */
function enforce(actionType, options = {}) {
  if (!actionType || typeof actionType !== 'string') {
    throw new Error('[PEP] enforce(actionType) requires a non-empty actionType string');
  }

  return async function pepMiddleware(req, res, next) {
    try {
      const userId = req.user && (req.user.id || req.user.user_id);
      const sessionId = (req.session && req.session.session_id) || (req.user && req.user.session_id) || null;

      if (!userId || !sessionId) {
        return sendError(res, 401, 'unauthorized', 'Authentication and active session are required');
      }

      // 0. Validate request schema BEFORE recording a security event if route validator is configured
      if (typeof options.validateRequest === 'function') {
        const validation = await options.validateRequest(req);
        if (validation && validation.valid === false) {
          return sendError(
            res,
            validation.status || 400,
            validation.code || 'invalid_request',
            validation.message || 'Invalid request payload'
          );
        }
      }

      // 1. Capture single immutable policy snapshot for this decision
      const activePolicy = policyLoader.getActivePolicy();
      const policyVersion = `${activePolicy.policy_id}@${activePolicy.schema_version}`;

      // 2. Resolve route-defined sensitivity and required elevation scope (never from req.body/req.query)
      const policyDefaultSensitivity =
        (activePolicy.DEFAULT_ACTION_SENSITIVITY && activePolicy.DEFAULT_ACTION_SENSITIVITY[actionType]) ||
        'high';
      let routeSensitivity = policyDefaultSensitivity;
      if (
        options.sensitivity &&
        SENSITIVITY_RANKS[options.sensitivity] !== undefined &&
        SENSITIVITY_RANKS[options.sensitivity] > SENSITIVITY_RANKS[policyDefaultSensitivity]
      ) {
        routeSensitivity = options.sensitivity;
      } else if (options.sensitivity && SENSITIVITY_RANKS[options.sensitivity] !== undefined) {
        routeSensitivity = options.sensitivity;
      }

      const requiredScope =
        options.scope || ACTION_ELEVATION_SCOPE_MAP[actionType] || 'sensitive_action';

      // 3. Extract server-derived request context and arrival timestamp
      const now = new Date();
      const context = await extractServerRequestContext(req);

      // 4. Record the security event and evaluate current session/sequence risk
      const eventRecord = await recordSecurityEvent({
        userId,
        sessionId,
        eventType: actionType,
        timestamp: now,
        context,
        metadata: {
          action_sensitivity: routeSensitivity,
          action_status: 'attempted'
        }
      });

      const assessmentRecord = eventRecord._assessment || null;
      const isRiskAvailable = Boolean(assessmentRecord && assessmentRecord.risk_tier);

      const signalNames =
        isRiskAvailable && Array.isArray(assessmentRecord.contributing_signals)
          ? assessmentRecord.contributing_signals.map((s) => s.signal)
          : [];

      const decisionInput = {
        risk: isRiskAvailable
          ? {
              status: 'ok',
              risk_tier: assessmentRecord.risk_tier,
              signal_names: signalNames
            }
          : {
              status: 'unavailable',
              risk_tier: null,
              signal_names: []
            },
        action: {
          event_type: actionType,
          provided_sensitivity: routeSensitivity
        }
      };

      // 5. Evaluate pure PDP decision against the single activePolicy snapshot
      const pdpResult = decide(decisionInput, activePolicy);
      const recommendedDecision = pdpResult.decision;
      const enforcementMode = pdpResult.enforcement_mode || 'automatic';
      const effectiveRiskScore = isRiskAvailable ? assessmentRecord.risk_score : 100;
      const effectiveRiskTier = isRiskAvailable ? assessmentRecord.risk_tier : 'critical';
      const contributingSignals = isRiskAvailable ? assessmentRecord.contributing_signals || [] : [];

      let effectiveDecision = recommendedDecision;
      let enforcementOutcome = 'blocked';
      let actionStatus = 'halted';
      let isFailSafe = !isRiskAvailable;
      let containmentCheck = { qualifies: false, reason: null };
      let requiresContainment = false;

      // When Risk Engine is unavailable on a protected state-changing route,
      // never silently allow/monitor without at least step-up re-verification
      if (isFailSafe && (recommendedDecision === 'allow' || recommendedDecision === 'monitor')) {
        effectiveDecision = 'reverify';
      }

      // 6. Determine enforcement outcome
      if (enforcementMode === 'recommend_only') {
        if (recommendedDecision === 'allow') {
          effectiveDecision = 'allow';
        } else {
          effectiveDecision = 'monitor';
        }
        enforcementOutcome = 'recommend_only_allowed';
        actionStatus = 'authorized';
      } else if (effectiveDecision === 'allow') {
        enforcementOutcome = 'allowed';
        actionStatus = 'authorized';
      } else if (effectiveDecision === 'monitor') {
        enforcementOutcome = 'monitored';
        actionStatus = 'authorized';
      } else if (effectiveDecision === 'reverify') {
        // Elevation may satisfy 'reverify' ONLY (and only if current risk tier has not exceeded grant tier)
        const elevStatus = await checkElevation({
          sessionId,
          scope: requiredScope,
          parentSession: req.session || null,
          currentRiskTier: isRiskAvailable ? assessmentRecord.risk_tier : null,
          recordUse: true,
          actionType,
          throwOnRedisError: true
        });

        if (elevStatus.elevated) {
          effectiveDecision = 'allow';
          enforcementOutcome = 'elevated_allowed';
          actionStatus = 'authorized';
        } else {
          effectiveDecision = 'reverify';
          enforcementOutcome = isFailSafe ? 'fail_safe_challenged' : 'step_up_challenged';
          actionStatus = 'halted';
        }
      } else if (effectiveDecision === 'delay') {
        // Elevation NEVER bypasses 'delay'
        enforcementOutcome = 'delayed';
        actionStatus = 'halted';
      } else {
        // 'block' — Elevation NEVER bypasses 'block'
        effectiveDecision = 'block';
        containmentCheck = shouldTriggerContainmentForDecision({
          effectiveDecision: 'block',
          riskTier: isRiskAvailable ? assessmentRecord.risk_tier : 'high',
          reasons: pdpResult.reasons
        });
        requiresContainment = Boolean(containmentCheck.qualifies && !isFailSafe);
        // Never record 'contained_and_blocked' before containment actually succeeds
        enforcementOutcome = isFailSafe ? 'fail_safe_blocked' : 'blocked';
        actionStatus = 'halted';
      }

      // 7. Durably persist PolicyDecision record BEFORE any route execution or containment side-effect
      const decisionRecord = await PolicyDecision.create({
        event_id: eventRecord.event_id,
        risk_assessment_id: assessmentRecord ? assessmentRecord.id : null,
        user_id: userId,
        session_id: sessionId,
        action_type: actionType,
        action_sensitivity: routeSensitivity,
        risk_score: effectiveRiskScore,
        risk_tier: effectiveRiskTier,
        recommended_decision: recommendedDecision,
        effective_decision: effectiveDecision,
        enforcement_outcome: enforcementOutcome,
        enforcement_mode: enforcementMode,
        policy_version: policyVersion,
        reasons: pdpResult.reasons || [],
        contributing_signals: contributingSignals,
        explanation: pdpResult.explanation || {
          user_facing: '',
          admin_facing: ''
        },
        decided_at: now
      });

      // 8. Update security_events.metadata with enforcement outcome and current action_status
      await eventRecord.update({
        metadata: {
          ...(eventRecord.metadata || {}),
          action_sensitivity: routeSensitivity,
          action_status: actionStatus,
          decision_id: decisionRecord.id,
          recommended_decision: recommendedDecision,
          effective_decision: effectiveDecision,
          enforcement_outcome: enforcementOutcome,
          enforcement_mode: enforcementMode,
          policy_version: policyVersion,
          ...(requiresContainment ? { containment_status: 'pending' } : {})
        }
      });

      // 9. If qualifying critical block requires containment, execute containment BEFORE
      //    claiming 'contained_and_blocked' or broadcasting decision:recorded
      let containmentResult = {
        session_contained: false,
        account_locked: false,
        locked_until: null,
        retry_after_seconds: null
      };

      if (requiresContainment) {
        try {
          containmentResult = await containSessionAndLockAccount({
            userId,
            sessionId,
            reason: containmentCheck.reason || 'critical_risk_action_blocked',
            triggeringEventId: eventRecord.event_id,
            triggeringDecisionId: decisionRecord.id,
            context,
            now
          });
        } catch (containmentErr) {
          await eventRecord
            .update({
              metadata: {
                ...(eventRecord.metadata || {}),
                action_sensitivity: routeSensitivity,
                action_status: 'halted',
                decision_id: decisionRecord.id,
                recommended_decision: recommendedDecision,
                effective_decision: effectiveDecision,
                enforcement_outcome: 'blocked',
                enforcement_mode: enforcementMode,
                policy_version: policyVersion,
                containment_status: 'failed',
                containment_error: containmentErr.message
              }
            })
            .catch(() => {});
          throw containmentErr;
        }

        enforcementOutcome = 'contained_and_blocked';
        await decisionRecord.update({
          enforcement_outcome: enforcementOutcome
        });
        await eventRecord.update({
          metadata: {
            ...(eventRecord.metadata || {}),
            action_sensitivity: routeSensitivity,
            action_status: 'halted',
            decision_id: decisionRecord.id,
            recommended_decision: recommendedDecision,
            effective_decision: effectiveDecision,
            enforcement_outcome: enforcementOutcome,
            enforcement_mode: enforcementMode,
            policy_version: policyVersion,
            containment_status: 'completed'
          }
        });
      }

      // 10. Emit real-time decision broadcast (after containment if required)
      const plainDecision =
        typeof decisionRecord.get === 'function'
          ? decisionRecord.get({ plain: true })
          : { ...decisionRecord, enforcement_outcome: enforcementOutcome };
      eventBus.safeEmit('policy:decision_recorded', {
        decision: plainDecision
      });

      // 11. Execute PEP response
      if (actionStatus === 'authorized') {
        req.policyDecision = plainDecision;
        req.securityEvent = eventRecord;
        req.requestContext = context;
        req.completeProtectedAction = (extraMetadata = {}) =>
          completeProtectedAction(req, extraMetadata);
        req.rejectProtectedAction = (reason, extraMetadata = {}) =>
          rejectProtectedAction(req, reason, extraMetadata);
        req.failProtectedAction = (error, extraMetadata = {}) =>
          failProtectedAction(req, error, extraMetadata);
        return next();
      }

      if (effectiveDecision === 'reverify') {
        return res.status(403).json({
          error: {
            code: 'step_up_required',
            message:
              (pdpResult.explanation && pdpResult.explanation.user_facing) ||
              'Additional identity verification is required before completing this action.',
            decision_id: decisionRecord.id,
            decision: 'reverify',
            required_scope: requiredScope,
            risk_tier: effectiveRiskTier,
            challenge_endpoint: `/api/v1/sessions/${sessionId}/step-up/challenge`,
            verify_endpoint: `/api/v1/sessions/${sessionId}/step-up/verify`,
            elevate_endpoint: `/api/v1/sessions/${sessionId}/elevate`,
            explanation:
              (pdpResult.explanation && pdpResult.explanation.user_facing) ||
              'Additional identity verification is required before completing this action.'
          }
        });
      }

      if (effectiveDecision === 'delay') {
        const delaySeconds =
          typeof options.delaySeconds === 'number' && options.delaySeconds > 0
            ? options.delaySeconds
            : DEFAULT_DELAY_SECONDS;
        return activeDelayHandler(req, res, {
          decisionRecord: plainDecision,
          riskTier: effectiveRiskTier,
          explanation: pdpResult.explanation,
          delaySeconds
        });
      }

      // effectiveDecision === 'block'
      return res.status(403).json({
        error: {
          code: 'action_blocked',
          message:
            (pdpResult.explanation && pdpResult.explanation.user_facing) ||
            'This action has been restricted for security reasons.',
          decision_id: decisionRecord.id,
          decision: 'block',
          risk_tier: effectiveRiskTier,
          session_contained: Boolean(containmentResult.session_contained),
          account_locked: Boolean(containmentResult.account_locked),
          ...(containmentResult.locked_until ? { locked_until: containmentResult.locked_until } : {}),
          ...(containmentResult.retry_after_seconds
            ? { retry_after_seconds: containmentResult.retry_after_seconds }
            : {}),
          explanation:
            (pdpResult.explanation && pdpResult.explanation.user_facing) ||
            'This action has been restricted for security reasons.'
        }
      });
    } catch (err) {
      console.error('[PEP] Policy enforcement failed closed:', err.message);
      return res.status(503).json({
        error: {
          code: 'policy_enforcement_unavailable',
          message: 'Security policy enforcement is temporarily unavailable. Action halted for safety.'
        }
      });
    }
  };
}

module.exports = {
  enforce,
  completeProtectedAction,
  rejectProtectedAction,
  failProtectedAction,
  setDelayHandler,
  resetDelayHandler,
  DEFAULT_DELAY_SECONDS
};

