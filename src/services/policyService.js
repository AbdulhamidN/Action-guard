const riskEngineService = require('./riskEngineService');
const policyConfig = require('../config/policyConfig');
const { decide } = require('../utils/policyDecision');

/**
 * Evaluates policy for a proposed action in an advisory manner.
 * Advisory only: results are never persisted, affect no sequence tables or Redis caches,
 * and Module 10 must never trust them as authorization or audit truth.
 *
 * @param {object} params - Input event parameters
 * @param {object} [options={}] - Additional evaluation options
 * @returns {Promise<object>} Policy decision result with evaluated_at
 */
async function evaluateActionPolicy(params, options = {}) {
  if (!params || typeof params !== 'object') {
    throw new Error('params must be a non-null object');
  }

  const userId = params.user_id || params.userId;
  const sessionId = params.session_id || params.sessionId || null;
  const eventType = params.event_type || params.eventType;
  const providedSensitivity =
    (params.metadata && params.metadata.action_sensitivity) ||
    params.action_sensitivity ||
    params.actionSensitivity ||
    null;

  const eventForRisk = {
    user_id: userId,
    session_id: sessionId,
    event_type: eventType,
    timestamp: params.timestamp || new Date(),
    context: params.context || {},
    metadata: {
      ...(params.metadata || {}),
      ...(providedSensitivity ? { action_sensitivity: providedSensitivity } : {})
    }
  };

  // Advisory evaluation through riskEngineService with proposedEvent
  const riskResult = await riskEngineService.evaluateRisk(eventForRisk, {
    ...options,
    proposedEvent: eventForRisk
  });

  const signalNames = Array.isArray(riskResult.contributing_signals)
    ? riskResult.contributing_signals.map((s) => s.signal)
    : [];

  const decisionInput = {
    risk: {
      status: riskResult.status,
      risk_tier: riskResult.risk_tier,
      signal_names: signalNames
    },
    action: {
      event_type: eventType,
      provided_sensitivity: providedSensitivity
    }
  };

  const decisionResult = decide(decisionInput, policyConfig);

  return {
    ...decisionResult,
    evaluated_at: new Date()
  };
}

module.exports = {
  evaluateActionPolicy
};
