/**
 * Pure functions for building sanitized real-time broadcast payloads.
 * No I/O, no database imports, no external service or socket dependencies.
 * Never mutates inputs; strictly picks allowlisted attributes.
 */

/**
 * Builds user-facing risk payload.
 * Omit numeric score, signals breakdown, weights, admin explanation, and user_id.
 *
 * @param {object} event
 * @param {object} assessment
 * @returns {{
 *   event_id: string|null,
 *   session_id: string|null,
 *   risk_tier: string,
 *   evaluated_at: string,
 *   explanation: { user_facing: string }
 * }}
 */
function buildUserRiskPayload(event, assessment) {
  if (!assessment || typeof assessment !== 'object') {
    throw new TypeError('assessment is required to build user risk payload');
  }

  const eventId =
    (event && (event.event_id || event.eventId)) ||
    assessment.event_id ||
    assessment.eventId ||
    null;

  const sessionId =
    event && event.session_id !== undefined
      ? event.session_id
      : assessment.session_id !== undefined
      ? assessment.session_id
      : null;

  const riskTier = assessment.risk_tier || 'low';

  let evaluatedAt = null;
  if (assessment.evaluated_at) {
    evaluatedAt =
      assessment.evaluated_at instanceof Date
        ? assessment.evaluated_at.toISOString()
        : String(assessment.evaluated_at);
  } else if (event && event.timestamp) {
    evaluatedAt =
      event.timestamp instanceof Date
        ? event.timestamp.toISOString()
        : String(event.timestamp);
  } else {
    evaluatedAt = new Date().toISOString();
  }

  const userFacing =
    assessment.explanation && typeof assessment.explanation.user_facing === 'string'
      ? assessment.explanation.user_facing
      : '';

  return {
    event_id: eventId,
    session_id: sessionId,
    risk_tier: riskTier,
    evaluated_at: evaluatedAt,
    explanation: {
      user_facing: userFacing
    }
  };
}

/**
 * Builds admin-facing risk payload with full technical breakdown.
 *
 * @param {object} event
 * @param {object} assessment
 * @returns {{
 *   event_id: string|null,
 *   user_id: string|null,
 *   session_id: string|null,
 *   risk_score: number,
 *   risk_tier: string,
 *   contributing_signals: Array<{ signal: string, category: string, weight: number }>,
 *   evaluated_at: string,
 *   explanation: { user_facing: string, admin_facing: string }
 * }}
 */
function buildAdminRiskPayload(event, assessment) {
  if (!assessment || typeof assessment !== 'object') {
    throw new TypeError('assessment is required to build admin risk payload');
  }

  const eventId =
    (event && (event.event_id || event.eventId)) ||
    assessment.event_id ||
    assessment.eventId ||
    null;

  const userId =
    (event && (event.user_id || event.userId)) ||
    assessment.user_id ||
    assessment.userId ||
    null;

  const sessionId =
    event && event.session_id !== undefined
      ? event.session_id
      : assessment.session_id !== undefined
      ? assessment.session_id
      : null;

  const riskScore = typeof assessment.risk_score === 'number' ? assessment.risk_score : 0;
  const riskTier = assessment.risk_tier || 'low';

  const contributingSignals = Array.isArray(assessment.contributing_signals)
    ? assessment.contributing_signals.map((s) => ({
        signal: s && typeof s.signal === 'string' ? s.signal : '',
        category: s && typeof s.category === 'string' ? s.category : '',
        weight: s && typeof s.weight === 'number' ? s.weight : 0
      }))
    : [];

  let evaluatedAt = null;
  if (assessment.evaluated_at) {
    evaluatedAt =
      assessment.evaluated_at instanceof Date
        ? assessment.evaluated_at.toISOString()
        : String(assessment.evaluated_at);
  } else if (event && event.timestamp) {
    evaluatedAt =
      event.timestamp instanceof Date
        ? event.timestamp.toISOString()
        : String(event.timestamp);
  } else {
    evaluatedAt = new Date().toISOString();
  }

  const userFacing =
    assessment.explanation && typeof assessment.explanation.user_facing === 'string'
      ? assessment.explanation.user_facing
      : '';

  const adminFacing =
    assessment.explanation && typeof assessment.explanation.admin_facing === 'string'
      ? assessment.explanation.admin_facing
      : '';

  return {
    event_id: eventId,
    user_id: userId,
    session_id: sessionId,
    risk_score: riskScore,
    risk_tier: riskTier,
    contributing_signals: contributingSignals,
    evaluated_at: evaluatedAt,
    explanation: {
      user_facing: userFacing,
      admin_facing: adminFacing
    }
  };
}

/**
 * Builds sanitized event:recorded payload.
 *
 * @param {object} event
 * @param {object|null} [assessment=null]
 * @param {object} [options={}]
 * @param {boolean} [options.includeUserId=false]
 * @returns {object}
 */
function buildEventRecordedPayload(event, assessment = null, options = {}) {
  if (!event || typeof event !== 'object') {
    throw new TypeError('event must be a valid object');
  }

  const includeUserId = Boolean(options && options.includeUserId);

  const eventId =
    event.event_id ||
    event.eventId ||
    (assessment && (assessment.event_id || assessment.eventId)) ||
    null;

  const userId =
    event.user_id ||
    event.userId ||
    (assessment && (assessment.user_id || assessment.userId)) ||
    null;

  const sessionId =
    event.session_id !== undefined
      ? event.session_id
      : assessment && assessment.session_id !== undefined
      ? assessment.session_id
      : null;

  const eventType = event.event_type || event.eventType || null;

  let timestamp = null;
  if (event.timestamp) {
    timestamp =
      event.timestamp instanceof Date
        ? event.timestamp.toISOString()
        : String(event.timestamp);
  }

  const ctx = event.context || {};
  let coarse_location = null;
  if (ctx.geo_country || ctx.geo_region) {
    coarse_location = {
      country: ctx.geo_country || null,
      region: ctx.geo_region || null
    };
  }

  // Derive novelty from assessment's contributing signals
  const hasUnrecognizedDevice = Boolean(
    assessment &&
      Array.isArray(assessment.contributing_signals) &&
      assessment.contributing_signals.some((s) => s && s.signal === 'unrecognized_device')
  );

  const hasUnrecognizedCountry = Boolean(
    assessment &&
      Array.isArray(assessment.contributing_signals) &&
      assessment.contributing_signals.some((s) => s && s.signal === 'unrecognized_country')
  );

  const payload = {
    event_id: eventId
  };

  if (includeUserId) {
    payload.user_id = userId;
  }

  payload.session_id = sessionId;
  payload.event_type = eventType;
  payload.timestamp = timestamp;
  payload.coarse_location = coarse_location;

  if (hasUnrecognizedDevice) {
    payload.is_new_device = true;
  }

  if (hasUnrecognizedCountry) {
    payload.is_new_country = true;
  }

  return payload;
}

/**
 * Builds sanitized user-facing policy decision payload.
 * Omits user_id, numeric risk_score, contributing_signals, policy_version, reasons, and admin_facing.
 *
 * @param {object} decisionRecord
 * @returns {object}
 */
function buildUserDecisionPayload(decisionRecord) {
  if (!decisionRecord || typeof decisionRecord !== 'object') {
    throw new TypeError('decisionRecord is required to build user decision payload');
  }

  const decidedAt = decisionRecord.decided_at
    ? decisionRecord.decided_at instanceof Date
      ? decisionRecord.decided_at.toISOString()
      : String(decisionRecord.decided_at)
    : new Date().toISOString();

  const userFacing =
    decisionRecord.explanation && typeof decisionRecord.explanation.user_facing === 'string'
      ? decisionRecord.explanation.user_facing
      : '';

  return {
    decision_id: decisionRecord.id || decisionRecord.decision_id || null,
    event_id: decisionRecord.event_id || null,
    session_id: decisionRecord.session_id || null,
    action_type: decisionRecord.action_type || null,
    decision: decisionRecord.effective_decision || decisionRecord.decision || null,
    enforcement_outcome: decisionRecord.enforcement_outcome || null,
    risk_tier: decisionRecord.risk_tier || 'low',
    decided_at: decidedAt,
    explanation: {
      user_facing: userFacing
    }
  };
}

/**
 * Builds full admin-facing policy decision payload.
 *
 * @param {object} decisionRecord
 * @returns {object}
 */
function buildAdminDecisionPayload(decisionRecord) {
  if (!decisionRecord || typeof decisionRecord !== 'object') {
    throw new TypeError('decisionRecord is required to build admin decision payload');
  }

  const decidedAt = decisionRecord.decided_at
    ? decisionRecord.decided_at instanceof Date
      ? decisionRecord.decided_at.toISOString()
      : String(decisionRecord.decided_at)
    : new Date().toISOString();

  const userFacing =
    decisionRecord.explanation && typeof decisionRecord.explanation.user_facing === 'string'
      ? decisionRecord.explanation.user_facing
      : '';

  const adminFacing =
    decisionRecord.explanation && typeof decisionRecord.explanation.admin_facing === 'string'
      ? decisionRecord.explanation.admin_facing
      : '';

  const contributingSignals = Array.isArray(decisionRecord.contributing_signals)
    ? decisionRecord.contributing_signals.map((s) => ({
        signal: s && typeof s.signal === 'string' ? s.signal : '',
        category: s && typeof s.category === 'string' ? s.category : '',
        weight: s && typeof s.weight === 'number' ? s.weight : 0
      }))
    : [];

  const reasons = Array.isArray(decisionRecord.reasons)
    ? decisionRecord.reasons.map((r) => (typeof r === 'object' && r !== null ? { ...r } : r))
    : [];

  return {
    decision_id: decisionRecord.id || decisionRecord.decision_id || null,
    event_id: decisionRecord.event_id || null,
    risk_assessment_id: decisionRecord.risk_assessment_id || null,
    user_id: decisionRecord.user_id || null,
    session_id: decisionRecord.session_id || null,
    action_type: decisionRecord.action_type || null,
    action_sensitivity: decisionRecord.action_sensitivity || null,
    risk_score: typeof decisionRecord.risk_score === 'number' ? decisionRecord.risk_score : 0,
    risk_tier: decisionRecord.risk_tier || 'low',
    recommended_decision: decisionRecord.recommended_decision || null,
    effective_decision: decisionRecord.effective_decision || null,
    enforcement_outcome: decisionRecord.enforcement_outcome || null,
    enforcement_mode: decisionRecord.enforcement_mode || 'automatic',
    policy_version: decisionRecord.policy_version || null,
    reasons,
    contributing_signals: contributingSignals,
    decided_at: decidedAt,
    explanation: {
      user_facing: userFacing,
      admin_facing: adminFacing
    }
  };
}

module.exports = {
  buildUserRiskPayload,
  buildAdminRiskPayload,
  buildEventRecordedPayload,
  buildUserDecisionPayload,
  buildAdminDecisionPayload
};
