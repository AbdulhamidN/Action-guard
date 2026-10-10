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

module.exports = {
  buildUserRiskPayload,
  buildAdminRiskPayload,
  buildEventRecordedPayload
};
