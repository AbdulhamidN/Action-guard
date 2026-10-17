const crypto = require('crypto');

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

  if (options && options.includeDeviceRef) {
    let device_ref = null;
    const rawFp =
      event.device_fingerprint ||
      (event.context && (event.context.device_fingerprint || event.context.fingerprint)) ||
      null;
    if (rawFp && typeof rawFp === 'string') {
      device_ref = crypto.createHash('sha256').update(rawFp).digest('hex').slice(0, 12);
    }
    payload.device_ref = device_ref;
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

/**
 * Builds user-facing session payload.
 *
 * @param {object} session
 * @param {boolean} [isCurrent=false]
 * @param {object|null} [latestAssessment=null]
 * @returns {{
 *   session_id: string|null,
 *   created_at: string,
 *   expires_at: string,
 *   is_active: boolean,
 *   is_current: boolean,
 *   risk_tier: string|null
 * }}
 */
function buildUserSessionPayload(session, isCurrent = false, latestAssessment = null) {
  if (!session || typeof session !== 'object') {
    throw new TypeError('session is required to build user session payload');
  }

  if (typeof isCurrent === 'object' && isCurrent !== null) {
    latestAssessment = isCurrent;
    isCurrent = false;
  }

  const createdAt =
    session.created_at instanceof Date
      ? session.created_at.toISOString()
      : session.created_at
      ? String(session.created_at)
      : new Date().toISOString();

  const expiresAt =
    session.expires_at instanceof Date
      ? session.expires_at.toISOString()
      : session.expires_at
      ? String(session.expires_at)
      : new Date().toISOString();

  const riskTier = latestAssessment && latestAssessment.risk_tier ? latestAssessment.risk_tier : null;

  return {
    session_id: session.id || session.session_id || null,
    created_at: createdAt,
    expires_at: expiresAt,
    is_active: Boolean(session.is_active),
    is_current: Boolean(isCurrent),
    risk_tier: riskTier
  };
}

/**
 * Builds admin-facing session payload.
 *
 * @param {object} session
 * @param {object|null} [latestAssessment=null]
 * @returns {{
 *   session_id: string|null,
 *   user_id: string|null,
 *   created_at: string,
 *   expires_at: string,
 *   is_active: boolean,
 *   risk_tier: string|null,
 *   risk_score: number|null,
 *   evaluated_at: string|null
 * }}
 */
function buildAdminSessionPayload(session, latestAssessment = null, eventOrMeta = null) {
  if (!session || typeof session !== 'object') {
    throw new TypeError('session is required to build admin session payload');
  }

  const createdAt =
    session.created_at instanceof Date
      ? session.created_at.toISOString()
      : session.created_at
      ? String(session.created_at)
      : new Date().toISOString();

  const expiresAt =
    session.expires_at instanceof Date
      ? session.expires_at.toISOString()
      : session.expires_at
      ? String(session.expires_at)
      : new Date().toISOString();

  const riskTier = latestAssessment && latestAssessment.risk_tier ? latestAssessment.risk_tier : null;
  const riskScore =
    latestAssessment && typeof latestAssessment.risk_score === 'number'
      ? latestAssessment.risk_score
      : null;

  let evaluatedAt = null;
  if (latestAssessment && latestAssessment.evaluated_at) {
    evaluatedAt =
      latestAssessment.evaluated_at instanceof Date
        ? latestAssessment.evaluated_at.toISOString()
        : String(latestAssessment.evaluated_at);
  }

  let deviceRef = null;
  let coarseLocation = null;

  if (eventOrMeta) {
    const rawFp =
      eventOrMeta.device_fingerprint ||
      (eventOrMeta.context && (eventOrMeta.context.device_fingerprint || eventOrMeta.context.fingerprint)) ||
      null;
    if (rawFp && typeof rawFp === 'string') {
      deviceRef = crypto.createHash('sha256').update(rawFp).digest('hex').slice(0, 12);
    }

    const ctx = eventOrMeta.context || {};
    if (ctx.geo_country || ctx.geo_region) {
      coarseLocation = {
        country: ctx.geo_country || null,
        region: ctx.geo_region || null
      };
    }
  }

  return {
    session_id: session.id || session.session_id || null,
    user_id: session.user_id || session.userId || null,
    created_at: createdAt,
    expires_at: expiresAt,
    is_active: Boolean(session.is_active),
    risk_tier: riskTier,
    risk_score: riskScore,
    evaluated_at: evaluatedAt,
    device_ref: deviceRef,
    coarse_location: coarseLocation
  };
}

/**
 * Builds user-facing risk history item.
 *
 * @param {object} assessment
 * @returns {{
 *   event_id: string|null,
 *   session_id: string|null,
 *   risk_tier: string,
 *   evaluated_at: string
 * }}
 */
function buildUserRiskHistoryItem(assessment) {
  if (!assessment || typeof assessment !== 'object') {
    throw new TypeError('assessment is required to build user risk history item');
  }

  const evaluatedAt =
    assessment.evaluated_at instanceof Date
      ? assessment.evaluated_at.toISOString()
      : assessment.evaluated_at
      ? String(assessment.evaluated_at)
      : new Date().toISOString();

  return {
    event_id: assessment.event_id || assessment.eventId || null,
    session_id:
      assessment.session_id !== undefined ? assessment.session_id : assessment.sessionId !== undefined ? assessment.sessionId : null,
    risk_tier: assessment.risk_tier || 'low',
    evaluated_at: evaluatedAt
  };
}

/**
 * Builds admin-facing sequence payload.
 *
 * @param {object} sequence
 * @returns {object}
 */
function buildAdminSequencePayload(sequence) {
  if (!sequence || typeof sequence !== 'object') {
    throw new TypeError('sequence is required to build admin sequence payload');
  }

  const startedAt =
    sequence.started_at instanceof Date
      ? sequence.started_at.toISOString()
      : sequence.started_at
      ? String(sequence.started_at)
      : new Date().toISOString();

  const lastEventAt =
    sequence.last_event_at instanceof Date
      ? sequence.last_event_at.toISOString()
      : sequence.last_event_at
      ? String(sequence.last_event_at)
      : new Date().toISOString();

  const events = Array.isArray(sequence.sequenceEvents)
    ? sequence.sequenceEvents.map((se) => {
        const ev = se.securityEvent;
        const ts =
          ev && ev.timestamp
            ? ev.timestamp instanceof Date
              ? ev.timestamp.toISOString()
              : String(ev.timestamp)
            : null;

        return {
          event_id: ev ? ev.event_id : se.event_id,
          session_id: ev ? ev.session_id : null,
          event_type: ev ? ev.event_type : null,
          step_order: typeof se.step_order === 'number' ? se.step_order : 1,
          timestamp: ts,
          action_sensitivity: (ev && ev.metadata && ev.metadata.action_sensitivity) || null
        };
      })
    : [];

  return {
    id: sequence.id,
    user_id: sequence.user_id || sequence.userId || null,
    session_id: sequence.session_id || sequence.sessionId || null,
    started_at: startedAt,
    last_event_at: lastEventAt,
    event_count: typeof sequence.event_count === 'number' ? sequence.event_count : events.length,
    events
  };
}

module.exports = {
  buildUserRiskPayload,
  buildAdminRiskPayload,
  buildEventRecordedPayload,
  buildUserDecisionPayload,
  buildAdminDecisionPayload,
  buildUserSessionPayload,
  buildAdminSessionPayload,
  buildUserRiskHistoryItem,
  buildAdminSequencePayload
};
