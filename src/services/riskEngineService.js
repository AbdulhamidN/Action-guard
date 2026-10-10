/**
 * Risk Engine Coordinator & Input Assembly (Sub-module 6.3a)
 *
 * Coordinates risk evaluation for security events:
 * 1. Assembles evaluation context (device novelty, country novelty, travel anomaly,
 *    bot timing, baseline deviation, step-up verification).
 * 2. Loads active sequence and maps events into the analyzer's format.
 * 3. Runs sequenceRiskService.analyzeSequence, riskScoring.scoreRisk, and buildExplanation.
 * 4. Persists RiskAssessment records to MySQL (non-advisory path).
 * 5. Provides indexed lookup for the latest risk assessment.
 *
 * All DB and Redis access lives here. SequenceRiskService and riskScoring remain pure.
 */

const { Op } = require('sequelize');
const {
  SecurityEvent,
  RiskAssessment,
  ActionSequence,
  SequenceEvent
} = require('../database/models');
const riskConfig = require('../config/riskConfig');
const {
  scoreRisk,
  buildExplanation,
  tierForScore,
  RiskInputError
} = require('../utils/riskScoring');
const {
  analyzeSequence,
  appendProposedEvent
} = require('./sequenceRiskService');
const { getActiveSequenceFromCache } = require('./sequenceCacheService');
const { getLatestSequenceForUser, getSequenceById } = require('./sequenceStorageService');
const { evaluateBaselineDeviationForUser } = require('./baselineDeviationService');

/**
 * Derives device and country novelty for an event using strictly earlier login_success events.
 *
 * Rulings:
 * - A login_success event is a first-sighting device only if:
 *   - context.device_fingerprint is present and non-empty
 *   - the user has at least one earlier login_success (any device)
 *   - no earlier login_success for this user carries the same fingerprint
 * - Country novelty uses the same shape on context.geo_country.
 * - A null or absent country, or a null fingerprint, produces no signal (never unrecognized).
 * - If the user has no earlier login_success at all (first-ever login), emit no novelty signals.
 * - "Earlier" means strictly earlier timestamp, excluding the event itself.
 * - Only login_success counts as prior use. login_failed and other event types never count.
 * - Uses existence query (LIMIT 1) on (user_id, event_type, timestamp).
 *
 * @param {string} userId
 * @param {Date|string|number} eventTimestamp
 * @param {string|null} currentEventId - Optional event ID to exclude
 * @param {string|null} fingerprint
 * @param {string|null} country
 * @returns {Promise<{ is_new_device: boolean, is_new_country: boolean }>}
 */
async function deriveNoveltyFlags(userId, eventTimestamp, currentEventId = null, fingerprint = null, country = null) {
  const result = {
    is_new_device: false,
    is_new_country: false
  };

  if (!userId) {
    return result;
  }

  const timestampDate = eventTimestamp instanceof Date ? eventTimestamp : new Date(eventTimestamp);

  // Check 1: Does the user have at least one earlier login_success (any device/country)?
  const earlierWhere = {
    user_id: userId,
    event_type: 'login_success',
    timestamp: { [Op.lt]: timestampDate }
  };
  if (currentEventId) {
    earlierWhere.event_id = { [Op.ne]: currentEventId };
  }

  const priorLogin = await SecurityEvent.findOne({
    attributes: ['event_id'],
    where: earlierWhere,
    limit: 1
  });

  // If no earlier login_success at all (first-ever login), emit no novelty signals
  if (!priorLogin) {
    return result;
  }

  // Device novelty check
  const trimmedFingerprint = typeof fingerprint === 'string' ? fingerprint.trim() : null;
  if (trimmedFingerprint) {
    const priorMatchingDevice = await SecurityEvent.findOne({
      attributes: ['event_id'],
      where: {
        ...earlierWhere,
        'context.device_fingerprint': trimmedFingerprint
      },
      limit: 1
    });

    if (!priorMatchingDevice) {
      result.is_new_device = true;
    }
  }

  // Country novelty check
  const trimmedCountry = typeof country === 'string' ? country.trim() : null;
  if (trimmedCountry) {
    const priorMatchingCountry = await SecurityEvent.findOne({
      attributes: ['event_id'],
      where: {
        ...earlierWhere,
        'context.geo_country': trimmedCountry
      },
      limit: 1
    });

    if (!priorMatchingCountry) {
      result.is_new_country = true;
    }
  }

  return result;
}

/**
 * Assembles evaluation context for a security event per Amendment 1 & rulings.
 *
 * @param {object} event - SecurityEvent instance or plain object
 * @param {object} [options={}]
 * @returns {Promise<object>} Plain scoring input payload ready for scoreRisk
 */
async function assembleEvaluationContext(event, options = {}) {
  if (!event || typeof event !== 'object') {
    throw new RiskInputError('event must be a non-null object');
  }

  const eventType = event.event_type || event.eventType;
  const userId = event.user_id || event.userId;
  const sessionId = event.session_id || event.sessionId || null;
  const eventId = event.event_id || event.eventId || null;
  const timestamp = event.timestamp ? new Date(event.timestamp) : new Date();
  const context = event.context || {};
  const metadata = event.metadata || {};

  const fingerprint = context.device_fingerprint || metadata.device_fingerprint || null;
  const country = context.geo_country || metadata.geo_country || null;

  // 1. Device and Country recognition / novelty
  let unrecognizedDevice = false;
  let unrecognizedCountry = false;

  if (userId) {
    const novelty = await deriveNoveltyFlags(userId, timestamp, eventId, fingerprint, country);
    unrecognizedDevice = novelty.is_new_device;
    unrecognizedCountry = novelty.is_new_country;

    // For non-login events within a session, if device or country was unrecognized at session login,
    // inherit the session's novelty context (unless the event brought its own new device/country)
    if (sessionId && (!unrecognizedDevice || !unrecognizedCountry)) {
      const priorLoginInSession = await SecurityEvent.findOne({
        attributes: ['event_id', 'timestamp', 'context'],
        where: {
          user_id: userId,
          session_id: sessionId,
          event_type: 'login_success'
        },
        order: [['timestamp', 'DESC']],
        limit: 1
      });

      if (priorLoginInSession) {
        const loginContext = priorLoginInSession.context || {};
        const loginFp = loginContext.device_fingerprint || null;
        const loginCountry = loginContext.geo_country || null;
        const loginTime = priorLoginInSession.timestamp;
        const sessionNovelty = await deriveNoveltyFlags(
          userId,
          loginTime,
          priorLoginInSession.event_id,
          loginFp,
          loginCountry
        );
        if (!unrecognizedDevice && sessionNovelty.is_new_device) {
          unrecognizedDevice = true;
        }
        if (!unrecognizedCountry && sessionNovelty.is_new_country) {
          unrecognizedCountry = true;
        }
      }
    }
  }

  // 2. Travel anomaly:
  // Use the event's own metadata.travel_anomaly if present;
  // otherwise inherit impossible_travel from the latest login_success with the same session_id; if none, no signal.
  let impossibleTravel = false;
  if (metadata.travel_anomaly && typeof metadata.travel_anomaly.impossible_travel === 'boolean') {
    impossibleTravel = metadata.travel_anomaly.impossible_travel;
  } else if (sessionId && userId) {
    const priorLoginInSession = await SecurityEvent.findOne({
      attributes: ['event_id', 'metadata'],
      where: {
        user_id: userId,
        session_id: sessionId,
        event_type: 'login_success'
      },
      order: [['timestamp', 'DESC']],
      limit: 1
    });

    if (
      priorLoginInSession &&
      priorLoginInSession.metadata &&
      priorLoginInSession.metadata.travel_anomaly &&
      typeof priorLoginInSession.metadata.travel_anomaly.impossible_travel === 'boolean'
    ) {
      impossibleTravel = priorLoginInSession.metadata.travel_anomaly.impossible_travel;
    }
  }

  // 3. Bot timing:
  // Login-only; non-login events contribute nothing.
  let automationSuspected = false;
  if (eventType === 'login_success' || eventType === 'login_failed') {
    if (metadata.bot_detection && typeof metadata.bot_detection.automation_suspected === 'boolean') {
      automationSuspected = metadata.bot_detection.automation_suspected;
    }
  }

  // 4. Baseline deviation:
  // Insufficient history takes the weight-0 informational path.
  let baselinePayload = {
    evaluated: false,
    has_sufficient_history: false,
    deviation_score: 0.0
  };

  if (metadata.behavioral_deviation && typeof metadata.behavioral_deviation === 'object') {
    const bDev = metadata.behavioral_deviation;
    baselinePayload = {
      evaluated: Boolean(bDev.is_evaluated),
      has_sufficient_history: Boolean(bDev.has_sufficient_history),
      deviation_score: typeof bDev.deviation_score === 'number' ? bDev.deviation_score : 0.0
    };
  } else if (userId && (eventType === 'login_success' || eventType === 'login_failed')) {
    try {
      const bDev = await evaluateBaselineDeviationForUser(userId, context, timestamp);
      if (bDev) {
        baselinePayload = {
          evaluated: Boolean(bDev.is_evaluated),
          has_sufficient_history: Boolean(bDev.has_sufficient_history),
          deviation_score: typeof bDev.deviation_score === 'number' ? bDev.deviation_score : 0.0
        };
      }
    } catch {
      // Safe fallback
      baselinePayload = {
        evaluated: false,
        has_sufficient_history: false,
        deviation_score: 0.0
      };
    }
  }

  // 5. Verification confidence discount:
  // elapsed_seconds from the most recent verification_success with the SAME session_id within 900 s; null session_id gives null.
  let verificationPayload = null;
  if (sessionId && userId) {
    const maxWindowSecs = riskConfig.VERIFICATION?.window_seconds ?? 900;
    const minTimestamp = new Date(timestamp.getTime() - maxWindowSecs * 1000);

    const latestVerification = await SecurityEvent.findOne({
      attributes: ['event_id', 'timestamp'],
      where: {
        user_id: userId,
        session_id: sessionId,
        event_type: 'verification_success',
        timestamp: {
          [Op.gte]: minTimestamp,
          [Op.lte]: timestamp
        }
      },
      order: [['timestamp', 'DESC']],
      limit: 1
    });

    if (latestVerification) {
      const vTime = new Date(latestVerification.timestamp).getTime();
      const elapsedSecs = Math.max(0, Math.round((timestamp.getTime() - vTime) / 1000));
      if (elapsedSecs <= maxWindowSecs) {
        verificationPayload = {
          elapsed_seconds: elapsedSecs
        };
      }
    }
  }

  // Action sensitivity resolution
  const actionSensitivity = metadata.action_sensitivity || options.action_sensitivity || 'medium';

  return {
    event_type: eventType,
    action_sensitivity: actionSensitivity,
    context: {
      unrecognized_device: unrecognizedDevice,
      unrecognized_country: unrecognizedCountry,
      impossible_travel: impossibleTravel
    },
    timing: {
      automation_suspected: automationSuspected
    },
    baseline: baselinePayload,
    verification: verificationPayload
  };
}

/**
 * Loads the active sequence of events for a user and maps them to the plain format
 * expected by sequenceRiskService.analyzeSequence (including is_new_device and device_recognized).
 *
 * @param {string} userId
 * @param {object} [currentEvent=null] - The event currently being evaluated (if not yet in sequence)
 * @returns {Promise<Array<object>>} Plain events array
 */
async function loadActiveSequenceForUser(userId, currentEvent = null) {
  if (!userId) {
    return [];
  }

  let eventIds = [];

  // Try Redis cache first
  try {
    const cached = await getActiveSequenceFromCache(userId);
    if (cached && Array.isArray(cached.event_ids)) {
      eventIds = cached.event_ids;
    }
  } catch (err) {
    console.warn('[RiskEngine] Redis cache read failed, falling back to MySQL:', err.message);
  }

  // Fallback to MySQL if no event IDs from cache
  if (eventIds.length === 0) {
    const latestSeq = await getLatestSequenceForUser(userId);
    if (latestSeq) {
      const fullSeq = await getSequenceById(latestSeq.id, { includeEvents: true });
      if (fullSeq && fullSeq.sequenceEvents) {
        eventIds = fullSeq.sequenceEvents.map((se) => se.event_id);
      }
    }
  }

  let dbEvents = [];
  if (eventIds.length > 0) {
    dbEvents = await SecurityEvent.findAll({
      where: { event_id: { [Op.in]: eventIds } }
    });
    // Order according to eventIds
    const map = new Map(dbEvents.map((e) => [e.event_id, e]));
    dbEvents = eventIds.map((id) => map.get(id)).filter(Boolean);
  }

  // If currentEvent is provided and not already in dbEvents, add it
  const currentEventId = currentEvent ? (currentEvent.event_id || currentEvent.eventId) : null;
  if (currentEvent && (!currentEventId || !dbEvents.some((e) => e.event_id === currentEventId))) {
    dbEvents.push(currentEvent);
  }

  // Map each event to the plain shape sequenceRiskService expects:
  // { event_type, timestamp, is_new_device, device_recognized, is_trusted_device }
  const plainEvents = [];
  for (const ev of dbEvents) {
    const evType = ev.event_type || ev.eventType;
    const evTimestamp = ev.timestamp instanceof Date ? ev.timestamp : new Date(ev.timestamp);
    const evContext = ev.context || {};
    const evMetadata = ev.metadata || {};
    const evId = ev.event_id || ev.eventId || null;

    const plain = {
      event_id: evId,
      event_type: evType,
      timestamp: evTimestamp.toISOString()
    };

    if (evType === 'login_success') {
      // Check if is_new_device or device_recognized already explicitly supplied
      if (typeof ev.is_new_device === 'boolean') {
        plain.is_new_device = ev.is_new_device;
        plain.device_recognized = typeof ev.device_recognized === 'boolean' ? ev.device_recognized : !ev.is_new_device;
      } else if (typeof evContext.is_new_device === 'boolean') {
        plain.is_new_device = evContext.is_new_device;
        plain.device_recognized = !evContext.is_new_device;
      } else {
        const fp = evContext.device_fingerprint || evMetadata.device_fingerprint || null;
        const country = evContext.geo_country || evMetadata.geo_country || null;
        const novelty = await deriveNoveltyFlags(userId, evTimestamp, evId, fp, country);
        plain.is_new_device = novelty.is_new_device;
        plain.device_recognized = !novelty.is_new_device;
      }
    }

    plainEvents.push(plain);
  }

  return plainEvents;
}

/**
 * Builds the plain input, loads the active sequence, runs analyzeSequence, scoreRisk,
 * and buildExplanation.
 *
 * @param {object} event - SecurityEvent instance or plain object
 * @param {object} [options={}]
 * @param {object} [options.proposedEvent] - Optional proposed event for advisory scoring
 * @returns {Promise<object>} Result object or unavailable object
 */
async function evaluateRisk(event, options = {}) {
  try {
    if (!event || typeof event !== 'object') {
      throw new RiskInputError('event must be a non-null object');
    }

    const userId = event.user_id || event.userId;
    const assembledContext = await assembleEvaluationContext(event, options);

    // Load active sequence
    let sequenceEvents = [];
    if (userId) {
      sequenceEvents = await loadActiveSequenceForUser(userId, event);
    }

    // Handle advisory path with proposedEvent
    if (options.proposedEvent) {
      sequenceEvents = appendProposedEvent(sequenceEvents, options.proposedEvent);
    }

    // Run pure sequence analysis
    const sequenceAnalysis = analyzeSequence(sequenceEvents, riskConfig);

    // Attach sequence matched rules to scoring input
    assembledContext.sequence = sequenceAnalysis;

    // Run pure scoreRisk
    const scoredResult = scoreRisk(assembledContext, riskConfig);

    // Build explanations
    const explanation = buildExplanation(scoredResult);

    return {
      status: 'ok',
      risk_score: scoredResult.risk_score,
      risk_tier: scoredResult.risk_tier,
      contributing_signals: scoredResult.contributing_signals,
      explanation
    };
  } catch (err) {
    console.warn('[RiskEngine] Risk evaluation failed:', err.message);
    return {
      status: 'unavailable',
      risk_score: null,
      risk_tier: null,
      contributing_signals: [],
      error_code: 'risk_evaluation_failed',
      explanation: {
        user_facing: 'Security risk evaluation is temporarily unavailable.',
        admin_facing: 'Risk engine failed to evaluate context: risk_evaluation_failed.'
      }
    };
  }
}

/**
 * Evaluates and stores risk assessment for a security event in the database.
 * If !event.user_id, returns null silently (no warning, no throw).
 * Persists a risk_assessments row only when status is 'ok'.
 * Never persists unavailable results. Never throws to the caller.
 *
 * @param {object} event - SecurityEvent instance or plain object
 * @param {object} [options={}]
 * @returns {Promise<object|null>} Persisted RiskAssessment instance or null
 */
async function evaluateAndStoreRiskForEvent(event, options = {}) {
  try {
    if (!event || typeof event !== 'object') {
      return null;
    }

    const userId = event.user_id || event.userId;
    if (!userId) {
      return null;
    }

    const eventType = event.event_type || event.eventType;
    if (riskConfig.UNSCORED_EVENT_TYPES && riskConfig.UNSCORED_EVENT_TYPES.includes(eventType)) {
      return null;
    }

    const evaluation = await evaluateRisk(event, options);
    if (!evaluation || evaluation.status !== 'ok') {
      return null;
    }

    // Invariant check: sum of weights equals score, integer in [0, 100]
    const weightSum = evaluation.contributing_signals.reduce((acc, s) => acc + s.weight, 0);
    if (
      weightSum !== evaluation.risk_score ||
      !Number.isInteger(evaluation.risk_score) ||
      evaluation.risk_score < 0 ||
      evaluation.risk_score > 100
    ) {
      console.warn('[RiskEngine] Invariant violation in evaluateAndStoreRiskForEvent');
      return null;
    }

    const eventId = event.event_id || event.eventId || null;
    const sessionId = event.session_id || event.sessionId || null;
    const evaluatedAt = event.timestamp ? new Date(event.timestamp) : new Date();

    const record = await RiskAssessment.create({
      event_id: eventId,
      user_id: userId,
      session_id: sessionId,
      risk_score: evaluation.risk_score,
      risk_tier: evaluation.risk_tier,
      contributing_signals: evaluation.contributing_signals,
      explanation: evaluation.explanation,
      evaluated_at: evaluatedAt
    });

    return record;
  } catch (err) {
    console.warn('[RiskEngine] Failed to evaluate and store risk:', err.message);
    return null;
  }
}

/**
 * Retrieves the most recent risk assessment for a user and optional session.
 * Indexed read for Module 6.4. Returns null when none found.
 *
 * @param {string} userId
 * @param {string|null} [sessionId=null]
 * @returns {Promise<object|null>}
 */
async function getLatestRiskAssessment(userId, sessionId = null) {
  if (!userId || typeof userId !== 'string') {
    return null;
  }

  const where = {
    user_id: userId.trim()
  };

  if (sessionId) {
    where.session_id = sessionId;
  }

  return RiskAssessment.findOne({
    where,
    order: [
      ['evaluated_at', 'DESC'],
      ['id', 'DESC']
    ]
  });
}

module.exports = {
  deriveNoveltyFlags,
  assembleEvaluationContext,
  loadActiveSequenceForUser,
  evaluateRisk,
  evaluateAndStoreRiskForEvent,
  getLatestRiskAssessment
};
