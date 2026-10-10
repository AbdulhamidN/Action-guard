const { Op } = require('sequelize');
const { SecurityEvent } = require('../database/models');

/**
 * Records a security event in the persistent audit trail.
 * Operates as an append-only event-writing pipeline.
 *
 * @param {object} eventData
 * @param {string} [eventData.eventId] - Optional explicit event ID (defaults to evt_<uuid>)
 * @param {string} [eventData.event_id]
 * @param {string} eventData.userId - Required user ID referencing users table
 * @param {string} [eventData.user_id]
 * @param {string|null} [eventData.sessionId] - Optional session ID referencing sessions table
 * @param {string|null} [eventData.session_id]
 * @param {string} eventData.eventType - Required recognized event type
 * @param {string} [eventData.event_type]
 * @param {Date|string} [eventData.timestamp] - Optional event timestamp (defaults to current date/time)
 * @param {object} [eventData.context] - Plain contextual data (ip_address, user_agent, etc.)
 * @param {object} [eventData.metadata] - Plain action metadata (action_sensitivity, etc.)
 * @returns {Promise<object>} The created SecurityEvent database record
 */
async function recordSecurityEvent(eventData = {}) {
  const resolvedUserId = eventData.userId || eventData.user_id;
  const resolvedEventType = eventData.eventType || eventData.event_type;
  const resolvedSessionId =
    eventData.sessionId !== undefined
      ? eventData.sessionId
      : eventData.session_id !== undefined
      ? eventData.session_id
      : null;
  const resolvedEventId = eventData.eventId || eventData.event_id;
  const resolvedTimestamp = eventData.timestamp || new Date();
  const resolvedContext = eventData.context || {};
  const resolvedMetadata = eventData.metadata || {};

  if (!resolvedUserId) {
    throw new Error('user_id is required to record a security event');
  }

  if (!resolvedEventType) {
    throw new Error('event_type is required to record a security event');
  }

  const payload = {
    user_id: resolvedUserId,
    session_id: resolvedSessionId,
    event_type: resolvedEventType,
    timestamp: resolvedTimestamp,
    context: resolvedContext,
    metadata: resolvedMetadata
  };

  if (resolvedEventId) {
    payload.event_id = resolvedEventId;
  }

  const event = await SecurityEvent.create(payload);

  // Module 6.3b: Pipeline hooks
  if (event.user_id) {
    // Hook (b): Correlate event into active sequence
    try {
      const { correlateEventIntoSequence } = require('./sequenceGroupingService');
      await correlateEventIntoSequence(event);
    } catch (err) {
      console.warn('[EventPipeline] Sequence correlation failed:', err.message);
    }

    // Hook (c): Evaluate and persist risk assessment
    let assessmentRecord = null;
    try {
      const { evaluateAndStoreRiskForEvent } = require('./riskEngineService');
      assessmentRecord = await evaluateAndStoreRiskForEvent(event);
    } catch (err) {
      console.warn('[EventPipeline] Risk evaluation failed:', err.message);
    }

    // Module 7.2: Single emit point after correlation, scoring, and persistence
    try {
      const eventBus = require('../events/eventBus');
      const plainEvent = typeof event.get === 'function' ? event.get({ plain: true }) : { ...event };
      const plainAssessment = assessmentRecord
        ? (typeof assessmentRecord.get === 'function' ? assessmentRecord.get({ plain: true }) : { ...assessmentRecord })
        : null;

      eventBus.safeEmit('pipeline:event_processed', {
        event: plainEvent,
        assessment: plainAssessment
      });
    } catch (err) {
      console.warn('[EventPipeline] Event bus emit failed:', err.message);
    }
  }

  return event;
}

/**
 * Queries security events with filtering, pagination, and deterministic ordering.
 *
 * @param {object} [filters={}]
 * @param {string} [filters.user_id]
 * @param {string} [filters.session_id]
 * @param {string} [filters.event_type]
 * @param {string|Date} [filters.from]
 * @param {string|Date} [filters.to]
 * @param {object} [pagination={}]
 * @param {number|string} [pagination.limit=50]
 * @param {number|string} [pagination.offset=0]
 * @returns {Promise<{ events: Array, total: number, limit: number, offset: number }>}
 */
async function querySecurityEvents(filters = {}, pagination = {}) {
  const where = {};

  if (filters.user_id) {
    where.user_id = filters.user_id;
  }

  if (filters.session_id) {
    where.session_id = filters.session_id;
  }

  if (filters.event_type) {
    where.event_type = filters.event_type;
  }

  if (filters.from || filters.to) {
    where.timestamp = {};
    if (filters.from) {
      where.timestamp[Op.gte] = new Date(filters.from);
    }
    if (filters.to) {
      where.timestamp[Op.lte] = new Date(filters.to);
    }
  }

  const rawLimit = parseInt(pagination.limit, 10);
  const limit = isNaN(rawLimit) ? 50 : Math.min(Math.max(rawLimit, 1), 100);

  const rawOffset = parseInt(pagination.offset, 10);
  const offset = isNaN(rawOffset) ? 0 : Math.max(rawOffset, 0);

  const { rows, count } = await SecurityEvent.findAndCountAll({
    where,
    limit,
    offset,
    order: [
      ['timestamp', 'DESC'],
      ['event_id', 'DESC']
    ]
  });

  const events = rows.map((r) => ({
    event_id: r.event_id,
    user_id: r.user_id,
    session_id: r.session_id,
    event_type: r.event_type,
    timestamp: r.timestamp instanceof Date ? r.timestamp.toISOString() : new Date(r.timestamp).toISOString(),
    context: r.context || {},
    metadata: r.metadata || {}
  }));

  return {
    events,
    total: count,
    limit,
    offset
  };
}

module.exports = {
  recordSecurityEvent,
  querySecurityEvents
};
