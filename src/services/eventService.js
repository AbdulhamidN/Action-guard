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
  return event;
}

module.exports = {
  recordSecurityEvent
};
