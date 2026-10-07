const {
  createSequence,
  attachEventToSequence,
  getLatestSequenceForUser,
  getSequenceById
} = require('./sequenceStorageService');
const {
  DEFAULT_SEQUENCE_WINDOW_SECONDS,
  getSequenceWindowMs
} = require('../utils/sequenceConfig');
const {
  cacheActiveSequence,
  getActiveSequenceFromCache,
  invalidateSequenceCache,
  invalidateSessionInSequenceCache,
  getSequenceCacheKey,
  SEQUENCE_USER_KEY_PREFIX
} = require('./sequenceCacheService');

/**
 * Correlates an incoming event into an existing active sequence or starts a new sequence.
 *
 * Forward-only chronological window evaluation:
 *   (eventTime >= lastTime) && (eventTime - lastTime <= windowMs)
 *
 * Write-through side effect:
 *   Updates the user's active sequence in Redis cache on success,
 *   holding the sequence metadata and ordered event IDs.
 *
 * @param {object} event - SecurityEvent instance or object containing event_id, user_id, timestamp, session_id
 * @param {object} [options={}] - Grouping options
 * @param {number} [options.windowMs] - Optional time window override in ms
 * @returns {Promise<{ sequence: object, isNewSequence: boolean, stepOrder: number }>}
 */
async function correlateEventIntoSequence(event, options = {}) {
  if (!event || !event.event_id || !event.user_id) {
    throw new Error('event with event_id and user_id is required for correlation');
  }

  const eventTime = event.timestamp instanceof Date ? event.timestamp : new Date(event.timestamp || Date.now());
  const windowMs = getSequenceWindowMs(options);

  const latestSequence = await getLatestSequenceForUser(event.user_id);

  if (latestSequence) {
    const lastTime = new Date(latestSequence.last_event_at).getTime();
    const eventTimeMs = eventTime.getTime();

    // Simple forward-only check:
    // (eventTime >= lastTime) && (eventTime - lastTime <= windowMs)
    if (eventTimeMs >= lastTime && (eventTimeMs - lastTime) <= windowMs) {
      const nextStepOrder = latestSequence.event_count + 1;
      await attachEventToSequence(latestSequence.id, event.event_id, nextStepOrder);
      const updatedSequence = await getSequenceById(latestSequence.id, { includeEvents: true });

      const eventIds = updatedSequence && updatedSequence.sequenceEvents
        ? updatedSequence.sequenceEvents.map((se) => se.event_id)
        : [];

      // Write-through caching in Redis
      await cacheActiveSequence(
        event.user_id,
        updatedSequence,
        eventIds,
        Math.ceil(windowMs / 1000)
      );

      return {
        sequence: updatedSequence,
        isNewSequence: false,
        stepOrder: nextStepOrder
      };
    }
  }

  // No active matching sequence in window -> Start a new sequence
  const newSequence = await createSequence({
    user_id: event.user_id,
    session_id: event.session_id || null,
    started_at: eventTime,
    last_event_at: eventTime
  });

  await attachEventToSequence(newSequence.id, event.event_id, 1);
  const reloadedSequence = await getSequenceById(newSequence.id, { includeEvents: true });

  const eventIds = reloadedSequence && reloadedSequence.sequenceEvents
    ? reloadedSequence.sequenceEvents.map((se) => se.event_id)
    : [event.event_id];

  // Write-through caching in Redis
  await cacheActiveSequence(
    event.user_id,
    reloadedSequence,
    eventIds,
    Math.ceil(windowMs / 1000)
  );

  return {
    sequence: reloadedSequence,
    isNewSequence: true,
    stepOrder: 1
  };
}

module.exports = {
  DEFAULT_SEQUENCE_WINDOW_SECONDS,
  getSequenceWindowMs,
  correlateEventIntoSequence,
  getActiveSequenceFromCache,
  cacheActiveSequence,
  invalidateSequenceCache,
  invalidateSessionInSequenceCache,
  getSequenceCacheKey,
  SEQUENCE_USER_KEY_PREFIX
};
