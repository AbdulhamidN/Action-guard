const { getRedisClient } = require('../storage/redis');
const { getSequenceWindowMs } = require('../utils/sequenceConfig');
const {
  getLatestSequenceForUser,
  getSequenceById
} = require('./sequenceStorageService');
const { Session } = require('../database/models');

const SEQUENCE_USER_KEY_PREFIX = 'sequence:user:';

/**
 * Returns the Redis key for a user's active sequence.
 *
 * @param {string} userId
 * @returns {string}
 */
function getSequenceCacheKey(userId) {
  return `${SEQUENCE_USER_KEY_PREFIX}${userId}`;
}

/**
 * Formats a sequence and its ordered event IDs into the standard cache payload.
 *
 * @param {object} sequence
 * @param {Array<string>} [eventIds=[]]
 * @returns {object}
 */
function formatSequenceCachePayload(sequence, eventIds = []) {
  const startedAt = sequence.started_at instanceof Date
    ? sequence.started_at.toISOString()
    : new Date(sequence.started_at).toISOString();

  const lastEventAt = sequence.last_event_at instanceof Date
    ? sequence.last_event_at.toISOString()
    : new Date(sequence.last_event_at).toISOString();

  let resolvedEventIds = [];
  if (Array.isArray(eventIds) && eventIds.length > 0) {
    resolvedEventIds = eventIds;
  } else if (sequence.sequenceEvents && Array.isArray(sequence.sequenceEvents)) {
    resolvedEventIds = sequence.sequenceEvents.map((se) => se.event_id);
  }

  return {
    id: sequence.id,
    user_id: sequence.user_id,
    session_id: sequence.session_id || null,
    started_at: startedAt,
    last_event_at: lastEventAt,
    event_count: typeof sequence.event_count === 'number' ? sequence.event_count : resolvedEventIds.length,
    event_ids: resolvedEventIds
  };
}

/**
 * Stores or updates an active sequence in Redis cache for a user.
 *
 * @param {string} userId
 * @param {object} sequence
 * @param {Array<string>} [eventIds=[]]
 * @param {number} [ttlSeconds] - Optional explicit TTL in seconds
 * @returns {Promise<object>} The cached payload
 */
async function cacheActiveSequence(userId, sequence, eventIds = [], ttlSeconds = null) {
  if (!userId || typeof userId !== 'string' || userId.trim() === '') {
    throw new Error('userId is required to cache an active sequence');
  }
  if (!sequence || !sequence.id) {
    throw new Error('sequence with id is required to cache an active sequence');
  }

  const client = getRedisClient();
  const key = getSequenceCacheKey(userId.trim());
  const payload = formatSequenceCachePayload(sequence, eventIds);

  const ttl = typeof ttlSeconds === 'number' && ttlSeconds > 0
    ? ttlSeconds
    : Math.ceil(getSequenceWindowMs() / 1000);

  await client.set(key, JSON.stringify(payload), 'EX', ttl);
  return payload;
}

/**
 * Fast-read function: reads active sequence from Redis cache first.
 * On cache miss, falls back to MySQL via getLatestSequenceForUser and repopulates Redis.
 *
 * @param {string} userId
 * @param {object} [options={}]
 * @param {number} [options.windowMs]
 * @returns {Promise<object|null>}
 */
async function getActiveSequenceFromCache(userId, options = {}) {
  if (!userId || typeof userId !== 'string' || userId.trim() === '') {
    return null;
  }

  const normalizedUserId = userId.trim();
  const client = getRedisClient();
  const key = getSequenceCacheKey(normalizedUserId);

  // 1. Fast read from Redis
  const cachedRaw = await client.get(key);
  if (cachedRaw) {
    try {
      return JSON.parse(cachedRaw);
    } catch {
      // Malformed JSON -> fall through to MySQL fallback
    }
  }

  // 2. Cache miss -> query MySQL authoritative store
  const windowMs = getSequenceWindowMs(options);
  const latestSequence = await getLatestSequenceForUser(normalizedUserId);
  if (!latestSequence) {
    return null;
  }

  // Check if sequence is still active (within correlation window)
  const lastTime = new Date(latestSequence.last_event_at).getTime();
  const now = Date.now();
  const elapsed = now - lastTime;
  if (elapsed > windowMs) {
    // Sequence has gone quiet / expired past active window
    return null;
  }

  // 3. Retrieve ordered event IDs from MySQL
  const fullSequence = await getSequenceById(latestSequence.id, { includeEvents: true });
  const eventIds = fullSequence && fullSequence.sequenceEvents
    ? fullSequence.sequenceEvents.map((se) => se.event_id)
    : [];

  // 4. Repopulate Redis cache with remaining TTL
  const remainingSeconds = Math.max(1, Math.ceil((windowMs - elapsed) / 1000));
  const cachedData = await cacheActiveSequence(
    normalizedUserId,
    latestSequence,
    eventIds,
    remainingSeconds
  );

  return cachedData;
}

/**
 * Invalidates the entire active sequence cache for a user.
 *
 * @param {string} userId
 * @returns {Promise<boolean>}
 */
async function invalidateSequenceCache(userId) {
  if (!userId) return false;
  const client = getRedisClient();
  const key = getSequenceCacheKey(userId.trim());
  const deleted = await client.del(key);
  return deleted > 0;
}

/**
 * Handles cache invalidation on session deletion.
 * If a cached sequence's session_id matches sessionId, sets session_id to null in Redis
 * while preserving existing TTL, event list, and other metadata.
 *
 * @param {string} sessionId
 * @param {string} [userId]
 * @returns {Promise<boolean>}
 */
async function invalidateSessionInSequenceCache(sessionId, userId = null) {
  if (!sessionId) return false;

  const client = getRedisClient();
  let targetUserId = userId;

  if (!targetUserId) {
    try {
      const sessionRecord = await Session.findByPk(sessionId);
      if (sessionRecord) {
        targetUserId = sessionRecord.user_id;
      }
    } catch {
      // Ignored
    }
  }

  if (!targetUserId) {
    return false;
  }

  const key = getSequenceCacheKey(targetUserId.trim());
  const raw = await client.get(key);
  if (!raw) return false;

  try {
    const cached = JSON.parse(raw);
    if (cached.session_id === sessionId) {
      cached.session_id = null;
      const currentTtl = await client.ttl(key);
      if (currentTtl > 0) {
        await client.set(key, JSON.stringify(cached), 'EX', currentTtl);
      } else {
        await client.set(key, JSON.stringify(cached));
      }
      return true;
    }
  } catch {
    return false;
  }

  return false;
}

// Hook to automatically invalidate cached session_id on Session deletion
if (Session && typeof Session.addHook === 'function') {
  Session.addHook('afterDestroy', 'invalidateSessionInSequenceCacheOnDestroy', async (instance) => {
    if (instance && instance.id) {
      await invalidateSessionInSequenceCache(instance.id, instance.user_id);
    }
  });
}

module.exports = {
  SEQUENCE_USER_KEY_PREFIX,
  getSequenceCacheKey,
  cacheActiveSequence,
  getActiveSequenceFromCache,
  invalidateSequenceCache,
  invalidateSessionInSequenceCache
};
