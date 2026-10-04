/**
 * Bot Timing Service (Sub-module 3.4).
 *
 * Manages transient sliding-window request timestamps in Redis and evaluates
 * request timing heuristics for automation signals.
 *
 * Strictly operates on plain values. Independent of Express req/res objects.
 */

const { getRedisClient } = require('../storage/redis');
const {
  DEFAULT_TIMING_CONFIG,
  evaluateAutomationHeuristics
} = require('../utils/timing');

const REDIS_KEY_PREFIX = 'bot:timing:';

/**
 * Resolves the Redis key for a given source identity.
 *
 * @param {string} sourceIdentity - Canonical source identity (e.g. IP or user ID)
 * @returns {string}
 */
function getTimingRedisKey(sourceIdentity) {
  const sanitized = String(sourceIdentity || '').trim();
  if (sanitized.startsWith('ip:') || sanitized.startsWith('user:')) {
    return `${REDIS_KEY_PREFIX}${sanitized}`;
  }
  return `${REDIS_KEY_PREFIX}ip:${sanitized}`;
}

/**
 * Resolves window duration in seconds.
 *
 * @param {object} [options={}]
 * @returns {number}
 */
function getWindowSeconds(options = {}) {
  if (typeof options.windowSeconds === 'number' && Number.isFinite(options.windowSeconds) && options.windowSeconds > 0) {
    return options.windowSeconds;
  }
  const envVal = process.env.BOT_TIMING_WINDOW_SECONDS;
  if (envVal !== undefined && envVal.trim() !== '') {
    const parsed = parseInt(envVal, 10);
    if (!isNaN(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return DEFAULT_TIMING_CONFIG.windowSeconds;
}

/**
 * Resolves max history length.
 *
 * @param {object} [options={}]
 * @returns {number}
 */
function getMaxHistory(options = {}) {
  if (typeof options.maxHistory === 'number' && Number.isFinite(options.maxHistory) && options.maxHistory > 0) {
    return options.maxHistory;
  }
  const envVal = process.env.BOT_TIMING_MAX_HISTORY;
  if (envVal !== undefined && envVal.trim() !== '') {
    const parsed = parseInt(envVal, 10);
    if (!isNaN(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return DEFAULT_TIMING_CONFIG.maxHistory;
}

/**
 * Records a request arrival timestamp into the Redis sliding window and evaluates
 * the timing heuristic for potential automation patterns.
 *
 * Safe failure mode: if Redis fails or inputs are invalid, logs a warning and returns
 * a non-automated fallback result so authentication is never disrupted.
 *
 * @param {string} sourceIdentity - Canonical source identity (e.g. normalized client IP)
 * @param {Date|string|number} [currentTimestamp] - Exact request arrival timestamp
 * @param {object} [options={}] - Optional configuration overrides
 * @returns {Promise<{
 *   automation_suspected: boolean,
 *   sufficient_observations: boolean,
 *   sample_size: number,
 *   reasons: string[],
 *   metrics: object|null
 * }>}
 */
async function recordAndEvaluateTiming(sourceIdentity, currentTimestamp, options = {}) {
  if (!sourceIdentity || typeof sourceIdentity !== 'string' || sourceIdentity.trim() === '') {
    return {
      automation_suspected: false,
      sufficient_observations: false,
      sample_size: 0,
      reasons: [],
      metrics: null
    };
  }

  const nowMs =
    currentTimestamp instanceof Date
      ? currentTimestamp.getTime()
      : typeof currentTimestamp === 'number' && Number.isFinite(currentTimestamp)
      ? currentTimestamp
      : typeof currentTimestamp === 'string'
      ? new Date(currentTimestamp).getTime()
      : Date.now();

  const windowSecs = getWindowSeconds(options);
  const windowMs = windowSecs * 1000;
  const maxHistory = getMaxHistory(options);
  const key = getTimingRedisKey(sourceIdentity);

  let timestamps = [];

  try {
    const client = getRedisClient();
    const raw = await client.get(key);

    if (raw) {
      try {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          const cutoff = nowMs - windowMs;
          // Retain only timestamps within the sliding window
          timestamps = parsed.filter(
            (t) => typeof t === 'number' && Number.isFinite(t) && t >= cutoff && t <= nowMs
          );
        }
      } catch {
        timestamps = [];
      }
    }

    // Append single current observation
    timestamps.push(nowMs);

    // Bounded history: keep at most maxHistory recent timestamps
    if (timestamps.length > maxHistory) {
      timestamps = timestamps.slice(-maxHistory);
    }

    // Persist to Redis with sliding expiration
    await client.set(key, JSON.stringify(timestamps), 'EX', windowSecs);
  } catch (err) {
    // Fail-safe: telemetry storage failure must never break authentication
    console.warn('[BotTimingService] Redis telemetry unavailable:', err.message);
    return {
      automation_suspected: false,
      sufficient_observations: false,
      sample_size: 0,
      reasons: [],
      metrics: null
    };
  }

  return evaluateAutomationHeuristics(timestamps, options);
}

/**
 * Retrieves the raw timestamp array for a source identity (for testing/inspection).
 *
 * @param {string} sourceIdentity
 * @returns {Promise<number[]>}
 */
async function getTimingHistory(sourceIdentity) {
  try {
    const client = getRedisClient();
    const key = getTimingRedisKey(sourceIdentity);
    const raw = await client.get(key);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.warn('[BotTimingService] Error retrieving history:', err.message);
    return [];
  }
}

/**
 * Clears the timing history for a source identity (for testing/cleanup).
 *
 * @param {string} sourceIdentity
 * @returns {Promise<void>}
 */
async function clearTimingHistory(sourceIdentity) {
  try {
    const client = getRedisClient();
    const key = getTimingRedisKey(sourceIdentity);
    await client.del(key);
  } catch (err) {
    console.warn('[BotTimingService] Error clearing history:', err.message);
  }
}

module.exports = {
  REDIS_KEY_PREFIX,
  getTimingRedisKey,
  getWindowSeconds,
  getMaxHistory,
  recordAndEvaluateTiming,
  getTimingHistory,
  clearTimingHistory
};
