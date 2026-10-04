/**
 * Signal Collector for Basic Bot / Automation Detection (Sub-module 3.4).
 *
 * Evaluates request arrival intervals for potential automation patterns (rapid burst,
 * robotic periodicity) using a short-lived sliding window.
 *
 * Operates on plain values only. Decoupled from Express req/res objects.
 */

const {
  recordAndEvaluateTiming,
  clearTimingHistory,
  getTimingHistory
} = require('../services/botTimingService');

/**
 * Collects the bot/automation timing signal for a given canonical source identity.
 *
 * @param {string} sourceIdentity - Canonical source identity (e.g. normalized client IP)
 * @param {Date|string|number} [timestamp] - Current request arrival timestamp
 * @param {object} [options={}] - Optional evaluation configuration
 * @returns {Promise<{
 *   automation_suspected: boolean,
 *   sufficient_observations: boolean,
 *   sample_size: number,
 *   reasons: string[],
 *   metrics: {
 *     min_interval_ms: number,
 *     avg_interval_ms: number,
 *     interval_std_dev_ms: number,
 *     coefficient_of_variation: number|null
 *   }|null
 * }>}
 */
async function collectBotSignal(sourceIdentity, timestamp, options = {}) {
  try {
    const result = await recordAndEvaluateTiming(sourceIdentity, timestamp, options);
    // Strictly return the sanitized signal structure without internal Redis keys or source identity
    return {
      automation_suspected: result.automation_suspected,
      sufficient_observations: result.sufficient_observations,
      sample_size: result.sample_size,
      reasons: result.reasons,
      metrics: result.metrics
    };
  } catch (err) {
    // Fail-safe: telemetry unavailable must not break calling flow
    console.warn('[BotCollector] Telemetry unavailable:', err.message);
    return {
      automation_suspected: false,
      sufficient_observations: false,
      sample_size: 0,
      reasons: [],
      metrics: null
    };
  }
}

module.exports = {
  collectBotSignal,
  recordAndEvaluateTiming,
  clearTimingHistory,
  getTimingHistory
};
