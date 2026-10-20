const {
  detectImpossibleTravelForUser,
  DEFAULT_SPEED_THRESHOLD_KMH
} = require('../services/travelService');

/**
 * Signal Collector for Impossible-Travel Detection (Sub-module 3.3).
 *
 * Compares consecutive successful logins for the same user and evaluates
 * whether the required travel speed exceeds the configured threshold.
 *
 * @param {string} userId - User ID
 * @param {string} currentIp - Canonical client IP
 * @param {Date|string|number} currentTimestamp - Exact timestamp of current login
 * @param {object} [options={}] - Optional evaluation options (e.g. speedThresholdKmh)
 * @returns {Promise<{
 *   has_previous_login: boolean,
 *   has_sufficient_geo_data: boolean,
 *   distance_km: number|null,
 *   elapsed_minutes: number|null,
 *   required_speed_kmh: number|null,
 *   impossible_travel: boolean
 * }>}
 */
async function collectTravelAnomalySignal(userId, currentIp, currentTimestamp, options = {}) {
  return detectImpossibleTravelForUser(userId, currentIp, currentTimestamp, options);
}

module.exports = {
  collectTravelAnomalySignal,
  detectImpossibleTravelForUser,
  DEFAULT_SPEED_THRESHOLD_KMH
};
