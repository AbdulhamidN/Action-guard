const { Op } = require('sequelize');
const { SecurityEvent } = require('../database/models');
const geoService = require('./geoService');
const {
  roundToTwoDecimals,
  calculateHaversineDistance,
  calculateElapsedMinutes,
  calculateTravelSpeedKmh
} = require('../utils/geo');

const DEFAULT_SPEED_THRESHOLD_KMH = 900;

/**
 * Resolves the configured impossible-travel speed threshold in km/h.
 *
 * @param {object} [options={}]
 * @param {number} [options.speedThresholdKmh]
 * @returns {number}
 */
function getSpeedThreshold(options = {}) {
  if (
    options &&
    typeof options.speedThresholdKmh === 'number' &&
    Number.isFinite(options.speedThresholdKmh) &&
    options.speedThresholdKmh > 0
  ) {
    return options.speedThresholdKmh;
  }

  const envVal = process.env.IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD_KMH;
  if (envVal !== undefined && envVal !== '') {
    const parsed = parseFloat(envVal);
    if (!isNaN(parsed) && Number.isFinite(parsed) && parsed > 0) {
      return parsed;
    }
  }

  return DEFAULT_SPEED_THRESHOLD_KMH;
}

/**
 * Queries the immediately preceding successful login event for the specified user.
 * Bounded query: limits to 1 record strictly earlier than currentTimestamp.
 *
 * @param {string} userId - User ID
 * @param {Date|string|number} currentTimestamp - Current login timestamp
 * @returns {Promise<object|null>} The previous SecurityEvent record or null
 */
async function getPreviousSuccessfulLogin(userId, currentTimestamp) {
  if (!userId) {
    return null;
  }

  const where = {
    user_id: userId,
    event_type: 'login_success'
  };

  if (currentTimestamp) {
    where.timestamp = {
      [Op.lt]: new Date(currentTimestamp)
    };
  }

  const previousEvent = await SecurityEvent.findOne({
    where,
    order: [
      ['timestamp', 'DESC'],
      ['event_id', 'DESC']
    ]
  });

  return previousEvent;
}

/**
 * Detects impossible travel between consecutive successful logins for a user.
 *
 * Flow:
 * 1. Query immediately preceding login_success for the same user.
 * 2. Look up coordinates for both logins from GeoIP reader (in-memory only).
 * 3. Calculate Haversine distance and elapsed time.
 * 4. Coordinates are immediately discarded (never persisted or returned).
 * 5. Calculate speed and compare with threshold.
 *
 * @param {string} userId - User ID
 * @param {string} currentIp - Client IP of current login
 * @param {Date|string|number} currentTimestamp - Exact timestamp of current login
 * @param {object} [options={}] - Options (e.g. speedThresholdKmh)
 * @returns {Promise<{
 *   has_previous_login: boolean,
 *   has_sufficient_geo_data: boolean,
 *   distance_km: number|null,
 *   elapsed_minutes: number|null,
 *   required_speed_kmh: number|null,
 *   impossible_travel: boolean
 * }>}
 */
async function detectImpossibleTravelForUser(userId, currentIp, currentTimestamp, options = {}) {
  const previousLogin = await module.exports.getPreviousSuccessfulLogin(userId, currentTimestamp);

  if (!previousLogin) {
    return {
      has_previous_login: false,
      has_sufficient_geo_data: false,
      distance_km: null,
      elapsed_minutes: null,
      required_speed_kmh: null,
      impossible_travel: false
    };
  }

  const previousIp = previousLogin.context?.ip_address || null;

  // Resolve coordinates internally via GeoIP reader
  const [currentCoords, previousCoords] = await Promise.all([
    geoService.resolveCoordinates(currentIp),
    geoService.resolveCoordinates(previousIp)
  ]);

  if (!currentCoords || !previousCoords) {
    return {
      has_previous_login: true,
      has_sufficient_geo_data: false,
      distance_km: null,
      elapsed_minutes: null,
      required_speed_kmh: null,
      impossible_travel: false
    };
  }

  // Calculate distance with raw coordinates, then discard coordinates
  const rawDistance = calculateHaversineDistance(
    previousCoords.latitude,
    previousCoords.longitude,
    currentCoords.latitude,
    currentCoords.longitude
  );
  const distanceKm = roundToTwoDecimals(rawDistance);

  // Calculate elapsed time
  const rawElapsedMinutes = calculateElapsedMinutes(previousLogin.timestamp, currentTimestamp);

  // For non-positive or invalid elapsed time:
  // has_sufficient_geo_data remains true because coordinates were resolved,
  // but speed is not calculated and impossible_travel is false.
  if (rawElapsedMinutes === null || rawElapsedMinutes <= 0) {
    return {
      has_previous_login: true,
      has_sufficient_geo_data: true,
      distance_km: distanceKm,
      elapsed_minutes: null,
      required_speed_kmh: null,
      impossible_travel: false
    };
  }

  const elapsedMinutes = roundToTwoDecimals(rawElapsedMinutes);

  // If distance is zero, speed is 0 and travel cannot be impossible
  if (distanceKm === 0) {
    return {
      has_previous_login: true,
      has_sufficient_geo_data: true,
      distance_km: 0,
      elapsed_minutes: elapsedMinutes,
      required_speed_kmh: 0,
      impossible_travel: false
    };
  }

  const rawSpeed = calculateTravelSpeedKmh(rawDistance, rawElapsedMinutes);
  const requiredSpeedKmh = roundToTwoDecimals(rawSpeed);
  const thresholdKmh = getSpeedThreshold(options);
  const impossibleTravel = rawSpeed > thresholdKmh;

  return {
    has_previous_login: true,
    has_sufficient_geo_data: true,
    distance_km: distanceKm,
    elapsed_minutes: elapsedMinutes,
    required_speed_kmh: requiredSpeedKmh,
    impossible_travel: impossibleTravel
  };
}

module.exports = {
  DEFAULT_SPEED_THRESHOLD_KMH,
  getSpeedThreshold,
  getPreviousSuccessfulLogin,
  detectImpossibleTravelForUser
};
