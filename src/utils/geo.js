/**
 * Geographic calculation utilities for distance, time, and speed.
 */

const EARTH_RADIUS_KM = 6371;

/**
 * Rounds a number to two decimal places deterministically.
 *
 * @param {number} num
 * @returns {number}
 */
function roundToTwoDecimals(num) {
  if (typeof num !== 'number' || !Number.isFinite(num)) {
    return 0;
  }
  return Math.round((num + Number.EPSILON) * 100) / 100;
}

/**
 * Calculates the great-circle distance between two geographic coordinates
 * using the Haversine formula.
 *
 * @param {number} lat1 - Latitude of point 1 in degrees (-90 to 90)
 * @param {number} lon1 - Longitude of point 1 in degrees (-180 to 180)
 * @param {number} lat2 - Latitude of point 2 in degrees (-90 to 90)
 * @param {number} lon2 - Longitude of point 2 in degrees (-180 to 180)
 * @returns {number} Great-circle distance in kilometers
 */
function calculateHaversineDistance(lat1, lon1, lat2, lon2) {
  if (
    typeof lat1 !== 'number' ||
    typeof lon1 !== 'number' ||
    typeof lat2 !== 'number' ||
    typeof lon2 !== 'number' ||
    !Number.isFinite(lat1) ||
    !Number.isFinite(lon1) ||
    !Number.isFinite(lat2) ||
    !Number.isFinite(lon2)
  ) {
    throw new Error('All coordinate parameters must be finite numbers');
  }

  if (lat1 < -90 || lat1 > 90 || lat2 < -90 || lat2 > 90) {
    throw new Error('Latitude must be between -90 and 90 degrees');
  }

  if (lon1 < -180 || lon1 > 180 || lon2 < -180 || lon2 > 180) {
    throw new Error('Longitude must be between -180 and 180 degrees');
  }

  // Identical coordinates
  if (lat1 === lat2 && lon1 === lon2) {
    return 0;
  }

  const toRad = (deg) => (deg * Math.PI) / 180;

  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const radLat1 = toRad(lat1);
  const radLat2 = toRad(lat2);

  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(radLat1) * Math.cos(radLat2) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);

  // Math.min/Math.max clamp to handle slight floating point inaccuracies
  const clampedA = Math.min(Math.max(a, 0), 1);
  const c = 2 * Math.atan2(Math.sqrt(clampedA), Math.sqrt(1 - clampedA));

  return EARTH_RADIUS_KM * c;
}

/**
 * Calculates elapsed time in minutes between two timestamps.
 *
 * @param {Date|string|number} previousTime
 * @param {Date|string|number} currentTime
 * @returns {number|null} Elapsed minutes (can be negative or 0) or null if invalid
 */
function calculateElapsedMinutes(previousTime, currentTime) {
  const prevMs = new Date(previousTime).getTime();
  const currMs = new Date(currentTime).getTime();

  if (isNaN(prevMs) || isNaN(currMs)) {
    return null;
  }

  const diffMs = currMs - prevMs;
  return diffMs / (1000 * 60);
}

/**
 * Calculates required travel speed in km/h given distance and elapsed minutes.
 *
 * @param {number} distanceKm - Distance in kilometers
 * @param {number} elapsedMinutes - Elapsed time in minutes
 * @returns {number|null} Speed in km/h or null if elapsedMinutes is not positive
 */
function calculateTravelSpeedKmh(distanceKm, elapsedMinutes) {
  if (
    typeof distanceKm !== 'number' ||
    !Number.isFinite(distanceKm) ||
    distanceKm < 0 ||
    typeof elapsedMinutes !== 'number' ||
    !Number.isFinite(elapsedMinutes) ||
    elapsedMinutes <= 0
  ) {
    return null;
  }

  if (distanceKm === 0) {
    return 0;
  }

  const elapsedHours = elapsedMinutes / 60;
  return distanceKm / elapsedHours;
}

module.exports = {
  EARTH_RADIUS_KM,
  roundToTwoDecimals,
  calculateHaversineDistance,
  calculateElapsedMinutes,
  calculateTravelSpeedKmh
};
