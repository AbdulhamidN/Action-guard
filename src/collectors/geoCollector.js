const { resolveGeoLocation } = require('../services/geoService');

/**
 * Signal Collector for IP and Geographic Resolution (Sub-module 3.2).
 *
 * Resolves approximate country and region for canonical request IPs using
 * MaxMind GeoLite2 data.
 *
 * @param {string} ip - Canonical client IP
 * @returns {Promise<{ geo_country: string|null, geo_region: string|null }>}
 */
async function collectGeoSignal(ip) {
  const result = await resolveGeoLocation(ip);
  return {
    geo_country: result.geo_country,
    geo_region: result.geo_region
  };
}

module.exports = {
  collectGeoSignal,
  resolveGeoLocation
};
