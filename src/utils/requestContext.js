'use strict';

const { normalizeIp } = require('./ip');
const geoService = require('../services/geoService');
const { validateDeviceFingerprint } = require('../services/deviceService');

/**
 * Extracts canonical security context strictly from server-side request metadata.
 * Never reads context, ip_address, geo_country, geo_region, device_fingerprint,
 * or timestamp from req.body or req.query.
 *
 * @param {import('express').Request} req
 * @param {string|null} [explicitFingerprint]
 * @returns {Promise<{ ip_address: string|null, user_agent: string|null, device_fingerprint?: string, geo_country?: string, geo_region?: string }>}
 */
async function extractServerRequestContext(req, explicitFingerprint = null) {
  const rawIp = req.ip || req.socket?.remoteAddress || null;
  const ip = normalizeIp(rawIp) || (typeof rawIp === 'string' ? rawIp.trim() : null);

  const context = {
    ip_address: ip,
    user_agent: (req.headers && req.headers['user-agent']) || null
  };

  let fingerprint = null;
  if (explicitFingerprint && validateDeviceFingerprint(explicitFingerprint)) {
    fingerprint = explicitFingerprint.trim();
  } else {
    const headerFp = req.headers && req.headers['x-device-fingerprint'];
    if (validateDeviceFingerprint(headerFp)) {
      fingerprint = headerFp.trim();
    } else if (req.session && req.session.device_fingerprint) {
      fingerprint = req.session.device_fingerprint;
    }
  }

  if (fingerprint) {
    context.device_fingerprint = fingerprint;
  }

  if (ip) {
    try {
      const geo = await geoService.resolveGeoLocation(ip);
      if (geo && geo.geo_country) {
        context.geo_country = geo.geo_country;
      }
      if (geo && geo.geo_region) {
        context.geo_region = geo.geo_region;
      }
    } catch {
      // Safe fallback if GeoIP lookup fails
    }
  }

  return context;
}

module.exports = {
  extractServerRequestContext
};
