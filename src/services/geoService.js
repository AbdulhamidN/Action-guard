const fs = require('fs');
const path = require('path');
const maxmind = require('maxmind');
const { normalizeIp, isPrivateOrLoopbackIp } = require('../utils/ip');

let readerInstance = null;
let initPromise = null;
let warnedMissing = false;

function getDefaultDbPath() {
  if (process.env.MAXMIND_DB_PATH && process.env.MAXMIND_DB_PATH.trim() !== '') {
    return path.resolve(process.env.MAXMIND_DB_PATH.trim());
  }
  return path.resolve(process.cwd(), 'data', 'GeoLite2-City.mmdb');
}

/**
 * Initializes the singleton MaxMind GeoLite2 reader if not already open.
 * Returns null if the database file is unavailable.
 *
 * @param {string|null} [customPath=null]
 * @returns {Promise<object|null>}
 */
async function initReader(customPath = null) {
  if (readerInstance) {
    return readerInstance;
  }

  if (initPromise) {
    return initPromise;
  }

  initPromise = (async () => {
    const dbPath = customPath ? path.resolve(customPath) : getDefaultDbPath();

    if (!fs.existsSync(dbPath)) {
      if (!warnedMissing) {
        console.warn(`[GeoService] GeoLite2-City database not found at '${dbPath}'. Geolocation resolution is disabled.`);
        warnedMissing = true;
      }
      readerInstance = null;
      return null;
    }

    try {
      readerInstance = await maxmind.open(dbPath);
      return readerInstance;
    } catch (err) {
      console.warn(`[GeoService] Failed to load GeoLite2 database at '${dbPath}':`, err.message);
      readerInstance = null;
      return null;
    } finally {
      initPromise = null;
    }
  })();

  return initPromise;
}

/**
 * Gets the active reader instance (or attempts to initialize it).
 *
 * @returns {Promise<object|null>}
 */
async function getReader() {
  if (readerInstance) return readerInstance;
  return initReader();
}

/**
 * Injects or sets the reader instance (for testing/mocking).
 *
 * @param {object|null} reader
 */
function setReader(reader) {
  readerInstance = reader;
}

/**
 * Closes the active reader instance and resets state.
 */
function closeReader() {
  readerInstance = null;
  initPromise = null;
  warnedMissing = false;
}

/**
 * Resolves approximate country and region from a client IP address.
 * Geolocation is strictly an approximate signal:
 * - Returns country ISO code (geo_country) and first subdivision ISO code (geo_region)
 * - Excludes latitude, longitude, postal codes, and coordinates
 * - Local, private, loopback, or invalid IPs return nulls without guessing
 *
 * @param {string} rawIp - The client IP address
 * @returns {Promise<{ ip: string|null, geo_country: string|null, geo_region: string|null }>}
 */
async function resolveGeoLocation(rawIp) {
  const normalized = normalizeIp(rawIp);

  if (!normalized || isPrivateOrLoopbackIp(normalized)) {
    return {
      ip: normalized || (typeof rawIp === 'string' ? rawIp.trim() : null),
      geo_country: null,
      geo_region: null
    };
  }

  const reader = await getReader();
  if (!reader) {
    return {
      ip: normalized,
      geo_country: null,
      geo_region: null
    };
  }

  try {
    const record = reader.get(normalized);
    if (!record) {
      return {
        ip: normalized,
        geo_country: null,
        geo_region: null
      };
    }

    // Country ISO code (fallback to registered_country)
    const countryCode = record.country?.iso_code || record.registered_country?.iso_code || null;

    // Region ISO code (first available subdivision)
    const regionCode = record.subdivisions?.[0]?.iso_code || null;

    return {
      ip: normalized,
      geo_country: countryCode ? String(countryCode).toUpperCase() : null,
      geo_region: regionCode ? String(regionCode).toUpperCase() : null
    };
  } catch (err) {
    // Fail-safe: never crash on unexpected lookup error
    return {
      ip: normalized,
      geo_country: null,
      geo_region: null
    };
  }
}

module.exports = {
  initReader,
  getReader,
  setReader,
  closeReader,
  resolveGeoLocation,
  getDefaultDbPath
};
