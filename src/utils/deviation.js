/**
 * Sub-module 4.2: Baseline Deviation Scoring Utilities
 *
 * Provides pure, deterministic mathematical functions for comparing a current
 * login's security context against a user's historical behavioral baseline.
 */

const { roundToTwoDecimals } = require('./baseline');

const COMPONENT_WEIGHTS = {
  DEVICE: 0.40,
  COUNTRY: 0.40,
  LOGIN_HOUR: 0.20
};

/**
 * Clamps a numerical value within [min, max].
 *
 * @param {number} val
 * @param {number} min
 * @param {number} max
 * @returns {number}
 */
function clamp(val, min = 0.0, max = 1.0) {
  if (typeof val !== 'number' || !Number.isFinite(val)) {
    return min;
  }
  return Math.min(Math.max(val, min), max);
}

/**
 * Calculates the circular deviation of a current login timestamp from baseline login hours.
 *
 * @param {Date|string|number} currentTimestamp - Current login request timestamp
 * @param {object|null} baselineLoginHours - Baseline login_hours object from BehavioralBaseline
 * @returns {{
 *   evaluated: boolean,
 *   current_hour_utc?: number,
 *   mean_hour_utc?: number,
 *   circular_distance_hours?: number,
 *   deviation?: number,
 *   weight?: number
 * }}
 */
function calculateHourDeviation(currentTimestamp, baselineLoginHours) {
  if (!currentTimestamp || !baselineLoginHours) {
    return { evaluated: false };
  }

  const date = currentTimestamp instanceof Date ? currentTimestamp : new Date(currentTimestamp);
  if (isNaN(date.getTime())) {
    return { evaluated: false };
  }

  const meanHour = baselineLoginHours.mean_hour;
  const stdDev = baselineLoginHours.circular_std_dev_hours;
  const R = baselineLoginHours.resultant_vector_r;

  // If circular baseline statistics are undefined, canceled out, or invalid
  if (
    typeof meanHour !== 'number' ||
    !Number.isFinite(meanHour) ||
    typeof stdDev !== 'number' ||
    !Number.isFinite(stdDev) ||
    typeof R !== 'number' ||
    R <= 0
  ) {
    return { evaluated: false };
  }

  // If user dispersion is >= 12 hours, logins are uniformly spread, so no meaningful pattern exists
  if (stdDev >= 12) {
    return { evaluated: false };
  }

  const currentHourUtc = roundToTwoDecimals(
    date.getUTCHours() + date.getUTCMinutes() / 60 + date.getUTCSeconds() / 3600
  );

  // Shortest circular distance modulo 24
  const hourDiff = Math.abs(currentHourUtc - meanHour);
  const circularDistance = Math.min(hourDiff, 24 - hourDiff);
  const roundedCircularDistance = roundToTwoDecimals(circularDistance);

  // Within 1 standard deviation -> 0.0 deviation
  if (circularDistance <= stdDev) {
    return {
      evaluated: true,
      current_hour_utc: currentHourUtc,
      mean_hour_utc: meanHour,
      circular_distance_hours: roundedCircularDistance,
      deviation: 0.0,
      weight: COMPONENT_WEIGHTS.LOGIN_HOUR
    };
  }

  // Distance beyond standard deviation scaled to max possible distance (12h)
  const rawDeviation = (circularDistance - stdDev) / (12 - stdDev);
  const deviation = roundToTwoDecimals(clamp(rawDeviation, 0.0, 1.0));

  return {
    evaluated: true,
    current_hour_utc: currentHourUtc,
    mean_hour_utc: meanHour,
    circular_distance_hours: roundedCircularDistance,
    deviation,
    weight: COMPONENT_WEIGHTS.LOGIN_HOUR
  };
}

/**
 * Calculates device deviation using pure binary MVP comparison.
 * Never exposes raw device fingerprint in output.
 *
 * @param {string|null} deviceFingerprint - Current device fingerprint
 * @param {Array<object>|null} typicalDevices - Baseline typical_devices array
 * @returns {{
 *   evaluated: boolean,
 *   is_recognized?: boolean,
 *   deviation?: number,
 *   weight?: number
 * }}
 */
function calculateDeviceDeviation(deviceFingerprint, typicalDevices) {
  if (
    !deviceFingerprint ||
    typeof deviceFingerprint !== 'string' ||
    deviceFingerprint.trim() === '' ||
    !Array.isArray(typicalDevices) ||
    typicalDevices.length === 0
  ) {
    return { evaluated: false };
  }

  const normalizedFp = deviceFingerprint.trim();
  const matchedDevice = typicalDevices.find(
    (d) => d && typeof d.fingerprint === 'string' && d.fingerprint.trim() === normalizedFp
  );

  const isRecognized = !!matchedDevice;
  const deviation = isRecognized ? 0.0 : 1.0;

  return {
    evaluated: true,
    is_recognized: isRecognized,
    deviation,
    weight: COMPONENT_WEIGHTS.DEVICE
  };
}

/**
 * Calculates country deviation using pure binary MVP comparison.
 *
 * @param {string|null} geoCountry - Current country (2-letter ISO code)
 * @param {Array<object>|null} typicalCountries - Baseline typical_countries array
 * @returns {{
 *   evaluated: boolean,
 *   country?: string,
 *   is_recognized?: boolean,
 *   deviation?: number,
 *   weight?: number
 * }}
 */
function calculateCountryDeviation(geoCountry, typicalCountries) {
  if (
    !geoCountry ||
    typeof geoCountry !== 'string' ||
    geoCountry.trim() === '' ||
    !Array.isArray(typicalCountries) ||
    typicalCountries.length === 0
  ) {
    return { evaluated: false };
  }

  const normalizedCountry = geoCountry.trim().toUpperCase();
  const matchedCountry = typicalCountries.find(
    (c) => c && typeof c.country === 'string' && c.country.trim().toUpperCase() === normalizedCountry
  );

  const isRecognized = !!matchedCountry;
  const deviation = isRecognized ? 0.0 : 1.0;

  return {
    evaluated: true,
    country: normalizedCountry,
    is_recognized: isRecognized,
    deviation,
    weight: COMPONENT_WEIGHTS.COUNTRY
  };
}

/**
 * Evaluates behavioral deviation between a current login and a persisted baseline.
 *
 * Safeguards:
 * - Never calls baseline rebuild
 * - Strictly handles insufficient history (returns null deviation)
 * - Dynamic re-normalization when components are missing
 * - Returns null deviation with reason "insufficient_signals" when no components are evaluable
 * - Output never contains raw device fingerprint or redundant user_id
 * - Explanation describes behavioral deviation without claiming compromise
 *
 * @param {object|null} baseline - Existing BehavioralBaseline record/object
 * @param {object} context - Current login request context
 * @param {Date|string|number} timestamp - Current login timestamp
 * @returns {object} The behavioral deviation signal
 */
function evaluateBaselineDeviation(baseline, context = {}, timestamp = new Date()) {
  if (!baseline || !baseline.has_sufficient_history) {
    return {
      deviation_score: null,
      deviation_percentage: null,
      has_sufficient_history: false,
      is_evaluated: false,
      reason: 'insufficient_history',
      components: {
        login_hour: { evaluated: false },
        device: { evaluated: false },
        country: { evaluated: false }
      },
      explanation: {
        summary: 'Insufficient historical activity to evaluate behavioral deviation.',
        factors: []
      }
    };
  }

  const hourComp = calculateHourDeviation(timestamp, baseline.login_hours);
  const deviceComp = calculateDeviceDeviation(context?.device_fingerprint, baseline.typical_devices);
  const countryComp = calculateCountryDeviation(context?.geo_country, baseline.typical_countries);

  const evaluableComponents = [];
  if (hourComp.evaluated) evaluableComponents.push(hourComp);
  if (deviceComp.evaluated) evaluableComponents.push(deviceComp);
  if (countryComp.evaluated) evaluableComponents.push(countryComp);

  if (evaluableComponents.length === 0) {
    return {
      deviation_score: null,
      deviation_percentage: null,
      has_sufficient_history: true,
      is_evaluated: false,
      reason: 'insufficient_signals',
      components: {
        login_hour: hourComp,
        device: deviceComp,
        country: countryComp
      },
      explanation: {
        summary: 'No comparable security context available to evaluate baseline deviation.',
        factors: []
      }
    };
  }

  // Dynamic re-normalization over available components
  let weightedSum = 0;
  let totalAvailableWeight = 0;

  for (const comp of evaluableComponents) {
    weightedSum += comp.weight * comp.deviation;
    totalAvailableWeight += comp.weight;
  }

  const rawNormalizedDeviation = totalAvailableWeight > 0 ? weightedSum / totalAvailableWeight : 0;
  const clampedDeviation = clamp(rawNormalizedDeviation, 0.0, 1.0);
  const deviationScore = roundToTwoDecimals(clampedDeviation);
  const deviationPercentage = Math.round(clampedDeviation * 100);

  // Build objective, non-accusatory factors
  const factors = [];
  if (hourComp.evaluated && hourComp.deviation > 0) {
    factors.push(
      `Access time (${String(Math.floor(hourComp.current_hour_utc)).padStart(2, '0')}:${String(
        Math.round((hourComp.current_hour_utc % 1) * 60)
      ).padStart(2, '0')} UTC) is outside the user's normal hours (mean ${String(
        Math.floor(hourComp.mean_hour_utc)
      ).padStart(2, '0')}:${String(Math.round((hourComp.mean_hour_utc % 1) * 60)).padStart(2, '0')} UTC).`
    );
  }
  if (deviceComp.evaluated && !deviceComp.is_recognized) {
    factors.push('Unrecognized device.');
  }
  if (countryComp.evaluated && !countryComp.is_recognized) {
    factors.push(`Unrecognized country (${countryComp.country}).`);
  }

  const summary = `Login deviates ${deviationPercentage}% from the user's historical behavioral baseline.`;

  return {
    deviation_score: deviationScore,
    deviation_percentage: deviationPercentage,
    has_sufficient_history: true,
    is_evaluated: true,
    reason: null,
    components: {
      login_hour: hourComp,
      device: deviceComp,
      country: countryComp
    },
    explanation: {
      summary,
      factors
    }
  };
}

module.exports = {
  COMPONENT_WEIGHTS,
  clamp,
  calculateHourDeviation,
  calculateDeviceDeviation,
  calculateCountryDeviation,
  evaluateBaselineDeviation
};
