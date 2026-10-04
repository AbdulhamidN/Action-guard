const DEFAULT_BASELINE_MIN_LOGINS = 5;

/**
 * Resolves the baseline minimum login threshold from options or environment.
 * Strict positive integer validation:
 * - valid positive integer -> use configured value
 * - missing / zero / negative / non-numeric -> returns 5
 *
 * @param {object} [options={}]
 * @param {number} [options.minLogins]
 * @returns {number}
 */
function getBaselineMinLogins(options = {}) {
  if (
    options &&
    typeof options.minLogins === 'number' &&
    Number.isInteger(options.minLogins) &&
    options.minLogins > 0
  ) {
    return options.minLogins;
  }

  const envVal = process.env.BASELINE_MIN_LOGINS;
  if (envVal !== undefined && envVal !== null && String(envVal).trim() !== '') {
    const parsed = parseInt(String(envVal).trim(), 10);
    if (!isNaN(parsed) && Number.isInteger(parsed) && parsed > 0) {
      return parsed;
    }
  }

  return DEFAULT_BASELINE_MIN_LOGINS;
}

/**
 * Rounds a number to four decimal places.
 *
 * @param {number} num
 * @returns {number}
 */
function roundToFourDecimals(num) {
  if (typeof num !== 'number' || !Number.isFinite(num)) return 0;
  return Math.round(num * 10000) / 10000;
}

/**
 * Rounds a number to two decimal places.
 *
 * @param {number} num
 * @returns {number}
 */
function roundToTwoDecimals(num) {
  if (typeof num !== 'number' || !Number.isFinite(num)) return 0;
  return Math.round(num * 100) / 100;
}

/**
 * Calculates circular 24-hour time-of-day statistics and hourly distribution.
 *
 * Prevents linear averaging distortions at the day boundary (e.g. 23:55 and 00:05).
 * Safeguards:
 * - handles R <= 0 safely (returns null mean and dispersion, preserving histogram)
 * - handles R >= 1.0 (dispersion = 0)
 * - never outputs NaN or Infinity
 *
 * @param {Array<Date|string|number>} timestamps
 * @returns {object|null}
 */
function calculateCircularHourStats(timestamps = []) {
  if (!Array.isArray(timestamps) || timestamps.length === 0) {
    return null;
  }

  const hourlyDistribution = Array(24).fill(0);
  let sumSin = 0;
  let sumCos = 0;
  let validCount = 0;

  for (const rawTimestamp of timestamps) {
    const date = rawTimestamp instanceof Date ? rawTimestamp : new Date(rawTimestamp);
    if (isNaN(date.getTime())) {
      continue;
    }

    const utcHours = date.getUTCHours();
    const utcMinutes = date.getUTCMinutes();
    const utcSeconds = date.getUTCSeconds();

    hourlyDistribution[utcHours] += 1;

    const fractionalHour = utcHours + utcMinutes / 60 + utcSeconds / 3600;
    const angle = (2 * Math.PI * fractionalHour) / 24;

    sumSin += Math.sin(angle);
    sumCos += Math.cos(angle);
    validCount += 1;
  }

  if (validCount === 0) {
    return null;
  }

  const S = sumSin;
  const C = sumCos;
  const resultantLength = Math.sqrt(S * S + C * C);
  const R = resultantLength / validCount;

  // Edge case: resultant vector cancels out completely (R <= 0 or near zero)
  if (resultantLength < 1e-7 || R <= 0) {
    return {
      mean_hour: null,
      circular_std_dev_hours: null,
      resultant_vector_r: 0,
      hourly_distribution: hourlyDistribution
    };
  }

  // Edge case: all observations identical or floating point slight overshoot (R >= 1.0)
  if (R >= 1.0) {
    const meanAngle = Math.atan2(S, C);
    const meanHour = ((meanAngle / (2 * Math.PI)) * 24 + 24) % 24;
    return {
      mean_hour: roundToTwoDecimals(meanHour),
      circular_std_dev_hours: 0,
      resultant_vector_r: 1,
      hourly_distribution: hourlyDistribution
    };
  }

  // General circular case: 0 < R < 1.0
  const meanAngle = Math.atan2(S, C);
  const meanHour = ((meanAngle / (2 * Math.PI)) * 24 + 24) % 24;

  const rawVariance = -2 * Math.log(R);
  let circularStdDevHours = null;
  if (rawVariance >= 0 && Number.isFinite(rawVariance)) {
    const sigmaRad = Math.sqrt(rawVariance);
    const sigmaHours = (24 / (2 * Math.PI)) * sigmaRad;
    if (Number.isFinite(sigmaHours)) {
      circularStdDevHours = roundToTwoDecimals(sigmaHours);
    }
  }

  return {
    mean_hour: roundToTwoDecimals(meanHour),
    circular_std_dev_hours: circularStdDevHours,
    resultant_vector_r: roundToFourDecimals(R),
    hourly_distribution: hourlyDistribution
  };
}

/**
 * Calculates typical devices and frequencies.
 *
 * Strict denominator rule:
 * device_frequency = device_count / number_of_login_success_events_with_device_fingerprint
 *
 * last_seen_at is derived strictly from the most recent SecurityEvent timestamp for that device.
 *
 * @param {Array<object>} events
 * @returns {Array<{ fingerprint: string, count: number, frequency: number, last_seen_at: string }>}
 */
function calculateTypicalDevices(events = []) {
  if (!Array.isArray(events) || events.length === 0) {
    return [];
  }

  const eventsWithDevice = events.filter((e) => {
    const fp = e?.context?.device_fingerprint;
    return typeof fp === 'string' && fp.trim().length > 0;
  });

  const totalWithDevice = eventsWithDevice.length;
  if (totalWithDevice === 0) {
    return [];
  }

  const deviceMap = new Map();

  for (const event of eventsWithDevice) {
    const fingerprint = event.context.device_fingerprint.trim();
    const eventTime = event.timestamp instanceof Date ? event.timestamp : new Date(event.timestamp);
    const timeIso = !isNaN(eventTime.getTime()) ? eventTime.toISOString() : null;

    if (!deviceMap.has(fingerprint)) {
      deviceMap.set(fingerprint, {
        fingerprint,
        count: 0,
        lastSeenDate: eventTime,
        last_seen_at: timeIso
      });
    }

    const entry = deviceMap.get(fingerprint);
    entry.count += 1;

    if (timeIso && (!entry.lastSeenDate || eventTime > entry.lastSeenDate)) {
      entry.lastSeenDate = eventTime;
      entry.last_seen_at = timeIso;
    }
  }

  const result = Array.from(deviceMap.values()).map((item) => ({
    fingerprint: item.fingerprint,
    count: item.count,
    frequency: roundToFourDecimals(item.count / totalWithDevice),
    last_seen_at: item.last_seen_at
  }));

  // Sort by count descending, then last_seen_at descending
  result.sort((a, b) => {
    if (b.count !== a.count) return b.count - a.count;
    if (a.last_seen_at && b.last_seen_at) {
      return new Date(b.last_seen_at).getTime() - new Date(a.last_seen_at).getTime();
    }
    return 0;
  });

  return result;
}

/**
 * Calculates typical countries and frequencies.
 *
 * Strict denominator rule:
 * country_frequency = country_count / number_of_login_success_events_with_geo_country
 *
 * @param {Array<object>} events
 * @returns {Array<{ country: string, count: number, frequency: number }>}
 */
function calculateTypicalCountries(events = []) {
  if (!Array.isArray(events) || events.length === 0) {
    return [];
  }

  const eventsWithCountry = events.filter((e) => {
    const c = e?.context?.geo_country;
    return typeof c === 'string' && c.trim().length > 0;
  });

  const totalWithCountry = eventsWithCountry.length;
  if (totalWithCountry === 0) {
    return [];
  }

  const countryMap = new Map();

  for (const event of eventsWithCountry) {
    const country = event.context.geo_country.trim().toUpperCase();

    if (!countryMap.has(country)) {
      countryMap.set(country, 0);
    }
    countryMap.set(country, countryMap.get(country) + 1);
  }

  const result = Array.from(countryMap.entries()).map(([country, count]) => ({
    country,
    count,
    frequency: roundToFourDecimals(count / totalWithCountry)
  }));

  // Sort by count descending, then country code ascending
  result.sort((a, b) => {
    if (b.count !== a.count) return b.count - a.count;
    return a.country.localeCompare(b.country);
  });

  return result;
}

module.exports = {
  DEFAULT_BASELINE_MIN_LOGINS,
  getBaselineMinLogins,
  roundToTwoDecimals,
  roundToFourDecimals,
  calculateCircularHourStats,
  calculateTypicalDevices,
  calculateTypicalCountries
};
