/**
 * Timing & Statistical Utilities for Bot/Automation Detection (Sub-module 3.4).
 *
 * Provides pure mathematical and statistical evaluation of request arrival intervals.
 * Completely decoupled from Express, Redis, and database models.
 */

const DEFAULT_TIMING_CONFIG = {
  windowSeconds: 60,
  maxHistory: 10,
  minRequests: 3,
  burstMinIntervalMs: 150,
  burstAvgIntervalMs: 300,
  regularityMaxIntervalMs: 5000,
  regularityCvThreshold: 0.15
};

/**
 * Rounds a floating-point number to two decimal places.
 *
 * @param {number} value
 * @returns {number}
 */
function roundToTwoDecimals(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return 0;
  }
  return Math.round((value + Number.EPSILON) * 100) / 100;
}

/**
 * Parses and sorts timestamps into strictly ascending numeric milliseconds.
 *
 * @param {Array<number|string|Date>} timestamps
 * @returns {number[]} Array of sorted millisecond timestamps
 */
function parseAndSortTimestamps(timestamps) {
  if (!Array.isArray(timestamps)) {
    return [];
  }

  const numeric = timestamps
    .map((t) => {
      if (t instanceof Date) return t.getTime();
      if (typeof t === 'string') {
        const parsed = new Date(t).getTime();
        return isNaN(parsed) ? null : parsed;
      }
      if (typeof t === 'number' && Number.isFinite(t)) {
        return t;
      }
      return null;
    })
    .filter((t) => t !== null);

  numeric.sort((a, b) => a - b);
  return numeric;
}

/**
 * Calculates consecutive intervals (delta_t = t_{i+1} - t_i) from sorted timestamps.
 *
 * @param {number[]} sortedTimestamps - Ascending array of millisecond timestamps
 * @returns {number[]} Array of consecutive intervals in milliseconds
 */
function calculateConsecutiveIntervals(sortedTimestamps) {
  if (!Array.isArray(sortedTimestamps) || sortedTimestamps.length < 2) {
    return [];
  }

  const intervals = [];
  for (let i = 1; i < sortedTimestamps.length; i++) {
    intervals.push(sortedTimestamps[i] - sortedTimestamps[i - 1]);
  }
  return intervals;
}

/**
 * Calculates statistical metrics over consecutive intervals:
 * - min_interval_ms
 * - avg_interval_ms
 * - interval_std_dev_ms (sample standard deviation)
 * - coefficient_of_variation (CV = std_dev / mean, null if mean <= 0)
 *
 * @param {number[]} intervals - Array of millisecond intervals
 * @returns {{
 *   min_interval_ms: number,
 *   avg_interval_ms: number,
 *   interval_std_dev_ms: number,
 *   coefficient_of_variation: number|null
 * }|null}
 */
function calculateIntervalMetrics(intervals) {
  if (!Array.isArray(intervals) || intervals.length === 0) {
    return null;
  }

  const k = intervals.length;
  const minInterval = Math.min(...intervals);
  const sum = intervals.reduce((acc, val) => acc + val, 0);
  const mean = sum / k;

  let stdDev = 0;
  if (k >= 2) {
    const variance =
      intervals.reduce((acc, val) => acc + Math.pow(val - mean, 2), 0) / (k - 1);
    stdDev = Math.sqrt(variance);
  }

  let cv = null;
  // CV is only mathematically meaningful when mean is strictly positive
  if (mean > 0) {
    cv = stdDev / mean;
  }

  return {
    min_interval_ms: roundToTwoDecimals(minInterval),
    avg_interval_ms: roundToTwoDecimals(mean),
    interval_std_dev_ms: roundToTwoDecimals(stdDev),
    coefficient_of_variation: cv !== null ? roundToTwoDecimals(cv) : null
  };
}

/**
 * Resolves configuration thresholds from options or environment variables.
 *
 * @param {object} [options={}]
 * @returns {object}
 */
function resolveConfig(options = {}) {
  const getNum = (optVal, envKey, defaultVal) => {
    if (typeof optVal === 'number' && Number.isFinite(optVal) && optVal > 0) {
      return optVal;
    }
    const envVal = process.env[envKey];
    if (envVal !== undefined && envVal.trim() !== '') {
      const parsed = parseFloat(envVal);
      if (!isNaN(parsed) && Number.isFinite(parsed) && parsed > 0) {
        return parsed;
      }
    }
    return defaultVal;
  };

  return {
    minRequests: getNum(
      options.minRequests,
      'BOT_TIMING_MIN_REQUESTS',
      DEFAULT_TIMING_CONFIG.minRequests
    ),
    burstMinIntervalMs: getNum(
      options.burstMinIntervalMs,
      'BOT_TIMING_BURST_MIN_INTERVAL_MS',
      DEFAULT_TIMING_CONFIG.burstMinIntervalMs
    ),
    burstAvgIntervalMs: getNum(
      options.burstAvgIntervalMs,
      'BOT_TIMING_BURST_AVG_INTERVAL_MS',
      DEFAULT_TIMING_CONFIG.burstAvgIntervalMs
    ),
    regularityMaxIntervalMs: getNum(
      options.regularityMaxIntervalMs,
      'BOT_TIMING_REGULARITY_MAX_INTERVAL_MS',
      DEFAULT_TIMING_CONFIG.regularityMaxIntervalMs
    ),
    regularityCvThreshold: getNum(
      options.regularityCvThreshold,
      'BOT_TIMING_REGULARITY_CV_THRESHOLD',
      DEFAULT_TIMING_CONFIG.regularityCvThreshold
    )
  };
}

/**
 * Evaluates automation heuristics on an array of timestamps.
 *
 * Heuristics:
 * 1. Rapid Burst:
 *    Flagged if min interval > 0 and < burstMinIntervalMs,
 *    OR avg interval > 0 and < burstAvgIntervalMs.
 *    (Zero/duplicate intervals do NOT trigger burst).
 * 2. Robotic Periodicity:
 *    Flagged if sample_size >= 4 (at least 3 intervals),
 *    avg interval > 0 and <= regularityMaxIntervalMs,
 *    and coefficient_of_variation !== null and < regularityCvThreshold.
 *    (If mean <= 0, CV is null and periodicity never triggers).
 *
 * @param {Array<number|string|Date>} rawTimestamps
 * @param {object} [options={}]
 * @returns {{
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
 * }}
 */
function evaluateAutomationHeuristics(rawTimestamps, options = {}) {
  const sorted = parseAndSortTimestamps(rawTimestamps);
  const sampleSize = sorted.length;
  const config = resolveConfig(options);

  // Insufficient observations guard:
  // Requires at least minRequests to evaluate intervals meaningfully
  if (sampleSize < config.minRequests) {
    return {
      automation_suspected: false,
      sufficient_observations: false,
      sample_size: sampleSize,
      reasons: [],
      metrics: null
    };
  }

  const intervals = calculateConsecutiveIntervals(sorted);
  const metrics = calculateIntervalMetrics(intervals);

  const reasons = [];

  // Check 1: Rapid Burst (Sub-human speed)
  // Must evaluate distinct, positive intervals (> 0 ms).
  // Zero-length / duplicate artifacts must not trigger rapid burst.
  const hasRapidMin =
    metrics.min_interval_ms > 0 && metrics.min_interval_ms < config.burstMinIntervalMs;
  const hasRapidAvg =
    metrics.avg_interval_ms > 0 && metrics.avg_interval_ms < config.burstAvgIntervalMs;

  if (hasRapidMin || hasRapidAvg) {
    reasons.push('rapid_burst');
  }

  // Check 2: Robotic Periodicity (Low Jitter / High Regularity)
  // Requires:
  // - at least 4 requests (3 intervals) to verify a consistent repeating cycle;
  // - strictly positive mean interval (metrics.avg_interval_ms > 0);
  // - mean interval within active loop window (<= regularityMaxIntervalMs);
  // - coefficient of variation !== null and below regularityCvThreshold (< 0.15).
  // Duplicate timestamps with mean <= 0 produce cv = null and NEVER trigger periodicity.
  if (
    sampleSize >= 4 &&
    metrics.avg_interval_ms > 0 &&
    metrics.avg_interval_ms <= config.regularityMaxIntervalMs &&
    metrics.coefficient_of_variation !== null &&
    metrics.coefficient_of_variation < config.regularityCvThreshold
  ) {
    reasons.push('robotic_periodicity');
  }

  const automationSuspected = reasons.length > 0;

  return {
    automation_suspected: automationSuspected,
    sufficient_observations: true,
    sample_size: sampleSize,
    reasons,
    metrics
  };
}

module.exports = {
  DEFAULT_TIMING_CONFIG,
  roundToTwoDecimals,
  parseAndSortTimestamps,
  calculateConsecutiveIntervals,
  calculateIntervalMetrics,
  resolveConfig,
  evaluateAutomationHeuristics
};
