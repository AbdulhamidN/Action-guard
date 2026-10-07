const DEFAULT_SEQUENCE_WINDOW_SECONDS = 900; // 15 minutes default

/**
 * Resolves configured sequence grouping window in milliseconds.
 *
 * @param {object} [options={}]
 * @returns {number}
 */
function getSequenceWindowMs(options = {}) {
  if (typeof options.windowMs === 'number' && Number.isFinite(options.windowMs) && options.windowMs > 0) {
    return options.windowMs;
  }

  const envVal = process.env.ACTION_SEQUENCE_WINDOW_SECONDS;
  if (envVal !== undefined && envVal.trim() !== '') {
    const parsed = parseInt(envVal, 10);
    if (!isNaN(parsed) && parsed > 0) {
      return parsed * 1000;
    }
  }

  return DEFAULT_SEQUENCE_WINDOW_SECONDS * 1000;
}

module.exports = {
  DEFAULT_SEQUENCE_WINDOW_SECONDS,
  getSequenceWindowMs
};
