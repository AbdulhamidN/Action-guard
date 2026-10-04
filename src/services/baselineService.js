const { SecurityEvent, BehavioralBaseline } = require('../database/models');
const {
  getBaselineMinLogins,
  calculateCircularHourStats,
  calculateTypicalDevices,
  calculateTypicalCountries
} = require('../utils/baseline');

/**
 * Builds or recalculates the behavioral baseline for a specific user.
 *
 * Strictly idempotent with respect to behavioral metrics:
 * - Queries historical login_success records from SecurityEvent table as ground truth
 * - Completely re-aggregates totals, frequencies, distributions, and statistics
 * - Replaces the stored baseline fields
 * - Updates last_calculated_at to the current calculation timestamp
 *
 * @param {string} userId - Target user ID
 * @param {object} [options={}] - Optional overrides (e.g. minLogins)
 * @returns {Promise<object>} The updated BehavioralBaseline record
 */
async function buildUserBaseline(userId, options = {}) {
  if (!userId || typeof userId !== 'string' || userId.trim() === '') {
    throw new Error('userId is required to build a baseline');
  }

  const normalizedUserId = userId.trim();
  const minLogins = getBaselineMinLogins(options);
  const currentCalculationTime = new Date();

  // Query historical login_success events strictly for this user
  const events = await SecurityEvent.findAll({
    attributes: ['event_id', 'timestamp', 'context'],
    where: {
      user_id: normalizedUserId,
      event_type: 'login_success'
    },
    order: [['timestamp', 'ASC']]
  });

  const totalLogins = events.length;
  const hasSufficientHistory = totalLogins >= minLogins;

  const timestamps = events.map((e) => e.timestamp);
  const loginHours = calculateCircularHourStats(timestamps);
  const typicalDevices = calculateTypicalDevices(events);
  const typicalCountries = calculateTypicalCountries(events);

  // Check for existing baseline record
  let baseline = await BehavioralBaseline.findOne({
    where: { user_id: normalizedUserId }
  });

  if (baseline) {
    baseline.total_logins = totalLogins;
    baseline.has_sufficient_history = hasSufficientHistory;
    baseline.login_hours = loginHours;
    baseline.typical_devices = typicalDevices;
    baseline.typical_countries = typicalCountries;
    baseline.last_calculated_at = currentCalculationTime;
    await baseline.save();
  } else {
    baseline = await BehavioralBaseline.create({
      user_id: normalizedUserId,
      total_logins: totalLogins,
      has_sufficient_history: hasSufficientHistory,
      login_hours: loginHours,
      typical_devices: typicalDevices,
      typical_countries: typicalCountries,
      last_calculated_at: currentCalculationTime
    });
  }

  return baseline;
}

/**
 * Retrieves the current behavioral baseline for a user, or null if none exists.
 *
 * @param {string} userId
 * @returns {Promise<object|null>}
 */
async function getUserBaseline(userId) {
  if (!userId || typeof userId !== 'string') {
    return null;
  }

  return BehavioralBaseline.findOne({
    where: { user_id: userId.trim() }
  });
}

module.exports = {
  buildUserBaseline,
  getUserBaseline
};
