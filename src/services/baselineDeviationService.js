/**
 * Sub-module 4.2: Baseline Deviation Service
 *
 * Compares a current login's security context against the user's persisted behavioral baseline.
 *
 * CRITICAL ARCHITECTURAL SAFEGUARDS:
 * 1. NEVER calls buildUserBaseline() - only retrieves existing persisted baseline via getUserBaseline().
 * 2. The current login being scored is NEVER added to the baseline before scoring.
 * 3. Does not generate risk scores or policy decisions.
 */

const { getUserBaseline } = require('./baselineService');
const { evaluateBaselineDeviation } = require('../utils/deviation');

/**
 * Evaluates behavioral baseline deviation for a user.
 *
 * @param {string} userId - Target user ID
 * @param {object} currentContext - Current login context (ip_address, geo_country, device_fingerprint)
 * @param {Date|string|number} [currentTimestamp] - Exact timestamp of current login
 * @returns {Promise<object>} The behavioral deviation signal
 */
async function evaluateBaselineDeviationForUser(userId, currentContext = {}, currentTimestamp = new Date()) {
  if (!userId || typeof userId !== 'string' || userId.trim() === '') {
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

  // Strictly retrieve existing persisted baseline - NEVER rebuild here
  const baseline = await getUserBaseline(userId.trim());

  return evaluateBaselineDeviation(baseline, currentContext, currentTimestamp);
}

module.exports = {
  evaluateBaselineDeviationForUser
};
