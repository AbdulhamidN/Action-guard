/**
 * Signal Collector for Baseline Deviation Scoring (Sub-module 4.2).
 *
 * Compares current login security context against the user's existing historical baseline.
 * Decoupled from Express req/res objects and fails safe on unexpected errors.
 */

const { evaluateBaselineDeviationForUser } = require('../services/baselineDeviationService');

/**
 * Collects the behavioral deviation signal for a given user and current login context.
 *
 * @param {string} userId - User ID
 * @param {object} currentContext - Current login context
 * @param {Date|string|number} [currentTimestamp] - Exact arrival timestamp
 * @returns {Promise<object>}
 */
async function collectBaselineDeviationSignal(userId, currentContext = {}, currentTimestamp = new Date()) {
  try {
    return await evaluateBaselineDeviationForUser(userId, currentContext, currentTimestamp);
  } catch (err) {
    console.warn('[BaselineCollector] Evaluation failed:', err.message);
    return {
      deviation_score: null,
      deviation_percentage: null,
      has_sufficient_history: false,
      is_evaluated: false,
      reason: 'collector_error',
      components: {
        login_hour: { evaluated: false },
        device: { evaluated: false },
        country: { evaluated: false }
      },
      explanation: {
        summary: 'Baseline deviation evaluation could not be completed.',
        factors: []
      }
    };
  }
}

module.exports = {
  collectBaselineDeviationSignal
};
