const cron = require('node-cron');
const { User } = require('../database/models');
const baselineService = require('../services/baselineService');

let scheduledTask = null;
let isRecalculating = false;

/**
 * Executes a deterministic sequential baseline recalculation across all users.
 *
 * Sequence:
 * 1. Load user IDs deterministically ordered by id ASC.
 * 2. Prevent overlapping runs via an in-memory execution guard.
 * 3. Sequentially invoke baselineService.buildUserBaseline(userId) for each user.
 * 4. Isolate failures per user so one failure does not abort the rest of the run.
 *
 * @param {object} [options={}]
 * @param {object} [options.baselineOptions={}] - Optional options passed to buildUserBaseline
 * @returns {Promise<object>} Run summary statistics
 */
async function runBaselineRecalculation(options = {}) {
  if (isRecalculating) {
    console.warn('[BaselineRecalculationJob] Previous recalculation run is still active; skipping execution.');
    return {
      skipped: true,
      reason: 'already_running',
      totalUsers: 0,
      processed: 0,
      succeeded: 0,
      failed: 0,
      errors: []
    };
  }

  isRecalculating = true;
  const startTime = Date.now();
  const summary = {
    skipped: false,
    totalUsers: 0,
    processed: 0,
    succeeded: 0,
    failed: 0,
    errors: [],
    durationMs: 0
  };

  try {
    const users = await User.findAll({
      attributes: ['id'],
      order: [['id', 'ASC']]
    });

    summary.totalUsers = users.length;

    for (const user of users) {
      summary.processed += 1;
      try {
        await baselineService.buildUserBaseline(user.id, options.baselineOptions);
        summary.succeeded += 1;
      } catch (err) {
        summary.failed += 1;
        summary.errors.push({
          userId: user.id,
          message: err.message
        });
        console.error(`[BaselineRecalculationJob] Error recalculating baseline for user ${user.id}:`, err.message);
      }
    }
  } catch (err) {
    console.error('[BaselineRecalculationJob] Unexpected failure loading users:', err.message);
    throw err;
  } finally {
    isRecalculating = false;
    summary.durationMs = Date.now() - startTime;
  }

  return summary;
}

/**
 * Returns whether a recalculation is currently in progress.
 *
 * @returns {boolean}
 */
function isRecalculationRunning() {
  return isRecalculating;
}

/**
 * Starts the scheduled recurring recalculation job using node-cron.
 *
 * @param {object} [config={}]
 * @param {string} [config.schedule] - Cron pattern (defaults to env or '0 2 * * *')
 * @param {string} [config.timezone] - Cron timezone (defaults to 'UTC')
 * @returns {object|null} The created cron task or null if already scheduled
 */
function startBaselineRecalculationSchedule(config = {}) {
  if (scheduledTask) {
    return scheduledTask;
  }

  const schedulePattern = config.schedule || process.env.BASELINE_RECALCULATION_SCHEDULE || '0 2 * * *';
  const timezone = config.timezone || 'UTC';

  scheduledTask = cron.schedule(
    schedulePattern,
    async () => {
      try {
        await runBaselineRecalculation();
      } catch (err) {
        console.error('[BaselineRecalculationJob] Scheduled run encountered an error:', err.message);
      }
    },
    {
      scheduled: true,
      timezone
    }
  );

  return scheduledTask;
}

/**
 * Stops and clears the recurring scheduled task.
 */
function stopBaselineRecalculationSchedule() {
  if (scheduledTask) {
    scheduledTask.stop();
    scheduledTask = null;
  }
}

/**
 * Retrieves the current cron task instance.
 *
 * @returns {object|null}
 */
function getScheduledTask() {
  return scheduledTask;
}

module.exports = {
  runBaselineRecalculation,
  isRecalculationRunning,
  startBaselineRecalculationSchedule,
  stopBaselineRecalculationSchedule,
  getScheduledTask
};
