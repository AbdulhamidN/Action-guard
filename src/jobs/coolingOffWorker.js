'use strict';

const crypto = require('crypto');
const { Op } = require('sequelize');
const { DelayedAction, SecurityEvent } = require('../database/models');
const {
  executeDelayedAction,
  reconcileStaleExecutingActions
} = require('../services/coolingOffService');
const { REDIS_PREFIXES } = require('../config/sessionConfig');
const redisStorage = require('../storage/redis');
const eventBus = require('../events/eventBus');

const WORKER_LOCK_KEY = 'cooling_off:worker_lock';
const WORKER_LOCK_TTL_SECONDS = 15;

let workerIntervalId = null;
let isProcessing = false;

/**
 * Scans and processes overdue cooling-off actions, reconciles stale executing actions,
 * and marks expired pending actions.
 *
 * @param {object} [options={}]
 * @param {number} [options.staleTimeoutMs]
 * @returns {Promise<{ skipped: boolean, reason?: string, processed: number, executedCount: number, expiredCount: number, reconciledStaleCount: number, errors: number }>}
 */
async function processOverdueActions(options = {}) {
  if (isProcessing) {
    return {
      skipped: true,
      reason: 'in_process',
      processed: 0,
      executedCount: 0,
      expiredCount: 0,
      reconciledStaleCount: 0,
      errors: 0
    };
  }

  const rawRedis = redisStorage.getRedisClient();
  const lockValue = `worker_${crypto.randomUUID()}`;
  let lockAcquired = false;

  // Atomic distributed worker lock acquisition (SET ... EX ... NX)
  try {
    const acquired = await rawRedis.set(
      WORKER_LOCK_KEY,
      lockValue,
      'EX',
      WORKER_LOCK_TTL_SECONDS,
      'NX'
    );
    if (acquired !== 'OK') {
      return {
        skipped: true,
        reason: 'lock_held',
        processed: 0,
        executedCount: 0,
        expiredCount: 0,
        reconciledStaleCount: 0,
        errors: 0
      };
    }
    lockAcquired = true;
  } catch (_err) {
    // Proceed with in-process guard if Redis lock check fails
  }

  isProcessing = true;
  let processedCount = 0;
  let expiredCount = 0;
  let reconciledStaleCount = 0;
  let errorCount = 0;

  try {
    // 0. Reconcile stale 'executing' rows left behind by crashed or timed-out workers (C-04)
    try {
      reconciledStaleCount = await reconcileStaleExecutingActions(options.staleTimeoutMs);
    } catch (reconcileErr) {
      errorCount++;
      console.error('[CoolingOffWorker] Error reconciling stale executing actions:', reconcileErr.message);
    }

    const now = new Date();

    // 1. Mark expired actions
    const expiredActions = await DelayedAction.findAll({
      where: {
        status: 'pending',
        expires_at: { [Op.lte]: now }
      },
      limit: 50
    });

    for (const exp of expiredActions) {
      try {
        const [updated] = await DelayedAction.update(
          { status: 'expired', updated_at: now },
          { where: { id: exp.id, status: 'pending' } }
        );
        if (updated > 0) {
          expiredCount++;
          if (exp.event_id) {
            const secEv = await SecurityEvent.findByPk(exp.event_id).catch(() => null);
            if (secEv) {
              await secEv
                .update({
                  metadata: {
                    ...(secEv.metadata || {}),
                    action_status: 'expired',
                    delayed_action_id: exp.id,
                    expired_at: now.toISOString()
                  }
                })
                .catch(() => {});
            }
          }
          try {
            if (exp.cancellation_token_hash) {
              await rawRedis.del(`${REDIS_PREFIXES.COOLING_OFF_TOKEN_MAP}${exp.cancellation_token_hash}`);
            }
            if (exp.user_id) {
              await rawRedis.srem(`${REDIS_PREFIXES.COOLING_OFF_USER_INDEX}${exp.user_id}`, exp.id);
            }
            await rawRedis.del(`${REDIS_PREFIXES.COOLING_OFF_ACTION}${exp.id}`);
          } catch {}
          eventBus.safeEmit('cooling_off:expired', { action_id: exp.id });
        }
      } catch (err) {
        errorCount++;
        console.error(`[CoolingOffWorker] Error expiring action ${exp.id}:`, err.message);
      }
    }

    // 2. Process overdue pending actions
    const overdueActions = await DelayedAction.findAll({
      where: {
        status: 'pending',
        execute_at: { [Op.lte]: now },
        expires_at: { [Op.gt]: now }
      },
      order: [['execute_at', 'ASC']],
      limit: 50
    });

    for (const action of overdueActions) {
      try {
        await executeDelayedAction({
          actionId: action.id,
          triggeredBy: 'worker'
        });
        processedCount++;
      } catch (execErr) {
        errorCount++;
        if (execErr.code !== 'concurrent_execution_conflict' && execErr.code !== 'action_not_pending') {
          console.error(`[CoolingOffWorker] Error processing action ${action.id}:`, execErr.message);
        }
      }
    }
  } catch (err) {
    console.error('[CoolingOffWorker] Error in processOverdueActions run:', err.message);
  } finally {
    isProcessing = false;
    if (lockAcquired) {
      try {
        await redisStorage.executeReleaseLock(WORKER_LOCK_KEY, lockValue);
      } catch (_err) {
        // Ignore lock release error
      }
    }
  }

  return {
    skipped: false,
    processed: processedCount,
    executedCount: processedCount,
    expiredCount,
    reconciledStaleCount,
    errors: errorCount
  };
}

/**
 * Starts the background cooling-off worker polling timer.
 *
 * @param {number} [intervalMs=5000]
 */
function startCoolingOffWorker(intervalMs = 5000) {
  if (workerIntervalId) {
    return;
  }

  workerIntervalId = setInterval(() => {
    processOverdueActions().catch((err) => {
      console.error('[CoolingOffWorker] Unhandled rejection:', err.message);
    });
  }, intervalMs);

  if (typeof workerIntervalId.unref === 'function') {
    workerIntervalId.unref();
  }
}

/**
 * Stops the background cooling-off worker polling timer.
 */
function stopCoolingOffWorker() {
  if (workerIntervalId) {
    clearInterval(workerIntervalId);
    workerIntervalId = null;
  }
}

module.exports = {
  processOverdueActions,
  startCoolingOffWorker,
  stopCoolingOffWorker,
  WORKER_LOCK_KEY
};

