'use strict';

const eventBus = require('../events/eventBus');
const {
  DEFAULT_BATCH_SIZE,
  DEFAULT_CONCURRENCY_LIMIT,
  DEFAULT_LEASE_TIMEOUT_MS,
  DEFAULT_MAX_ATTEMPTS,
  DEFAULT_RECONCILE_LOOKBACK_MS,
  DEFAULT_RECONCILE_BATCH_SIZE,
  enqueueWebhooksForEvent,
  reconcileMissingWebhookEnqueues,
  processPendingWebhookDeliveries
} = require('../services/webhookDeliveryService');

const DEFAULT_POLL_INTERVAL_MS = 5000;
const DEFAULT_RECONCILE_INTERVAL_MS = 30000;

let unsubPipelineEventProcessed = null;
let unsubPolicyDecisionRecorded = null;
let pollIntervalId = null;
let wakeupTimerId = null;
let isRunning = false;
let isCycleRunning = false;
let pendingWakeup = false;
let activeCyclePromise = null;
let lastMissingReconcileAtMs = 0;
let workerOptions = {};
const inFlightEnqueues = new Set();

/**
 * Extracts a valid non-empty string identifier from candidate fields.
 *
 * @param {...unknown} candidates
 * @returns {string|null}
 */
function resolveIdentifier(...candidates) {
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.trim().length > 0) {
      return candidate.trim();
    }
  }
  return null;
}

/**
 * Schedules a non-blocking immediate worker cycle wake-up when new webhook jobs
 * are enqueued via the in-process eventBus.
 */
function scheduleImmediateWakeup() {
  if (!isRunning) {
    return;
  }

  if (isCycleRunning) {
    pendingWakeup = true;
    return;
  }

  if (wakeupTimerId) {
    return;
  }

  wakeupTimerId = setTimeout(() => {
    wakeupTimerId = null;
    if (!isRunning) {
      return;
    }
    runWebhookWorkerCycle(workerOptions).catch((err) => {
      console.error('[WebhookDeliveryWorker] Wakeup cycle error:', err.message);
    });
  }, 0);

  if (typeof wakeupTimerId.unref === 'function') {
    wakeupTimerId.unref();
  }
}

/**
 * Attaches idempotent listeners on the ActionGuard eventBus for:
 * - `pipeline:event_processed` -> webhook event `event.processed`
 * - `policy:decision_recorded` -> webhook event `decision.recorded`
 *
 * Prevents duplicate listener registration and isolates all enqueue errors so
 * webhook failures never block core security-event or PEP processing.
 *
 * @param {object} [options={}]
 * @param {Function} [options.onEnqueued] - Optional callback invoked when jobs are enqueued
 * @returns {() => void} Cleanup function that detaches the listeners
 */
function attachWebhookEventListeners(options = {}) {
  detachWebhookEventListeners();

  const handleEnqueueAsync = (eventType, sourceEventId) => {
    const task = Promise.resolve()
      .then(() =>
        enqueueWebhooksForEvent({
          eventType,
          sourceEventId
        })
      )
      .then((res) => {
        if (res && Array.isArray(res.enqueued) && res.enqueued.length > 0) {
          if (typeof options.onEnqueued === 'function') {
            options.onEnqueued(res);
          } else {
            scheduleImmediateWakeup();
          }
        }
        return res;
      })
      .catch((err) => {
        console.warn(
          `[WebhookDeliveryWorker] Failed to enqueue webhook for ${eventType} (${sourceEventId}):`,
          err.message
        );
      })
      .finally(() => {
        inFlightEnqueues.delete(task);
      });

    inFlightEnqueues.add(task);
    return task;
  };

  const onPipelineEventProcessed = (payload) => {
    if (!payload || typeof payload !== 'object' || !payload.event) {
      return;
    }
    const sourceEventId = resolveIdentifier(
      payload.event.event_id,
      payload.event.eventId
    );
    if (!sourceEventId) {
      return;
    }
    handleEnqueueAsync('event.processed', sourceEventId);
  };

  const onPolicyDecisionRecorded = (payload) => {
    if (!payload || typeof payload !== 'object' || !payload.decision) {
      return;
    }
    const sourceDecisionId = resolveIdentifier(
      payload.decision.id,
      payload.decision.decision_id,
      payload.decision.decisionId
    );
    if (!sourceDecisionId) {
      return;
    }
    handleEnqueueAsync('decision.recorded', sourceDecisionId);
  };

  unsubPipelineEventProcessed = eventBus.on(
    'pipeline:event_processed',
    onPipelineEventProcessed
  );
  unsubPolicyDecisionRecorded = eventBus.on(
    'policy:decision_recorded',
    onPolicyDecisionRecorded
  );

  return detachWebhookEventListeners;
}

/**
 * Removes the webhook eventBus listeners if currently registered.
 */
function detachWebhookEventListeners() {
  if (typeof unsubPipelineEventProcessed === 'function') {
    unsubPipelineEventProcessed();
    unsubPipelineEventProcessed = null;
  }
  if (typeof unsubPolicyDecisionRecorded === 'function') {
    unsubPolicyDecisionRecorded();
    unsubPolicyDecisionRecorded = null;
  }
}

/**
 * Waits for any currently in-flight asynchronous event-listener enqueue calls to settle.
 *
 * @returns {Promise<void>}
 */
async function flushInFlightWebhookEnqueues() {
  while (inFlightEnqueues.size > 0) {
    await Promise.allSettled(Array.from(inFlightEnqueues));
  }
}

/**
 * Executes a single webhook worker cycle:
 * 1. Runs missing-job reconciliation (`reconcileMissingWebhookEnqueues`) on startup,
 *    when `forceReconcile: true`, or when `reconcileIntervalMs` has elapsed.
 * 2. Runs `processPendingWebhookDeliveries`, which reconciles stale expired leases
 *    first (`reconcileStaleLockedDeliveries`) before polling due jobs in bounded
 *    batches with bounded concurrency.
 *
 * @param {object} [options={}]
 * @param {boolean} [options.forceReconcile=false]
 * @param {number} [options.reconcileIntervalMs=DEFAULT_RECONCILE_INTERVAL_MS]
 * @param {number} [options.lookbackMs=DEFAULT_RECONCILE_LOOKBACK_MS]
 * @param {number} [options.reconcileBatchSize=DEFAULT_RECONCILE_BATCH_SIZE]
 * @param {number} [options.batchSize=DEFAULT_BATCH_SIZE]
 * @param {number} [options.concurrency=DEFAULT_CONCURRENCY_LIMIT]
 * @param {number} [options.leaseTimeoutMs=DEFAULT_LEASE_TIMEOUT_MS]
 * @param {number} [options.maxAttempts=DEFAULT_MAX_ATTEMPTS]
 * @param {Date} [options.now]
 * @returns {Promise<{
 *   skipped: boolean,
 *   reason?: string,
 *   missingReconciliation: object|null,
 *   staleReconciliation: object|null,
 *   processed: number,
 *   deliveredCount: number,
 *   retriedCount: number,
 *   failedCount: number,
 *   errors: number
 * }>}
 */
async function runWebhookWorkerCycle(options = {}) {
  if (isCycleRunning) {
    pendingWakeup = true;
    return {
      skipped: true,
      reason: 'already_running',
      missingReconciliation: null,
      staleReconciliation: null,
      processed: 0,
      deliveredCount: 0,
      retriedCount: 0,
      failedCount: 0,
      errors: 0
    };
  }

  isCycleRunning = true;

  const executeCycle = async () => {
    let missingReconciliation = null;
    let staleReconciliation = null;
    let processed = 0;
    let deliveredCount = 0;
    let retriedCount = 0;
    let failedCount = 0;
    let errors = 0;

    try {
      await flushInFlightWebhookEnqueues();

      const now =
        options.now instanceof Date
          ? options.now
          : new Date(options.now || Date.now());
      const reconcileIntervalMs =
        typeof options.reconcileIntervalMs === 'number' &&
        options.reconcileIntervalMs >= 0
          ? options.reconcileIntervalMs
          : DEFAULT_RECONCILE_INTERVAL_MS;

      const shouldReconcileMissing =
        options.forceReconcile === true ||
        lastMissingReconcileAtMs === 0 ||
        now.getTime() - lastMissingReconcileAtMs >= reconcileIntervalMs;

      if (shouldReconcileMissing) {
        try {
          missingReconciliation = await reconcileMissingWebhookEnqueues({
            now,
            lookbackMs: options.lookbackMs,
            batchSize: options.reconcileBatchSize
          });
          lastMissingReconcileAtMs = now.getTime();
        } catch (reconcileErr) {
          errors += 1;
          console.error(
            '[WebhookDeliveryWorker] Error reconciling missing webhook jobs:',
            reconcileErr.message
          );
        }
      }

      try {
        const deliverySummary = await processPendingWebhookDeliveries({
          ...options,
          now
        });
        staleReconciliation = deliverySummary.reconciled;
        processed = deliverySummary.processed;
        deliveredCount = deliverySummary.deliveredCount;
        retriedCount = deliverySummary.retriedCount;
        failedCount = deliverySummary.failedCount;
      } catch (pollErr) {
        errors += 1;
        console.error(
          '[WebhookDeliveryWorker] Error processing pending webhook deliveries:',
          pollErr.message
        );
      }
    } finally {
      isCycleRunning = false;
      activeCyclePromise = null;

      if (pendingWakeup && isRunning) {
        pendingWakeup = false;
        scheduleImmediateWakeup();
      } else {
        pendingWakeup = false;
      }
    }

    return {
      skipped: false,
      missingReconciliation,
      staleReconciliation,
      processed,
      deliveredCount,
      retriedCount,
      failedCount,
      errors
    };
  };

  activeCyclePromise = executeCycle();
  return activeCyclePromise;
}

/**
 * Starts the background webhook delivery worker:
 * - Attaches eventBus listeners (`pipeline:event_processed`, `policy:decision_recorded`).
 * - Runs an immediate startup reconciliation + delivery cycle (unless `runOnStart === false`).
 * - Starts an unreferenced periodic polling interval.
 *
 * Idempotent: calling `startWebhookDeliveryWorker` while already running is a safe no-op.
 *
 * @param {object} [options={}]
 * @param {number} [options.pollIntervalMs=DEFAULT_POLL_INTERVAL_MS]
 * @param {number} [options.reconcileIntervalMs=DEFAULT_RECONCILE_INTERVAL_MS]
 * @param {boolean} [options.runOnStart=true]
 * @returns {{ isRunning: boolean }}
 */
function startWebhookDeliveryWorker(options = {}) {
  if (isRunning) {
    return { isRunning: true };
  }

  const envPollInterval = Number.parseInt(
    process.env.WEBHOOK_WORKER_POLL_INTERVAL_MS || '',
    10
  );
  const pollIntervalMs =
    typeof options.pollIntervalMs === 'number' && options.pollIntervalMs >= 20
      ? Math.floor(options.pollIntervalMs)
      : Number.isFinite(envPollInterval) && envPollInterval >= 20
      ? envPollInterval
      : DEFAULT_POLL_INTERVAL_MS;

  workerOptions = { ...options };
  isRunning = true;
  lastMissingReconcileAtMs = 0;

  attachWebhookEventListeners({
    onEnqueued: () => {
      scheduleImmediateWakeup();
    }
  });

  if (options.runOnStart !== false) {
    runWebhookWorkerCycle({
      ...workerOptions,
      forceReconcile: true
    }).catch((err) => {
      console.error(
        '[WebhookDeliveryWorker] Startup cycle failed:',
        err.message
      );
    });
  }

  pollIntervalId = setInterval(() => {
    if (!isRunning) {
      return;
    }
    runWebhookWorkerCycle(workerOptions).catch((err) => {
      console.error(
        '[WebhookDeliveryWorker] Scheduled cycle error:',
        err.message
      );
    });
  }, pollIntervalMs);

  if (typeof pollIntervalId.unref === 'function') {
    pollIntervalId.unref();
  }

  return { isRunning: true };
}

/**
 * Stops the background webhook delivery worker, detaches eventBus listeners,
 * clears all timers, and awaits any in-flight enqueue or delivery cycle work.
 *
 * @returns {Promise<void>}
 */
async function stopWebhookDeliveryWorker() {
  isRunning = false;
  pendingWakeup = false;

  detachWebhookEventListeners();

  if (wakeupTimerId) {
    clearTimeout(wakeupTimerId);
    wakeupTimerId = null;
  }

  if (pollIntervalId) {
    clearInterval(pollIntervalId);
    pollIntervalId = null;
  }

  await flushInFlightWebhookEnqueues();

  if (activeCyclePromise) {
    try {
      await activeCyclePromise;
    } catch {
      // Errors are already logged inside runWebhookWorkerCycle
    }
  }
}

/**
 * Returns whether the background webhook delivery worker is currently active.
 *
 * @returns {boolean}
 */
function isWebhookDeliveryWorkerRunning() {
  return isRunning;
}

module.exports = {
  DEFAULT_POLL_INTERVAL_MS,
  DEFAULT_RECONCILE_INTERVAL_MS,
  attachWebhookEventListeners,
  detachWebhookEventListeners,
  flushInFlightWebhookEnqueues,
  runWebhookWorkerCycle,
  startWebhookDeliveryWorker,
  stopWebhookDeliveryWorker,
  isWebhookDeliveryWorkerRunning
};
