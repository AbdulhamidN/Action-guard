'use strict';

const path = require('node:path');
const { spawn } = require('node:child_process');
const {
  startWebhookDeliveryWorker,
  stopWebhookDeliveryWorker,
  isWebhookDeliveryWorkerRunning
} = require('../src/jobs/webhookDeliveryWorker');

/**
 * Polls an async predicate until truthy or timeout.
 */
async function waitForCondition(predicate, timeoutMs = 4000, intervalMs = 25) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() <= deadline) {
    try {
      const result = await predicate();
      if (result) {
        return result;
      }
    } catch (err) {
      lastError = err;
    }
    await new Promise((resolve) => {
      const timer = setTimeout(resolve, intervalMs);
      if (typeof timer.unref === 'function') {
        timer.unref();
      }
    });
  }
  if (lastError) {
    throw lastError;
  }
  throw new Error(`Condition not met within ${timeoutMs}ms`);
}

describe('Module 11.2c — Webhook Delivery Worker Startup Integration Regression', () => {
  afterEach(async () => {
    await stopWebhookDeliveryWorker();
  });

  test('T11-STARTUP-01: startWebhookDeliveryWorker returns synchronous state object and is not a Promise', () => {
    const result = startWebhookDeliveryWorker({
      runOnStart: false,
      pollIntervalMs: 5000
    });

    // Contract verification
    expect(result).toBeDefined();
    expect(typeof result).toBe('object');
    expect(result.isRunning).toBe(true);
    expect(typeof result.then).toBe('undefined'); // Confirms non-thenable / not a Promise
    expect(isWebhookDeliveryWorkerRunning()).toBe(true);
  });

  test('T11-STARTUP-02: Application startup initiates webhook delivery worker synchronously without Promise (.then) TypeError', async () => {
    const indexPath = path.resolve(__dirname, '../src/index.js');

    const env = {
      ...process.env,
      PORT: '0', // Ephemeral port assigned by OS
      BASELINE_RECALCULATION_AUTO_START: 'false',
      COOLING_OFF_WORKER_AUTO_START: 'false',
      WEBHOOK_WORKER_AUTO_START: 'true'
    };

    let stdoutData = '';
    let stderrData = '';
    let processExitedEarly = false;
    let exitCode = null;

    const child = spawn(process.execPath, [indexPath], {
      env,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    child.stdout.on('data', (chunk) => {
      stdoutData += chunk.toString('utf8');
    });

    child.stderr.on('data', (chunk) => {
      stderrData += chunk.toString('utf8');
    });

    child.on('exit', (code) => {
      processExitedEarly = true;
      exitCode = code;
    });

    try {
      // Wait for server to bind and startup scheduler to initialize worker
      await waitForCondition(() => {
        return (
          stdoutData.includes('[Scheduler] Webhook delivery worker started.') ||
          processExitedEarly
        );
      }, 5000);

      // Verify that startup succeeded and did not crash with Promise .then TypeError
      expect(processExitedEarly).toBe(false);
      expect(stdoutData).toContain('ActionGuard server running on port');
      expect(stdoutData).toContain('[Scheduler] Webhook delivery worker started.');
      expect(stderrData).not.toContain('startWebhookDeliveryWorker(...).then is not a function');
      expect(stderrData).not.toContain('TypeError');
    } finally {
      // Clean teardown: terminate child process
      if (!processExitedEarly) {
        child.kill('SIGTERM');
        await waitForCondition(() => processExitedEarly, 3000).catch(() => {
          child.kill('SIGKILL');
        });
      }
    }
  });
});
