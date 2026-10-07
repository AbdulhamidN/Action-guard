const bcrypt = require('bcrypt');
const cron = require('node-cron');
const {
  sequelize,
  User,
  Session,
  Device,
  SecurityEvent,
  BehavioralBaseline
} = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const {
  runBaselineRecalculation,
  isRecalculationRunning,
  startBaselineRecalculationSchedule,
  stopBaselineRecalculationSchedule,
  getScheduledTask
} = require('../src/jobs/baselineRecalculationJob');
const baselineService = require('../src/services/baselineService');

describe('Sub-module 4.3 — Scheduled Baseline Recalculation Job', () => {
  let user1;
  let user2;
  let user3;

  beforeAll(async () => {
    await runMigrations();

    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await BehavioralBaseline.destroy({ where: {}, force: true });
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    const passwordHash = await bcrypt.hash('Password123!', 10);

    // Create 3 distinct users
    user1 = await User.create({
      email: 'cron-user1@example.com',
      password_hash: passwordHash
    });

    user2 = await User.create({
      email: 'cron-user2@example.com',
      password_hash: passwordHash
    });

    user3 = await User.create({
      email: 'cron-user3@example.com',
      password_hash: passwordHash
    });

    // Seed events for user1 (5 logins: 09:00 UTC, US, dev1)
    const baseDate = new Date('2026-05-01T09:00:00Z');
    for (let i = 0; i < 5; i++) {
      const ts = new Date(baseDate.getTime() + i * 86400000);
      await SecurityEvent.create({
        user_id: user1.id,
        event_type: 'login_success',
        timestamp: ts,
        context: {
          ip_address: '1.2.3.4',
          geo_country: 'US',
          device_fingerprint: 'fp_dev_user1'
        }
      });
    }

    // Seed events for user2 (2 logins: below baseline min threshold)
    for (let i = 0; i < 2; i++) {
      const ts = new Date(baseDate.getTime() + i * 86400000);
      await SecurityEvent.create({
        user_id: user2.id,
        event_type: 'login_success',
        timestamp: ts,
        context: {
          ip_address: '5.6.7.8',
          geo_country: 'GB',
          device_fingerprint: 'fp_dev_user2'
        }
      });
    }
    // user3 has 0 events (cold start)
  });

  afterAll(async () => {
    stopBaselineRecalculationSchedule();
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await BehavioralBaseline.destroy({ where: {}, force: true });
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');
  });

  afterEach(() => {
    stopBaselineRecalculationSchedule();
    jest.restoreAllMocks();
  });

  describe('1. Sequential Recalculation Execution', () => {
    test('recalculates all users sequentially and synchronizes with SecurityEvent data', async () => {
      const buildUserBaselineSpy = jest.spyOn(baselineService, 'buildUserBaseline');

      const summary = await runBaselineRecalculation();

      expect(summary.skipped).toBe(false);
      expect(summary.totalUsers).toBe(3);
      expect(summary.processed).toBe(3);
      expect(summary.succeeded).toBe(3);
      expect(summary.failed).toBe(0);
      expect(summary.errors).toHaveLength(0);

      // Verify buildUserBaseline was invoked sequentially for each user in order
      expect(buildUserBaselineSpy).toHaveBeenCalledTimes(3);
      const calledUserIds = buildUserBaselineSpy.mock.calls.map((call) => call[0]);
      // Users ordered deterministically by ID ASC
      const expectedIds = [user1.id, user2.id, user3.id].sort();
      expect(calledUserIds).toEqual(expectedIds);

      // Verify user1 baseline persisted
      const b1 = await BehavioralBaseline.findOne({ where: { user_id: user1.id } });
      expect(b1).not.toBeNull();
      expect(b1.total_logins).toBe(5);
      expect(b1.has_sufficient_history).toBe(true);
      expect(b1.login_hours.mean_hour).toBe(9);
      expect(b1.typical_devices.some((d) => d.fingerprint === 'fp_dev_user1')).toBe(true);
      expect(b1.typical_countries.some((c) => c.country === 'US')).toBe(true);

      // Verify user2 baseline persisted
      const b2 = await BehavioralBaseline.findOne({ where: { user_id: user2.id } });
      expect(b2).not.toBeNull();
      expect(b2.total_logins).toBe(2);
      expect(b2.has_sufficient_history).toBe(false);
      expect(b2.typical_devices.some((d) => d.fingerprint === 'fp_dev_user2')).toBe(true);
      expect(b2.typical_countries.some((c) => c.country === 'GB')).toBe(true);

      // Verify user3 baseline persisted
      const b3 = await BehavioralBaseline.findOne({ where: { user_id: user3.id } });
      expect(b3).not.toBeNull();
      expect(b3.total_logins).toBe(0);
      expect(b3.has_sufficient_history).toBe(false);
    });

    test('is strictly idempotent on subsequent recalculation runs', async () => {
      const summary1 = await runBaselineRecalculation();
      expect(summary1.succeeded).toBe(3);

      const b1First = await BehavioralBaseline.findOne({ where: { user_id: user1.id } });

      const summary2 = await runBaselineRecalculation();
      expect(summary2.succeeded).toBe(3);

      const b1Second = await BehavioralBaseline.findOne({ where: { user_id: user1.id } });
      expect(b1Second.total_logins).toBe(b1First.total_logins);
      expect(b1Second.login_hours.mean_hour).toBe(b1First.login_hours.mean_hour);
      expect(b1Second.typical_devices).toEqual(b1First.typical_devices);
    });
  });

  describe('2. Failure Isolation Between Users', () => {
    test('continues processing remaining users when one user baseline calculation throws', async () => {
      const originalBuild = baselineService.buildUserBaseline;
      const sortedIds = [user1.id, user2.id, user3.id].sort();
      const failingUserId = sortedIds[1]; // Fail middle user

      jest.spyOn(baselineService, 'buildUserBaseline').mockImplementation(async (uid, opts) => {
        if (uid === failingUserId) {
          throw new Error(`Simulated database failure for ${uid}`);
        }
        return originalBuild(uid, opts);
      });

      const summary = await runBaselineRecalculation();

      expect(summary.totalUsers).toBe(3);
      expect(summary.processed).toBe(3);
      expect(summary.succeeded).toBe(2);
      expect(summary.failed).toBe(1);
      expect(summary.errors).toHaveLength(1);
      expect(summary.errors[0].userId).toBe(failingUserId);
      expect(summary.errors[0].message).toContain('Simulated database failure');

      // Verify the other two users succeeded
      const otherUserIds = sortedIds.filter((id) => id !== failingUserId);
      for (const id of otherUserIds) {
        const baseline = await BehavioralBaseline.findOne({ where: { user_id: id } });
        expect(baseline).not.toBeNull();
      }
    });
  });

  describe('3. Overlapping Execution Prevention', () => {
    test('skips execution and logs a warning if a previous recalculation is still in progress', async () => {
      let resolveFirstRun;
      const holdPromise = new Promise((resolve) => {
        resolveFirstRun = resolve;
      });

      const originalBuild = baselineService.buildUserBaseline;
      jest.spyOn(baselineService, 'buildUserBaseline').mockImplementation(async (uid, opts) => {
        await holdPromise;
        return originalBuild(uid, opts);
      });

      // Start first recalculation in background
      const firstRunPromise = runBaselineRecalculation();

      expect(isRecalculationRunning()).toBe(true);

      // Attempt second overlapping recalculation
      const secondRunResult = await runBaselineRecalculation();

      expect(secondRunResult.skipped).toBe(true);
      expect(secondRunResult.reason).toBe('already_running');

      // Release first run
      resolveFirstRun();
      const firstRunResult = await firstRunPromise;

      expect(firstRunResult.skipped).toBe(false);
      expect(isRecalculationRunning()).toBe(false);
    });
  });

  describe('4. Schedule Lifecycle & Configuration', () => {
    test('starts and stops cron schedule cleanly', () => {
      expect(getScheduledTask()).toBeNull();

      const task = startBaselineRecalculationSchedule({
        schedule: '0 2 * * *',
        timezone: 'UTC'
      });

      expect(task).not.toBeNull();
      expect(getScheduledTask()).toBe(task);

      // Calling start again returns existing task without duplicate creation
      const secondCallTask = startBaselineRecalculationSchedule();
      expect(secondCallTask).toBe(task);

      // Stopping cancels task
      stopBaselineRecalculationSchedule();
      expect(getScheduledTask()).toBeNull();
    });

    test('schedule triggers runBaselineRecalculation handler', async () => {
      let scheduledCallback = null;
      jest.spyOn(cron, 'schedule').mockImplementation((pattern, fn, opts) => {
        scheduledCallback = fn;
        return {
          start: jest.fn(),
          stop: jest.fn()
        };
      });

      startBaselineRecalculationSchedule({ schedule: '0 2 * * *' });
      expect(typeof scheduledCallback).toBe('function');

      // Trigger the scheduled callback
      await scheduledCallback();

      // Verify baselines are recalculated
      const b1 = await BehavioralBaseline.findOne({ where: { user_id: user1.id } });
      expect(b1).not.toBeNull();
      expect(b1.total_logins).toBe(5);
    });
  });
});
