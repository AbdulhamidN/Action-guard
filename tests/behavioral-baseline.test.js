const bcrypt = require('bcrypt');
const {
  sequelize,
  User,
  Session,
  Device,
  SecurityEvent,
  BehavioralBaseline
} = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const migration003 = require('../src/database/migrations/003_behavioral_baselines');
const {
  getBaselineMinLogins,
  calculateCircularHourStats,
  calculateTypicalDevices,
  calculateTypicalCountries,
  roundToTwoDecimals,
  roundToFourDecimals
} = require('../src/utils/baseline');
const {
  buildUserBaseline,
  getUserBaseline
} = require('../src/services/baselineService');

describe('Sub-module 4.1 — Per-User Baseline Builder', () => {
  let userA;
  let userB;
  let userCold;

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

    userA = await User.create({
      email: 'user-a-baseline@example.com',
      password_hash: passwordHash
    });

    userB = await User.create({
      email: 'user-b-baseline@example.com',
      password_hash: passwordHash
    });

    userCold = await User.create({
      email: 'user-cold-baseline@example.com',
      password_hash: passwordHash
    });
  });

  afterAll(async () => {
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await BehavioralBaseline.destroy({ where: {}, force: true });
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');
  });

  describe('1. Configuration & Validation (BASELINE_MIN_LOGINS)', () => {
    const originalEnv = process.env.BASELINE_MIN_LOGINS;

    afterEach(() => {
      if (originalEnv !== undefined) {
        process.env.BASELINE_MIN_LOGINS = originalEnv;
      } else {
        delete process.env.BASELINE_MIN_LOGINS;
      }
    });

    test('returns 5 by default when missing from env and options', () => {
      delete process.env.BASELINE_MIN_LOGINS;
      expect(getBaselineMinLogins()).toBe(5);
      expect(getBaselineMinLogins({})).toBe(5);
    });

    test('uses valid positive integer from options', () => {
      expect(getBaselineMinLogins({ minLogins: 10 })).toBe(10);
      expect(getBaselineMinLogins({ minLogins: 1 })).toBe(1);
    });

    test('uses valid positive integer from environment variable', () => {
      process.env.BASELINE_MIN_LOGINS = '8';
      expect(getBaselineMinLogins()).toBe(8);
    });

    test('gracefully falls back to 5 for non-positive or invalid environment values', () => {
      const invalidValues = ['0', '-1', '-10', 'abc', 'NaN', 'false', '', '  '];
      for (const val of invalidValues) {
        process.env.BASELINE_MIN_LOGINS = val;
        expect(getBaselineMinLogins()).toBe(5);
      }
    });

    test('gracefully falls back to 5 for invalid options values', () => {
      expect(getBaselineMinLogins({ minLogins: 0 })).toBe(5);
      expect(getBaselineMinLogins({ minLogins: -3 })).toBe(5);
      expect(getBaselineMinLogins({ minLogins: '7' })).toBe(5);
      expect(getBaselineMinLogins({ minLogins: null })).toBe(5);
    });
  });

  describe('2. Circular Time-of-Day Calculation & Edge Cases', () => {
    test('accurately calculates day boundary wrap-around (23:55 and 00:05)', () => {
      // 23:55 UTC (23.9167h) and 00:05 UTC (0.0833h) on consecutive or same dates
      const t1 = new Date('2026-10-01T23:55:00.000Z');
      const t2 = new Date('2026-10-02T00:05:00.000Z');

      const stats = calculateCircularHourStats([t1, t2]);
      expect(stats).not.toBeNull();

      // In circular coordinates, the mean of 23:55 and 00:05 is 00:00 (midnight)
      // Linear averaging would falsely give (23.9167 + 0.0833) / 2 = 12:00 (noon)
      expect(stats.mean_hour).toBeCloseTo(0.0, 1);
      expect(stats.resultant_vector_r).toBeGreaterThan(0.99); // tightly clustered
      expect(stats.circular_std_dev_hours).toBeLessThan(0.5);

      // Hourly distribution shows one login at hour 23 and one at hour 0
      expect(stats.hourly_distribution[23]).toBe(1);
      expect(stats.hourly_distribution[0]).toBe(1);
      expect(stats.hourly_distribution[12]).toBe(0);
    });

    test('handles identical timestamps (R >= 1.0) with zero dispersion', () => {
      const t1 = new Date('2026-10-01T14:30:00.000Z');
      const t2 = new Date('2026-10-02T14:30:00.000Z');

      const stats = calculateCircularHourStats([t1, t2]);
      expect(stats).not.toBeNull();
      expect(stats.mean_hour).toBe(14.5);
      expect(stats.circular_std_dev_hours).toBe(0);
      expect(stats.resultant_vector_r).toBe(1);
      expect(stats.hourly_distribution[14]).toBe(2);
    });

    test('handles diametrically opposed timestamps safely without NaN or Infinity', () => {
      // 06:00 UTC and 18:00 UTC are exactly 12 hours apart on opposite sides of 24h clock
      const t1 = new Date('2026-10-01T06:00:00.000Z');
      const t2 = new Date('2026-10-01T18:00:00.000Z');

      const stats = calculateCircularHourStats([t1, t2]);
      expect(stats).not.toBeNull();
      // Direction cancels out: mean_hour and circular_std_dev_hours are undefined (null)
      expect(stats.mean_hour).toBeNull();
      expect(stats.circular_std_dev_hours).toBeNull();
      expect(stats.resultant_vector_r).toBe(0);
      // Hourly distribution is strictly preserved
      expect(stats.hourly_distribution[6]).toBe(1);
      expect(stats.hourly_distribution[18]).toBe(1);
    });

    test('returns null for empty or invalid timestamps', () => {
      expect(calculateCircularHourStats([])).toBeNull();
      expect(calculateCircularHourStats(['invalid-date'])).toBeNull();
      expect(calculateCircularHourStats(null)).toBeNull();
    });
  });

  describe('3. Categorical Frequencies & Denominator Isolation', () => {
    test('calculates device frequency using only events with device_fingerprint', () => {
      const events = [
        { timestamp: new Date('2026-10-01T10:00:00Z'), context: { device_fingerprint: 'fp_alpha' } },
        { timestamp: new Date('2026-10-02T11:00:00Z'), context: { device_fingerprint: 'fp_alpha' } },
        { timestamp: new Date('2026-10-03T12:00:00Z'), context: { device_fingerprint: 'fp_beta' } },
        // Two events without device fingerprints (missing or empty)
        { timestamp: new Date('2026-10-04T13:00:00Z'), context: {} },
        { timestamp: new Date('2026-10-05T14:00:00Z'), context: { device_fingerprint: '  ' } }
      ];

      const devices = calculateTypicalDevices(events);
      // Only 3 valid device events: fp_alpha (2/3 = 0.6667), fp_beta (1/3 = 0.3333)
      expect(devices).toHaveLength(2);

      const alpha = devices.find((d) => d.fingerprint === 'fp_alpha');
      expect(alpha).toBeDefined();
      expect(alpha.count).toBe(2);
      expect(alpha.frequency).toBe(0.6667);
      expect(alpha.last_seen_at).toBe(new Date('2026-10-02T11:00:00Z').toISOString());

      const beta = devices.find((d) => d.fingerprint === 'fp_beta');
      expect(beta).toBeDefined();
      expect(beta.count).toBe(1);
      expect(beta.frequency).toBe(0.3333);
      expect(beta.last_seen_at).toBe(new Date('2026-10-03T12:00:00Z').toISOString());
    });

    test('derives device last_seen_at strictly from latest SecurityEvent timestamp', () => {
      const events = [
        { timestamp: new Date('2026-10-01T08:00:00Z'), context: { device_fingerprint: 'fp_gamma' } },
        { timestamp: new Date('2026-10-04T15:00:00Z'), context: { device_fingerprint: 'fp_gamma' } },
        { timestamp: new Date('2026-10-02T12:00:00Z'), context: { device_fingerprint: 'fp_gamma' } }
      ];

      const devices = calculateTypicalDevices(events);
      expect(devices[0].last_seen_at).toBe(new Date('2026-10-04T15:00:00Z').toISOString());
    });

    test('calculates country frequency using only events with geo_country', () => {
      const events = [
        { timestamp: new Date('2026-10-01T10:00:00Z'), context: { geo_country: 'US' } },
        { timestamp: new Date('2026-10-02T11:00:00Z'), context: { geo_country: 'us' } }, // case normalized
        { timestamp: new Date('2026-10-03T12:00:00Z'), context: { geo_country: 'DE' } },
        // Two events without geo_country
        { timestamp: new Date('2026-10-04T13:00:00Z'), context: {} },
        { timestamp: new Date('2026-10-05T14:00:00Z'), context: { geo_country: '' } }
      ];

      const countries = calculateTypicalCountries(events);
      // Only 3 valid country events: US (2/3 = 0.6667), DE (1/3 = 0.3333)
      expect(countries).toHaveLength(2);

      const us = countries.find((c) => c.country === 'US');
      expect(us).toBeDefined();
      expect(us.count).toBe(2);
      expect(us.frequency).toBe(0.6667);

      const de = countries.find((c) => c.country === 'DE');
      expect(de).toBeDefined();
      expect(de.count).toBe(1);
      expect(de.frequency).toBe(0.3333);
    });

    test('returns empty array when no events contain device or country', () => {
      const events = [
        { timestamp: new Date(), context: {} },
        { timestamp: new Date(), context: { ip_address: '1.2.3.4' } }
      ];
      expect(calculateTypicalDevices(events)).toEqual([]);
      expect(calculateTypicalCountries(events)).toEqual([]);
    });
  });

  describe('4. Cold-Start & History Sufficiency Tiers', () => {
    test('tier 1: zero history (0 logins) creates empty baseline with has_sufficient_history: false', async () => {
      const baseline = await buildUserBaseline(userCold.id);

      expect(baseline).toBeDefined();
      expect(baseline.user_id).toBe(userCold.id);
      expect(baseline.total_logins).toBe(0);
      expect(baseline.has_sufficient_history).toBe(false);
      expect(baseline.login_hours).toBeNull();
      expect(baseline.typical_devices).toEqual([]);
      expect(baseline.typical_countries).toEqual([]);
      expect(baseline.last_calculated_at).toBeInstanceOf(Date);
    });

    test('tier 2: sparse history (1-4 logins) calculates metrics but has_sufficient_history: false', async () => {
      // Seed 3 logins for userB
      await SecurityEvent.bulkCreate([
        {
          user_id: userB.id,
          event_type: 'login_success',
          timestamp: new Date('2026-10-01T09:00:00Z'),
          context: { device_fingerprint: 'fp_sparse_1', geo_country: 'US' }
        },
        {
          user_id: userB.id,
          event_type: 'login_success',
          timestamp: new Date('2026-10-02T09:30:00Z'),
          context: { device_fingerprint: 'fp_sparse_1', geo_country: 'US' }
        },
        {
          user_id: userB.id,
          event_type: 'login_success',
          timestamp: new Date('2026-10-03T10:00:00Z'),
          context: { device_fingerprint: 'fp_sparse_2', geo_country: 'GB' }
        }
      ]);

      const baseline = await buildUserBaseline(userB.id, { minLogins: 5 });

      expect(baseline.total_logins).toBe(3);
      expect(baseline.has_sufficient_history).toBe(false);
      expect(baseline.login_hours).not.toBeNull();
      expect(baseline.login_hours.mean_hour).toBeCloseTo(9.5, 1);
      expect(baseline.typical_devices).toHaveLength(2);
      expect(baseline.typical_countries).toHaveLength(2);
      expect(baseline.last_calculated_at).toBeInstanceOf(Date);
    });

    test('tier 3: established history (5+ logins) sets has_sufficient_history: true', async () => {
      // Seed 5 logins for userA
      const seedEvents = [
        {
          user_id: userA.id,
          event_type: 'login_success',
          timestamp: new Date('2026-10-01T14:00:00Z'),
          context: { device_fingerprint: 'fp_user_a_main', geo_country: 'FR' }
        },
        {
          user_id: userA.id,
          event_type: 'login_success',
          timestamp: new Date('2026-10-02T14:15:00Z'),
          context: { device_fingerprint: 'fp_user_a_main', geo_country: 'FR' }
        },
        {
          user_id: userA.id,
          event_type: 'login_success',
          timestamp: new Date('2026-10-03T14:30:00Z'),
          context: { device_fingerprint: 'fp_user_a_main', geo_country: 'FR' }
        },
        {
          user_id: userA.id,
          event_type: 'login_success',
          timestamp: new Date('2026-10-04T14:45:00Z'),
          context: { device_fingerprint: 'fp_user_a_alt', geo_country: 'FR' }
        },
        {
          user_id: userA.id,
          event_type: 'login_success',
          timestamp: new Date('2026-10-05T15:00:00Z'),
          context: { device_fingerprint: 'fp_user_a_alt', geo_country: 'DE' }
        }
      ];

      await SecurityEvent.bulkCreate(seedEvents);

      const baseline = await buildUserBaseline(userA.id, { minLogins: 5 });

      expect(baseline.total_logins).toBe(5);
      expect(baseline.has_sufficient_history).toBe(true);
      expect(baseline.login_hours.mean_hour).toBeCloseTo(14.5, 1);
      expect(baseline.typical_devices[0].fingerprint).toBe('fp_user_a_main');
      expect(baseline.typical_devices[0].count).toBe(3);
      expect(baseline.typical_devices[0].frequency).toBe(0.6);
      expect(baseline.typical_countries[0].country).toBe('FR');
      expect(baseline.typical_countries[0].count).toBe(4);
      expect(baseline.typical_countries[0].frequency).toBe(0.8);
    });
  });

  describe('5. Idempotent Recalculation', () => {
    test('repeated recalculation on unchanged events preserves exact behavioral metrics', async () => {
      // First baseline build for userA
      const firstRun = await buildUserBaseline(userA.id);
      const firstMetrics = {
        total_logins: firstRun.total_logins,
        has_sufficient_history: firstRun.has_sufficient_history,
        login_hours: firstRun.login_hours,
        typical_devices: firstRun.typical_devices,
        typical_countries: firstRun.typical_countries
      };
      const firstCalculationTime = new Date(firstRun.last_calculated_at).getTime();

      // Wait a slight tick to allow last_calculated_at timestamp to advance
      await new Promise((resolve) => setTimeout(resolve, 50));

      // Second baseline build with unchanged events
      const secondRun = await buildUserBaseline(userA.id);

      // Behavioral metrics must remain identical (no double-counting or delta accumulation)
      expect(secondRun.total_logins).toBe(firstMetrics.total_logins);
      expect(secondRun.has_sufficient_history).toBe(firstMetrics.has_sufficient_history);
      expect(secondRun.typical_devices).toEqual(firstMetrics.typical_devices);
      expect(secondRun.typical_countries).toEqual(firstMetrics.typical_countries);
      expect(secondRun.login_hours).toEqual(firstMetrics.login_hours);

      // last_calculated_at updates to reflect recalculation time
      expect(new Date(secondRun.last_calculated_at).getTime()).toBeGreaterThanOrEqual(firstCalculationTime);
    });

    test('recalculation after adding new events correctly updates counts and metrics', async () => {
      // Add 2 new events for userA
      await SecurityEvent.bulkCreate([
        {
          user_id: userA.id,
          event_type: 'login_success',
          timestamp: new Date('2026-10-06T15:15:00Z'),
          context: { device_fingerprint: 'fp_user_a_main', geo_country: 'FR' }
        },
        {
          user_id: userA.id,
          event_type: 'login_success',
          timestamp: new Date('2026-10-07T15:30:00Z'),
          context: { device_fingerprint: 'fp_user_a_main', geo_country: 'FR' }
        }
      ]);

      const updatedBaseline = await buildUserBaseline(userA.id);
      expect(updatedBaseline.total_logins).toBe(7); // 5 + 2 = 7
      expect(updatedBaseline.typical_devices[0].count).toBe(5); // 3 + 2 = 5
      expect(updatedBaseline.typical_devices[0].frequency).toBe(roundToFourDecimals(5 / 7));
    });
  });

  describe('6. Multi-User Isolation', () => {
    test('user baseline is derived strictly from that user and never mixes across users', async () => {
      const baselineA = await getUserBaseline(userA.id);
      const baselineB = await getUserBaseline(userB.id);

      expect(baselineA.total_logins).toBe(7);
      expect(baselineB.total_logins).toBe(3);

      const devicesA = baselineA.typical_devices.map((d) => d.fingerprint);
      const devicesB = baselineB.typical_devices.map((d) => d.fingerprint);

      // Verify no device crossover
      expect(devicesA).toContain('fp_user_a_main');
      expect(devicesA).not.toContain('fp_sparse_1');

      expect(devicesB).toContain('fp_sparse_1');
      expect(devicesB).not.toContain('fp_user_a_main');
    });

    test('non-login events do not affect the baseline calculation', async () => {
      // Add password_change and login_failed for userB
      await SecurityEvent.bulkCreate([
        {
          user_id: userB.id,
          event_type: 'login_failed',
          timestamp: new Date(),
          context: { device_fingerprint: 'fp_attacker' }
        },
        {
          user_id: userB.id,
          event_type: 'password_change',
          timestamp: new Date(),
          context: { device_fingerprint: 'fp_sparse_1' }
        }
      ]);

      const baselineB = await buildUserBaseline(userB.id);
      // Still 3 logins; non-login events must not be counted
      expect(baselineB.total_logins).toBe(3);
    });
  });

  describe('7. Data Model Associations & Migration Safety', () => {
    test('1-to-1 User <-> BehavioralBaseline relationship functions correctly', async () => {
      const fetchedUser = await User.findByPk(userA.id, {
        include: [{ model: BehavioralBaseline, as: 'baseline' }]
      });

      expect(fetchedUser).not.toBeNull();
      expect(fetchedUser.baseline).not.toBeNull();
      expect(fetchedUser.baseline.user_id).toBe(userA.id);

      const fetchedBaseline = await BehavioralBaseline.findOne({
        where: { user_id: userA.id },
        include: [{ model: User, as: 'user' }]
      });

      expect(fetchedBaseline).not.toBeNull();
      expect(fetchedBaseline.user).not.toBeNull();
      expect(fetchedBaseline.user.id).toBe(userA.id);
    });

    test('cascades deletion of BehavioralBaseline when User is deleted', async () => {
      const tempUser = await User.create({
        email: 'temp-user-baseline@example.com',
        password_hash: await bcrypt.hash('Password123!', 10)
      });

      await buildUserBaseline(tempUser.id);
      let baseline = await getUserBaseline(tempUser.id);
      expect(baseline).not.toBeNull();

      // Delete user
      await tempUser.destroy();

      baseline = await getUserBaseline(tempUser.id);
      expect(baseline).toBeNull();
    });

    test('migration 003 tracks composite index state and rolls back safely', async () => {
      expect(typeof migration003.wasCompositeIndexCreated).toBe('function');
      expect(typeof migration003.resetCompositeIndexState).toBe('function');

      const queryInterface = sequelize.getQueryInterface();
      const existingIndexes = await queryInterface.showIndex('security_events');
      const hasCompositeIndex = existingIndexes.some(
        (idx) => idx.name === 'idx_security_events_user_type_time'
      );
      expect(hasCompositeIndex).toBe(true);
    });
  });
});
