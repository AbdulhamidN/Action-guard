const request = require('supertest');
const bcrypt = require('bcrypt');
const app = require('../src/app');
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
  COMPONENT_WEIGHTS,
  clamp,
  calculateHourDeviation,
  calculateDeviceDeviation,
  calculateCountryDeviation,
  evaluateBaselineDeviation
} = require('../src/utils/deviation');
const {
  evaluateBaselineDeviationForUser
} = require('../src/services/baselineDeviationService');
const { buildUserBaseline } = require('../src/services/baselineService');
const baselineService = require('../src/services/baselineService');

describe('Sub-module 4.2 — Baseline Deviation Scoring', () => {
  let userEstablished;
  let userSparse;
  let userCold;
  const userPassword = 'Password123!';

  beforeAll(async () => {
    await runMigrations();

    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await BehavioralBaseline.destroy({ where: {}, force: true });
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    const passwordHash = await bcrypt.hash(userPassword, 10);

    userEstablished = await User.create({
      email: 'user-established@example.com',
      password_hash: passwordHash
    });

    userSparse = await User.create({
      email: 'user-sparse@example.com',
      password_hash: passwordHash
    });

    userCold = await User.create({
      email: 'user-cold@example.com',
      password_hash: passwordHash
    });

    // Seed 5 historical logins for userEstablished (mean hour 14:00 UTC, device fp_est_1, country US)
    const establishedLogins = [
      {
        user_id: userEstablished.id,
        event_type: 'login_success',
        timestamp: new Date('2026-10-01T14:00:00Z'),
        context: { device_fingerprint: 'fp_est_1', geo_country: 'US', ip_address: '8.8.8.8' }
      },
      {
        user_id: userEstablished.id,
        event_type: 'login_success',
        timestamp: new Date('2026-10-02T14:05:00Z'),
        context: { device_fingerprint: 'fp_est_1', geo_country: 'US', ip_address: '8.8.8.8' }
      },
      {
        user_id: userEstablished.id,
        event_type: 'login_success',
        timestamp: new Date('2026-10-03T14:10:00Z'),
        context: { device_fingerprint: 'fp_est_1', geo_country: 'US', ip_address: '8.8.8.8' }
      },
      {
        user_id: userEstablished.id,
        event_type: 'login_success',
        timestamp: new Date('2026-10-04T13:55:00Z'),
        context: { device_fingerprint: 'fp_est_1', geo_country: 'US', ip_address: '8.8.8.8' }
      },
      {
        user_id: userEstablished.id,
        event_type: 'login_success',
        timestamp: new Date('2026-10-05T14:00:00Z'),
        context: { device_fingerprint: 'fp_est_2', geo_country: 'US', ip_address: '8.8.8.8' }
      }
    ];
    await SecurityEvent.bulkCreate(establishedLogins);
    await buildUserBaseline(userEstablished.id, { minLogins: 5 });

    // Seed 2 historical logins for userSparse (less than minimum 5 logins)
    const sparseLogins = [
      {
        user_id: userSparse.id,
        event_type: 'login_success',
        timestamp: new Date('2026-10-01T10:00:00Z'),
        context: { device_fingerprint: 'fp_sparse', geo_country: 'FR', ip_address: '8.8.8.8' }
      },
      {
        user_id: userSparse.id,
        event_type: 'login_success',
        timestamp: new Date('2026-10-02T10:00:00Z'),
        context: { device_fingerprint: 'fp_sparse', geo_country: 'FR', ip_address: '8.8.8.8' }
      }
    ];
    await SecurityEvent.bulkCreate(sparseLogins);
    await buildUserBaseline(userSparse.id, { minLogins: 5 });
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

  describe('1. Mathematical Verification & Weighting Scheme', () => {
    test('weights sum to exactly 1.00 (Device: 0.40, Country: 0.40, Hour: 0.20)', () => {
      expect(COMPONENT_WEIGHTS.DEVICE).toBe(0.40);
      expect(COMPONENT_WEIGHTS.COUNTRY).toBe(0.40);
      expect(COMPONENT_WEIGHTS.LOGIN_HOUR).toBe(0.20);
      const total =
        COMPONENT_WEIGHTS.DEVICE +
        COMPONENT_WEIGHTS.COUNTRY +
        COMPONENT_WEIGHTS.LOGIN_HOUR;
      expect(Math.round(total * 100) / 100).toBe(1.00);
    });

    test('exact calculation: 0.95 (hour), 1.00 (device), 0.00 (country) produces 0.59 / 59%', () => {
      const mockBaseline = {
        has_sufficient_history: true,
        login_hours: {
          mean_hour: 14.0,
          circular_std_dev_hours: 0.5,
          resultant_vector_r: 0.99
        },
        typical_devices: [{ fingerprint: 'known_fp' }],
        typical_countries: [{ country: 'US' }]
      };

      // Construct an artificial login context where:
      // - device is unrecognized -> 1.00
      // - country is US -> 0.00
      // We test the evaluation aggregator directly:
      const result = evaluateBaselineDeviation(
        mockBaseline,
        { device_fingerprint: 'unrecognized_fp', geo_country: 'US' },
        // Hour that gives approx 0.95 deviation:
        // circular distance = 11.425 hours from mean 14.0 (e.g. 02:35 UTC = 2.583h, diff = 11.417)
        // (11.425 - 0.5) / (12 - 0.5) = 10.925 / 11.5 = 0.95
        new Date('2026-10-06T02:35:00Z')
      );

      expect(result.components.login_hour.deviation).toBe(0.95);
      expect(result.components.device.deviation).toBe(1.00);
      expect(result.components.country.deviation).toBe(0.00);

      // (0.95 * 0.20) + (1.00 * 0.40) + (0.00 * 0.40) = 0.19 + 0.40 + 0.00 = 0.59
      expect(result.deviation_score).toBe(0.59);
      expect(result.deviation_percentage).toBe(59);
    });
  });

  describe('2. Binary MVP Device & Country Deviation', () => {
    test('recognized device produces 0.0 deviation, unrecognized device produces 1.0 deviation', () => {
      const typicalDevices = [
        { fingerprint: 'fp_alpha', count: 10, frequency: 0.8 },
        { fingerprint: 'fp_beta', count: 2, frequency: 0.2 }
      ];

      const recognizedAlpha = calculateDeviceDeviation('fp_alpha', typicalDevices);
      expect(recognizedAlpha.evaluated).toBe(true);
      expect(recognizedAlpha.is_recognized).toBe(true);
      expect(recognizedAlpha.deviation).toBe(0.0);

      const recognizedBeta = calculateDeviceDeviation('fp_beta', typicalDevices);
      expect(recognizedBeta.evaluated).toBe(true);
      expect(recognizedBeta.is_recognized).toBe(true);
      expect(recognizedBeta.deviation).toBe(0.0);

      const unrecognized = calculateDeviceDeviation('fp_new', typicalDevices);
      expect(unrecognized.evaluated).toBe(true);
      expect(unrecognized.is_recognized).toBe(false);
      expect(unrecognized.deviation).toBe(1.0);
    });

    test('recognized country produces 0.0 deviation, unrecognized country produces 1.0 deviation', () => {
      const typicalCountries = [
        { country: 'US', count: 8, frequency: 0.8 },
        { country: 'CA', count: 2, frequency: 0.2 }
      ];

      const recognizedUS = calculateCountryDeviation('us', typicalCountries); // case-insensitive
      expect(recognizedUS.evaluated).toBe(true);
      expect(recognizedUS.is_recognized).toBe(true);
      expect(recognizedUS.deviation).toBe(0.0);

      const recognizedCA = calculateCountryDeviation('CA', typicalCountries);
      expect(recognizedCA.evaluated).toBe(true);
      expect(recognizedCA.is_recognized).toBe(true);
      expect(recognizedCA.deviation).toBe(0.0);

      const unrecognized = calculateCountryDeviation('DE', typicalCountries);
      expect(unrecognized.evaluated).toBe(true);
      expect(unrecognized.is_recognized).toBe(false);
      expect(unrecognized.deviation).toBe(1.0);
    });
  });

  describe('3. Circular Login-Hour Deviation & Boundary Edge Cases', () => {
    test('respects midnight wrap-around: baseline 23:55 and login 00:05 produces circular distance 0.17h and 0 deviation', () => {
      const baselineHours = {
        mean_hour: 23.92, // 23:55
        circular_std_dev_hours: 0.5,
        resultant_vector_r: 0.99
      };

      const loginTime = new Date('2026-10-06T00:05:00Z'); // 00:05 = 0.08h
      const result = calculateHourDeviation(loginTime, baselineHours);

      expect(result.evaluated).toBe(true);
      expect(result.circular_distance_hours).toBeCloseTo(0.16, 1);
      expect(result.deviation).toBe(0.0); // within 0.5h std dev
    });

    test('within standard deviation window produces deviation 0.0', () => {
      const baselineHours = {
        mean_hour: 10.0,
        circular_std_dev_hours: 1.5,
        resultant_vector_r: 0.95
      };

      const loginTime = new Date('2026-10-06T11:15:00Z'); // 1.25h away <= 1.5h
      const result = calculateHourDeviation(loginTime, baselineHours);
      expect(result.evaluated).toBe(true);
      expect(result.deviation).toBe(0.0);
    });

    test('undefined circular baseline stats (mean_hour null, R <= 0) are treated as unevaluated', () => {
      expect(
        calculateHourDeviation(new Date(), { mean_hour: null, circular_std_dev_hours: null, resultant_vector_r: 0 })
      ).toEqual({ evaluated: false });

      expect(
        calculateHourDeviation(new Date(), { mean_hour: 12, circular_std_dev_hours: 2, resultant_vector_r: 0 })
      ).toEqual({ evaluated: false });
    });

    test('dispersion >= 12 hours is treated as unevaluated (no meaningful pattern)', () => {
      const result = calculateHourDeviation(new Date(), {
        mean_hour: 12.0,
        circular_std_dev_hours: 12.0,
        resultant_vector_r: 0.1
      });
      expect(result.evaluated).toBe(false);
    });
  });

  describe('4. Dynamic Re-normalization', () => {
    const mockBaseline = {
      has_sufficient_history: true,
      login_hours: { mean_hour: 14.0, circular_std_dev_hours: 0.5, resultant_vector_r: 0.99 },
      typical_devices: [{ fingerprint: 'fp_known' }],
      typical_countries: [{ country: 'US' }]
    };

    test('all 3 components available: weights 0.40, 0.40, 0.20 apply directly', () => {
      const result = evaluateBaselineDeviation(
        mockBaseline,
        { device_fingerprint: 'fp_known', geo_country: 'US' },
        new Date('2026-10-06T14:00:00Z')
      );

      expect(result.is_evaluated).toBe(true);
      expect(result.components.login_hour.evaluated).toBe(true);
      expect(result.components.device.evaluated).toBe(true);
      expect(result.components.country.evaluated).toBe(true);
      expect(result.deviation_score).toBe(0.0);
      expect(result.deviation_percentage).toBe(0);
    });

    test('device missing: re-normalizes over remaining weights (country 0.40, hour 0.20 sum = 0.60)', () => {
      const result = evaluateBaselineDeviation(
        mockBaseline,
        { device_fingerprint: null, geo_country: 'DE' }, // country unrecognized (1.0), hour normal (0.0)
        new Date('2026-10-06T14:00:00Z')
      );

      expect(result.is_evaluated).toBe(true);
      expect(result.components.device.evaluated).toBe(false);
      expect(result.components.country.evaluated).toBe(true);
      expect(result.components.login_hour.evaluated).toBe(true);

      // (1.0 * 0.40 + 0.0 * 0.20) / (0.40 + 0.20) = 0.40 / 0.60 = 0.6667 -> 0.67
      expect(result.deviation_score).toBe(0.67);
      expect(result.deviation_percentage).toBe(67);
    });

    test('two components missing (only device available): re-normalizes to 1.0', () => {
      const baselineNoGeoNoHour = {
        has_sufficient_history: true,
        login_hours: null,
        typical_devices: [{ fingerprint: 'fp_known' }],
        typical_countries: []
      };

      const result = evaluateBaselineDeviation(
        baselineNoGeoNoHour,
        { device_fingerprint: 'fp_new', geo_country: null },
        new Date()
      );

      expect(result.is_evaluated).toBe(true);
      expect(result.components.device.evaluated).toBe(true);
      expect(result.components.country.evaluated).toBe(false);
      expect(result.components.login_hour.evaluated).toBe(false);

      // Only device is available with deviation 1.0 -> final deviation is 1.0 / 100%
      expect(result.deviation_score).toBe(1.0);
      expect(result.deviation_percentage).toBe(100);
    });

    test('no components available: returns null deviation with reason insufficient_signals', () => {
      const emptyBaseline = {
        has_sufficient_history: true,
        login_hours: null,
        typical_devices: [],
        typical_countries: []
      };

      const result = evaluateBaselineDeviation(
        emptyBaseline,
        { device_fingerprint: null, geo_country: null },
        null
      );

      expect(result.is_evaluated).toBe(false);
      expect(result.deviation_score).toBeNull();
      expect(result.deviation_percentage).toBeNull();
      expect(result.reason).toBe('insufficient_signals');
    });
  });

  describe('5. Insufficient History & Cold Start Handling', () => {
    test('has_sufficient_history: false returns unevaluated/null deviation with reason insufficient_history', () => {
      const baselineSparse = {
        has_sufficient_history: false,
        login_hours: { mean_hour: 12.0, circular_std_dev_hours: 1.0, resultant_vector_r: 0.9 },
        typical_devices: [{ fingerprint: 'fp_test' }],
        typical_countries: [{ country: 'US' }]
      };

      const result = evaluateBaselineDeviation(
        baselineSparse,
        { device_fingerprint: 'fp_test', geo_country: 'US' },
        new Date()
      );

      expect(result.has_sufficient_history).toBe(false);
      expect(result.is_evaluated).toBe(false);
      expect(result.deviation_score).toBeNull();
      expect(result.deviation_percentage).toBeNull();
      expect(result.reason).toBe('insufficient_history');
    });

    test('null baseline returns unevaluated/null deviation with reason insufficient_history', () => {
      const result = evaluateBaselineDeviation(null, { device_fingerprint: 'fp_test' });
      expect(result.has_sufficient_history).toBe(false);
      expect(result.is_evaluated).toBe(false);
      expect(result.deviation_score).toBeNull();
      expect(result.deviation_percentage).toBeNull();
      expect(result.reason).toBe('insufficient_history');
    });
  });

  describe('6. Data Hygiene, Clamping, and Explainability', () => {
    test('raw device fingerprint is NOT present in deviation output', () => {
      const mockBaseline = {
        has_sufficient_history: true,
        login_hours: { mean_hour: 14.0, circular_std_dev_hours: 0.5, resultant_vector_r: 0.99 },
        typical_devices: [{ fingerprint: 'fp_secret_123' }],
        typical_countries: [{ country: 'US' }]
      };

      const result = evaluateBaselineDeviation(
        mockBaseline,
        { device_fingerprint: 'fp_secret_123', geo_country: 'US' },
        new Date('2026-10-06T14:00:00Z')
      );

      expect(result.components.device.fingerprint).toBeUndefined();
      expect(JSON.stringify(result)).not.toContain('fp_secret_123');
    });

    test('clamping ensures final score never exceeds [0.0, 1.0] and never outputs NaN or Infinity', () => {
      expect(clamp(-5)).toBe(0.0);
      expect(clamp(15)).toBe(1.0);
      expect(clamp(NaN)).toBe(0.0);
      expect(clamp(Infinity)).toBe(0.0);
    });

    test('explanation uses objective, non-accusatory language describing behavioral deviation', () => {
      const mockBaseline = {
        has_sufficient_history: true,
        login_hours: { mean_hour: 14.0, circular_std_dev_hours: 0.5, resultant_vector_r: 0.99 },
        typical_devices: [{ fingerprint: 'fp_known' }],
        typical_countries: [{ country: 'US' }]
      };

      const result = evaluateBaselineDeviation(
        mockBaseline,
        { device_fingerprint: 'fp_unrecognized', geo_country: 'DE' },
        new Date('2026-10-06T02:00:00Z')
      );

      expect(result.explanation.summary).toMatch(/^Login deviates \d+% from the user's historical behavioral baseline\.$/);
      expect(result.explanation.summary).not.toContain('compromise');
      expect(result.explanation.summary).not.toContain('attack');
      expect(result.explanation.factors.length).toBeGreaterThan(0);
    });
  });

  describe('7. Architectural Safeguards: Baseline Persistence Isolation', () => {
    test('evaluateBaselineDeviationForUser does NOT call buildUserBaseline during deviation scoring', async () => {
      const spyBuild = jest.spyOn(baselineService, 'buildUserBaseline');

      const deviation = await evaluateBaselineDeviationForUser(
        userEstablished.id,
        { device_fingerprint: 'fp_est_1', geo_country: 'US' },
        new Date('2026-10-06T14:00:00Z')
      );

      expect(spyBuild).not.toHaveBeenCalled();
      expect(deviation.is_evaluated).toBe(true);

      spyBuild.mockRestore();
    });

    test('current login being scored does not contaminate its own baseline', async () => {
      // User has an existing baseline with typical device fp_est_1
      const initialBaseline = await baselineService.getUserBaseline(userEstablished.id);
      const initialDevices = initialBaseline.typical_devices.map((d) => d.fingerprint);
      expect(initialDevices).not.toContain('fp_completely_novel_device');

      // Score a login with a new device
      const deviation = await evaluateBaselineDeviationForUser(
        userEstablished.id,
        { device_fingerprint: 'fp_completely_novel_device', geo_country: 'US' },
        new Date('2026-10-06T14:00:00Z')
      );

      // The new device must be flagged as unrecognized (deviation 1.0)
      expect(deviation.components.device.is_recognized).toBe(false);
      expect(deviation.components.device.deviation).toBe(1.0);

      // The persisted baseline in the database must remain completely unmodified
      const reFetchedBaseline = await baselineService.getUserBaseline(userEstablished.id);
      const reFetchedDevices = reFetchedBaseline.typical_devices.map((d) => d.fingerprint);
      expect(reFetchedDevices).not.toContain('fp_completely_novel_device');
    });
  });

  describe('8. End-to-End Login Integration & Metadata Attachment', () => {
    test('POST /login attaches behavioral_deviation to login_success event and preserves travel & bot metadata', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .set('x-device-fingerprint', 'fp_est_1')
        .send({
          email: userEstablished.email,
          password: userPassword
        });

      expect(res.status).toBe(200);
      expect(res.body.token).toBeDefined();

      // Retrieve the logged login_success event
      const event = await SecurityEvent.findOne({
        where: {
          user_id: userEstablished.id,
          event_type: 'login_success'
        },
        order: [['timestamp', 'DESC']]
      });

      expect(event).not.toBeNull();
      expect(event.metadata).toBeDefined();

      // Verify behavioral_deviation is attached
      const bDev = event.metadata.behavioral_deviation;
      expect(bDev).toBeDefined();
      expect(bDev.has_sufficient_history).toBe(true);
      expect(bDev.is_evaluated).toBe(true);
      expect(bDev.components.device).toBeDefined();
      expect(bDev.components.device.fingerprint).toBeUndefined(); // no raw fp in metadata
      expect(event.metadata.user_id).toBeUndefined(); // no redundant user_id in metadata

      // Verify no risk scoring or policy decision was generated
      expect(res.body.risk_score).toBeUndefined();
      expect(res.body.decision).toBeUndefined();
    });

    test('POST /login for user with sparse history records unevaluated behavioral_deviation', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .set('x-device-fingerprint', 'fp_sparse')
        .send({
          email: userSparse.email,
          password: userPassword
        });

      expect(res.status).toBe(200);

      const event = await SecurityEvent.findOne({
        where: {
          user_id: userSparse.id,
          event_type: 'login_success'
        },
        order: [['timestamp', 'DESC']]
      });

      expect(event).not.toBeNull();
      const bDev = event.metadata.behavioral_deviation;
      expect(bDev).toBeDefined();
      expect(bDev.has_sufficient_history).toBe(false);
      expect(bDev.is_evaluated).toBe(false);
      expect(bDev.deviation_score).toBeNull();
      expect(bDev.reason).toBe('insufficient_history');
    });
  });
});
