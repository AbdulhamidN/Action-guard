const request = require('supertest');
const bcrypt = require('bcrypt');
const app = require('../src/app');
const { sequelize, User, Session, Device, SecurityEvent } = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const { getRedisClient } = require('../src/storage/redis');
const {
  roundToTwoDecimals,
  parseAndSortTimestamps,
  calculateConsecutiveIntervals,
  calculateIntervalMetrics,
  evaluateAutomationHeuristics,
  DEFAULT_TIMING_CONFIG
} = require('../src/utils/timing');
const {
  recordAndEvaluateTiming,
  getTimingHistory,
  clearTimingHistory,
  getTimingRedisKey
} = require('../src/services/botTimingService');
const { collectBotSignal } = require('../src/collectors/botCollector');

describe('Sub-module 3.4 — Basic Bot / Automation Signal', () => {
  let testUser;
  const userPassword = 'CorrectPassword123!';

  beforeAll(async () => {
    await runMigrations();
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    testUser = await User.create({
      email: 'bot-target-user@actionguard.test',
      password_hash: await bcrypt.hash(userPassword, 10)
    });
  });

  afterAll(async () => {
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');
  });

  beforeEach(async () => {
    // Clear test Redis timing keys before each test
    await clearTimingHistory('192.0.2.1');
    await clearTimingHistory('192.0.2.2');
    await clearTimingHistory('198.51.100.1');
    await clearTimingHistory('198.51.100.2');
    await clearTimingHistory('127.0.0.1');
    await clearTimingHistory('::1');
  });

  afterEach(async () => {
    // Clear test Redis timing keys after each test
    await clearTimingHistory('192.0.2.1');
    await clearTimingHistory('192.0.2.2');
    await clearTimingHistory('198.51.100.1');
    await clearTimingHistory('198.51.100.2');
    await clearTimingHistory('127.0.0.1');
    await clearTimingHistory('::1');
  });

  describe('1. Timing Mathematics & Statistics Utilities (src/utils/timing.js)', () => {
    test('roundToTwoDecimals rounds correctly and handles edge cases', () => {
      expect(roundToTwoDecimals(12.3456)).toBe(12.35);
      expect(roundToTwoDecimals(12.3444)).toBe(12.34);
      expect(roundToTwoDecimals(0)).toBe(0);
      expect(roundToTwoDecimals(null)).toBe(0);
      expect(roundToTwoDecimals('abc')).toBe(0);
      expect(roundToTwoDecimals(NaN)).toBe(0);
      expect(roundToTwoDecimals(Infinity)).toBe(0);
    });

    test('parseAndSortTimestamps parses Dates, strings, numbers, filters invalid, and sorts', () => {
      const inputs = [
        new Date('2026-10-04T10:00:03.000Z'),
        '2026-10-04T10:00:01.000Z',
        1791108002000,
        'invalid-date',
        null,
        undefined
      ];
      const result = parseAndSortTimestamps(inputs);
      expect(result).toHaveLength(3);
      expect(result[0]).toBeLessThan(result[1]);
      expect(result[1]).toBeLessThan(result[2]);
    });

    test('calculateConsecutiveIntervals calculates correct delta_t between timestamps', () => {
      expect(calculateConsecutiveIntervals([])).toEqual([]);
      expect(calculateConsecutiveIntervals([1000])).toEqual([]);
      expect(calculateConsecutiveIntervals([1000, 1250, 1600])).toEqual([250, 350]);
    });

    test('calculateIntervalMetrics computes min, avg, sample standard deviation, and CV', () => {
      const periodic = calculateIntervalMetrics([1000, 1000, 1000]);
      expect(periodic).toEqual({
        min_interval_ms: 1000,
        avg_interval_ms: 1000,
        interval_std_dev_ms: 0,
        coefficient_of_variation: 0
      });

      const varied = calculateIntervalMetrics([200, 400]);
      expect(varied.min_interval_ms).toBe(200);
      expect(varied.avg_interval_ms).toBe(300);
      expect(varied.interval_std_dev_ms).toBe(141.42);
      expect(varied.coefficient_of_variation).toBe(0.47);
    });

    test('calculateIntervalMetrics sets CV to null when mean interval <= 0', () => {
      const zeroMetrics = calculateIntervalMetrics([0, 0, 0]);
      expect(zeroMetrics.avg_interval_ms).toBe(0);
      expect(zeroMetrics.coefficient_of_variation).toBeNull();
    });

    test('evaluateAutomationHeuristics returns insufficient_observations for sample_size < minRequests', () => {
      const result1 = evaluateAutomationHeuristics([1000]);
      expect(result1).toEqual({
        automation_suspected: false,
        sufficient_observations: false,
        sample_size: 1,
        reasons: [],
        metrics: null
      });

      const result2 = evaluateAutomationHeuristics([1000, 1200]);
      expect(result2).toEqual({
        automation_suspected: false,
        sufficient_observations: false,
        sample_size: 2,
        reasons: [],
        metrics: null
      });
    });

    test('evaluateAutomationHeuristics detects rapid burst when min interval < 150ms', () => {
      const timestamps = [1000, 1100, 1600];
      const result = evaluateAutomationHeuristics(timestamps);
      expect(result.automation_suspected).toBe(true);
      expect(result.sufficient_observations).toBe(true);
      expect(result.sample_size).toBe(3);
      expect(result.reasons).toContain('rapid_burst');
      expect(result.metrics.min_interval_ms).toBe(100);
    });

    test('evaluateAutomationHeuristics detects rapid burst when avg interval < 300ms', () => {
      const timestamps = [1000, 1200, 1450];
      const result = evaluateAutomationHeuristics(timestamps);
      expect(result.automation_suspected).toBe(true);
      expect(result.sufficient_observations).toBe(true);
      expect(result.reasons).toContain('rapid_burst');
      expect(result.metrics.avg_interval_ms).toBe(225);
    });

    test('evaluateAutomationHeuristics detects robotic periodicity for low jitter (CV < 0.15)', () => {
      const timestamps = [1000, 2000, 3010, 4000];
      const result = evaluateAutomationHeuristics(timestamps);
      expect(result.automation_suspected).toBe(true);
      expect(result.sufficient_observations).toBe(true);
      expect(result.sample_size).toBe(4);
      expect(result.reasons).toContain('robotic_periodicity');
      expect(result.metrics.coefficient_of_variation).toBeLessThan(0.15);
    });

    test('evaluateAutomationHeuristics does NOT flag periodicity for sample_size < 4', () => {
      const timestamps = [1000, 2000, 3000];
      const result = evaluateAutomationHeuristics(timestamps);
      expect(result.reasons).not.toContain('robotic_periodicity');
      expect(result.automation_suspected).toBe(false);
    });

    test('evaluateAutomationHeuristics does NOT flag periodicity when mean interval > 5000ms', () => {
      const timestamps = [1000, 7000, 13000, 19000];
      const result = evaluateAutomationHeuristics(timestamps);
      expect(result.reasons).not.toContain('robotic_periodicity');
      expect(result.automation_suspected).toBe(false);
    });

    test('evaluateAutomationHeuristics does NOT flag automation for irregular human-like intervals', () => {
      const timestamps = [1000, 2200, 6300, 8600];
      const result = evaluateAutomationHeuristics(timestamps);
      expect(result.automation_suspected).toBe(false);
      expect(result.sufficient_observations).toBe(true);
      expect(result.sample_size).toBe(4);
      expect(result.reasons).toHaveLength(0);
      expect(result.metrics.coefficient_of_variation).toBeGreaterThan(0.30);
    });

    test('duplicate timestamps and zero intervals do NOT trigger robotic_periodicity or artificial rapid_burst', () => {
      const duplicateTimestamps = [1000, 1000, 1000, 1000];
      const result = evaluateAutomationHeuristics(duplicateTimestamps);

      expect(result.metrics.avg_interval_ms).toBe(0);
      expect(result.metrics.coefficient_of_variation).toBeNull();
      expect(result.reasons).not.toContain('robotic_periodicity');
      expect(result.reasons).not.toContain('rapid_burst');
      expect(result.automation_suspected).toBe(false);
    });

    test('threshold boundary behavior matches exact specification', () => {
      const exactBoundary = [1000, 1150, 1600];
      const resBoundary = evaluateAutomationHeuristics(exactBoundary);
      expect(resBoundary.metrics.min_interval_ms).toBe(150);
      expect(resBoundary.metrics.avg_interval_ms).toBe(300);
      expect(resBoundary.reasons).not.toContain('rapid_burst');
      expect(resBoundary.automation_suspected).toBe(false);
    });
  });

  describe('2. Redis Sliding Window & Bot Timing Service (src/services/botTimingService.js)', () => {
    test('getTimingRedisKey formats key properly with IP and user namespaces', () => {
      expect(getTimingRedisKey('192.0.2.1')).toBe('bot:timing:ip:192.0.2.1');
      expect(getTimingRedisKey('ip:192.0.2.1')).toBe('bot:timing:ip:192.0.2.1');
      expect(getTimingRedisKey('user:usr_12345')).toBe('bot:timing:user:usr_12345');
    });

    test('recordAndEvaluateTiming bounds history to maximum 10 timestamps', async () => {
      const sourceIp = '192.0.2.1';
      const baseTime = 1791100000000;

      for (let i = 0; i < 15; i++) {
        await recordAndEvaluateTiming(sourceIp, baseTime + i * 1000);
      }

      const history = await getTimingHistory(sourceIp);
      expect(history).toHaveLength(10);
      expect(history[0]).toBe(baseTime + 5 * 1000);
      expect(history[9]).toBe(baseTime + 14 * 1000);
    });

    test('recordAndEvaluateTiming prunes timestamps outside the 60-second sliding window', async () => {
      const sourceIp = '192.0.2.2';
      const t0 = 1791100000000;

      await recordAndEvaluateTiming(sourceIp, t0);
      await recordAndEvaluateTiming(sourceIp, t0 + 1000);
      await recordAndEvaluateTiming(sourceIp, t0 + 2000);

      const tNew = t0 + 65000;
      const res = await recordAndEvaluateTiming(sourceIp, tNew);

      const history = await getTimingHistory(sourceIp);
      expect(history).toEqual([tNew]);
      expect(res.sample_size).toBe(1);
      expect(res.sufficient_observations).toBe(false);
      expect(res.automation_suspected).toBe(false);
    });

    test('source identities remain isolated in Redis', async () => {
      const ipA = '198.51.100.1';
      const ipB = '198.51.100.2';
      const now = Date.now();

      await recordAndEvaluateTiming(ipA, now);
      await recordAndEvaluateTiming(ipA, now + 100);
      await recordAndEvaluateTiming(ipA, now + 200);

      await recordAndEvaluateTiming(ipB, now);

      const historyA = await getTimingHistory(ipA);
      const historyB = await getTimingHistory(ipB);

      expect(historyA).toHaveLength(3);
      expect(historyB).toHaveLength(1);
    });

    test('Redis failure returns safe fallback without throwing or breaking', async () => {
      const client = getRedisClient();
      const originalGet = client.get;

      client.get = jest.fn().mockRejectedValue(new Error('Connection timeout to Redis'));

      try {
        const result = await recordAndEvaluateTiming('192.0.2.1', Date.now());
        expect(result).toEqual({
          automation_suspected: false,
          sufficient_observations: false,
          sample_size: 0,
          reasons: [],
          metrics: null
        });
      } finally {
        client.get = originalGet;
      }
    });
  });

  describe('3. Signal Collector Interface (src/collectors/botCollector.js)', () => {
    test('collectBotSignal operates on plain values and omits internal source_identity and Redis keys', async () => {
      const now = Date.now();
      const ip = '198.51.100.1';

      await collectBotSignal(ip, now);
      await collectBotSignal(ip, now + 100);
      const signal = await collectBotSignal(ip, now + 200);

      expect(signal).toHaveProperty('automation_suspected', true);
      expect(signal).toHaveProperty('sufficient_observations', true);
      expect(signal).toHaveProperty('sample_size', 3);
      expect(signal).toHaveProperty('reasons');
      expect(signal).toHaveProperty('metrics');

      expect(signal).not.toHaveProperty('source_identity');
      expect(signal).not.toHaveProperty('redis_key');
      expect(signal).not.toHaveProperty('key');
    });
  });

  describe('4. Authentication Route Integration (POST /api/v1/auth/login)', () => {
    test('single login request records exactly one timestamp in Redis', async () => {
      await clearTimingHistory('127.0.0.1');

      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: userPassword
        });

      expect(res.status).toBe(200);

      const history = await getTimingHistory('127.0.0.1');
      expect(history).toHaveLength(1);
    });

    test('failed login records bot_detection in SecurityEvent metadata', async () => {
      await clearTimingHistory('127.0.0.1');

      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: 'WrongPassword!'
        });

      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('authentication_failed');

      const event = await SecurityEvent.findOne({
        where: {
          user_id: testUser.id,
          event_type: 'login_failed'
        },
        order: [['event_id', 'DESC']]
      });

      expect(event).not.toBeNull();
      expect(event.metadata).toHaveProperty('bot_detection');
      expect(event.metadata.bot_detection).toHaveProperty('automation_suspected', false);
      expect(event.metadata.bot_detection).toHaveProperty('sample_size', 1);
      expect(event.metadata.bot_detection).not.toHaveProperty('source_identity');
    });

    test('successful login records bot_detection and preserves travel_anomaly in metadata', async () => {
      await clearTimingHistory('127.0.0.1');

      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: userPassword
        });

      expect(res.status).toBe(200);

      const event = await SecurityEvent.findOne({
        where: {
          user_id: testUser.id,
          session_id: res.body.session_id,
          event_type: 'login_success'
        }
      });

      expect(event).not.toBeNull();
      expect(event.metadata).toHaveProperty('bot_detection');
      expect(event.metadata).toHaveProperty('travel_anomaly');
      expect(event.metadata.bot_detection.sample_size).toBe(1);
      expect(event.metadata.bot_detection).not.toHaveProperty('source_identity');
    });

    test('rapid burst of login attempts flags automation_suspected: true in metadata without blocking requests', async () => {
      await clearTimingHistory('127.0.0.1');

      // Seed 3 rapid burst requests directly into Redis for 127.0.0.1 relative to Date.now() (inter-arrival intervals < 150ms)
      const baseTime = Date.now();
      await recordAndEvaluateTiming('127.0.0.1', baseTime - 150);
      await recordAndEvaluateTiming('127.0.0.1', baseTime - 100);
      await recordAndEvaluateTiming('127.0.0.1', baseTime - 50);

      // 4th request arriving via HTTP (~50ms after preceding burst observation)
      const r4 = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: testUser.email, password: userPassword });

      // Non-blocking verification: valid login STILL succeeds with 200 OK
      expect(r4.status).toBe(200);
      expect(r4.body).toHaveProperty('token');
      expect(r4.body).toHaveProperty('session_id');

      const event = await SecurityEvent.findOne({
        where: {
          user_id: testUser.id,
          session_id: r4.body.session_id,
          event_type: 'login_success'
        }
      });

      expect(event).not.toBeNull();
      expect(event.metadata.bot_detection.automation_suspected).toBe(true);
      expect(event.metadata.bot_detection.reasons).toContain('rapid_burst');
      expect(event.metadata.bot_detection.sample_size).toBe(4);
    });

    test('robotic periodicity flags automation_suspected: true with robotic_periodicity', async () => {
      await clearTimingHistory('127.0.0.1');

      // Seed 3 periodic requests at 1000ms intervals directly into Redis for 127.0.0.1
      const baseTime = Date.now();
      await recordAndEvaluateTiming('127.0.0.1', baseTime - 3000);
      await recordAndEvaluateTiming('127.0.0.1', baseTime - 2000);
      await recordAndEvaluateTiming('127.0.0.1', baseTime - 1000);

      // 4th request arriving at baseTime (~1000ms interval) via HTTP
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: userPassword
        });

      expect(res.status).toBe(200);

      const event = await SecurityEvent.findOne({
        where: {
          user_id: testUser.id,
          session_id: res.body.session_id,
          event_type: 'login_success'
        }
      });

      expect(event).not.toBeNull();
      expect(event.metadata.bot_detection.sample_size).toBe(4);
      expect(event.metadata.bot_detection.automation_suspected).toBe(true);
      expect(event.metadata.bot_detection.reasons).toContain('robotic_periodicity');
    });

    test('no secrets or credentials are ever stored in Redis or event metadata', async () => {
      await clearTimingHistory('127.0.0.1');

      const secretPassword = 'UltraSecretPassword!999';

      await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: secretPassword
        });

      const client = getRedisClient();
      const rawRedisData = await client.get('bot:timing:ip:127.0.0.1');
      expect(rawRedisData).not.toBeNull();
      expect(rawRedisData).not.toContain(secretPassword);
      expect(rawRedisData).not.toContain('password');

      const event = await SecurityEvent.findOne({
        where: { user_id: testUser.id },
        order: [['event_id', 'DESC']]
      });

      const metadataString = JSON.stringify(event.metadata);
      expect(metadataString).not.toContain(secretPassword);
      expect(metadataString).not.toContain('password');
      expect(metadataString).not.toContain('bot:timing');
    });

    test('Redis failure during bot timing collection does not break authentication flow', async () => {
      const client = getRedisClient();
      const originalSet = client.set;

      // Mock Redis set failure specifically for bot:timing: keys
      client.set = jest.fn().mockImplementation((key, ...args) => {
        if (typeof key === 'string' && key.startsWith('bot:timing:')) {
          return Promise.reject(new Error('Redis cluster unreachable'));
        }
        return originalSet.call(client, key, ...args);
      });

      try {
        const res = await request(app)
          .post('/api/v1/auth/login')
          .send({
            email: testUser.email,
            password: userPassword
          });

        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty('token');
      } finally {
        client.set = originalSet;
      }
    });
  });
});
