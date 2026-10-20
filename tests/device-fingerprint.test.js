const request = require('supertest');
const app = require('../src/app');
const { sequelize, User, Session, Device, SecurityEvent } = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const { getSession } = require('../src/storage/redis');
const {
  validateDeviceFingerprint,
  getOrCreateDevice
} = require('../src/services/deviceService');
const { createSession } = require('../src/services/sessionService');

describe('Sub-module 3.1 — Device Fingerprint Collection', () => {
  let testUser;

  beforeAll(async () => {
    await runMigrations();
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    testUser = await User.create({
      email: 'device-tester@example.com',
      password_hash: await require('bcrypt').hash('Password123!', 10)
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

  describe('1. Fingerprint Validation (validateDeviceFingerprint)', () => {
    test('accepts valid FingerprintJS-compatible identifiers', () => {
      // Hex hash, visitorId formats, alphanumeric with delimiters
      expect(validateDeviceFingerprint('fp_a1b2c3')).toBe(true);
      expect(validateDeviceFingerprint('9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d')).toBe(true);
      expect(validateDeviceFingerprint('dev_visitor_12345-abc.def:01')).toBe(true);
      expect(validateDeviceFingerprint('abcd')).toBe(true);
      expect(validateDeviceFingerprint('a'.repeat(255))).toBe(true);
    });

    test('rejects non-string inputs', () => {
      expect(validateDeviceFingerprint(null)).toBe(false);
      expect(validateDeviceFingerprint(undefined)).toBe(false);
      expect(validateDeviceFingerprint(12345)).toBe(false);
      expect(validateDeviceFingerprint({})).toBe(false);
      expect(validateDeviceFingerprint(['fp_123'])).toBe(false);
      expect(validateDeviceFingerprint(true)).toBe(false);
    });

    test('rejects empty or whitespace-only strings', () => {
      expect(validateDeviceFingerprint('')).toBe(false);
      expect(validateDeviceFingerprint('    ')).toBe(false);
      expect(validateDeviceFingerprint('\t\n')).toBe(false);
    });

    test('rejects strings shorter than 4 characters', () => {
      expect(validateDeviceFingerprint('a')).toBe(false);
      expect(validateDeviceFingerprint('ab')).toBe(false);
      expect(validateDeviceFingerprint('abc')).toBe(false);
    });

    test('rejects arbitrarily large strings (> 255 chars)', () => {
      expect(validateDeviceFingerprint('a'.repeat(256))).toBe(false);
      expect(validateDeviceFingerprint('a'.repeat(10000))).toBe(false);
    });

    test('rejects dangerous or disallowed characters', () => {
      expect(validateDeviceFingerprint('fp_test with space')).toBe(false);
      expect(validateDeviceFingerprint('fp_<script>alert(1)</script>')).toBe(false);
      expect(validateDeviceFingerprint('fp_"OR"1"="1')).toBe(false);
      expect(validateDeviceFingerprint("fp_'OR'1'='1")).toBe(false);
      expect(validateDeviceFingerprint('fp_\0nullbyte')).toBe(false);
      expect(validateDeviceFingerprint('fp_\nnewline')).toBe(false);
    });
  });

  describe('2. Device Association (getOrCreateDevice)', () => {
    test('creates a new untrusted device record for unknown fingerprint', async () => {
      const fingerprint = 'fp_test_device_first_seen_001';
      const result = await getOrCreateDevice(testUser.id, fingerprint);

      expect(result.isNew).toBe(true);
      expect(result.device).toBeDefined();
      expect(result.device.id).toBeDefined();
      expect(result.device.user_id).toBe(testUser.id);
      expect(result.device.fingerprint).toBe(fingerprint);
      expect(result.device.is_trusted).toBe(false);
      expect(result.device.first_seen_at).toBeDefined();

      // Check directly in database
      const dbDevice = await Device.findByPk(result.device.id);
      expect(dbDevice).not.toBeNull();
      expect(dbDevice.is_trusted).toBe(false);
    });

    test('returns existing device without duplicate creation and preserves is_trusted', async () => {
      const fingerprint = 'fp_test_device_reused_002';

      // First call: creates record
      const first = await getOrCreateDevice(testUser.id, fingerprint);
      expect(first.isNew).toBe(true);

      // Manually set is_trusted to true to test preservation
      await Device.update({ is_trusted: true }, { where: { id: first.device.id } });

      // Second call: recognizes existing device
      const second = await getOrCreateDevice(testUser.id, fingerprint);
      expect(second.isNew).toBe(false);
      expect(second.device.id).toBe(first.device.id);
      expect(second.device.is_trusted).toBe(true); // Preserved

      // Verify no duplicate in database
      const allForFp = await Device.findAll({
        where: { user_id: testUser.id, fingerprint }
      });
      expect(allForFp.length).toBe(1);
    });

    test('throws on missing userId or invalid fingerprint', async () => {
      await expect(getOrCreateDevice(null, 'fp_valid_123')).rejects.toThrow();
      await expect(getOrCreateDevice(testUser.id, 'sh')).rejects.toThrow();
      await expect(getOrCreateDevice(testUser.id, 'bad char !')).rejects.toThrow();
    });
  });

  describe('3. Session Association (createSession & Redis)', () => {
    test('stores device_id and device_fingerprint in Redis when provided', async () => {
      const deviceId = 'dev_test_session_assoc_001';
      const fingerprint = 'fp_session_assoc_001';

      const { sessionId } = await createSession(testUser.id, testUser.email, 60, {
        device_id: deviceId,
        device_fingerprint: fingerprint
      });

      const redisSession = await getSession(sessionId);
      expect(redisSession).not.toBeNull();
      expect(redisSession.device_id).toBe(deviceId);
      expect(redisSession.device_fingerprint).toBe(fingerprint);
      // is_trusted_device must NOT be a separate session field
      expect(redisSession.is_trusted_device).toBeUndefined();
    });

    test('stores session normally when device data is omitted', async () => {
      const { sessionId } = await createSession(testUser.id, testUser.email, 60);

      const redisSession = await getSession(sessionId);
      expect(redisSession).not.toBeNull();
      expect(redisSession.user_id).toBe(testUser.id);
      expect(redisSession.device_id).toBeUndefined();
      expect(redisSession.device_fingerprint).toBeUndefined();
    });
  });

  describe('4. End-to-End Authentication Flow with X-Device-Fingerprint', () => {
    test('login with canonical X-Device-Fingerprint associates device, session, and events', async () => {
      const fingerprint = 'fp_client_login_flow_123';

      const res = await request(app)
        .post('/api/v1/auth/login')
        .set('X-Device-Fingerprint', fingerprint)
        .send({
          email: testUser.email,
          password: 'Password123!'
        })
        .expect(200);

      const { token, session_id } = res.body;
      expect(token).toBeDefined();
      expect(session_id).toBeDefined();

      // 1. Verify Device record in MySQL
      const dbDevice = await Device.findOne({
        where: { user_id: testUser.id, fingerprint }
      });
      expect(dbDevice).not.toBeNull();
      expect(dbDevice.is_trusted).toBe(false);

      // 2. Verify Session in Redis has device association
      const redisSession = await getSession(session_id);
      expect(redisSession.device_id).toBe(dbDevice.id);
      expect(redisSession.device_fingerprint).toBe(fingerprint);

      // 3. Verify login_success SecurityEvent has device_fingerprint in context
      const loginSuccessEvent = await SecurityEvent.findOne({
        where: {
          user_id: testUser.id,
          session_id,
          event_type: 'login_success'
        }
      });
      expect(loginSuccessEvent).not.toBeNull();
      expect(loginSuccessEvent.context.device_fingerprint).toBe(fingerprint);

      // 4. Verify session_created SecurityEvent has device_fingerprint in context
      const sessionCreatedEvent = await SecurityEvent.findOne({
        where: {
          user_id: testUser.id,
          session_id,
          event_type: 'session_created'
        }
      });
      expect(sessionCreatedEvent).not.toBeNull();
      expect(sessionCreatedEvent.context.device_fingerprint).toBe(fingerprint);

      // 5. Verify logout attaches device_fingerprint from session to session_terminated
      await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      const logoutEvent = await SecurityEvent.findOne({
        where: {
          user_id: testUser.id,
          session_id,
          event_type: 'session_terminated'
        }
      });
      expect(logoutEvent).not.toBeNull();
      expect(logoutEvent.context.device_fingerprint).toBe(fingerprint);
    });

    test('failed login with X-Device-Fingerprint records fingerprint in event context without creating Device record', async () => {
      const fingerprint = 'fp_failed_login_attempt_777';
      const devicesCountBefore = await Device.count({ where: { fingerprint } });

      await request(app)
        .post('/api/v1/auth/login')
        .set('X-Device-Fingerprint', fingerprint)
        .send({
          email: testUser.email,
          password: 'IncorrectPassword999!'
        })
        .expect(401);

      // Device record must NOT be created for failed login
      const devicesCountAfter = await Device.count({ where: { fingerprint } });
      expect(devicesCountAfter).toBe(devicesCountBefore);

      // login_failed event must record the fingerprint in context
      const failedEvents = await SecurityEvent.findAll({
        where: {
          user_id: testUser.id,
          event_type: 'login_failed'
        },
        order: [['timestamp', 'DESC']]
      });
      expect(failedEvents.length).toBeGreaterThan(0);
      expect(failedEvents[0].context.device_fingerprint).toBe(fingerprint);
    });

    test('login without X-Device-Fingerprint preserves existing behavior without fabricating fingerprint', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: 'Password123!'
        })
        .expect(200);

      const { session_id } = res.body;

      const redisSession = await getSession(session_id);
      expect(redisSession.device_id).toBeUndefined();
      expect(redisSession.device_fingerprint).toBeUndefined();

      const loginSuccessEvent = await SecurityEvent.findOne({
        where: {
          user_id: testUser.id,
          session_id,
          event_type: 'login_success'
        }
      });
      expect(loginSuccessEvent.context.device_fingerprint).toBeUndefined();
    });

    test('login with invalid or oversized X-Device-Fingerprint safely ignores it without breaking or exposing it', async () => {
      const maliciousFingerprint = '<script>alert("hack")</script>' + 'a'.repeat(300);

      const res = await request(app)
        .post('/api/v1/auth/login')
        .set('X-Device-Fingerprint', maliciousFingerprint)
        .send({
          email: testUser.email,
          password: 'Password123!'
        })
        .expect(200);

      const { session_id } = res.body;

      // Ensure no device record was created with the malicious string
      const badDevice = await Device.findOne({
        where: { fingerprint: maliciousFingerprint }
      });
      expect(badDevice).toBeNull();

      // Ensure session does not have the invalid fingerprint
      const redisSession = await getSession(session_id);
      expect(redisSession.device_fingerprint).toBeUndefined();

      // Ensure event context does not have the invalid fingerprint
      const loginSuccessEvent = await SecurityEvent.findOne({
        where: {
          user_id: testUser.id,
          session_id,
          event_type: 'login_success'
        }
      });
      expect(loginSuccessEvent.context.device_fingerprint).toBeUndefined();
    });

    test('logout prioritizes session device_fingerprint A over different header B, and uses header B as fallback when session has none', async () => {
      const fingerprintA = 'fp_login_device_AAA';
      const fingerprintB = 'fp_logout_header_BBB';

      // 1. Create/login with valid device fingerprint A
      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .set('X-Device-Fingerprint', fingerprintA)
        .send({
          email: testUser.email,
          password: 'Password123!'
        })
        .expect(200);

      const { token, session_id } = loginRes.body;

      // 2. Confirm Redis session contains fingerprint A
      const redisSession = await getSession(session_id);
      expect(redisSession).not.toBeNull();
      expect(redisSession.device_fingerprint).toBe(fingerprintA);

      // 3. Send logout with a different valid X-Device-Fingerprint value B
      await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Device-Fingerprint', fingerprintB)
        .expect(200);

      // 4. Verify resulting session_terminated SecurityEvent uses fingerprint A from the active session, not B
      const logoutEventA = await SecurityEvent.findOne({
        where: {
          user_id: testUser.id,
          session_id,
          event_type: 'session_terminated'
        }
      });
      expect(logoutEventA).not.toBeNull();
      expect(logoutEventA.context.device_fingerprint).toBe(fingerprintA);
      expect(logoutEventA.context.device_fingerprint).not.toBe(fingerprintB);

      // 5. Verify that when active session has no stored fingerprint, a valid header may be used as fallback
      const loginNoFpRes = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: 'Password123!'
        })
        .expect(200);

      const tokenNoFp = loginNoFpRes.body.token;
      const sessionIdNoFp = loginNoFpRes.body.session_id;

      const redisSessionNoFp = await getSession(sessionIdNoFp);
      expect(redisSessionNoFp.device_fingerprint).toBeUndefined();

      // Logout with valid header B when session has no stored fingerprint
      await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${tokenNoFp}`)
        .set('X-Device-Fingerprint', fingerprintB)
        .expect(200);

      const logoutEventFallback = await SecurityEvent.findOne({
        where: {
          user_id: testUser.id,
          session_id: sessionIdNoFp,
          event_type: 'session_terminated'
        }
      });
      expect(logoutEventFallback).not.toBeNull();
      expect(logoutEventFallback.context.device_fingerprint).toBe(fingerprintB);
    });
  });
});
