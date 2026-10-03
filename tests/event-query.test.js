const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../src/app');
const { sequelize, User, Session, SecurityEvent } = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const { JWT_SECRET } = require('../src/middleware/auth');

const TEST_API_KEY = 'test_secret_api_key_module_2_3';

describe('Sub-module 2.3 — Basic Event Query API (GET /api/v1/events)', () => {
  let userA;
  let userB;
  let sessionA;

  beforeAll(async () => {
    process.env.API_KEY = TEST_API_KEY;

    await runMigrations();
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SecurityEvent.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    userA = await User.create({
      id: 'usr_test_query_001',
      email: 'usera@example.com',
      password_hash: 'hash123'
    });

    userB = await User.create({
      id: 'usr_test_query_002',
      email: 'userb@example.com',
      password_hash: 'hash123'
    });

    sessionA = await Session.create({
      id: 'sess_test_query_001',
      user_id: userA.id,
      expires_at: new Date(Date.now() + 3600000),
      is_active: true
    });

    // Seed events for testing
    // User A events
    await SecurityEvent.create({
      event_id: 'evt_a_login_001',
      user_id: userA.id,
      session_id: sessionA.id,
      event_type: 'login_success',
      timestamp: new Date('2026-10-01T10:00:00Z'),
      context: { ip_address: '10.0.0.1' },
      metadata: { action_sensitivity: 'low' }
    });

    await SecurityEvent.create({
      event_id: 'evt_a_pwd_002',
      user_id: userA.id,
      session_id: sessionA.id,
      event_type: 'password_change',
      timestamp: new Date('2026-10-01T12:00:00Z'),
      context: { ip_address: '10.0.0.1' },
      metadata: { action_sensitivity: 'high' }
    });

    await SecurityEvent.create({
      event_id: 'evt_a_fail_003',
      user_id: userA.id,
      session_id: null,
      event_type: 'login_failed',
      timestamp: new Date('2026-10-02T10:00:00Z'),
      context: { ip_address: '192.168.1.1' },
      metadata: {}
    });

    // User B events
    await SecurityEvent.create({
      event_id: 'evt_b_login_001',
      user_id: userB.id,
      session_id: null,
      event_type: 'login_success',
      timestamp: new Date('2026-10-03T08:00:00Z'),
      context: { ip_address: '172.16.0.1' },
      metadata: { action_sensitivity: 'low' }
    });
  });

  afterAll(async () => {
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SecurityEvent.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');
  });

  describe('Authentication & Access Control', () => {
    test('rejects requests missing Authorization header with 401', async () => {
      const res = await request(app)
        .get('/api/v1/events')
        .expect(401);

      expect(res.body.error.code).toBe('unauthorized');
    });

    test('rejects requests with malformed Authorization header with 401', async () => {
      const res = await request(app)
        .get('/api/v1/events')
        .set('Authorization', 'Basic dXNlcjpwYXNz')
        .expect(401);

      expect(res.body.error.code).toBe('unauthorized');
    });

    test('rejects requests using user JWT token with 401 (service API key required)', async () => {
      const userToken = jwt.sign(
        { id: userA.id, email: userA.email, session_id: sessionA.id },
        JWT_SECRET,
        { expiresIn: '1h' }
      );

      const res = await request(app)
        .get('/api/v1/events')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(401);

      expect(res.body.error.code).toBe('unauthorized');
    });

    test('rejects requests with incorrect API key with 401', async () => {
      const res = await request(app)
        .get('/api/v1/events')
        .set('Authorization', 'Bearer wrong_invalid_api_key')
        .expect(401);

      expect(res.body.error.code).toBe('unauthorized');
    });

    test('rejects requests when API_KEY is unset in environment (no hardcoded fallback)', async () => {
      const savedKey = process.env.API_KEY;
      delete process.env.API_KEY;
      delete process.env.ACTIONGUARD_API_KEY;

      const res = await request(app)
        .get('/api/v1/events')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .expect(401);

      expect(res.body.error.code).toBe('unauthorized');

      process.env.API_KEY = savedKey;
    });

    test('allows requests with valid configured API key with 200', async () => {
      const res = await request(app)
        .get('/api/v1/events')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .expect(200);

      expect(res.body.events).toBeDefined();
      expect(Array.isArray(res.body.events)).toBe(true);
      expect(res.body.total).toBe(4);
    });
  });

  describe('Query Filtering', () => {
    test('filters events by user_id', async () => {
      const res = await request(app)
        .get(`/api/v1/events?user_id=${userA.id}`)
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .expect(200);

      expect(res.body.total).toBe(3);
      expect(res.body.events.length).toBe(3);
      res.body.events.forEach((evt) => {
        expect(evt.user_id).toBe(userA.id);
      });
    });

    test('filters events by session_id', async () => {
      const res = await request(app)
        .get(`/api/v1/events?session_id=${sessionA.id}`)
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .expect(200);

      expect(res.body.total).toBe(2);
      expect(res.body.events.length).toBe(2);
      res.body.events.forEach((evt) => {
        expect(evt.session_id).toBe(sessionA.id);
      });
    });

    test('filters events by event_type', async () => {
      const res = await request(app)
        .get('/api/v1/events?event_type=password_change')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .expect(200);

      expect(res.body.total).toBe(1);
      expect(res.body.events[0].event_type).toBe('password_change');
      expect(res.body.events[0].event_id).toBe('evt_a_pwd_002');
    });

    test('filters events by time range (from and to)', async () => {
      const from = '2026-10-01T11:00:00Z';
      const to = '2026-10-02T12:00:00Z';

      const res = await request(app)
        .get(`/api/v1/events?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`)
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .expect(200);

      // Should match evt_a_pwd_002 (Oct 1 12:00) and evt_a_fail_003 (Oct 2 10:00)
      expect(res.body.total).toBe(2);
      const ids = res.body.events.map((e) => e.event_id);
      expect(ids).toContain('evt_a_pwd_002');
      expect(ids).toContain('evt_a_fail_003');
    });

    test('combines multiple filters (user_id and event_type)', async () => {
      const res = await request(app)
        .get(`/api/v1/events?user_id=${userA.id}&event_type=login_success`)
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .expect(200);

      expect(res.body.total).toBe(1);
      expect(res.body.events[0].event_id).toBe('evt_a_login_001');
    });
  });

  describe('Validation of Query Parameters', () => {
    test('rejects unrecognized event_type with 400 invalid_event_type', async () => {
      const res = await request(app)
        .get('/api/v1/events?event_type=unknown_fabricated_type')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .expect(400);

      expect(res.body.error.code).toBe('invalid_event_type');
    });

    test('rejects invalid from date with 400 invalid_request', async () => {
      const res = await request(app)
        .get('/api/v1/events?from=not-a-date')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .expect(400);

      expect(res.body.error.code).toBe('invalid_request');
    });

    test('rejects invalid to date with 400 invalid_request', async () => {
      const res = await request(app)
        .get('/api/v1/events?to=not-a-date')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .expect(400);

      expect(res.body.error.code).toBe('invalid_request');
    });

    test('rejects when from date is after to date with 400 invalid_request', async () => {
      const res = await request(app)
        .get('/api/v1/events?from=2026-10-05T00:00:00Z&to=2026-10-01T00:00:00Z')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .expect(400);

      expect(res.body.error.code).toBe('invalid_request');
    });

    test('rejects invalid limit with 400 invalid_request', async () => {
      const res = await request(app)
        .get('/api/v1/events?limit=invalid')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .expect(400);

      expect(res.body.error.code).toBe('invalid_request');
    });

    test('rejects negative offset with 400 invalid_request', async () => {
      const res = await request(app)
        .get('/api/v1/events?offset=-5')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .expect(400);

      expect(res.body.error.code).toBe('invalid_request');
    });
  });

  describe('Pagination, Ordering & Response Contract', () => {
    test('applies default limit 50 and offset 0', async () => {
      const res = await request(app)
        .get('/api/v1/events')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .expect(200);

      expect(res.body.limit).toBe(50);
      expect(res.body.offset).toBe(0);
      expect(res.body.total).toBe(4);
    });

    test('respects custom limit and offset pagination', async () => {
      // Page 1 (limit 2, offset 0)
      const page1 = await request(app)
        .get('/api/v1/events?limit=2&offset=0')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .expect(200);

      expect(page1.body.events.length).toBe(2);
      expect(page1.body.limit).toBe(2);
      expect(page1.body.offset).toBe(0);
      expect(page1.body.total).toBe(4);

      // Page 2 (limit 2, offset 2)
      const page2 = await request(app)
        .get('/api/v1/events?limit=2&offset=2')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .expect(200);

      expect(page2.body.events.length).toBe(2);
      expect(page2.body.limit).toBe(2);
      expect(page2.body.offset).toBe(2);

      // Verify no overlap between page 1 and page 2
      const page1Ids = page1.body.events.map((e) => e.event_id);
      const page2Ids = page2.body.events.map((e) => e.event_id);
      expect(page1Ids.some((id) => page2Ids.includes(id))).toBe(false);
    });

    test('orders events deterministically (timestamp DESC, event_id DESC)', async () => {
      const res = await request(app)
        .get('/api/v1/events')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .expect(200);

      for (let i = 0; i < res.body.events.length - 1; i++) {
        const curr = new Date(res.body.events[i].timestamp).getTime();
        const next = new Date(res.body.events[i + 1].timestamp).getTime();
        expect(curr).toBeGreaterThanOrEqual(next);
      }
    });

    test('response conforms to API contract structure without fabricated risk_score/decision', async () => {
      const res = await request(app)
        .get('/api/v1/events?limit=1')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .expect(200);

      const event = res.body.events[0];
      expect(event.event_id).toBeDefined();
      expect(event.user_id).toBeDefined();
      expect(event.event_type).toBeDefined();
      expect(event.timestamp).toBeDefined();
      expect(event.context).toBeDefined();
      expect(event.metadata).toBeDefined();

      // Ensure Module 2 does not fabricate risk_score or decision
      expect(event.risk_score).toBeUndefined();
      expect(event.decision).toBeUndefined();
    });
  });
});
