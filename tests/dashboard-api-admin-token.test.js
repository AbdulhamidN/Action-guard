const http = require('http');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const request = require('supertest');
const { io: ioClient } = require('socket.io-client');

const app = require('../src/app');
const {
  sequelize,
  User,
  Session,
  Device,
  SecurityEvent,
  RiskAssessment,
  PolicyDecision,
  ActionSequence,
  SequenceEvent
} = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const { getRedisClient } = require('../src/storage/redis');
const { REDIS_PREFIXES } = require('../src/config/sessionConfig');
const { JWT_SECRET } = require('../src/middleware/auth');
const { createSession } = require('../src/services/sessionService');
const {
  createAdminToken,
  validateAdminToken,
  revokeAdminToken,
  hashAdminToken
} = require('../src/services/adminTokenService');
const {
  initSocketServer,
  getSocketServer,
  closeSocketServer
} = require('../src/realtime/socketServer');

const TEST_ADMIN_KEY = 'admin_secret_key_with_at_least_32_characters_12345';
const TEST_PASSWORD = 'Password123!';

async function waitForCondition(predicate, timeoutMs = 3000, intervalMs = 25) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await predicate()) return true;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return false;
}

function createClient(port, options = {}) {
  return ioClient(`http://localhost:${port}`, {
    transports: ['websocket'],
    autoConnect: false,
    reconnection: false,
    ...options
  });
}

function connectClient(client) {
  return new Promise((resolve, reject) => {
    client.on('connect', () => resolve(client));
    client.on('connect_error', (err) => reject(err));
    client.connect();
  });
}

describe('Module 12a — Dashboard API, Admin Session Token & REST Alignment', () => {
  let server;
  let serverPort;
  let userA;
  let userB;
  let sessionA;
  let sessionB;
  let tokenA;
  let tokenB;
  let adminToken;
  let origAdminKey;

  beforeAll(async () => {
    origAdminKey = process.env.ACTIONGUARD_ADMIN_API_KEY;
    process.env.ACTIONGUARD_ADMIN_API_KEY = TEST_ADMIN_KEY;

    await runMigrations();

    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await PolicyDecision.destroy({ where: {}, force: true });
    await RiskAssessment.destroy({ where: {}, force: true });
    await SequenceEvent.destroy({ where: {}, force: true });
    await ActionSequence.destroy({ where: {}, force: true });
    await SecurityEvent.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    const passwordHash = await bcrypt.hash(TEST_PASSWORD, 10);
    userA = await User.create({
      id: `usr_${crypto.randomUUID()}`,
      email: 'alice.test@example.com',
      password_hash: passwordHash
    });

    userB = await User.create({
      id: `usr_${crypto.randomUUID()}`,
      email: 'bob.test@example.com',
      password_hash: passwordHash
    });

    const sessionDataA = await createSession(userA.id, userA.email, 3600);
    sessionA = await Session.findByPk(sessionDataA.sessionId);

    const sessionDataB = await createSession(userB.id, userB.email, 3600);
    sessionB = await Session.findByPk(sessionDataB.sessionId);

    tokenA = jwt.sign(
      { id: userA.id, email: userA.email, session_id: sessionA.id },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    tokenB = jwt.sign(
      { id: userB.id, email: userB.email, session_id: sessionB.id },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Ephemeral HTTP server for Socket.IO testing
    server = http.createServer(app);
    await new Promise((resolve) => {
      server.listen(0, () => {
        serverPort = server.address().port;
        resolve();
      });
    });

    initSocketServer(server, { revalidationIntervalMs: 50 });

    const adminTokRes = await createAdminToken();
    adminToken = adminTokRes.admin_token;
  });

  afterAll(async () => {
    process.env.ACTIONGUARD_ADMIN_API_KEY = origAdminKey;

    await closeSocketServer();
    if (server && server.listening) {
      await new Promise((resolve) => server.close(resolve));
    }

    const redis = getRedisClient();
    if (typeof redis.keys === 'function') {
      const keys = await redis.keys(`${REDIS_PREFIXES.ADMIN_TOKEN}*`);
      if (keys.length > 0) {
        await redis.del(...keys);
      }
    } else if (redis.store && typeof redis.store.clear === 'function') {
      redis.store.clear();
    }
  });

  // ---------------------------------------------------------------------------
  // 1. Admin Authentication & Token Lifecycle
  // ---------------------------------------------------------------------------
  describe('1. Admin Auth & Token Lifecycle', () => {
    test('1.1 correct key exchanges for admin token with expected expiry and format', async () => {
      const res = await request(app)
        .post('/api/v1/admin/auth/login')
        .send({ admin_key: TEST_ADMIN_KEY })
        .expect(200);

      expect(typeof res.body.admin_token).toBe('string');
      expect(res.body.admin_token.startsWith('agadm_')).toBe(true);
      expect(typeof res.body.expires_at).toBe('string');
      expect(new Date(res.body.expires_at).getTime()).toBeGreaterThan(Date.now());

      adminToken = res.body.admin_token;
    });

    test('1.2 short key (<32 chars) rejected at login with generic 401', async () => {
      const shortKey = '1234567890123456789012345678901'; // 31 chars
      const res = await request(app)
        .post('/api/v1/admin/auth/login')
        .send({ admin_key: shortKey })
        .expect(401);

      expect(res.body.error).toBe('unauthorized');
      expect(res.body.message).toBe('Invalid admin credentials');
    });

    test('1.3 unset key rejects login with generic 401', async () => {
      const orig = process.env.ACTIONGUARD_ADMIN_API_KEY;
      delete process.env.ACTIONGUARD_ADMIN_API_KEY;

      const res = await request(app)
        .post('/api/v1/admin/auth/login')
        .send({ admin_key: TEST_ADMIN_KEY })
        .expect(401);

      expect(res.body.error).toBe('unauthorized');
      expect(res.body.message).toBe('Invalid admin credentials');

      process.env.ACTIONGUARD_ADMIN_API_KEY = orig;
    });

    test('1.4 raw admin key rejected on /api/v1/admin/* read routes (Bearer and X-Admin-Api-Key)', async () => {
      // Rejection when passed in Authorization: Bearer <raw-key>
      await request(app)
        .get('/api/v1/admin/users')
        .set('Authorization', `Bearer ${TEST_ADMIN_KEY}`)
        .expect(401);

      // Rejection when passed in X-Admin-Api-Key
      await request(app)
        .get('/api/v1/admin/users')
        .set('X-Admin-Api-Key', TEST_ADMIN_KEY)
        .expect(401);
    });

    test('1.5 user JWT rejected on /api/v1/admin/* read routes', async () => {
      const res = await request(app)
        .get('/api/v1/admin/users')
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(401);

      const errCode = typeof res.body.error === 'object' ? res.body.error.code : res.body.error;
      expect(errCode).toBe('unauthorized');
    });

    test('1.6 valid admin token accepted on /api/v1/admin/* read routes', async () => {
      const res = await request(app)
        .get('/api/v1/admin/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(Array.isArray(res.body.users)).toBe(true);
      expect(typeof res.body.total).toBe('number');
    });

    test('1.7 query parameter token rejected on REST endpoint', async () => {
      // Query param token must NOT be accepted
      await request(app)
        .get(`/api/v1/admin/users?admin_token=${adminToken}`)
        .expect(401);

      await request(app)
        .get(`/api/v1/admin/users?token=${adminToken}`)
        .expect(401);
    });

    test('1.8 token is stored in Redis ONLY as SHA-256 hash (never raw token)', async () => {
      const redis = getRedisClient();
      const rawVal = await redis.get(adminToken);
      expect(rawVal).toBeNull();

      const tokenHash = hashAdminToken(adminToken);
      const hashKey = `${REDIS_PREFIXES.ADMIN_TOKEN}${tokenHash}`;
      const hashVal = await redis.get(hashKey);
      expect(hashVal).not.toBeNull();
      expect(hashVal).not.toContain(adminToken);
    });

    test('1.9 logout revokes token immediately in Redis', async () => {
      const { admin_token: logoutTok } = await createAdminToken();

      // Ensure valid before logout
      await request(app)
        .get('/api/v1/admin/users')
        .set('Authorization', `Bearer ${logoutTok}`)
        .expect(200);

      // Call logout
      await request(app)
        .post('/api/v1/admin/auth/logout')
        .set('Authorization', `Bearer ${logoutTok}`)
        .expect(200);

      // Subsequent call must return 401
      await request(app)
        .get('/api/v1/admin/users')
        .set('Authorization', `Bearer ${logoutTok}`)
        .expect(401);
    });

    test('1.10 sliding idle TTL refreshed on use; absolute cap strictly enforced', async () => {
      const baseNow = Date.now();
      const tokenResult = await createAdminToken({
        now: baseNow,
        idleTtlSeconds: 100,
        maxLifetimeSeconds: 200
      });
      const testTok = tokenResult.admin_token;

      // Validate at +50s: should slide
      const val1 = await validateAdminToken(testTok, { now: baseNow + 50 * 1000, touch: true });
      expect(val1).toBeDefined();

      // Validate at +150s: within absolute cap (200s), slides again
      const val2 = await validateAdminToken(testTok, { now: baseNow + 150 * 1000, touch: true });
      expect(val2).toBeDefined();

      // Validate at +201s: exceeds absolute cap (200s) -> strictly rejected
      const val3 = await validateAdminToken(testTok, { now: baseNow + 201 * 1000, touch: true });
      expect(val3).toBeNull();

      // Token should now be removed from Redis
      const val4 = await validateAdminToken(testTok, { now: baseNow + 202 * 1000 });
      expect(val4).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Socket.IO Real-time Admin Connection
  // ---------------------------------------------------------------------------
  describe('2. Socket.IO Real-time Connection', () => {
    test('2.1 handshake accepts valid adminToken and joins admin:stream room', async () => {
      const client = createClient(serverPort, {
        auth: { adminToken }
      });

      await connectClient(client);
      expect(client.connected).toBe(true);

      const io = getSocketServer();
      const adminSockets = await io.in('admin:stream').fetchSockets();
      const found = adminSockets.find((s) => s.id === client.id);
      expect(found).toBeDefined();

      client.disconnect();
    });

    test('2.2 handshake strictly rejects invalid or expired adminToken', async () => {
      const client = createClient(serverPort, {
        auth: { adminToken: 'agadm_invalid_token_12345' }
      });

      await expect(connectClient(client)).rejects.toThrow();
      expect(client.connected).toBe(false);
    });

    test('2.3 handshake strictly rejects admin token in query parameter', async () => {
      const client = createClient(serverPort, {
        query: { adminToken }
      });

      await expect(connectClient(client)).rejects.toThrow();
      expect(client.connected).toBe(false);
    });

    test('2.4 disconnects client when admin token is revoked mid-connection on tick', async () => {
      const { admin_token: streamTok } = await createAdminToken();

      const client = createClient(serverPort, {
        auth: { adminToken: streamTok }
      });

      await connectClient(client);
      expect(client.connected).toBe(true);

      // Revoke the token in Redis
      await revokeAdminToken(streamTok);

      // Poll until client is disconnected on the socket server tick
      const disconnected = await waitForCondition(() => !client.connected, 3000, 30);
      expect(disconnected).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // 3. REST Alignment & Tier-only Contract Verification
  // ---------------------------------------------------------------------------
  describe('3. REST Alignment & Tier-only Contract', () => {
    test('3.1 GET /api/v1/sessions/:id returns tier-only risk fields; strips score and signals', async () => {
      // Seed a risk assessment for sessionA
      await RiskAssessment.create({
        id: `ra_${crypto.randomUUID()}`,
        user_id: userA.id,
        session_id: sessionA.id,
        risk_score: 42,
        risk_tier: 'medium',
        contributing_signals: [{ signal: 'unrecognized_device', category: 'device', weight: 42 }],
        evaluated_at: new Date(),
        explanation: {
          user_facing: 'Activity from a new device was observed.',
          admin_facing: 'Device fingerprint unrecognized.'
        }
      });

      const res = await request(app)
        .get(`/api/v1/sessions/${sessionA.id}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);

      expect(res.body.risk).toBeDefined();
      expect(res.body.risk.risk_tier).toBe('medium');
      expect(typeof res.body.risk.evaluated_at).toBe('string');
      expect(res.body.risk.explanation).toBeDefined();
      expect(typeof res.body.risk.explanation.user_facing).toBe('string');

      // Stripped fields must be undefined
      expect(res.body.risk.current_risk_score).toBeUndefined();
      expect(res.body.risk.risk_score).toBeUndefined();
      expect(res.body.risk.contributing_signals).toBeUndefined();
      expect(res.body.risk.explanation.admin_facing).toBeUndefined();
    });

    test('3.2 POST /api/v1/risk/evaluate returns tier-only risk fields; strips score and signals', async () => {
      const res = await request(app)
        .post('/api/v1/risk/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          session_id: sessionA.id,
          event_type: 'login_success',
          metadata: { action_sensitivity: 'low' }
        })
        .expect(200);

      expect(['low', 'medium', 'high', 'critical']).toContain(res.body.risk_tier);
      expect(typeof res.body.evaluated_at).toBe('string');
      expect(res.body.explanation).toBeDefined();
      expect(typeof res.body.explanation.user_facing).toBe('string');

      // Stripped fields must be undefined
      expect(res.body.risk_score).toBeUndefined();
      expect(res.body.current_risk_score).toBeUndefined();
      expect(res.body.contributing_signals).toBeUndefined();
      expect(res.body.explanation.admin_facing).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // 4. User Read Endpoints (/api/v1/me/*)
  // ---------------------------------------------------------------------------
  describe('4. User Read Endpoints (/api/v1/me/*)', () => {
    test('4.1 GET /api/v1/me/sessions returns user sessions with tier-only risk and is_current', async () => {
      const res = await request(app)
        .get('/api/v1/me/sessions')
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);

      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBeGreaterThanOrEqual(1);

      const s = res.body.find((item) => item.session_id === sessionA.id);
      expect(s).toBeDefined();
      expect(s.is_current).toBe(true);
      expect(s.risk_tier).toBe('medium');
      expect(s.risk_score).toBeUndefined();
    });

    test('4.2 GET /api/v1/me/events returns user events without user_id; validates pagination', async () => {
      // Seed an event for userA
      await SecurityEvent.create({
        event_id: `evt_${crypto.randomUUID()}`,
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'login_success',
        timestamp: new Date(),
        metadata: { action_sensitivity: 'low' }
      });

      const res = await request(app)
        .get('/api/v1/me/events?limit=10')
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);

      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBeGreaterThanOrEqual(1);
      const ev = res.body[0];
      expect(ev.event_id).toBeDefined();
      expect(ev.session_id).toBe(sessionA.id);
      // Privacy invariant: user_id must NOT be present
      expect(ev.user_id).toBeUndefined();

      // Invalid limit rejected
      await request(app)
        .get('/api/v1/me/events?limit=0')
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(400);

      // Invalid before rejected
      await request(app)
        .get('/api/v1/me/events?before=invalid-date')
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(400);
    });

    test('4.3 GET /api/v1/me/risk-history returns tier-only history; returns 404 for another user session', async () => {
      const res = await request(app)
        .get('/api/v1/me/risk-history')
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);

      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBeGreaterThanOrEqual(1);
      expect(res.body[0].risk_tier).toBeDefined();
      expect(res.body[0].risk_score).toBeUndefined();

      // Querying session owned by userB returns 404
      await request(app)
        .get(`/api/v1/me/risk-history?session_id=${sessionB.id}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(404);
    });

    test('4.4 GET /api/v1/me/decisions returns user policy decisions', async () => {
      await PolicyDecision.create({
        id: `dec_${crypto.randomUUID()}`,
        user_id: userA.id,
        session_id: sessionA.id,
        action_type: 'login',
        action_sensitivity: 'low',
        risk_score: 10,
        risk_tier: 'low',
        recommended_decision: 'allow',
        effective_decision: 'allow',
        enforcement_outcome: 'allowed',
        enforcement_mode: 'automatic',
        policy_version: '1.0.0',
        decided_at: new Date(),
        explanation: {
          user_facing: 'Action permitted.',
          admin_facing: 'Low risk action allowed.'
        }
      });

      const res = await request(app)
        .get('/api/v1/me/decisions')
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);

      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBeGreaterThanOrEqual(1);
      const dec = res.body[0];
      expect(dec.decision_id).toBeDefined();
      expect(dec.decision).toBe('allow');
      expect(dec.risk_tier).toBe('low');
      // Stripped fields
      expect(dec.user_id).toBeUndefined();
      expect(dec.risk_score).toBeUndefined();
      expect(dec.explanation.admin_facing).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // 5. Admin Read Endpoints (/api/v1/admin/*)
  // ---------------------------------------------------------------------------
  describe('5. Admin Read Endpoints (/api/v1/admin/*)', () => {
    test('5.1 GET /api/v1/admin/users lists users with email prefix search, active sessions, and latest risk tier', async () => {
      // Create user with underscore in email to verify LIKE escaping
      const specialUser = await User.create({
        id: `usr_${crypto.randomUUID()}`,
        email: 'special_user@example.com',
        password_hash: 'hash'
      });

      const res = await request(app)
        .get('/api/v1/admin/users?search=special_')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(res.body.users).toBeDefined();
      expect(res.body.users.length).toBe(1);
      expect(res.body.users[0].email).toBe('special_user@example.com');
      expect(res.body.users[0].active_sessions).toBe(0);
      expect(res.body.total).toBe(1);

      // Pagination check
      const pageRes = await request(app)
        .get('/api/v1/admin/users?limit=1&offset=0')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(pageRes.body.users.length).toBe(1);
      expect(pageRes.body.total).toBeGreaterThanOrEqual(3);

      await specialUser.destroy();
    });

    test('5.2 GET /api/v1/admin/users/:id/events returns full admin events; 404 on unknown user', async () => {
      const res = await request(app)
        .get(`/api/v1/admin/users/${userA.id}/events`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body[0].user_id).toBe(userA.id);

      await request(app)
        .get('/api/v1/admin/users/usr_nonexistent/events')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(404);
    });

    test('5.3 GET /api/v1/admin/users/:id/risk-history returns full admin risk history; 404 on unknown user', async () => {
      const res = await request(app)
        .get(`/api/v1/admin/users/${userA.id}/risk-history`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body[0].user_id).toBe(userA.id);
      expect(typeof res.body[0].risk_score).toBe('number');
      expect(Array.isArray(res.body[0].contributing_signals)).toBe(true);
      expect(res.body[0].explanation.admin_facing).toBeDefined();

      await request(app)
        .get('/api/v1/admin/users/usr_nonexistent/risk-history')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(404);
    });

    test('5.4 GET /api/v1/admin/users/:id/decisions returns full admin decisions; 404 on unknown user', async () => {
      const res = await request(app)
        .get(`/api/v1/admin/users/${userA.id}/decisions`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body[0].user_id).toBe(userA.id);
      expect(res.body[0].risk_score).toBe(10);
      expect(res.body[0].explanation.admin_facing).toBeDefined();

      await request(app)
        .get('/api/v1/admin/users/usr_nonexistent/decisions')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(404);
    });

    test('5.5 GET /api/v1/admin/users/:id/sessions returns admin sessions with risk details; 404 on unknown user', async () => {
      const res = await request(app)
        .get(`/api/v1/admin/users/${userA.id}/sessions`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(Array.isArray(res.body)).toBe(true);
      const s = res.body.find((item) => item.session_id === sessionA.id);
      expect(s).toBeDefined();
      expect(s.user_id).toBe(userA.id);
      expect(s.risk_tier).toBe('medium');
      expect(s.risk_score).toBe(42);

      await request(app)
        .get('/api/v1/admin/users/usr_nonexistent/sessions')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(404);
    });

    test('5.6 GET /api/v1/admin/users/:id/sequence returns active sequence; returns { sequence: null } if none', async () => {
      // User with no sequence returns { sequence: null }
      const resEmpty = await request(app)
        .get(`/api/v1/admin/users/${userB.id}/sequence`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(resEmpty.body.sequence).toBeNull();

      // Seed a sequence for userA
      const seq = await ActionSequence.create({
        id: `seq_${crypto.randomUUID()}`,
        user_id: userA.id,
        session_id: sessionA.id,
        started_at: new Date(),
        last_event_at: new Date(),
        event_count: 0
      });

      const resSeq = await request(app)
        .get(`/api/v1/admin/users/${userA.id}/sequence`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(resSeq.body.sequence).toBeDefined();
      expect(resSeq.body.sequence.id).toBe(seq.id);
      expect(Array.isArray(resSeq.body.sequence.events)).toBe(true);

      await request(app)
        .get('/api/v1/admin/users/usr_nonexistent/sequence')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(404);
    });

    test('5.7 GET /api/v1/admin/policy returns active policy summary', async () => {
      const res = await request(app)
        .get('/api/v1/admin/policy')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(res.body.policy_id).toBeDefined();
      expect(res.body.schema_version).toBeDefined();
      expect(res.body.description).toBeDefined();
    });

    test('5.8 GET /api/v1/admin/overview returns pure SQL aggregates over time window', async () => {
      // Seed decisions with various outcomes
      await PolicyDecision.create({
        id: `dec_${crypto.randomUUID()}`,
        user_id: userA.id,
        session_id: sessionA.id,
        action_type: 'password_change',
        action_sensitivity: 'critical',
        risk_score: 90,
        risk_tier: 'critical',
        recommended_decision: 'block',
        effective_decision: 'block',
        enforcement_outcome: 'contained_and_blocked',
        enforcement_mode: 'automatic',
        policy_version: '1.0.0',
        decided_at: new Date()
      });

      const res = await request(app)
        .get('/api/v1/admin/overview?window=24h')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(res.body.window).toBe('24h');
      expect(new Date(res.body.window_start).getTime()).toBeLessThan(new Date(res.body.window_end).getTime());

      // Decisions by outcome check
      expect(res.body.decisions_by_outcome).toBeDefined();
      expect(res.body.decisions_by_outcome.contained_and_blocked).toBeGreaterThanOrEqual(1);
      expect(res.body.decisions_by_outcome.allow).toBeGreaterThanOrEqual(1);

      // Assessments by tier check
      expect(res.body.assessments_by_tier).toBeDefined();
      expect(res.body.assessments_by_tier.medium).toBeGreaterThanOrEqual(1);

      // Active & contained sessions
      expect(typeof res.body.active_sessions).toBe('number');
      expect(res.body.active_sessions).toBeGreaterThanOrEqual(2);
      expect(res.body.contained_sessions).toBeGreaterThanOrEqual(1);
    });

    test('5.9 GET /api/v1/admin/overview rejects invalid window parameters (> 7d or invalid string)', async () => {
      await request(app)
        .get('/api/v1/admin/overview?window=8d')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(400);

      await request(app)
        .get('/api/v1/admin/overview?window=invalid')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(400);
    });
  });

  // ---------------------------------------------------------------------------
  // 6. Security & Rate Limiting Invariants
  // ---------------------------------------------------------------------------
  describe('6. Security & Rate Limiting Invariants', () => {
    test('6.1 no secrets/keys logged or leaked in responses', async () => {
      const res = await request(app)
        .get(`/api/v1/admin/users/${userA.id}/sessions`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      const jsonStr = JSON.stringify(res.body);
      expect(jsonStr).not.toContain(TEST_ADMIN_KEY);
      expect(jsonStr).not.toContain(adminToken);
      expect(jsonStr).not.toContain('Password123!');
      expect(jsonStr).not.toContain(JWT_SECRET);
    });
  });

  // ---------------------------------------------------------------------------
  // 7. Closeout Invariant & Privacy Tests
  // ---------------------------------------------------------------------------
  describe('7. Closeout Invariant & Privacy Tests', () => {
    test('admin token rejected on /me/*', async () => {
      // Admin token should not be accepted as user JWT Bearer token
      await request(app)
        .get('/api/v1/me/sessions')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(401);

      await request(app)
        .get('/api/v1/me/events')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(401);

      await request(app)
        .get('/api/v1/me/risk-history')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(401);

      await request(app)
        .get('/api/v1/me/decisions')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(401);
    });

    test('unset, short and empty admin keys all give the same 401 as a wrong key', async () => {
      const wrongKey = 'wrong_admin_key_with_at_least_32_characters_12345';
      const shortKey = 'short_key_under_32_chars';
      const emptyKey = '';

      const resWrong = await request(app)
        .post('/api/v1/admin/auth/login')
        .send({ admin_key: wrongKey })
        .expect(401);

      const resShort = await request(app)
        .post('/api/v1/admin/auth/login')
        .send({ admin_key: shortKey })
        .expect(401);

      const resEmpty = await request(app)
        .post('/api/v1/admin/auth/login')
        .send({ admin_key: emptyKey })
        .expect(401);

      const resUnset = await request(app)
        .post('/api/v1/admin/auth/login')
        .send({})
        .expect(401);

      const expectedShape = {
        error: 'unauthorized',
        message: 'Invalid admin credentials'
      };

      expect(resWrong.body).toEqual(expectedShape);
      expect(resShort.body).toEqual(expectedShape);
      expect(resEmpty.body).toEqual(expectedShape);
      expect(resUnset.body).toEqual(expectedShape);
    });

    test('login rate limit', async () => {
      const origMax = process.env.RATE_LIMIT_AUTH_MAX;
      process.env.RATE_LIMIT_AUTH_MAX = '3';

      try {
        // First 3 requests should be accepted (even if 401 due to bad key)
        for (let i = 0; i < 3; i++) {
          await request(app)
            .post('/api/v1/admin/auth/login')
            .send({ admin_key: 'dummy' });
        }

        // 4th request must be rate limited with 429
        const res = await request(app)
          .post('/api/v1/admin/auth/login')
          .send({ admin_key: 'dummy' })
          .expect(429);

        expect(res.body.error.code).toBe('rate_limited');
      } finally {
        if (origMax !== undefined) {
          process.env.RATE_LIMIT_AUTH_MAX = origMax;
        } else {
          delete process.env.RATE_LIMIT_AUTH_MAX;
        }
      }
    });

    test('a handshake with both adminToken and token is rejected', async () => {
      const client = createClient(serverPort, {
        auth: { adminToken, token: tokenA }
      });
      await expect(connectClient(client)).rejects.toThrow('unauthorized');
      client.close();
    });

    test('an expired or revoked adminToken is rejected at handshake', async () => {
      const tokRes = await createAdminToken();
      await revokeAdminToken(tokRes.admin_token);

      const client = createClient(serverPort, {
        auth: { adminToken: tokRes.admin_token }
      });
      await expect(connectClient(client)).rejects.toThrow('unauthorized');
      client.close();
    });

    test('SQL metacharacters in the user search', async () => {
      const metaUser = await User.create({
        id: `usr_${crypto.randomUUID()}`,
        email: 'meta_%_user@example.com',
        password_hash: await bcrypt.hash(TEST_PASSWORD, 10)
      });

      // Searching for 'meta_%' matches the exact literal prefix
      const matchRes = await request(app)
        .get('/api/v1/admin/users?search=meta_%')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);
      expect(matchRes.body.users.some((u) => u.email === 'meta_%_user@example.com')).toBe(true);

      // Searching for 'meta_x' does not match because '_' is not treated as wildcard
      const noMatchRes = await request(app)
        .get('/api/v1/admin/users?search=meta_x')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);
      expect(noMatchRes.body.users.some((u) => u.email === 'meta_%_user@example.com')).toBe(false);

      await metaUser.destroy();
    });

    test('overview counts match seeded data', async () => {
      const now = new Date();
      // Seed isolated decisions and assessments
      const testEvent = await SecurityEvent.create({
        event_id: `evt_overview_${crypto.randomUUID()}`,
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'login_success',
        timestamp: now,
        ip_address: '10.0.0.1',
        user_agent: 'TestAgent'
      });

      const dec1 = await PolicyDecision.create({
        id: `dec_${crypto.randomUUID()}`,
        event_id: testEvent.event_id,
        user_id: userA.id,
        session_id: sessionA.id,
        action_type: 'password_change',
        action_sensitivity: 'critical',
        risk_score: 10,
        risk_tier: 'low',
        recommended_decision: 'allow',
        effective_decision: 'allow',
        enforcement_outcome: 'allowed',
        enforcement_mode: 'automatic',
        policy_version: 'default-v1@1.0.0',
        reasons: [],
        contributing_signals: [],
        explanation: { user_facing: '', admin_facing: '' },
        decided_at: now
      });

      const res = await request(app)
        .get('/api/v1/admin/overview?window=24h')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(res.body.decisions_by_outcome.allow).toBeGreaterThanOrEqual(1);
      expect(typeof res.body.active_sessions).toBe('number');
      expect(typeof res.body.contained_sessions).toBe('number');
      expect(typeof res.body.assessments_by_tier.low).toBe('number');

      await dec1.destroy();
      await testEvent.destroy();
    });

    test('exact key sets for each admin response', async () => {
      // 1. /admin/auth/login
      const loginRes = await request(app)
        .post('/api/v1/admin/auth/login')
        .send({ admin_key: TEST_ADMIN_KEY })
        .expect(200);
      expect(Object.keys(loginRes.body).sort()).toEqual(['admin_token', 'expires_at'].sort());

      // 2. /admin/auth/logout
      const logoutRes = await request(app)
        .post('/api/v1/admin/auth/logout')
        .set('Authorization', `Bearer ${loginRes.body.admin_token}`)
        .expect(200);
      expect(Object.keys(logoutRes.body).sort()).toEqual(['message'].sort());

      // 3. /admin/users
      const usersRes = await request(app)
        .get('/api/v1/admin/users?limit=1')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);
      expect(Object.keys(usersRes.body).sort()).toEqual(['total', 'users'].sort());
      if (usersRes.body.users.length > 0) {
        expect(Object.keys(usersRes.body.users[0]).sort()).toEqual(
          ['active_sessions', 'created_at', 'email', 'id', 'latest_risk_at', 'latest_risk_tier', 'locked_until'].sort()
        );
      }

      // 4. /admin/users/:id/events
      const eventsRes = await request(app)
        .get(`/api/v1/admin/users/${userA.id}/events?limit=1`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);
      if (eventsRes.body.length > 0) {
        expect(Object.keys(eventsRes.body[0]).sort()).toEqual(
          ['coarse_location', 'device_ref', 'event_id', 'event_type', 'session_id', 'timestamp', 'user_id'].sort()
        );
      }

      // 5. /admin/users/:id/risk-history
      const riskRes = await request(app)
        .get(`/api/v1/admin/users/${userA.id}/risk-history?limit=1`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);
      if (riskRes.body.length > 0) {
        expect(Object.keys(riskRes.body[0]).sort()).toEqual(
          ['contributing_signals', 'evaluated_at', 'event_id', 'explanation', 'id', 'risk_score', 'risk_tier', 'session_id', 'user_id'].sort()
        );
      }

      // 6. /admin/users/:id/decisions
      const decRes = await request(app)
        .get(`/api/v1/admin/users/${userA.id}/decisions?limit=1`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);
      if (decRes.body.length > 0) {
        expect(Object.keys(decRes.body[0]).sort()).toEqual(
          ['action_sensitivity', 'action_type', 'contributing_signals', 'decided_at', 'decision_id', 'effective_decision', 'enforcement_mode', 'enforcement_outcome', 'event_id', 'explanation', 'policy_version', 'reasons', 'recommended_decision', 'risk_assessment_id', 'risk_score', 'risk_tier', 'session_id', 'user_id'].sort()
        );
      }

      // 7. /admin/users/:id/sessions
      const sessRes = await request(app)
        .get(`/api/v1/admin/users/${userA.id}/sessions`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);
      if (sessRes.body.length > 0) {
        expect(Object.keys(sessRes.body[0]).sort()).toEqual(
          ['coarse_location', 'created_at', 'device_ref', 'evaluated_at', 'expires_at', 'is_active', 'risk_score', 'risk_tier', 'session_id', 'user_id'].sort()
        );
      }

      // 8. /admin/users/:id/sequence
      const seqRes = await request(app)
        .get(`/api/v1/admin/users/${userA.id}/sequence`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);
      expect(Object.keys(seqRes.body).sort()).toEqual(['sequence'].sort());

      // 9. /admin/policy
      const polRes = await request(app)
        .get('/api/v1/admin/policy')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);
      expect(Object.keys(polRes.body).sort()).toEqual(
        [
          'ACCOUNT_MODIFICATION_TYPES',
          'BASE_MATRIX',
          'DECISION_ORDER',
          'DEFAULT_ACTION_SENSITIVITY',
          'ENFORCEMENT_MODE_BY_DECISION',
          'ESCALATION_RULES',
          'FAIL_SAFE_BY_SENSITIVITY',
          'RECOMMENDED_ACTIONS',
          'description',
          'policy_id',
          'schema_version'
        ].sort()
      );

      // 10. /admin/overview
      const overRes = await request(app)
        .get('/api/v1/admin/overview?window=24h')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);
      expect(Object.keys(overRes.body).sort()).toEqual(
        ['active_sessions', 'assessments_by_tier', 'contained_sessions', 'decisions_by_outcome', 'window', 'window_end', 'window_start'].sort()
      );
    });

    test('ordering of /me endpoints (time DESC with a deterministic tie-break)', async () => {
      const fixedTime = new Date('2026-10-15T12:00:00.000Z');

      const ev1 = await SecurityEvent.create({
        event_id: 'evt_tie_1',
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'login_success',
        timestamp: fixedTime,
        ip_address: '127.0.0.1'
      });
      const ev2 = await SecurityEvent.create({
        event_id: 'evt_tie_2',
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'login_success',
        timestamp: fixedTime,
        ip_address: '127.0.0.1'
      });
      const ev3 = await SecurityEvent.create({
        event_id: 'evt_tie_3',
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'login_success',
        timestamp: fixedTime,
        ip_address: '127.0.0.1'
      });

      const resEvents = await request(app)
        .get('/api/v1/me/events?limit=10')
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);

      const tieEvents = resEvents.body.filter((e) => e.event_id && e.event_id.startsWith('evt_tie_'));
      expect(tieEvents.map((e) => e.event_id)).toEqual(['evt_tie_3', 'evt_tie_2', 'evt_tie_1']);

      await ev1.destroy();
      await ev2.destroy();
      await ev3.destroy();
    });

    test('Privacy: seeds events with a known IP, fingerprint and user agent, then serializes every admin and user response and asserts none of the raw values appears', async () => {
      const SENSITIVE_IP = '198.51.100.99';
      const SENSITIVE_FP = 'fp_super_secret_fingerprint_xyz';
      const SENSITIVE_UA = 'CustomSecretUserAgent/9.9.9';
      const SENSITIVE_LAT = 48.8566;
      const SENSITIVE_LONG = 2.3522;

      const privEvent = await SecurityEvent.create({
        event_id: `evt_priv_${crypto.randomUUID()}`,
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'login_success',
        timestamp: new Date(),
        context: {
          ip_address: SENSITIVE_IP,
          device_fingerprint: SENSITIVE_FP,
          user_agent: SENSITIVE_UA,
          geo_country: 'FR',
          geo_region: 'IDF',
          geo_city: 'Paris',
          geo_lat: SENSITIVE_LAT,
          geo_long: SENSITIVE_LONG
        }
      });

      const privAssessment = await RiskAssessment.create({
        id: `ass_priv_${crypto.randomUUID()}`,
        event_id: privEvent.event_id,
        user_id: userA.id,
        session_id: sessionA.id,
        risk_score: 25,
        risk_tier: 'low',
        contributing_signals: [{ signal: 'unrecognized_device', category: 'device', weight: 20 }],
        explanation: { user_facing: 'All good', admin_facing: 'Admin technical notes' },
        evaluated_at: new Date()
      });

      const privDecision = await PolicyDecision.create({
        event_id: privEvent.event_id,
        risk_assessment_id: privAssessment.id,
        user_id: userA.id,
        session_id: sessionA.id,
        action_type: 'login',
        action_sensitivity: 'low',
        risk_score: 25,
        risk_tier: 'low',
        recommended_decision: 'allow',
        effective_decision: 'allow',
        enforcement_outcome: 'allowed',
        enforcement_mode: 'automatic',
        policy_version: 'default-v1@1.0.0',
        reasons: [{ rule: 'rule_1', reason: 'benign' }],
        contributing_signals: [{ signal: 'unrecognized_device', category: 'device', weight: 20 }],
        explanation: { user_facing: 'Allowed', admin_facing: 'Admin details' },
        decided_at: new Date()
      });

      // Fetch all user and admin responses
      const endpoints = [
        // User endpoints
        request(app).get('/api/v1/me/sessions').set('Authorization', `Bearer ${tokenA}`),
        request(app).get('/api/v1/me/events').set('Authorization', `Bearer ${tokenA}`),
        request(app).get('/api/v1/me/risk-history').set('Authorization', `Bearer ${tokenA}`),
        request(app).get('/api/v1/me/decisions').set('Authorization', `Bearer ${tokenA}`),
        request(app).get(`/api/v1/sessions/${sessionA.id}`).set('Authorization', `Bearer ${tokenA}`),
        request(app)
          .post('/api/v1/risk/evaluate')
          .set('Authorization', `Bearer ${tokenA}`)
          .send({ user_id: userA.id, event_type: 'login_success', session_id: sessionA.id }),
        // Admin endpoints
        request(app).get('/api/v1/admin/users').set('Authorization', `Bearer ${adminToken}`),
        request(app).get(`/api/v1/admin/users/${userA.id}/events`).set('Authorization', `Bearer ${adminToken}`),
        request(app).get(`/api/v1/admin/users/${userA.id}/risk-history`).set('Authorization', `Bearer ${adminToken}`),
        request(app).get(`/api/v1/admin/users/${userA.id}/decisions`).set('Authorization', `Bearer ${adminToken}`),
        request(app).get(`/api/v1/admin/users/${userA.id}/sessions`).set('Authorization', `Bearer ${adminToken}`),
        request(app).get(`/api/v1/admin/users/${userA.id}/sequence`).set('Authorization', `Bearer ${adminToken}`),
        request(app).get('/api/v1/admin/overview?window=24h').set('Authorization', `Bearer ${adminToken}`)
      ];

      const responses = await Promise.all(endpoints);

      const expectedDeviceRef = crypto.createHash('sha256').update(SENSITIVE_FP).digest('hex').slice(0, 12);

      for (const res of responses) {
        if (res.status !== 200) {
          console.error('FAILED ENDPOINT:', res.request?.method, res.request?.url, res.status, res.body);
        }
        expect(res.status).toBe(200);
        const serialized = JSON.stringify(res.body);

        // Strict Privacy Assertions: NO raw identifiers or coordinates
        expect(serialized).not.toContain(SENSITIVE_IP);
        expect(serialized).not.toContain(SENSITIVE_FP);
        expect(serialized).not.toContain(SENSITIVE_UA);
        expect(serialized).not.toContain(String(SENSITIVE_LAT));
        expect(serialized).not.toContain(String(SENSITIVE_LONG));
      }

      // Assert device_ref and coarse_location are properly populated in admin events
      const adminEventsRes = responses[7]; // GET /api/v1/admin/users/:id/events
      const matchingEvent = adminEventsRes.body.find((e) => e.event_id === privEvent.event_id);
      expect(matchingEvent).toBeDefined();
      expect(matchingEvent.device_ref).toBe(expectedDeviceRef);
      expect(matchingEvent.coarse_location).toEqual({ country: 'FR', region: 'IDF' });

      // Clean up
      await privDecision.destroy();
      await privAssessment.destroy();
      await privEvent.destroy();
    });
  });
});
