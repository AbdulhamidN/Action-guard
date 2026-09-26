const request = require('supertest');
const app = require('../src/app');
const { sequelize, User, Session } = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const { getSession, getSessionTTL } = require('../src/storage/redis');
const { createSession } = require('../src/services/sessionService');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../src/middleware/auth');

describe('Sub-module 1.4 — Session Creation & Redis Storage', () => {
  beforeAll(async () => {
    await runMigrations();
  });

  afterAll(async () => {
    await sequelize.close();
  });

  test('complete flow: signup -> login -> session created -> GET /api/v1/me -> logout -> old session rejected', async () => {
    // 1. Signup
    const signupRes = await request(app)
      .post('/api/v1/auth/signup')
      .send({
        email: 'flow-user@example.com',
        password: 'Password123!'
      })
      .expect(201);

    const userId = signupRes.body.id;
    expect(userId).toBeDefined();

    // 2. Login
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({
        email: 'flow-user@example.com',
        password: 'Password123!'
      })
      .expect(200);

    const { token, session_id } = loginRes.body;
    expect(token).toBeDefined();
    expect(session_id).toBeDefined();

    // 3. Verify MySQL session is created and active
    const mysqlSession = await Session.findByPk(session_id);
    expect(mysqlSession).not.toBeNull();
    expect(mysqlSession.user_id).toBe(userId);
    expect(mysqlSession.is_active).toBe(true);

    // 4. Verify Redis session is created and active
    const redisSession = await getSession(session_id);
    expect(redisSession).not.toBeNull();
    expect(redisSession.user_id).toBe(userId);
    expect(redisSession.is_active).toBe(true);

    // 5. Verify Redis TTL is set
    const ttl = await getSessionTTL(session_id);
    expect(ttl).toBeGreaterThan(0);

    // 6. Access protected route GET /api/v1/me
    const meRes = await request(app)
      .get('/api/v1/me')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(meRes.body.id).toBe(userId);
    expect(meRes.body.email).toBe('flow-user@example.com');

    // 7. Logout
    const logoutRes = await request(app)
      .post('/api/v1/auth/logout')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(logoutRes.body.message).toBe('Successfully logged out');

    // 8. Verify Redis state removed
    const redisSessionAfterLogout = await getSession(session_id);
    expect(redisSessionAfterLogout).toBeNull();

    // 9. Verify MySQL session marked inactive
    const mysqlSessionAfterLogout = await Session.findByPk(session_id);
    expect(mysqlSessionAfterLogout.is_active).toBe(false);

    // 10. Verify old session is rejected on subsequent request
    const rejectedRes = await request(app)
      .get('/api/v1/me')
      .set('Authorization', `Bearer ${token}`)
      .expect(401);

    expect(rejectedRes.body.error).toBeDefined();
    expect(rejectedRes.body.error.code).toBe('invalid_session');
  });

  test('Redis session expires according to TTL', async () => {
    // Create test user
    const user = await User.create({
      email: 'ttl-test@example.com',
      password_hash: 'dummyhash'
    });

    // Create session with 1 second TTL
    const { sessionId, ttlSeconds } = await createSession(user.id, user.email, 1);
    expect(ttlSeconds).toBe(1);

    const ttlInitial = await getSessionTTL(sessionId);
    expect(ttlInitial).toBeGreaterThan(0);
    expect(ttlInitial).toBeLessThanOrEqual(1);

    // Wait 1.1 seconds for TTL expiration
    await new Promise((resolve) => setTimeout(resolve, 1100));

    const expiredRedisSession = await getSession(sessionId);
    expect(expiredRedisSession).toBeNull();

    // Token with expired session is rejected
    const token = jwt.sign(
      { id: user.id, email: user.email, session_id: sessionId },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    const res = await request(app)
      .get('/api/v1/me')
      .set('Authorization', `Bearer ${token}`)
      .expect(401);

    expect(res.body.error.code).toBe('invalid_session');
  });

  test('GET /api/v1/me rejects request without token', async () => {
    const res = await request(app)
      .get('/api/v1/me')
      .expect(401);

    expect(res.body.error.code).toBe('unauthorized');
  });

  test('GET /api/v1/me rejects request with malformed token', async () => {
    const res = await request(app)
      .get('/api/v1/me')
      .set('Authorization', 'InvalidFormat')
      .expect(401);

    expect(res.body.error.code).toBe('unauthorized');
  });
});
