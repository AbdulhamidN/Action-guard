'use strict';

const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../src/app');
const { User, Session } = require('../src/database/models');
const {
  createSession,
  invalidateSession,
  validateActiveSession,
  validateAndTouchSession,
  reconcileExpiredSessions,
  getSessionTTL
} = require('../src/services/sessionService');
const { getSession, storeSession, deleteSession } = require('../src/storage/redis');
const { JWT_SECRET } = require('../src/middleware/auth');
const {
  IDLE_TIMEOUT_SECONDS,
  MAX_SESSION_LIFETIME_SECONDS,
  RENEWAL_THROTTLE_SECONDS,
  loadAndValidateSessionConfig
} = require('../src/config/sessionConfig');

describe('Module 10a — Session Dual-Window Lifecycle (FR-23 & FR-25)', () => {
  let user;

  beforeEach(async () => {
    user = await User.create({
      email: `sess-test-${Date.now()}-${Math.random().toString(36).substring(7)}@example.com`,
      password_hash: 'dummyhash'
    });
  });

  // T1 (FR-23, FR-25): Session creation initializes idle timeout and absolute maximum lifetime
  test('T1 (FR-23, FR-25): Session creation initializes idle timeout and absolute maximum lifetime correctly in Redis and MySQL', async () => {
    const { sessionId, expiresAt, maxExpiresAt, ttlSeconds } = await createSession(
      user.id,
      user.email,
      IDLE_TIMEOUT_SECONDS,
      null,
      MAX_SESSION_LIFETIME_SECONDS
    );

    expect(sessionId).toMatch(/^sess_/);
    expect(ttlSeconds).toBe(IDLE_TIMEOUT_SECONDS);
    expect(maxExpiresAt.getTime()).toBeGreaterThan(expiresAt.getTime());

    // Verify MySQL record holds maxExpiresAt in expires_at column
    const dbRecord = await Session.findByPk(sessionId);
    expect(dbRecord).not.toBeNull();
    expect(dbRecord.is_active).toBe(true);
    expect(Math.abs(dbRecord.expires_at.getTime() - maxExpiresAt.getTime())).toBeLessThan(1000);

    // Verify Redis session holds dual-window metadata
    const redisRecord = await getSession(sessionId);
    expect(redisRecord).not.toBeNull();
    expect(redisRecord.is_active).toBe(true);
    expect(redisRecord.max_expires_at).toBe(maxExpiresAt.getTime());
    expect(redisRecord.idle_timeout_seconds).toBe(IDLE_TIMEOUT_SECONDS);
    expect(redisRecord.last_renewed_at).toBeDefined();

    const ttl = await getSessionTTL(sessionId);
    expect(ttl).toBeGreaterThan(IDLE_TIMEOUT_SECONDS - 5);
    expect(ttl).toBeLessThanOrEqual(IDLE_TIMEOUT_SECONDS);
  });

  // T2 (FR-23): Valid requests trigger sliding renewal only when write-throttle interval is reached, while passive checks never renew
  test('T2 (FR-23): Valid requests trigger sliding renewal only when write-throttle interval is reached, and passive checks do not renew', async () => {
    const customIdleTtl = 120;
    const { sessionId } = await createSession(user.id, user.email, customIdleTtl, null, 28800);
    const initialSession = await getSession(sessionId);
    const initialRenewedAt = initialSession.last_renewed_at;

    // 1. Immediate check (1 second elapsed) -> throttle should prevent write update
    const immediateRes = await validateAndTouchSession(sessionId, { nowMs: initialRenewedAt + 1000 });
    expect(immediateRes).not.toBeNull();
    expect(immediateRes.last_renewed_at).toBe(initialRenewedAt);

    // 2. Passive check (e.g., Socket.IO revalidation tick after 60s) -> must NOT renew even past throttle window
    const passiveTime = initialRenewedAt + 60 * 1000;
    const passiveRes = await validateActiveSession(sessionId, { nowMs: passiveTime });
    expect(passiveRes).not.toBeNull();
    expect(passiveRes.last_renewed_at).toBe(initialRenewedAt);

    // 3. Active request check past RENEWAL_THROTTLE_SECONDS (35s) -> renews using session's customIdleTtl (120s)
    const afterThrottleTime = initialRenewedAt + (RENEWAL_THROTTLE_SECONDS + 5) * 1000;
    const expectedRenewedIso = new Date(afterThrottleTime + customIdleTtl * 1000).toISOString();
    const throttledRenewRes = await validateAndTouchSession(sessionId, { nowMs: afterThrottleTime });
    expect(throttledRenewRes).not.toBeNull();
    expect(throttledRenewRes.last_renewed_at).toBe(afterThrottleTime);
    expect(throttledRenewRes.expires_at).toBe(expectedRenewedIso);

    // 4. Verify stored Redis session JSON and subsequent throttled read preserve renewed expires_at (F-4)
    const storedAfterRenew = await getSession(sessionId);
    expect(storedAfterRenew.last_renewed_at).toBe(afterThrottleTime);
    expect(storedAfterRenew.expires_at).toBe(expectedRenewedIso);

    const subsequentThrottledRes = await validateAndTouchSession(sessionId, {
      nowMs: afterThrottleTime + 5000
    });
    expect(subsequentThrottledRes.expires_at).toBe(expectedRenewedIso);

    const updatedTtl = await getSessionTTL(sessionId);
    expect(updatedTtl).toBeGreaterThan(customIdleTtl - 5);
    expect(updatedTtl).toBeLessThanOrEqual(customIdleTtl);
  });

  // T3 (FR-23, FR-25): Renewal never exceeds the absolute expiration
  test('T3 (FR-23, FR-25): Sliding renewal never exceeds the absolute maximum lifetime cap', async () => {
    const startTime = Date.now();
    const shortMaxLifetime = 60; // 60 seconds total lifetime cap
    const { sessionId } = await createSession(user.id, user.email, 900, null, shortMaxLifetime);

    // 40 seconds elapsed, only 20 seconds remaining until max lifetime
    const advancedTime = startTime + 40 * 1000;
    const renewRes = await validateAndTouchSession(sessionId, { nowMs: advancedTime });
    expect(renewRes).not.toBeNull();

    // The new TTL must be clamped to 20 seconds, NOT the full 900-second idle window
    const ttl = await getSessionTTL(sessionId);
    expect(ttl).toBeLessThanOrEqual(20);
    expect(ttl).toBeGreaterThan(0);
  });

  // T4 (FR-25): Session is rejected and removed when absolute lifetime expires
  test('T4 (FR-25): A session is rejected and deleted immediately when absolute lifetime expires', async () => {
    const startTime = Date.now();
    const maxLifetime = 100;
    const { sessionId } = await createSession(user.id, user.email, 900, null, maxLifetime);

    // Attempt to touch session when now >= maxExpiresAt
    const expiredTime = startTime + 105 * 1000;
    const res = await validateAndTouchSession(sessionId, { nowMs: expiredTime });
    expect(res).toBeNull();

    // Confirm session key was deleted in Redis
    const redisSession = await getSession(sessionId);
    expect(redisSession).toBeNull();
  });

  // T5 (FR-23, FR-25): Valid JWT rejected when Redis session is missing or idle-expired
  test('T5 (FR-23, FR-25): A validly signed JWT is rejected when its Redis session is missing or idle-expired', async () => {
    const { sessionId } = await createSession(user.id, user.email, 1, null, 28800);

    const token = jwt.sign(
      { id: user.id, email: user.email, session_id: sessionId },
      JWT_SECRET,
      { expiresIn: '8h' } // JWT valid for max session lifetime
    );

    // Delete session in Redis to simulate idle expiration
    await deleteSession(sessionId);

    const res = await request(app)
      .get('/api/v1/me')
      .set('Authorization', `Bearer ${token}`)
      .expect(401);

    expect(res.body.error).toBeDefined();
    expect(res.body.error.code).toBe('invalid_session');
  });

  // T6 (FR-23, FR-27): Concurrent logout and renewal cannot resurrect a session
  test('T6 (FR-23, FR-27): Concurrent logout and renewal via Promise.all cannot resurrect a deleted session', async () => {
    const { sessionId } = await createSession(user.id, user.email, 900, null, 28800);
    const futureNow = Date.now() + 50000;

    // Fire invalidation and sliding renewal concurrently
    await Promise.all([
      invalidateSession(sessionId),
      validateAndTouchSession(sessionId, { nowMs: futureNow })
    ]);

    // Regardless of which microtask ran first, once invalidateSession completes,
    // the session MUST NOT exist in Redis or be active in MySQL, and a subsequent touch MUST return null.
    const postRaceTouch = await validateAndTouchSession(sessionId, { nowMs: futureNow + 40000 });
    expect(postRaceTouch).toBeNull();

    const redisSession = await getSession(sessionId);
    expect(redisSession).toBeNull();

    const dbRecord = await Session.findByPk(sessionId);
    expect(dbRecord.is_active).toBe(false);
  });

  // T7 (FR-23, FR-25): Redis creation failure triggers safe compensating update
  test('T7 (FR-23, FR-25): Redis creation failure after database insert triggers safe compensation', async () => {
    const redis = require('../src/storage/redis');
    const originalStore = redis.storeSession;

    // Simulate Redis network / connection crash during session storage
    redis.storeSession = jest.fn().mockRejectedValue(new Error('Simulated Redis outage'));

    try {
      await expect(
        createSession(user.id, user.email, 900, null, 28800)
      ).rejects.toThrow('Simulated Redis outage');
    } finally {
      redis.storeSession = originalStore;
    }

    // Verify any created session in MySQL was marked inactive by compensation
    const inactiveSessions = await Session.findAll({
      where: { user_id: user.id, is_active: false }
    });
    expect(inactiveSessions.length).toBeGreaterThan(0);
  });

  // T8 (FR-25): Expired Redis sessions can be reconciled with MySQL without per-request DB queries, and config validation enforces invariants
  test('T8 (FR-25): Expired sessions reconcile in MySQL and sessionConfig rejects invalid or inconsistent settings', async () => {
    const pastDate = new Date(Date.now() - 5000);
    const staleSession = await Session.create({
      id: `sess_stale_${Date.now()}`,
      user_id: user.id,
      created_at: new Date(Date.now() - 60000),
      expires_at: pastDate,
      is_active: true
    });

    expect(staleSession.is_active).toBe(true);

    // Bounded sweeper reconciles stale rows
    const reconciledCount = await reconcileExpiredSessions({ now: new Date() });
    expect(reconciledCount).toBeGreaterThanOrEqual(1);

    const refreshed = await Session.findByPk(staleSession.id);
    expect(refreshed.is_active).toBe(false);

    // Verify configuration validation rejects malformed, zero, negative, and inverted settings
    expect(() =>
      loadAndValidateSessionConfig({ SESSION_IDLE_TIMEOUT_SECONDS: 'not_a_number' })
    ).toThrow(/Invalid configuration for SESSION_IDLE_TIMEOUT_SECONDS/);

    expect(() =>
      loadAndValidateSessionConfig({ SESSION_IDLE_TIMEOUT_SECONDS: '0' })
    ).toThrow(/Invalid configuration for SESSION_IDLE_TIMEOUT_SECONDS/);

    expect(() =>
      loadAndValidateSessionConfig({ SESSION_IDLE_TIMEOUT_SECONDS: '-30' })
    ).toThrow(/Invalid configuration for SESSION_IDLE_TIMEOUT_SECONDS/);

    expect(() =>
      loadAndValidateSessionConfig({
        SESSION_IDLE_TIMEOUT_SECONDS: '3600',
        MAX_SESSION_LIFETIME_SECONDS: '1800'
      })
    ).toThrow(/IDLE_TIMEOUT_SECONDS \(3600\) cannot exceed MAX_SESSION_LIFETIME_SECONDS \(1800\)/);

    expect(() =>
      loadAndValidateSessionConfig({
        DEFAULT_ELEVATION_DURATION_SECONDS: '1200',
        MAX_ELEVATION_DURATION_SECONDS: '900'
      })
    ).toThrow(/DEFAULT_ELEVATION_DURATION_SECONDS \(1200\) cannot exceed MAX_ELEVATION_DURATION_SECONDS \(900\)/);
  });
});
