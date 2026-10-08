const request = require('supertest');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const app = require('../src/app');
const {
  sequelize,
  User,
  Session,
  Device,
  SecurityEvent,
  BehavioralBaseline,
  ActionSequence,
  SequenceEvent
} = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const { JWT_SECRET } = require('../src/middleware/auth');
const { createSession } = require('../src/services/sessionService');
const { correlateEventIntoSequence } = require('../src/services/sequenceGroupingService');
const {
  invalidateSequenceCache,
  getSequenceCacheKey
} = require('../src/services/sequenceCacheService');
const { createSequence, attachEventToSequence } = require('../src/services/sequenceStorageService');
const { getRedisClient } = require('../src/storage/redis');

describe('Module 5.3 — Sequence Query/Timeline API (GET /api/v1/sequences/current)', () => {
  let userA;
  let userB;
  let userC;
  let sessionA;
  let sessionB;
  let tokenA;
  let tokenB;
  let tokenC;
  let redisClient;

  beforeAll(async () => {
    await runMigrations();

    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SequenceEvent.destroy({ where: {}, force: true });
    await ActionSequence.destroy({ where: {}, force: true });
    await BehavioralBaseline.destroy({ where: {}, force: true });
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    redisClient = getRedisClient();

    const passwordHash = await bcrypt.hash('ApiTestPassword123!', 10);

    userA = await User.create({
      email: 'seq-api-user-a@example.com',
      password_hash: passwordHash
    });

    userB = await User.create({
      email: 'seq-api-user-b@example.com',
      password_hash: passwordHash
    });

    userC = await User.create({
      email: 'seq-api-user-c@example.com',
      password_hash: passwordHash
    });

    // Create sessions with active Redis state
    const createdSessionA = await createSession(userA.id, userA.email);
    sessionA = createdSessionA;

    const createdSessionB = await createSession(userB.id, userB.email);
    sessionB = createdSessionB;

    tokenA = jwt.sign(
      { id: userA.id, email: userA.email, session_id: sessionA.sessionId },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    tokenB = jwt.sign(
      { id: userB.id, email: userB.email, session_id: sessionB.sessionId },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    // User C without active session
    tokenC = jwt.sign(
      { id: userC.id, email: userC.email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
  });

  afterAll(async () => {
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SequenceEvent.destroy({ where: {}, force: true });
    await ActionSequence.destroy({ where: {}, force: true });
    await BehavioralBaseline.destroy({ where: {}, force: true });
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');
  });

  beforeEach(async () => {
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SequenceEvent.destroy({ where: {}, force: true });
    await ActionSequence.destroy({ where: {}, force: true });
    await SecurityEvent.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    await invalidateSequenceCache(userA.id);
    await invalidateSequenceCache(userB.id);
    await invalidateSequenceCache(userC.id);
  });

  describe('1. Authenticated Request with Active Sequence', () => {
    test('returns 200 with chronological timeline and strictly permitted fields', async () => {
      const t1 = new Date('2026-10-07T12:00:00.000Z');
      const t2 = new Date('2026-10-07T12:02:00.000Z');

      const event1 = await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA.sessionId,
        event_type: 'login_success',
        timestamp: t1,
        context: { ip_address: '1.2.3.4', geo_country: 'US', device_fingerprint: 'fp_secret_1' },
        metadata: { action_sensitivity: 'low', custom_secret: 'hidden' }
      });

      const event2 = await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA.sessionId,
        event_type: 'recovery_email_change',
        timestamp: t2,
        context: { ip_address: '1.2.3.4', geo_country: 'US', device_fingerprint: 'fp_secret_1' },
        metadata: { action_sensitivity: 'high' }
      });

      await correlateEventIntoSequence(event1);
      await correlateEventIntoSequence(event2);

      const res = await request(app)
        .get('/api/v1/sequences/current')
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);

      expect(res.body).toHaveProperty('sequence');
      expect(res.body.sequence).not.toBeNull();

      const seq = res.body.sequence;

      // Exact field validation on sequence object
      const expectedSeqKeys = [
        'id',
        'started_at',
        'last_event_at',
        'event_count',
        'events'
      ].sort();
      expect(Object.keys(seq).sort()).toEqual(expectedSeqKeys);

      expect(seq.event_count).toBe(2);
      expect(seq.started_at).toBe(t1.toISOString());
      expect(seq.last_event_at).toBe(t2.toISOString());
      expect(Array.isArray(seq.events)).toBe(true);
      expect(seq.events).toHaveLength(2);

      // Verify chronological order (step_order ASC)
      expect(seq.events[0].event_id).toBe(event1.event_id);
      expect(seq.events[0].event_type).toBe('login_success');
      expect(seq.events[0].timestamp).toBe(t1.toISOString());

      expect(seq.events[1].event_id).toBe(event2.event_id);
      expect(seq.events[1].event_type).toBe('recovery_email_change');
      expect(seq.events[1].timestamp).toBe(t2.toISOString());

      // Exact field validation on each event object (field-level privacy)
      const expectedEventKeys = ['event_id', 'event_type', 'timestamp'].sort();
      for (const ev of seq.events) {
        expect(Object.keys(ev).sort()).toEqual(expectedEventKeys);
        expect(ev.context).toBeUndefined();
        expect(ev.metadata).toBeUndefined();
        expect(ev.risk_score).toBeUndefined();
        expect(ev.decision).toBeUndefined();
        expect(ev.ip_address).toBeUndefined();
        expect(ev.device_fingerprint).toBeUndefined();
        expect(ev.latitude).toBeUndefined();
        expect(ev.longitude).toBeUndefined();
        expect(ev.user_id).toBeUndefined();
        expect(ev.session_id).toBeUndefined();
      }
    });
  });

  describe('2. Authenticated Request with No Active Sequence', () => {
    test('returns 200 with { sequence: null } when user has no sequences', async () => {
      const res = await request(app)
        .get('/api/v1/sequences/current')
        .set('Authorization', `Bearer ${tokenC}`)
        .expect(200);

      expect(res.body).toEqual({ sequence: null });
    });

    test('returns 200 with { sequence: null } when user sequence has expired past correlation window', async () => {
      const oldTime = new Date(Date.now() - 30 * 60 * 1000); // 30 mins ago (> 15 min window)
      const oldSeq = await createSequence({
        user_id: userA.id,
        session_id: sessionA.sessionId,
        started_at: oldTime,
        last_event_at: oldTime
      });

      const oldEvt = await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA.sessionId,
        event_type: 'login_success',
        timestamp: oldTime
      });

      await attachEventToSequence(oldSeq.id, oldEvt.event_id, 1);

      const res = await request(app)
        .get('/api/v1/sequences/current')
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);

      expect(res.body).toEqual({ sequence: null });
    });
  });

  describe('3. Unauthenticated and Malformed Token Requests', () => {
    test('returns 401 with standard error format when Authorization header is missing', async () => {
      const res = await request(app)
        .get('/api/v1/sequences/current')
        .expect(401);

      expect(res.body).toHaveProperty('error');
      expect(res.body.error.code).toBe('unauthorized');
      expect(res.body.error.status).toBe(401);
      expect(res.body.error.message).toMatch(/Missing authorization token/);
    });

    test('returns 401 when Authorization header is malformed', async () => {
      const res = await request(app)
        .get('/api/v1/sequences/current')
        .set('Authorization', 'Basic 123456')
        .expect(401);

      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe('unauthorized');
      expect(res.body.error.status).toBe(401);
    });

    test('returns 401 when token is invalid or corrupted', async () => {
      const res = await request(app)
        .get('/api/v1/sequences/current')
        .set('Authorization', 'Bearer invalid.jwt.token')
        .expect(401);

      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe('unauthorized');
      expect(res.body.error.status).toBe(401);
    });

    test('returns 401 token_expired when JWT is expired', async () => {
      const expiredToken = jwt.sign(
        { id: userA.id, email: userA.email },
        JWT_SECRET,
        { expiresIn: '-1s' }
      );

      const res = await request(app)
        .get('/api/v1/sequences/current')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);

      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe('token_expired');
      expect(res.body.error.status).toBe(401);
    });
  });

  describe('4. Cross-User Isolation (User Token Scoping)', () => {
    test('strictly isolates active sequences so user A token never returns user B sequence', async () => {
      const now = new Date();

      const eventA = await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA.sessionId,
        event_type: 'login_success',
        timestamp: now
      });

      const eventB = await SecurityEvent.create({
        user_id: userB.id,
        session_id: sessionB.sessionId,
        event_type: 'password_change',
        timestamp: now
      });

      const resSeqA = await correlateEventIntoSequence(eventA);
      const resSeqB = await correlateEventIntoSequence(eventB);

      // User A requests current sequence
      const resA = await request(app)
        .get('/api/v1/sequences/current')
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);

      expect(resA.body.sequence.id).toBe(resSeqA.sequence.id);
      expect(resA.body.sequence.events[0].event_id).toBe(eventA.event_id);
      expect(resA.body.sequence.events[0].event_type).toBe('login_success');

      // User B requests current sequence
      const resB = await request(app)
        .get('/api/v1/sequences/current')
        .set('Authorization', `Bearer ${tokenB}`)
        .expect(200);

      expect(resB.body.sequence.id).toBe(resSeqB.sequence.id);
      expect(resB.body.sequence.events[0].event_id).toBe(eventB.event_id);
      expect(resB.body.sequence.events[0].event_type).toBe('password_change');

      // User C with no active sequence gets null
      const resC = await request(app)
        .get('/api/v1/sequences/current')
        .set('Authorization', `Bearer ${tokenC}`)
        .expect(200);

      expect(resC.body.sequence).toBeNull();
    });
  });

  describe('5. Cache-Miss Fallback Through API', () => {
    test('transparently falls back to MySQL and returns active sequence when Redis cache is evicted', async () => {
      const t1 = new Date(Date.now() - 4 * 60 * 1000);
      const t2 = new Date(Date.now() - 2 * 60 * 1000);

      const event1 = await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA.sessionId,
        event_type: 'login_success',
        timestamp: t1
      });

      const event2 = await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA.sessionId,
        event_type: 'recovery_email_change',
        timestamp: t2
      });

      const res1 = await correlateEventIntoSequence(event1);
      const res2 = await correlateEventIntoSequence(event2);

      // Explicitly remove/clear user's Redis sequence cache entry
      await invalidateSequenceCache(userA.id);
      const cacheBefore = await redisClient.get(getSequenceCacheKey(userA.id));
      expect(cacheBefore).toBeNull();

      // Request API -> must hit MySQL fallback, return sequence, and repopulate Redis
      const res = await request(app)
        .get('/api/v1/sequences/current')
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);

      expect(res.body.sequence).not.toBeNull();
      expect(res.body.sequence.id).toBe(res2.sequence.id);
      expect(res.body.sequence.event_count).toBe(2);
      expect(res.body.sequence.events).toHaveLength(2);

      // Verify ordered events (chronological order)
      expect(res.body.sequence.events[0].event_id).toBe(event1.event_id);
      expect(res.body.sequence.events[0].event_type).toBe('login_success');
      expect(res.body.sequence.events[1].event_id).toBe(event2.event_id);
      expect(res.body.sequence.events[1].event_type).toBe('recovery_email_change');

      // Verify Redis was repopulated with active sequence and ordered event_ids
      const repopulatedRaw = await redisClient.get(getSequenceCacheKey(userA.id));
      expect(repopulatedRaw).not.toBeNull();
      const repopulated = JSON.parse(repopulatedRaw);
      expect(repopulated.id).toBe(res2.sequence.id);
      expect(repopulated.event_count).toBe(2);
      expect(repopulated.event_ids).toEqual([event1.event_id, event2.event_id]);
    });
  });
});
