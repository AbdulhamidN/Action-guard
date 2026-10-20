const bcrypt = require('bcrypt');
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
const { getRedisClient } = require('../src/storage/redis');
const {
  correlateEventIntoSequence,
  getSequenceWindowMs,
  DEFAULT_SEQUENCE_WINDOW_SECONDS
} = require('../src/services/sequenceGroupingService');
const {
  getActiveSequenceFromCache,
  cacheActiveSequence,
  invalidateSequenceCache,
  invalidateSessionInSequenceCache,
  getSequenceCacheKey,
  SEQUENCE_USER_KEY_PREFIX
} = require('../src/services/sequenceCacheService');
const { createSequence, attachEventToSequence } = require('../src/services/sequenceStorageService');

describe('Module 5.2 — Redis Active Sequence State', () => {
  let userA;
  let userB;
  let sessionA1;
  let sessionB1;
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

    const passwordHash = await bcrypt.hash('TestPassword123!', 10);

    userA = await User.create({
      email: 'seq-redis-user-a@example.com',
      password_hash: passwordHash
    });

    userB = await User.create({
      email: 'seq-redis-user-b@example.com',
      password_hash: passwordHash
    });

    const future = new Date(Date.now() + 3600000);

    sessionA1 = await Session.create({
      user_id: userA.id,
      expires_at: future
    });

    sessionB1 = await Session.create({
      user_id: userB.id,
      expires_at: future
    });
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

    // Clear user keys in Redis before each test
    await invalidateSequenceCache(userA.id);
    await invalidateSequenceCache(userB.id);
  });

  describe('1. Redis Key Pattern and Payload Structure', () => {
    test('uses key sequence:user:<userId> and contains exactly the required fields', async () => {
      const eventTime = new Date('2026-10-07T12:00:00.000Z');
      const event = await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA1.id,
        event_type: 'login_success',
        timestamp: eventTime,
        context: { ip_address: '1.2.3.4' },
        metadata: { action_sensitivity: 'low' }
      });

      const { sequence } = await correlateEventIntoSequence(event);

      // Verify Redis key
      const expectedKey = `${SEQUENCE_USER_KEY_PREFIX}${userA.id}`;
      expect(getSequenceCacheKey(userA.id)).toBe(expectedKey);

      const raw = await redisClient.get(expectedKey);
      expect(raw).not.toBeNull();

      const parsed = JSON.parse(raw);
      expect(parsed.id).toBe(sequence.id);
      expect(parsed.user_id).toBe(userA.id);
      expect(parsed.session_id).toBe(sessionA1.id);
      expect(parsed.started_at).toBe(eventTime.toISOString());
      expect(parsed.last_event_at).toBe(eventTime.toISOString());
      expect(parsed.event_count).toBe(1);
      expect(parsed.event_ids).toEqual([event.event_id]);

      const expectedKeys = [
        'id',
        'user_id',
        'session_id',
        'started_at',
        'last_event_at',
        'event_count',
        'event_ids'
      ].sort();
      expect(Object.keys(parsed).sort()).toEqual(expectedKeys);

      // Ensure no extra signal/risk or coordinate leaks
      expect(parsed.risk_score).toBeUndefined();
      expect(parsed.latitude).toBeUndefined();
      expect(parsed.longitude).toBeUndefined();
      expect(parsed.context).toBeUndefined();
    });
  });

  describe('2. Write-Through on Grouping (correlateEventIntoSequence)', () => {
    test('updates Redis immediately when creating a new sequence and when joining an existing sequence', async () => {
      const t1 = new Date('2026-10-07T12:10:00.000Z');
      const t2 = new Date('2026-10-07T12:12:00.000Z');

      const event1 = await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA1.id,
        event_type: 'login_success',
        timestamp: t1
      });

      // Write 1: New sequence
      const res1 = await correlateEventIntoSequence(event1);
      expect(res1.isNewSequence).toBe(true);

      let cached = await getActiveSequenceFromCache(userA.id);
      expect(cached).not.toBeNull();
      expect(cached.id).toBe(res1.sequence.id);
      expect(cached.event_count).toBe(1);
      expect(cached.event_ids).toEqual([event1.event_id]);
      expect(cached.last_event_at).toBe(t1.toISOString());

      // Write 2: Append event to existing sequence
      const event2 = await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA1.id,
        event_type: 'recovery_email_change',
        timestamp: t2
      });

      const res2 = await correlateEventIntoSequence(event2);
      expect(res2.isNewSequence).toBe(false);
      expect(res2.sequence.id).toBe(res1.sequence.id);

      // Verify Redis was updated in the same operation
      cached = await getActiveSequenceFromCache(userA.id);
      expect(cached).not.toBeNull();
      expect(cached.id).toBe(res1.sequence.id);
      expect(cached.event_count).toBe(2);
      expect(cached.event_ids).toEqual([event1.event_id, event2.event_id]);
      expect(cached.last_event_at).toBe(t2.toISOString());
    });
  });

  describe('3. Fast-Read Function (getActiveSequenceFromCache)', () => {
    test('reads directly from Redis cache without querying MySQL on cache hit', async () => {
      const customPayload = {
        id: 'seq_fast_read_001',
        user_id: userA.id,
        session_id: sessionA1.id,
        started_at: new Date().toISOString(),
        last_event_at: new Date().toISOString(),
        event_count: 5,
        event_ids: ['evt_a', 'evt_b', 'evt_c', 'evt_d', 'evt_e']
      };

      // Set directly in Redis
      await redisClient.set(
        getSequenceCacheKey(userA.id),
        JSON.stringify(customPayload),
        'EX',
        900
      );

      // Read from cache
      const result = await getActiveSequenceFromCache(userA.id);
      expect(result).not.toBeNull();
      expect(result.id).toBe('seq_fast_read_001');
      expect(result.event_count).toBe(5);
      expect(result.event_ids).toHaveLength(5);
    });

    test('returns null for invalid or empty userId', async () => {
      expect(await getActiveSequenceFromCache(null)).toBeNull();
      expect(await getActiveSequenceFromCache('')).toBeNull();
      expect(await getActiveSequenceFromCache('   ')).toBeNull();
      expect(await getActiveSequenceFromCache(undefined)).toBeNull();
    });
  });

  describe('4. Cache Miss and MySQL Fallback Repopulation', () => {
    test('falls back to MySQL on cache miss, returns the sequence, and repopulates Redis with remaining TTL', async () => {
      const now = new Date();
      // Create sequence directly in MySQL
      const sequence = await createSequence({
        user_id: userA.id,
        session_id: sessionA1.id,
        started_at: now,
        last_event_at: now
      });

      const event = await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA1.id,
        event_type: 'password_change',
        timestamp: now
      });

      await attachEventToSequence(sequence.id, event.event_id, 1);

      // Ensure Redis cache is empty (cache miss)
      await invalidateSequenceCache(userA.id);
      const preCheck = await redisClient.get(getSequenceCacheKey(userA.id));
      expect(preCheck).toBeNull();

      // Read should miss Redis, fetch from MySQL, and repopulate Redis
      const result = await getActiveSequenceFromCache(userA.id);
      expect(result).not.toBeNull();
      expect(result.id).toBe(sequence.id);
      expect(result.event_count).toBe(1);
      expect(result.event_ids).toEqual([event.event_id]);

      // Check that Redis is now repopulated
      const postCheckRaw = await redisClient.get(getSequenceCacheKey(userA.id));
      expect(postCheckRaw).not.toBeNull();
      const postCheck = JSON.parse(postCheckRaw);
      expect(postCheck.id).toBe(sequence.id);

      // Verify TTL is positive and within window
      const ttl = await redisClient.ttl(getSequenceCacheKey(userA.id));
      expect(ttl).toBeGreaterThan(0);
      expect(ttl).toBeLessThanOrEqual(DEFAULT_SEQUENCE_WINDOW_SECONDS);
    });

    test('returns null when user has no sequences in MySQL', async () => {
      const unknownUserId = 'usr_non_existent_9999';
      const result = await getActiveSequenceFromCache(unknownUserId);
      expect(result).toBeNull();

      const cached = await redisClient.get(getSequenceCacheKey(unknownUserId));
      expect(cached).toBeNull();
    });
  });

  describe('5. TTL and Expiration Handling', () => {
    test('sets Redis TTL matching configured correlation windowMs', async () => {
      const event = await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA1.id,
        event_type: 'login_success',
        timestamp: new Date()
      });

      await correlateEventIntoSequence(event);

      const ttl = await redisClient.ttl(getSequenceCacheKey(userA.id));
      const expectedTtl = Math.ceil(getSequenceWindowMs() / 1000);
      expect(ttl).toBeGreaterThan(0);
      expect(ttl).toBeLessThanOrEqual(expectedTtl);
    });

    test('does not repopulate Redis when latest sequence in MySQL has expired past windowMs', async () => {
      const pastTime = new Date(Date.now() - 30 * 60 * 1000); // 30 minutes ago (> 15 min window)

      const oldSeq = await createSequence({
        user_id: userB.id,
        session_id: sessionB1.id,
        started_at: pastTime,
        last_event_at: pastTime
      });

      const oldEvent = await SecurityEvent.create({
        user_id: userB.id,
        session_id: sessionB1.id,
        event_type: 'login_success',
        timestamp: pastTime
      });

      await attachEventToSequence(oldSeq.id, oldEvent.event_id, 1);

      // Ensure cache is clear
      await invalidateSequenceCache(userB.id);

      // getActiveSequenceFromCache must recognize it has expired and return null
      const result = await getActiveSequenceFromCache(userB.id);
      expect(result).toBeNull();

      // Redis must NOT be repopulated with a stale sequence
      const inRedis = await redisClient.get(getSequenceCacheKey(userB.id));
      expect(inRedis).toBeNull();
    });
  });

  describe('6. Cache Invalidation on Session Deletion', () => {
    test('updates Redis cache entry to session_id: null when referenced session is deleted via session.destroy()', async () => {
      const tempSession = await Session.create({
        user_id: userA.id,
        expires_at: new Date(Date.now() + 3600000)
      });

      const event = await SecurityEvent.create({
        user_id: userA.id,
        session_id: tempSession.id,
        event_type: 'login_success',
        timestamp: new Date()
      });

      const { sequence } = await correlateEventIntoSequence(event);

      // Verify sequence is cached with session_id = tempSession.id
      let cached = await getActiveSequenceFromCache(userA.id);
      expect(cached).not.toBeNull();
      expect(cached.session_id).toBe(tempSession.id);

      // Delete the session in MySQL
      await tempSession.destroy();

      // Check Redis cache entry: session_id must be null
      const raw = await redisClient.get(getSequenceCacheKey(userA.id));
      expect(raw).not.toBeNull();
      const updatedCache = JSON.parse(raw);
      expect(updatedCache.session_id).toBeNull();
      expect(updatedCache.id).toBe(sequence.id);
      expect(updatedCache.user_id).toBe(userA.id);
      expect(updatedCache.event_count).toBe(sequence.event_count);
    });

    test('invalidateSessionInSequenceCache explicitly nullifies session_id in Redis', async () => {
      const dummySessionId = 'sess_dummy_to_nullify';
      const seqData = {
        id: 'seq_test_nullify',
        user_id: userA.id,
        session_id: dummySessionId,
        started_at: new Date().toISOString(),
        last_event_at: new Date().toISOString(),
        event_count: 1,
        event_ids: ['evt_1']
      };

      await redisClient.set(
        getSequenceCacheKey(userA.id),
        JSON.stringify(seqData),
        'EX',
        600
      );

      const modified = await invalidateSessionInSequenceCache(dummySessionId, userA.id);
      expect(modified).toBe(true);

      const raw = await redisClient.get(getSequenceCacheKey(userA.id));
      const parsed = JSON.parse(raw);
      expect(parsed.session_id).toBeNull();
      expect(parsed.id).toBe('seq_test_nullify');
    });

    test('deleting an unrelated session does not alter sequence cache session_id', async () => {
      const otherSession = await Session.create({
        user_id: userA.id,
        expires_at: new Date(Date.now() + 3600000)
      });

      const seqData = {
        id: 'seq_unrelated_test',
        user_id: userA.id,
        session_id: sessionA1.id,
        started_at: new Date().toISOString(),
        last_event_at: new Date().toISOString(),
        event_count: 1,
        event_ids: ['evt_test']
      };

      await redisClient.set(
        getSequenceCacheKey(userA.id),
        JSON.stringify(seqData),
        'EX',
        600
      );

      // Destroy otherSession (different ID)
      await otherSession.destroy();

      const raw = await redisClient.get(getSequenceCacheKey(userA.id));
      const parsed = JSON.parse(raw);
      expect(parsed.session_id).toBe(sessionA1.id);
    });
  });

  describe('7. Multi-User Isolation in Redis Cache', () => {
    test('maintains independent active sequence cache entries for different users', async () => {
      const now = new Date();
      const eventA = await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA1.id,
        event_type: 'login_success',
        timestamp: now
      });

      const eventB = await SecurityEvent.create({
        user_id: userB.id,
        session_id: sessionB1.id,
        event_type: 'login_success',
        timestamp: now
      });

      const resA = await correlateEventIntoSequence(eventA);
      const resB = await correlateEventIntoSequence(eventB);

      const cachedA = await getActiveSequenceFromCache(userA.id);
      const cachedB = await getActiveSequenceFromCache(userB.id);

      expect(cachedA.id).toBe(resA.sequence.id);
      expect(cachedA.user_id).toBe(userA.id);

      expect(cachedB.id).toBe(resB.sequence.id);
      expect(cachedB.user_id).toBe(userB.id);

      expect(cachedA.id).not.toBe(cachedB.id);

      // Invalidating User A cache does not affect User B
      await invalidateSequenceCache(userA.id);
      expect(await redisClient.get(getSequenceCacheKey(userA.id))).toBeNull();
      expect(await redisClient.get(getSequenceCacheKey(userB.id))).not.toBeNull();
    });
  });
});
