'use strict';

const request = require('supertest');
const app = require('../src/app');
const {
  sequelize,
  User,
  Session,
  SecurityEvent,
  RiskAssessment,
  ActionSequence,
  SequenceEvent
} = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const eventService = require('../src/services/eventService');
const riskEngineService = require('../src/services/riskEngineService');
const redisStorage = require('../src/storage/redis');
const { REDIS_PREFIXES } = require('../src/config/sessionConfig');
const {
  computeApiKeyFingerprint,
  releaseInProgressLease,
  completeInProgressLease,
  rollbackFailedScoredEvent
} = require('../src/services/eventIngestionService');
const {
  getSequenceCacheKey,
  getActiveSequenceFromCache,
  correlateEventIntoSequence
} = require('../src/services/sequenceGroupingService');
const eventBus = require('../src/events/eventBus');

const TEST_API_KEY = 'ext_integration_secret_api_key_11_2b_test';

const TEST_IDEMPOTENCY_KEYS = [
  'idem_replay_test_001',
  'idem_header_key_A',
  'idem_body_key_B',
  'idem_conflict_key_001',
  'idem_in_progress_key_001',
  'idem_failure_recovery_001',
  'idem_failure_existing_seq_001',
  'idem_no_double_work_001',
  'idem_atomic_lease_test_001',
  'idem_atomic_complete_test_001',
  'idem_scored_complete_path_001',
  'idem_unscored_complete_path_001'
];

function buildTestRedisIdemKey(idemKey, apiKey = TEST_API_KEY) {
  const apiKeyFp = computeApiKeyFingerprint(apiKey);
  return `${REDIS_PREFIXES.EXTERNAL_EVENT_IDEMPOTENCY}${apiKeyFp}:${idemKey}`;
}

async function deleteTestRedisIdemKey(idemKey, apiKey = TEST_API_KEY) {
  const redisClient = redisStorage.getRedisClient();
  if (!redisClient) return;
  const redisKey = buildTestRedisIdemKey(idemKey, apiKey);
  await redisClient.del(redisKey);
}

async function cleanupTestOwnedRedisKeys() {
  const redisClient = redisStorage.getRedisClient();
  if (!redisClient) return;

  for (const idemKey of TEST_IDEMPOTENCY_KEYS) {
    await redisClient.del(buildTestRedisIdemKey(idemKey, TEST_API_KEY));
  }
  await redisClient.del(getSequenceCacheKey('usr_ext_11_2b_a'));
  await redisClient.del(getSequenceCacheKey('usr_ext_11_2b_b'));
}

describe('Module 11.2b Stage 1 — External Event Ingestion (POST /api/v1/events)', () => {
  let userA;
  let userB;
  let sessionA;
  let sessionB;
  let savedApiKey;

  beforeAll(async () => {
    savedApiKey = process.env.API_KEY;
    process.env.API_KEY = TEST_API_KEY;

    await runMigrations();
  });

  beforeEach(async () => {
    process.env.API_KEY = TEST_API_KEY;

    await cleanupTestOwnedRedisKeys();

    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SequenceEvent.destroy({ where: {}, force: true });
    await ActionSequence.destroy({ where: {}, force: true });
    await RiskAssessment.destroy({ where: {}, force: true });
    await SecurityEvent.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    userA = await User.create({
      id: 'usr_ext_11_2b_a',
      email: 'ext-user-a@example.com',
      password_hash: '$2b$10$abcdefghijklmnopqrstuv'
    });

    userB = await User.create({
      id: 'usr_ext_11_2b_b',
      email: 'ext-user-b@example.com',
      password_hash: '$2b$10$abcdefghijklmnopqrstuv'
    });

    sessionA = await Session.create({
      id: 'sess_ext_11_2b_a',
      user_id: userA.id,
      expires_at: new Date(Date.now() + 3600 * 1000),
      is_active: true
    });

    sessionB = await Session.create({
      id: 'sess_ext_11_2b_b',
      user_id: userB.id,
      expires_at: new Date(Date.now() + 3600 * 1000),
      is_active: true
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  afterAll(async () => {
    await cleanupTestOwnedRedisKeys();

    if (savedApiKey !== undefined) {
      process.env.API_KEY = savedApiKey;
    } else {
      delete process.env.API_KEY;
    }
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SequenceEvent.destroy({ where: {}, force: true });
    await ActionSequence.destroy({ where: {}, force: true });
    await RiskAssessment.destroy({ where: {}, force: true });
    await SecurityEvent.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');
  });

  test('T11.2b-01: Valid event ingestion persists event, correlates sequence, evaluates risk/policy, and stamps external source attribution', async () => {
    const emittedEvents = [];
    const listener = (payload) => emittedEvents.push(payload);
    eventBus.on('pipeline:event_processed', listener);

    try {
      const nowIso = new Date().toISOString();
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .send({
          user_id: userA.id,
          session_id: sessionA.id,
          event_type: 'password_change',
          timestamp: nowIso,
          context: {
            ip_address: '198.51.100.42',
            device_fingerprint: 'fp_valid_device_001',
            user_agent: 'ActionGuardPartnerApp/2.1'
          },
          metadata: {
            action_sensitivity: 'high',
            operation: 'rotate_account_password',
            correlation_id: 'corr_ext_001'
          }
        })
        .expect(201);

      expect(res.body.event_id).toMatch(/^evt_/);
      expect(res.body.user_id).toBe(userA.id);
      expect(res.body.session_id).toBe(sessionA.id);
      expect(res.body.event_type).toBe('password_change');
      expect(res.body.timestamp).toBe(nowIso);
      expect(typeof res.body.risk_score).toBe('number');
      expect(['low', 'medium', 'high', 'critical']).toContain(res.body.risk_tier);
      expect(['allow', 'monitor', 'reverify', 'delay', 'block']).toContain(res.body.decision);
      expect(Array.isArray(res.body.contributing_signals)).toBe(true);
      expect(res.body.explanation).toBeDefined();
      expect(typeof res.body.explanation.user_facing).toBe('string');
      expect(typeof res.body.explanation.admin_facing).toBe('string');
      expect(typeof res.body.cooling_off_seconds).toBe('number');

      // Verify DB persistence and server-controlled source attribution
      const storedEvent = await SecurityEvent.findByPk(res.body.event_id);
      expect(storedEvent).not.toBeNull();
      expect(storedEvent.metadata.source).toBe('external_api');
      expect(storedEvent.metadata.api_key_fingerprint).toBe(
        computeApiKeyFingerprint(TEST_API_KEY)
      );
      expect(storedEvent.metadata.api_key_fingerprint).not.toContain(TEST_API_KEY);

      // Verify RiskAssessment row was created
      const storedAssessment = await RiskAssessment.findOne({
        where: { event_id: res.body.event_id }
      });
      expect(storedAssessment).not.toBeNull();
      expect(storedAssessment.risk_score).toBe(res.body.risk_score);

      // Verify sequence correlation & eventBus emission happened exactly once
      const seqLink = await SequenceEvent.findOne({
        where: { event_id: res.body.event_id }
      });
      expect(seqLink).not.toBeNull();
      expect(emittedEvents).toHaveLength(1);
      expect(emittedEvents[0].event.event_id).toBe(res.body.event_id);
    } finally {
      eventBus.off('pipeline:event_processed', listener);
    }
  });

  test('T11.2b-02: Missing, malformed, query-string, or invalid API key is rejected with 401', async () => {
    const validPayload = {
      user_id: userA.id,
      event_type: 'login_success',
      timestamp: new Date().toISOString()
    };

    // Missing Authorization header
    const resMissing = await request(app)
      .post('/api/v1/events')
      .send(validPayload)
      .expect(401);
    expect(resMissing.body.error.code).toBe('unauthorized');

    // Wrong API key
    const resWrong = await request(app)
      .post('/api/v1/events')
      .set('Authorization', 'Bearer wrong_api_key_value')
      .send(validPayload)
      .expect(401);
    expect(resWrong.body.error.code).toBe('unauthorized');

    // Query parameter API key rejected even when valid header is supplied
    const resQuery = await request(app)
      .post(`/api/v1/events?api_key=${TEST_API_KEY}`)
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .send(validPayload)
      .expect(401);
    expect(resQuery.body.error.code).toBe('unauthorized');
  });

  test('T11.2b-03: Unknown top-level fields and attempts to override computed/authoritative fields are rejected with 400', async () => {
    const basePayload = {
      user_id: userA.id,
      event_type: 'login_success',
      timestamp: new Date().toISOString()
    };

    const forbiddenOverrides = [
      { unknown_custom_field: 'value' },
      { risk_score: 0 },
      { risk_tier: 'low' },
      { decision: 'allow' },
      { policy_decision: 'allow' },
      { is_trusted_device: true },
      { trusted_device: true },
      { event_id: 'evt_spoofed_123' },
      { source: 'internal_pep' },
      { metadata: { risk_score: 0 } },
      { metadata: { is_trusted_device: true } },
      { metadata: { decision: 'allow' } },
      { metadata: { details: { risk_score: 0 } } },
      { metadata: { details: { decision: 'allow' } } },
      { metadata: { details: { is_trusted_device: true } } },
      { metadata: { details: { trusted_device: true } } },
      { metadata: { details: { policy_decision: 'allow' } } },
      { metadata: { details: { Risk_Score: 0 } } },
      { context: { is_trusted_device: true } }
    ];

    for (const override of forbiddenOverrides) {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .send({ ...basePayload, ...override })
        .expect(400);

      expect(res.body.error.code).toBe('invalid_request');
    }

    const count = await SecurityEvent.count();
    expect(count).toBe(0);
  });

  test('T11.2b-04: Unsupported event_type is rejected with 400 invalid_event_type', async () => {
    const res = await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .send({
        user_id: userA.id,
        event_type: 'custom_unsupported_action',
        timestamp: new Date().toISOString()
      })
      .expect(400);

    expect(res.body.error.code).toBe('invalid_event_type');
    expect(await SecurityEvent.count()).toBe(0);
  });

  test('T11.2b-05: Nonexistent user_id is rejected with 400 invalid_request', async () => {
    const res = await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .send({
        user_id: 'usr_nonexistent_99999',
        event_type: 'login_success',
        timestamp: new Date().toISOString()
      })
      .expect(400);

    expect(res.body.error.code).toBe('invalid_request');
    expect(await SecurityEvent.count()).toBe(0);
  });

  test('T11.2b-06: session_id belonging to another user or nonexistent session is rejected with 400', async () => {
    // sessionB belongs to userB, submitted for userA
    const resWrongOwner = await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .send({
        user_id: userA.id,
        session_id: sessionB.id,
        event_type: 'password_change',
        timestamp: new Date().toISOString()
      })
      .expect(400);

    expect(resWrongOwner.body.error.code).toBe('invalid_request');

    // Nonexistent session_id
    const resMissingSession = await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .send({
        user_id: userA.id,
        session_id: 'sess_does_not_exist_999',
        event_type: 'password_change',
        timestamp: new Date().toISOString()
      })
      .expect(400);

    expect(resMissingSession.body.error.code).toBe('invalid_request');
    expect(await SecurityEvent.count()).toBe(0);
  });

  test('T11.2b-07: Invalid, rollover, excessively old (> 30d), and excessively future (> 5m) timestamps are rejected with 400', async () => {
    const nowMs = Date.now();
    const tenMinutesFuture = new Date(nowMs + 10 * 60 * 1000).toISOString();
    const thirtyOneDaysPast = new Date(nowMs - 31 * 24 * 60 * 60 * 1000).toISOString();

    const invalidTimestamps = [
      'not-a-timestamp',
      '2026-10-12', // date-only without time/timezone
      '2026-02-30T12:00:00Z', // calendar rollover date
      tenMinutesFuture,
      thirtyOneDaysPast
    ];

    for (const ts of invalidTimestamps) {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .send({
          user_id: userA.id,
          event_type: 'login_success',
          timestamp: ts
        })
        .expect(400);

      expect(res.body.error.code).toBe('invalid_request');
    }

    expect(await SecurityEvent.count()).toBe(0);
  });

  test('T11.2b-08: Malformed context/metadata, client-supplied geolocation/coordinates, and attempts to lower policy minimum sensitivity are enforced', async () => {
    const nowIso = new Date().toISOString();

    const invalidBodies = [
      // Invalid IP in context
      {
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: nowIso,
        context: { ip_address: '999.999.999.999' }
      },
      // Invalid device_fingerprint in context (too short)
      {
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: nowIso,
        context: { device_fingerprint: 'ab' }
      },
      // Excessive user_agent length (> 512)
      {
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: nowIso,
        context: { user_agent: 'A'.repeat(600) }
      },
      // Client-supplied geo_country or coordinates in context rejected
      {
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: nowIso,
        context: { ip_address: '198.51.100.1', geo_country: 'US' }
      },
      {
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: nowIso,
        context: { latitude: 37.7749, longitude: -122.4194 }
      },
      // Invalid action_sensitivity value
      {
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: nowIso,
        metadata: { action_sensitivity: 'extreme' }
      },
      // Excessive metadata.operation length (> 128)
      {
        user_id: userA.id,
        event_type: 'high_impact_action',
        timestamp: nowIso,
        metadata: { operation: 'X'.repeat(200) }
      }
    ];

    for (const payload of invalidBodies) {
      const res = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .send(payload)
        .expect(400);

      expect(res.body.error.code).toBe('invalid_request');
    }

    // Verify external input cannot lower policy-defined minimum sensitivity:
    // high_impact_action has policy default 'critical'. Passing 'low' must be floored to 'critical'.
    const resFloor = await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .send({
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'high_impact_action',
        timestamp: nowIso,
        metadata: {
          action_sensitivity: 'low',
          operation: 'wire_transfer'
        }
      })
      .expect(201);

    const stored = await SecurityEvent.findByPk(resFloor.body.event_id);
    expect(stored.metadata.action_sensitivity).toBe('critical');
    expect(
      resFloor.body.contributing_signals.some(
        (s) => s.signal === 'action_sensitivity_critical'
      )
    ).toBe(true);
  });

  test('T11.2b-09: Same-key same-payload replay returns 201 first then 200 cached response, and rejects mismatched header/body keys with 400', async () => {
    const nowIso = new Date().toISOString();
    const payload = {
      user_id: userA.id,
      session_id: sessionA.id,
      event_type: 'recovery_email_change',
      timestamp: nowIso,
      idempotency_key: 'idem_replay_test_001',
      context: {
        ip_address: '198.51.100.10',
        device_fingerprint: 'fp_idem_device_01'
      },
      metadata: {
        action_sensitivity: 'high'
      }
    };

    const firstRes = await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .set('Idempotency-Key', 'idem_replay_test_001')
      .send(payload)
      .expect(201);

    const replayRes = await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .set('Idempotency-Key', 'idem_replay_test_001')
      .send(payload)
      .expect(200);

    expect(replayRes.body).toEqual(firstRes.body);

    // Mismatched Idempotency-Key header and body idempotency_key rejected with 400
    const mismatchRes = await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .set('Idempotency-Key', 'idem_header_key_A')
      .send({
        ...payload,
        idempotency_key: 'idem_body_key_B'
      })
      .expect(400);

    expect(mismatchRes.body.error.code).toBe('invalid_request');
  });

  test('T11.2b-10: Reusing an idempotency key with a different canonical payload returns 409 idempotency_conflict', async () => {
    const nowIso = new Date().toISOString();

    await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .set('Idempotency-Key', 'idem_conflict_key_001')
      .send({
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: nowIso
      })
      .expect(201);

    const conflictRes = await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .set('Idempotency-Key', 'idem_conflict_key_001')
      .send({
        user_id: userA.id,
        event_type: 'password_change', // Different event_type with same idempotency key
        timestamp: nowIso
      })
      .expect(409);

    expect(conflictRes.body.error.code).toBe('idempotency_conflict');
    expect(await SecurityEvent.count()).toBe(1);
  });

  test('T11.2b-11: Concurrent/in-progress request with the same idempotency key returns 409 idempotency_in_progress', async () => {
    const nowIso = new Date().toISOString();
    const idemKey = 'idem_in_progress_key_001';
    const apiKeyFp = computeApiKeyFingerprint(TEST_API_KEY);
    const redisKey = `${REDIS_PREFIXES.EXTERNAL_EVENT_IDEMPOTENCY}${apiKeyFp}:${idemKey}`;

    const payload = {
      user_id: userA.id,
      session_id: null,
      event_type: 'login_success',
      timestamp: nowIso
    };

    // Simulate an active in-progress lease with the matching payload_hash
    const { computeCanonicalPayloadHash } = require('../src/services/eventIngestionService');
    const payloadHash = computeCanonicalPayloadHash({
      user_id: userA.id,
      session_id: null,
      event_type: 'login_success',
      timestamp: new Date(nowIso).toISOString(),
      context: {},
      metadata: {
        action_sensitivity: 'low',
        provided_action_sensitivity: null
      }
    });

    const redisClient = redisStorage.getRedisClient();
    await redisClient.set(
      redisKey,
      JSON.stringify({
        status: 'in_progress',
        payload_hash: payloadHash,
        owner_token: 'active_worker_token',
        started_at_ms: Date.now(),
        lease_expires_at_ms: Date.now() + 30000
      }),
      'EX',
      30,
      'NX'
    );

    const res = await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .set('Idempotency-Key', idemKey)
      .send(payload)
      .expect(409);

    expect(res.body.error.code).toBe('idempotency_in_progress');
    expect(await SecurityEvent.count()).toBe(0);
  });

  test('T11.2b-12: Recovery after Redis, database, or risk pipeline failure leaves idempotency state recoverable without duplicate events', async () => {
    const emittedEvents = [];
    const listener = (payload) => emittedEvents.push(payload);
    eventBus.on('pipeline:event_processed', listener);

    try {
      const baseMs = Date.now() - 2000;
      const t1Iso = new Date(baseMs).toISOString();
      const t2Iso = new Date(baseMs + 1000).toISOString();

      const idemKey1 = 'idem_failure_recovery_001';
      const payload1 = {
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'mfa_change',
        timestamp: t1Iso,
        idempotency_key: idemKey1
      };

      // 1. Newly-created-sequence failure path:
      // Simulate risk pipeline failure on attempt 1 (evaluateAndStoreRiskForEvent returns null)
      const riskSpy1 = jest
        .spyOn(riskEngineService, 'evaluateAndStoreRiskForEvent')
        .mockResolvedValueOnce(null);

      const failRes1 = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .send(payload1)
        .expect(503);

      expect(failRes1.body.error.code).toBe('pipeline_unavailable');
      riskSpy1.mockRestore();

      // Verify newly created empty sequence and sequence event were cleaned up,
      // Redis active sequence cache was cleared, and no pipeline:event_processed was emitted
      expect(await SecurityEvent.count()).toBe(0);
      expect(await ActionSequence.count()).toBe(0);
      expect(await SequenceEvent.count()).toBe(0);
      expect(emittedEvents).toHaveLength(0);

      const redisClient = redisStorage.getRedisClient();
      expect(await redisClient.get(getSequenceCacheKey(userA.id))).toBeNull();

      // 2. Retry with the same idempotency_key must succeed (201), produce 1 SecurityEvent,
      // 1 ActionSequence with event_count === 1, 1 SequenceEvent at step_order === 1,
      // and emit pipeline:event_processed exactly once
      const retryRes1 = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .send(payload1)
        .expect(201);

      expect(retryRes1.body.event_id).toMatch(/^evt_idem_/);
      expect(await SecurityEvent.count()).toBe(1);
      expect(await RiskAssessment.count()).toBe(1);
      expect(await ActionSequence.count()).toBe(1);

      const seqAfterRetry1 = await ActionSequence.findOne({ where: { user_id: userA.id } });
      expect(seqAfterRetry1).not.toBeNull();
      expect(seqAfterRetry1.event_count).toBe(1);

      const seqLinksAfterRetry1 = await SequenceEvent.findAll({
        where: { sequence_id: seqAfterRetry1.id },
        order: [['step_order', 'ASC']]
      });
      expect(seqLinksAfterRetry1).toHaveLength(1);
      expect(seqLinksAfterRetry1[0].event_id).toBe(retryRes1.body.event_id);
      expect(seqLinksAfterRetry1[0].step_order).toBe(1);
      expect(emittedEvents).toHaveLength(1);
      expect(emittedEvents[0].event.event_id).toBe(retryRes1.body.event_id);
      expect(emittedEvents[0].assessment).not.toBeNull();

      // 3. Simulate Redis eviction after commit: delete the specific idempotency key from Redis
      // (compatible with both InMemoryRedisClient and real ioredis) and retry with same idempotency_key.
      // Durable MySQL fallback must return 200 without creating a second SecurityEvent.
      await deleteTestRedisIdemKey(idemKey1);
      expect(await redisClient.get(buildTestRedisIdemKey(idemKey1))).toBeNull();

      const durableReplayRes = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .send(payload1)
        .expect(200);

      expect(durableReplayRes.body.event_id).toBe(retryRes1.body.event_id);
      expect(await SecurityEvent.count()).toBe(1);
      expect(await RiskAssessment.count()).toBe(1);
      expect(emittedEvents).toHaveLength(1);

      // 4. Existing-sequence failure path:
      // UserA now has an active sequence with event_count === 1.
      // Submit a second event that fails risk evaluation (503) and verify existing sequence is restored to event_count === 1.
      const idemKey2 = 'idem_failure_existing_seq_001';
      const payload2 = {
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'password_change',
        timestamp: t2Iso,
        idempotency_key: idemKey2
      };

      const riskSpy2 = jest
        .spyOn(riskEngineService, 'evaluateAndStoreRiskForEvent')
        .mockResolvedValueOnce(null);

      await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .send(payload2)
        .expect(503);

      riskSpy2.mockRestore();

      const seqAfterFail2 = await ActionSequence.findByPk(seqAfterRetry1.id);
      expect(seqAfterFail2).not.toBeNull();
      expect(seqAfterFail2.event_count).toBe(1);
      expect(new Date(seqAfterFail2.last_event_at).toISOString()).toBe(t1Iso);
      expect(await SequenceEvent.count()).toBe(1);
      expect(await SecurityEvent.count()).toBe(1);
      expect(emittedEvents).toHaveLength(1);

      // Rollback invalidates the user's sequence cache rather than writing an unlocked snapshot;
      // getActiveSequenceFromCache lazily repopulates from authoritative MySQL state
      expect(await redisClient.get(getSequenceCacheKey(userA.id))).toBeNull();
      const cachedSeqAfterFail2 = await getActiveSequenceFromCache(userA.id);
      expect(cachedSeqAfterFail2).not.toBeNull();
      expect(cachedSeqAfterFail2.event_count).toBe(1);
      expect(cachedSeqAfterFail2.event_ids).toEqual([retryRes1.body.event_id]);

      // Retry the second event -> succeeds (201), attaches at step_order === 2, event_count === 2, emits once
      const retryRes2 = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${TEST_API_KEY}`)
        .send(payload2)
        .expect(201);

      const seqAfterRetry2 = await ActionSequence.findByPk(seqAfterRetry1.id);
      expect(seqAfterRetry2.event_count).toBe(2);

      const seqLinksAfterRetry2 = await SequenceEvent.findAll({
        where: { sequence_id: seqAfterRetry1.id },
        order: [['step_order', 'ASC']]
      });
      expect(seqLinksAfterRetry2).toHaveLength(2);
      expect(seqLinksAfterRetry2[0].event_id).toBe(retryRes1.body.event_id);
      expect(seqLinksAfterRetry2[0].step_order).toBe(1);
      expect(seqLinksAfterRetry2[1].event_id).toBe(retryRes2.body.event_id);
      expect(seqLinksAfterRetry2[1].step_order).toBe(2);
      expect(emittedEvents).toHaveLength(2);
      expect(emittedEvents[1].event.event_id).toBe(retryRes2.body.event_id);
    } finally {
      eventBus.off('pipeline:event_processed', listener);
    }
  });

  test('T11.2b-13: Duplicate idempotent submissions do not create duplicate security events or duplicate pipeline evaluations', async () => {
    const recordSpy = jest.spyOn(eventService, 'recordSecurityEvent');
    const riskSpy = jest.spyOn(riskEngineService, 'evaluateAndStoreRiskForEvent');

    const nowIso = new Date().toISOString();
    const payload = {
      user_id: userA.id,
      session_id: sessionA.id,
      event_type: 'phone_number_change',
      timestamp: nowIso,
      idempotency_key: 'idem_no_double_work_001'
    };

    await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .send(payload)
      .expect(201);

    await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .send(payload)
      .expect(200);

    await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .send(payload)
      .expect(200);

    expect(recordSpy).toHaveBeenCalledTimes(1);
    expect(riskSpy).toHaveBeenCalledTimes(1);
    expect(await SecurityEvent.count()).toBe(1);
    expect(await RiskAssessment.count()).toBe(1);
  });

  test('T11.2b-14: Raw API keys and secret-bearing values are never persisted or logged, and GET /api/v1/events remains functional', async () => {
    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    const nowIso = new Date().toISOString();

    // 1. Top-level metadata secret key is rejected with 400
    await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .send({
        user_id: userA.id,
        event_type: 'login_failed',
        timestamp: nowIso,
        metadata: {
          password: 'SuperSecretPassword123!'
        }
      })
      .expect(400);

    // 2. Secret-bearing values inside allowlisted fields/details are sanitized/redacted before persistence
    const ingestRes = await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .send({
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'login_failed',
        timestamp: nowIso,
        metadata: {
          reason: `Auth failed with Bearer secret_jwt_token_value_12345 and ${TEST_API_KEY}`,
          details: {
            attempt_source: 'mobile_gateway',
            password_hash: '$2b$10$secretHashValueShouldBeStripped',
            raw_header: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
          }
        }
      })
      .expect(201);

    const storedEvent = await SecurityEvent.findByPk(ingestRes.body.event_id);
    const serializedEvent = JSON.stringify(storedEvent.toJSON());

    expect(serializedEvent).not.toContain(TEST_API_KEY);
    expect(serializedEvent).not.toContain('secret_jwt_token_value_12345');
    expect(serializedEvent).not.toContain('secretHashValueShouldBeStripped');
    expect(serializedEvent).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
    expect(storedEvent.metadata.details.password_hash).toBeUndefined();
    expect(storedEvent.metadata.details.raw_header).toContain('[REDACTED]');

    // Verify console logs never contain the raw API key or secret values
    const allLogs = [
      ...logSpy.mock.calls.flat(),
      ...warnSpy.mock.calls.flat(),
      ...errorSpy.mock.calls.flat()
    ]
      .map((item) => (typeof item === 'string' ? item : JSON.stringify(item)))
      .join(' ');

    expect(allLogs).not.toContain(TEST_API_KEY);
    expect(allLogs).not.toContain('SuperSecretPassword123!');
    expect(allLogs).not.toContain('secret_jwt_token_value_12345');

    // 3. Regression check: GET /api/v1/events returns the ingested event accurately
    const queryRes = await request(app)
      .get(`/api/v1/events?user_id=${userA.id}&event_type=login_failed`)
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .expect(200);

    expect(queryRes.body.total).toBe(1);
    expect(queryRes.body.events[0].event_id).toBe(ingestRes.body.event_id);
    expect(queryRes.body.events[0].user_id).toBe(userA.id);
  });

  test('T11.2b-15: Atomic Redis lease release deletes only matching owner lease and never deletes a replacement lease or falls back to non-atomic DEL', async () => {
    const redisClient = redisStorage.getRedisClient();
    const redisKey = buildTestRedisIdemKey('idem_atomic_lease_test_001');

    const expiredWorkerLease = JSON.stringify({
      status: 'in_progress',
      payload_hash: 'hash_a',
      owner_token: 'owner_worker_1',
      started_at_ms: Date.now() - 35000,
      lease_expires_at_ms: Date.now() - 5000
    });

    const replacementWorkerLease = JSON.stringify({
      status: 'in_progress',
      payload_hash: 'hash_a',
      owner_token: 'owner_worker_2',
      started_at_ms: Date.now(),
      lease_expires_at_ms: Date.now() + 30000
    });

    await redisClient.set(redisKey, replacementWorkerLease, 'EX', 30);

    // 1. Worker 1 attempts to release after Worker 2 acquired the replacement lease -> must NOT delete
    const mismatchedDeleted = await releaseInProgressLease(
      redisClient,
      redisKey,
      expiredWorkerLease
    );
    expect(mismatchedDeleted).toBe(0);
    expect(await redisClient.get(redisKey)).toBe(replacementWorkerLease);

    // 2. Client without atomic eval support fails safely (returns 0) without deleting the key
    const nonAtomicClient = {
      get: jest.fn(),
      del: jest.fn()
    };
    const unsafeDeleted = await releaseInProgressLease(
      nonAtomicClient,
      redisKey,
      replacementWorkerLease
    );
    expect(unsafeDeleted).toBe(0);
    expect(nonAtomicClient.get).not.toHaveBeenCalled();
    expect(nonAtomicClient.del).not.toHaveBeenCalled();
    expect(await redisClient.get(redisKey)).toBe(replacementWorkerLease);

    // 3. Worker 2 (matching owner) atomically releases its own lease -> deletes key and returns 1
    const ownerDeleted = await releaseInProgressLease(
      redisClient,
      redisKey,
      replacementWorkerLease
    );
    expect(ownerDeleted).toBe(1);
    expect(await redisClient.get(redisKey)).toBeNull();
  });

  test('T11.2b-16 (A2-01): recordSecurityEvent uses per-call requireAssessmentForEmit without global eventBus.safeEmit monkey-patching', async () => {
    // 1. Verify global eventBus.safeEmit is not monkey-patched and no installation flag exists
    expect(eventBus.__externalIngestionGuardInstalled).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(eventBus, 'safeEmit')).toBe(false);
    expect(eventBus.safeEmit).toBe(Object.getPrototypeOf(eventBus).safeEmit);

    const processedEmissions = [];
    const unrelatedEmissions = [];
    const onProcessed = (payload) => processedEmissions.push(payload);
    const onUnrelated = (payload) => unrelatedEmissions.push(payload);

    eventBus.on('pipeline:event_processed', onProcessed);
    eventBus.on('custom:unrelated_event', onUnrelated);

    try {
      // 2. Unrelated event-bus emissions work normally
      eventBus.safeEmit('custom:unrelated_event', { ok: true });
      expect(unrelatedEmissions).toEqual([{ ok: true }]);

      // 3. Per-call requireAssessmentForEmit: true suppresses emission when risk assessment fails
      const failSpy = jest
        .spyOn(riskEngineService, 'evaluateAndStoreRiskForEvent')
        .mockResolvedValueOnce(null);

      const suppressedEvt = await eventService.recordSecurityEvent(
        {
          userId: userA.id,
          sessionId: sessionA.id,
          eventType: 'password_change',
          timestamp: new Date()
        },
        { requireAssessmentForEmit: true }
      );
      failSpy.mockRestore();

      expect(suppressedEvt._assessment).toBeNull();
      expect(processedEmissions).toHaveLength(0);

      // 4. Default behavior for existing callers (requireAssessmentForEmit omitted) still emits on assessment failure
      const defaultFailSpy = jest
        .spyOn(riskEngineService, 'evaluateAndStoreRiskForEvent')
        .mockResolvedValueOnce(null);

      const defaultEvt = await eventService.recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA.id,
        eventType: 'password_change',
        timestamp: new Date()
      });
      defaultFailSpy.mockRestore();

      expect(processedEmissions).toHaveLength(1);
      expect(processedEmissions[0].event.event_id).toBe(defaultEvt.event_id);
      expect(processedEmissions[0].assessment).toBeNull();

      // 5. Successful scored assessment with requireAssessmentForEmit: true emits normally with assessment
      const successEvt = await eventService.recordSecurityEvent(
        {
          userId: userA.id,
          sessionId: sessionA.id,
          eventType: 'password_change',
          timestamp: new Date()
        },
        { requireAssessmentForEmit: true }
      );

      expect(successEvt._assessment).not.toBeNull();
      expect(processedEmissions).toHaveLength(2);
      expect(processedEmissions[1].event.event_id).toBe(successEvt.event_id);
      expect(processedEmissions[1].assessment).not.toBeNull();
    } finally {
      eventBus.off('pipeline:event_processed', onProcessed);
      eventBus.off('custom:unrelated_event', onUnrelated);
    }
  });

  test('T11.2b-17 (A2-02): rollbackFailedScoredEvent invalidates sequence cache without overwriting newer sequence state from a pre-commit snapshot', async () => {
    const t1 = new Date(Date.now() - 3000);
    const t2 = new Date(Date.now() - 2000);
    const t3 = new Date(Date.now() - 1000);

    // 1. Create event 1 in sequence
    const evt1 = await SecurityEvent.create({
      event_id: 'evt_a2_02_step1',
      user_id: userA.id,
      session_id: sessionA.id,
      event_type: 'login_success',
      timestamp: t1,
      context: {},
      metadata: {}
    });
    await correlateEventIntoSequence(evt1);

    // 2. Create event 2 (simulating a scored event whose risk assessment failed)
    const evt2 = await SecurityEvent.create({
      event_id: 'evt_a2_02_step2_failed',
      user_id: userA.id,
      session_id: sessionA.id,
      event_type: 'password_change',
      timestamp: t2,
      context: {},
      metadata: {}
    });
    await correlateEventIntoSequence(evt2);

    // 3. Intercept sequelize.transaction so that immediately after the rollback DB transaction commits
    // (releasing row locks, before post-commit Redis cleanup runs), a concurrent event 3 is correlated.
    const origTransaction = sequelize.transaction.bind(sequelize);
    let evt3Created = null;
    const txSpy = jest.spyOn(sequelize, 'transaction').mockImplementationOnce(async (cb) => {
      const txResult = await origTransaction(cb);
      evt3Created = await SecurityEvent.create({
        event_id: 'evt_a2_02_step3_newer',
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'mfa_change',
        timestamp: t3,
        context: {},
        metadata: {}
      });
      await correlateEventIntoSequence(evt3Created);
      return txResult;
    });

    await rollbackFailedScoredEvent(evt2.event_id, userA.id);
    txSpy.mockRestore();

    // Verify rollback invalidated the Redis sequence cache rather than overwriting it with the stale [evt1] snapshot
    const redisClient = redisStorage.getRedisClient();
    expect(await redisClient.get(getSequenceCacheKey(userA.id))).toBeNull();

    // Verify getActiveSequenceFromCache lazily repopulates from authoritative MySQL with the newer [evt1, evt3] sequence
    const activeCached = await getActiveSequenceFromCache(userA.id);
    expect(activeCached).not.toBeNull();
    expect(activeCached.event_count).toBe(2);
    expect(activeCached.event_ids).toEqual([evt1.event_id, evt3Created.event_id]);

    const repopulatedRaw = await redisClient.get(getSequenceCacheKey(userA.id));
    expect(repopulatedRaw).not.toBeNull();
    expect(JSON.parse(repopulatedRaw).event_ids).toEqual([evt1.event_id, evt3Created.event_id]);
  });

  test('T11.2b-18 (A2-03): Ownership-safe idempotency completion verifies lease ownership and supports both scored and unscored paths', async () => {
    const redisClient = redisStorage.getRedisClient();
    const redisKey = buildTestRedisIdemKey('idem_atomic_complete_test_001');

    const worker1Lease = JSON.stringify({
      status: 'in_progress',
      payload_hash: 'hash_complete_test',
      owner_token: 'worker_1_token',
      started_at_ms: Date.now() - 35000,
      lease_expires_at_ms: Date.now() - 5000
    });

    const worker2Lease = JSON.stringify({
      status: 'in_progress',
      payload_hash: 'hash_complete_test',
      owner_token: 'worker_2_token',
      started_at_ms: Date.now(),
      lease_expires_at_ms: Date.now() + 30000
    });

    const completedRecord = JSON.stringify({
      status: 'completed',
      payload_hash: 'hash_complete_test',
      response: { event_id: 'evt_test_complete' },
      completed_at: new Date().toISOString()
    });

    // Case 3: Completion when the lease has expired or disappeared -> returns 0 and does not write
    await redisClient.del(redisKey);
    const missingCompleted = await completeInProgressLease(
      redisClient,
      redisKey,
      worker1Lease,
      completedRecord,
      3600
    );
    expect(missingCompleted).toBe(0);
    expect(await redisClient.get(redisKey)).toBeNull();

    // Non-atomic client without eval fails safely (returns 0) without calling get or set
    const nonAtomicClient = {
      get: jest.fn(),
      set: jest.fn()
    };
    const unsafeCompleted = await completeInProgressLease(
      nonAtomicClient,
      redisKey,
      worker1Lease,
      completedRecord,
      3600
    );
    expect(unsafeCompleted).toBe(0);
    expect(nonAtomicClient.get).not.toHaveBeenCalled();
    expect(nonAtomicClient.set).not.toHaveBeenCalled();

    // Case 2: Completion after lease ownership has changed -> Worker 1 must NOT overwrite Worker 2's lease
    await redisClient.set(redisKey, worker2Lease, 'EX', 30);
    const staleCompleted = await completeInProgressLease(
      redisClient,
      redisKey,
      worker1Lease,
      completedRecord,
      3600
    );
    expect(staleCompleted).toBe(0);
    expect(await redisClient.get(redisKey)).toBe(worker2Lease);

    // Case 1: Completion by the current lease owner (Worker 2) -> writes completed record and preserves TTL
    const ownerCompleted = await completeInProgressLease(
      redisClient,
      redisKey,
      worker2Lease,
      completedRecord,
      3600
    );
    expect(ownerCompleted).toBe(1);
    expect(await redisClient.get(redisKey)).toBe(completedRecord);
    const ttlAfterComplete = await redisClient.ttl(redisKey);
    expect(ttlAfterComplete).toBeGreaterThan(3500);
    expect(ttlAfterComplete).toBeLessThanOrEqual(3600);

    // Case 4: Both scored and unscored ingestion completion paths transition owned leases to completed and replay 200
    const nowIso = new Date().toISOString();
    const scoredKey = 'idem_scored_complete_path_001';
    const unscoredKey = 'idem_unscored_complete_path_001';

    const scoredPayload = {
      user_id: userA.id,
      session_id: sessionA.id,
      event_type: 'password_change',
      timestamp: nowIso,
      idempotency_key: scoredKey
    };

    const scoredRes1 = await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .send(scoredPayload)
      .expect(201);

    const scoredStoredRaw = await redisClient.get(buildTestRedisIdemKey(scoredKey));
    expect(scoredStoredRaw).not.toBeNull();
    expect(JSON.parse(scoredStoredRaw).status).toBe('completed');

    const scoredRes2 = await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .send(scoredPayload)
      .expect(200);
    expect(scoredRes2.body).toEqual(scoredRes1.body);

    const unscoredPayload = {
      user_id: userA.id,
      session_id: sessionA.id,
      event_type: 'session_terminated',
      timestamp: nowIso,
      idempotency_key: unscoredKey
    };

    const unscoredRes1 = await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .send(unscoredPayload)
      .expect(201);

    const unscoredStoredRaw = await redisClient.get(buildTestRedisIdemKey(unscoredKey));
    expect(unscoredStoredRaw).not.toBeNull();
    expect(JSON.parse(unscoredStoredRaw).status).toBe('completed');

    const unscoredRes2 = await request(app)
      .post('/api/v1/events')
      .set('Authorization', `Bearer ${TEST_API_KEY}`)
      .send(unscoredPayload)
      .expect(200);
    expect(unscoredRes2.body).toEqual(unscoredRes1.body);
  });
});
