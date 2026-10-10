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
  SequenceEvent,
  RiskAssessment
} = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const { JWT_SECRET } = require('../src/middleware/auth');
const { createSession } = require('../src/services/sessionService');
const { recordSecurityEvent } = require('../src/services/eventService');
const { invalidateSequenceCache, getActiveSequenceFromCache } = require('../src/services/sequenceCacheService');
const riskEngineService = require('../src/services/riskEngineService');
const policyConfig = require('../src/config/policyConfig');

describe('Module 8 — Policy API Endpoints, Ownership Checks & Pipeline Scenarios', () => {
  let userA;
  let userB;
  let sessionA1;
  let sessionA2;
  let sessionB1;
  let tokenA;
  let tokenB;
  const passwordPlain = 'Password123!';

  beforeAll(async () => {
    await runMigrations();

    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await RiskAssessment.destroy({ where: {}, force: true });
    await SequenceEvent.destroy({ where: {}, force: true });
    await ActionSequence.destroy({ where: {}, force: true });
    await BehavioralBaseline.destroy({ where: {}, force: true });
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    const passwordHash = await bcrypt.hash(passwordPlain, 10);

    userA = await User.create({
      email: 'policy-api-user-a@example.com',
      password_hash: passwordHash
    });

    userB = await User.create({
      email: 'policy-api-user-b@example.com',
      password_hash: passwordHash
    });

    const sA1 = await createSession(userA.id, userA.email);
    sessionA1 = await Session.findByPk(sA1.sessionId);

    const sA2 = await createSession(userA.id, userA.email);
    sessionA2 = await Session.findByPk(sA2.sessionId);

    const sB1 = await createSession(userB.id, userB.email);
    sessionB1 = await Session.findByPk(sB1.sessionId);

    tokenA = jwt.sign(
      { id: userA.id, email: userA.email, session_id: sessionA1.id },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    tokenB = jwt.sign(
      { id: userB.id, email: userB.email, session_id: sessionB1.id },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
  });

  afterAll(async () => {
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await RiskAssessment.destroy({ where: {}, force: true });
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
    await RiskAssessment.destroy({ where: {}, force: true });
    await SequenceEvent.destroy({ where: {}, force: true });
    await ActionSequence.destroy({ where: {}, force: true });
    await SecurityEvent.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    await invalidateSequenceCache(userA.id);
    await invalidateSequenceCache(userB.id);
  });

  describe('T7. POST /api/v1/policy/evaluate Authentication, Authorization, Validation & Persistence', () => {
    test('401: rejects request without authorization header', async () => {
      const res = await request(app)
        .post('/api/v1/policy/evaluate')
        .send({
          user_id: userA.id,
          event_type: 'login_success'
        })
        .expect(401);

      expect(res.body.error.code).toBe('unauthorized');
    });

    test('401: rejects request with invalid authorization token', async () => {
      const res = await request(app)
        .post('/api/v1/policy/evaluate')
        .set('Authorization', 'Bearer invalid_or_corrupted_token')
        .send({
          user_id: userA.id,
          event_type: 'login_success'
        })
        .expect(401);

      expect(res.body.error.code).toBe('unauthorized');
    });

    test('403: rejects with forbidden on user_id mismatch between caller token and request body', async () => {
      const res = await request(app)
        .post('/api/v1/policy/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userB.id,
          event_type: 'login_success'
        })
        .expect(403);

      expect(res.body.error.code).toBe('forbidden');
      expect(res.body.error.message).toContain('caller is not authorized');
    });

    test('404: rejects with not_found for another user session and for a nonexistent session with identical bodies', async () => {
      // 1. Session belongs to user B, requested by user A
      const resAnotherUser = await request(app)
        .post('/api/v1/policy/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          session_id: sessionB1.id,
          event_type: 'login_success'
        })
        .expect(404);

      expect(resAnotherUser.body.error.code).toBe('not_found');
      expect(resAnotherUser.body.error.message).toBe('Session not found');

      // 2. Nonexistent session ID with identical body structure
      const resNonexistent = await request(app)
        .post('/api/v1/policy/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          session_id: 'sess_nonexistent_00000000_1111_2222',
          event_type: 'login_success'
        })
        .expect(404);

      expect(resNonexistent.body.error.code).toBe('not_found');
      expect(resNonexistent.body.error.message).toBe('Session not found');

      // Bodies must be completely identical
      expect(resAnotherUser.body).toEqual(resNonexistent.body);
    });

    test('400: rejects with invalid_request or invalid_event_type for missing user_id, invalid event_type, invalid action_sensitivity, invalid context', async () => {
      // Missing user_id
      const resMissingUser = await request(app)
        .post('/api/v1/policy/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          event_type: 'login_success'
        })
        .expect(400);
      expect(resMissingUser.body.error.code).toBe('invalid_request');

      // Missing event_type
      const resMissingEventType = await request(app)
        .post('/api/v1/policy/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id
        })
        .expect(400);
      expect(resMissingEventType.body.error.code).toBe('invalid_request');

      // Unrecognized event_type
      const resInvalidEventType = await request(app)
        .post('/api/v1/policy/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          event_type: 'unknown_unsupported_event'
        })
        .expect(400);
      expect(resInvalidEventType.body.error.code).toBe('invalid_event_type');

      // Invalid action_sensitivity in metadata
      const resInvalidSensitivity = await request(app)
        .post('/api/v1/policy/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          event_type: 'login_success',
          metadata: {
            action_sensitivity: 'extreme_danger'
          }
        })
        .expect(400);
      expect(resInvalidSensitivity.body.error.code).toBe('invalid_request');

      // Invalid device fingerprint format in context
      const resInvalidFp = await request(app)
        .post('/api/v1/policy/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          event_type: 'login_success',
          context: {
            device_fingerprint: '!!@@$$##'
          }
        })
        .expect(400);
      expect(resInvalidFp.body.error.code).toBe('invalid_request');
    });

    test('advisory evaluation persists nothing: assessments, sequences, events, and Redis caches remain completely unchanged', async () => {
      const assessmentCountBefore = await RiskAssessment.count();
      const sequenceCountBefore = await ActionSequence.count();
      const sequenceEventCountBefore = await SequenceEvent.count();
      const eventCountBefore = await SecurityEvent.count();
      const cachedSeqBefore = await getActiveSequenceFromCache(userA.id);

      const res = await request(app)
        .post('/api/v1/policy/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          session_id: sessionA1.id,
          event_type: 'password_change',
          metadata: {
            action_sensitivity: 'critical'
          }
        })
        .expect(200);

      expect(res.body.decision).toBeDefined();

      const assessmentCountAfter = await RiskAssessment.count();
      const sequenceCountAfter = await ActionSequence.count();
      const sequenceEventCountAfter = await SequenceEvent.count();
      const eventCountAfter = await SecurityEvent.count();
      const cachedSeqAfter = await getActiveSequenceFromCache(userA.id);

      expect(assessmentCountAfter).toBe(assessmentCountBefore);
      expect(sequenceCountAfter).toBe(sequenceCountBefore);
      expect(sequenceEventCountAfter).toBe(sequenceEventCountBefore);
      expect(eventCountAfter).toBe(eventCountBefore);
      expect(cachedSeqAfter).toEqual(cachedSeqBefore);
    });

    test('response key set equals exactly the allowlist with no scores, signals, rule ids, or admin_facing', async () => {
      const res = await request(app)
        .post('/api/v1/policy/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          session_id: sessionA1.id,
          event_type: 'recovery_email_change'
        })
        .expect(200);

      // Top-level allowlist
      const expectedTopKeys = ['decision', 'enforcement_mode', 'explanation', 'evaluated_at'];
      expect(Object.keys(res.body).sort()).toEqual(expectedTopKeys.sort());

      // Explanation allowlist
      const expectedExplanationKeys = ['user_facing'];
      expect(Object.keys(res.body.explanation).sort()).toEqual(expectedExplanationKeys.sort());

      // Explicit absence of leak fields
      expect(res.body.risk_score).toBeUndefined();
      expect(res.body.score).toBeUndefined();
      expect(res.body.signals).toBeUndefined();
      expect(res.body.signal_names).toBeUndefined();
      expect(res.body.rule_ids).toBeUndefined();
      expect(res.body.reasons).toBeUndefined();
      expect(res.body.explanation.admin_facing).toBeUndefined();
    });

    test('client-supplied timestamp is ignored and server generates current evaluated_at timestamp', async () => {
      const ancientClientTimestamp = '2010-01-01T00:00:00.000Z';
      const beforeReq = Date.now();

      const res = await request(app)
        .post('/api/v1/policy/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          session_id: sessionA1.id,
          event_type: 'login_success',
          timestamp: ancientClientTimestamp
        })
        .expect(200);

      const afterReq = Date.now();
      const evaluatedAtMs = new Date(res.body.evaluated_at).getTime();

      expect(res.body.evaluated_at).not.toBe(ancientClientTimestamp);
      expect(evaluatedAtMs).toBeGreaterThanOrEqual(beforeReq - 1000);
      expect(evaluatedAtMs).toBeLessThanOrEqual(afterReq + 1000);
    });

    test('unavailable risk yields 200 with fail-safe decision and user_facing explanation', async () => {
      const evaluateSpy = jest
        .spyOn(riskEngineService, 'evaluateRisk')
        .mockResolvedValueOnce({
          status: 'unavailable',
          risk_score: null,
          risk_tier: null,
          contributing_signals: [],
          error_code: 'risk_evaluation_failed',
          explanation: {
            user_facing: 'Security risk evaluation is temporarily unavailable.',
            admin_facing: 'Risk engine failed to evaluate context: risk_evaluation_failed.'
          }
        });

      const res = await request(app)
        .post('/api/v1/policy/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          session_id: sessionA1.id,
          event_type: 'password_change', // default high -> fail-safe block
          metadata: {
            action_sensitivity: 'high'
          }
        })
        .expect(200);

      evaluateSpy.mockRestore();

      expect(res.body.decision).toBe('block');
      expect(res.body.enforcement_mode).toBe('automatic');
      expect(typeof res.body.explanation.user_facing).toBe('string');
      expect(res.body.explanation.admin_facing).toBeUndefined();
    });
  });

  describe('T8. Real Pipeline Scenarios & Decision Table Verification', () => {
    test('Scenario A (Routine User Login + Medium Action): routine login followed by medium-sensitivity action produces allow or monitor', async () => {
      const baseTime = Date.now();

      // 1. Routine login 30 minutes ago
      await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.id,
        eventType: 'login_success',
        timestamp: new Date(baseTime - 30 * 60 * 1000),
        context: {
          device_fingerprint: 'fp_routine_desktop',
          geo_country: 'US',
          ip_address: '198.51.100.1'
        }
      });

      // 2. Evaluate policy for proposed medium-sensitivity action
      const res = await request(app)
        .post('/api/v1/policy/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          session_id: sessionA1.id,
          event_type: 'phone_number_change', // default sensitivity medium
          context: {
            device_fingerprint: 'fp_routine_desktop',
            geo_country: 'US',
            ip_address: '198.51.100.1'
          }
        })
        .expect(200);

      expect(['allow', 'monitor']).toContain(res.body.decision);
      expect(res.body.enforcement_mode).toBe('automatic');
    });

    test('Scenario B (Takeover Progression): records steps, evaluates policy per step; decisions never decrease and final password_change is block', async () => {
      const baseTime = Date.now();
      const attackerDevice = 'fp_attacker_laptop';

      // 0. Seed baseline legitimate login 1 hour ago
      await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.id,
        eventType: 'login_success',
        timestamp: new Date(baseTime - 60 * 60 * 1000),
        context: {
          device_fingerprint: 'fp_legit_office',
          geo_country: 'US',
          ip_address: '198.51.100.10'
        }
      });

      const decisionsTable = [];

      // Step 1: Impossible-travel login from new device & Russian IP
      await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA2.id,
        eventType: 'login_success',
        timestamp: new Date(baseTime),
        context: {
          device_fingerprint: attackerDevice,
          geo_country: 'RU',
          ip_address: '203.0.113.50'
        },
        metadata: {
          travel_anomaly: {
            impossible_travel: true
          }
        }
      });

      // Evaluate policy for Step 1 action
      const step1Res = await request(app)
        .post('/api/v1/policy/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          session_id: sessionA2.id,
          event_type: 'login_success',
          context: {
            device_fingerprint: attackerDevice,
            geo_country: 'RU'
          }
        })
        .expect(200);

      decisionsTable.push({ step: 1, action: 'login_success', decision: step1Res.body.decision });

      // Step 2: recovery_email_change 2 minutes later
      await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA2.id,
        eventType: 'recovery_email_change',
        timestamp: new Date(baseTime + 2 * 60 * 1000),
        context: {
          device_fingerprint: attackerDevice,
          geo_country: 'RU',
          ip_address: '203.0.113.50'
        },
        metadata: {
          action_sensitivity: 'medium'
        }
      });

      // Evaluate policy for Step 2 action
      const step2Res = await request(app)
        .post('/api/v1/policy/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          session_id: sessionA2.id,
          event_type: 'recovery_email_change',
          context: {
            device_fingerprint: attackerDevice,
            geo_country: 'RU'
          }
        })
        .expect(200);

      decisionsTable.push({ step: 2, action: 'recovery_email_change', decision: step2Res.body.decision });

      // Step 3: Critical password_change 4 minutes later with behavioral deviation 0.90
      await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA2.id,
        eventType: 'password_change',
        timestamp: new Date(baseTime + 4 * 60 * 1000),
        context: {
          device_fingerprint: attackerDevice,
          geo_country: 'RU',
          ip_address: '203.0.113.50'
        },
        metadata: {
          action_sensitivity: 'critical',
          behavioral_deviation: {
            is_evaluated: true,
            has_sufficient_history: true,
            deviation_score: 0.90
          }
        }
      });

      // Evaluate policy for Step 3 action
      const step3Res = await request(app)
        .post('/api/v1/policy/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          session_id: sessionA2.id,
          event_type: 'password_change',
          context: {
            device_fingerprint: attackerDevice,
            geo_country: 'RU'
          },
          metadata: {
            action_sensitivity: 'critical'
          }
        })
        .expect(200);

      decisionsTable.push({ step: 3, action: 'password_change', decision: step3Res.body.decision });

      // Assertions:
      // 1. Decisions never decrease across steps
      const rank1 = policyConfig.DECISION_ORDER.indexOf(decisionsTable[0].decision);
      const rank2 = policyConfig.DECISION_ORDER.indexOf(decisionsTable[1].decision);
      const rank3 = policyConfig.DECISION_ORDER.indexOf(decisionsTable[2].decision);

      expect(rank2).toBeGreaterThanOrEqual(rank1);
      expect(rank3).toBeGreaterThanOrEqual(rank2);

      // 2. Final critical password_change is strictly 'block'
      expect(decisionsTable[2].decision).toBe('block');
    });
  });
});
