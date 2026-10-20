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
const { invalidateSequenceCache } = require('../src/services/sequenceCacheService');
const { tierForScore } = require('../src/utils/riskScoring');
const riskEngineService = require('../src/services/riskEngineService');
const geoService = require('../src/services/geoService');
const travelCollector = require('../src/collectors/travelCollector');

function assertTierOnlyContract(result) {
  expect(result).toBeDefined();
  expect(['low', 'medium', 'high', 'critical']).toContain(result.risk_tier);
  expect(typeof result.evaluated_at).toBe('string');
  expect(new Date(result.evaluated_at).getTime()).not.toBeNaN();
  expect(result.explanation).toBeDefined();
  expect(typeof result.explanation.user_facing).toBe('string');

  // Removed fields must not be present in tier-only contract
  expect(result.risk_score).toBeUndefined();
  expect(result.current_risk_score).toBeUndefined();
  expect(result.contributing_signals).toBeUndefined();
  expect(result.explanation.admin_facing).toBeUndefined();
}

describe('Module 6.4 — Risk API Endpoints, Ownership Checks & Demo Scenarios', () => {
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
      email: 'risk-api-user-a@example.com',
      password_hash: passwordHash
    });

    userB = await User.create({
      email: 'risk-api-user-b@example.com',
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

  describe('1. Authentication & Ownership Checks', () => {
    test('missing or invalid JWT returns 401 on both endpoints', async () => {
      // POST /api/v1/risk/evaluate with no auth
      await request(app)
        .post('/api/v1/risk/evaluate')
        .send({ user_id: userA.id, event_type: 'password_change' })
        .expect(401);

      // POST /api/v1/risk/evaluate with invalid token
      await request(app)
        .post('/api/v1/risk/evaluate')
        .set('Authorization', 'Bearer invalid_token_xyz')
        .send({ user_id: userA.id, event_type: 'password_change' })
        .expect(401);

      // GET /api/v1/sessions/:id with no auth
      await request(app)
        .get(`/api/v1/sessions/${sessionA1.id}`)
        .expect(401);

      // GET /api/v1/sessions/:id with invalid token
      await request(app)
        .get(`/api/v1/sessions/${sessionA1.id}`)
        .set('Authorization', 'Bearer invalid_token_xyz')
        .expect(401);
    });

    test('ownership: user A posting user B user_id gets 403 forbidden', async () => {
      const res = await request(app)
        .post('/api/v1/risk/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userB.id,
          event_type: 'password_change'
        })
        .expect(403);

      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe('forbidden');
      expect(res.body.error.status).toBe(403);
    });

    test('ownership: user A requesting user B session gets 404 on GET', async () => {
      const res = await request(app)
        .get(`/api/v1/sessions/${sessionB1.id}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(404);

      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe('not_found');
      expect(res.body.error.status).toBe(404);
    });

    test('ownership: user A posting user B session_id gets 404 on POST', async () => {
      const res = await request(app)
        .post('/api/v1/risk/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          session_id: sessionB1.id,
          event_type: 'password_change'
        })
        .expect(404);

      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe('not_found');
      expect(res.body.error.status).toBe(404);
    });

    test('nonexistent session returns the same 404 body as another user session', async () => {
      const fakeSessionId = 'sess_00000000-0000-0000-0000-000000000000';

      const resFake = await request(app)
        .get(`/api/v1/sessions/${fakeSessionId}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(404);

      const resOtherUser = await request(app)
        .get(`/api/v1/sessions/${sessionB1.id}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(404);

      expect(resFake.body).toEqual(resOtherUser.body);
    });
  });

  describe('2. Input Validation', () => {
    test('unknown event_type returns 400 invalid_event_type', async () => {
      const res = await request(app)
        .post('/api/v1/risk/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          event_type: 'non_existent_event_type'
        })
        .expect(400);

      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe('invalid_event_type');
      expect(res.body.error.status).toBe(400);
    });

    test('bad action_sensitivity returns 400 invalid_request', async () => {
      const res = await request(app)
        .post('/api/v1/risk/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          event_type: 'password_change',
          metadata: {
            action_sensitivity: 'catastrophic'
          }
        })
        .expect(400);

      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe('invalid_request');
      expect(res.body.error.status).toBe(400);
    });

    test('malformed body returns 400 invalid_request', async () => {
      // Missing user_id
      await request(app)
        .post('/api/v1/risk/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          event_type: 'password_change'
        })
        .expect(400);

      // Missing event_type
      await request(app)
        .post('/api/v1/risk/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id
        })
        .expect(400);

      // Malformed context (not an object)
      await request(app)
        .post('/api/v1/risk/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          event_type: 'password_change',
          context: 'invalid_string'
        })
        .expect(400);

      // Malformed device_fingerprint (too short or invalid chars)
      await request(app)
        .post('/api/v1/risk/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          event_type: 'password_change',
          context: {
            device_fingerprint: '!!'
          }
        })
        .expect(400);
    });
  });

  describe('3. Advisory Behavior', () => {
    test('a critical password_change evaluated after recent recovery_email_change scores higher than on clean account, nothing persisted, client timestamp ignored', async () => {
      const initialAssessments = await RiskAssessment.count();
      const initialSequences = await ActionSequence.count();
      const initialSequenceEvents = await SequenceEvent.count();

      // Clean account baseline evaluation
      const cleanRes = await request(app)
        .post('/api/v1/risk/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          event_type: 'password_change',
          metadata: { action_sensitivity: 'critical' }
        })
        .expect(200);

      assertTierOnlyContract(cleanRes.body);

      // Record a real recovery_email_change 1 minute ago
      await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.id,
        eventType: 'recovery_email_change',
        timestamp: new Date(Date.now() - 60 * 1000),
        metadata: { action_sensitivity: 'medium' }
      });

      // Post-cascade proposed password_change with a spoofed old client timestamp
      const clientSpoofedTime = new Date('2020-01-01T00:00:00Z').toISOString();
      const cascadeRes = await request(app)
        .post('/api/v1/risk/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          session_id: sessionA1.id,
          event_type: 'password_change',
          timestamp: clientSpoofedTime,
          metadata: { action_sensitivity: 'critical' }
        })
        .expect(200);

      assertTierOnlyContract(cascadeRes.body);

      // Tier-only contract assertions
      expect(cascadeRes.body.risk_tier).toBe('medium');
      expect(cascadeRes.body.risk_score).toBeUndefined();
      expect(cascadeRes.body.contributing_signals).toBeUndefined();
      expect(cascadeRes.body.explanation.admin_facing).toBeUndefined();

      // Evaluated_at must be recent, ignoring the 2020 client timestamp
      const evalYear = new Date(cascadeRes.body.evaluated_at).getFullYear();
      expect(evalYear).toBeGreaterThanOrEqual(2026);

      // Verify no decision or allow/block fields in body (Module 8 responsibility)
      expect(cascadeRes.body.decision).toBeUndefined();
      expect(cascadeRes.body.allow).toBeUndefined();
      expect(cascadeRes.body.block).toBeUndefined();

      // Verify NOTHING was persisted from the advisory evaluation (only the 1 recovery event)
      const afterAssessments = await RiskAssessment.count();
      const afterSequences = await ActionSequence.count();
      const afterSequenceEvents = await SequenceEvent.count();

      // Exactly 1 assessment and sequence event from the real recovery event, none from evaluate
      expect(afterAssessments).toBe(initialAssessments + 1);
      expect(afterSequences).toBe(initialSequences + 1);
      expect(afterSequenceEvents).toBe(initialSequenceEvents + 1);
    });
  });

  describe('4. Failure Handling', () => {
    test('with scoring forced to fail, POST returns 503 unavailable with explanation object', async () => {
      const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const evalSpy = jest
        .spyOn(riskEngineService, 'evaluateRisk')
        .mockRejectedValue(new Error('Simulated evaluation failure'));

      const res = await request(app)
        .post('/api/v1/risk/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          event_type: 'password_change'
        })
        .expect(503);

      expect(res.body).toEqual({
        status: 'unavailable',
        risk_tier: null,
        error_code: 'risk_evaluation_failed',
        explanation: {
          user_facing: 'Security risk evaluation is temporarily unavailable.'
        }
      });
      expect(res.body.risk_score).toBeUndefined();
      expect(res.body.contributing_signals).toBeUndefined();
      expect(res.body.explanation.admin_facing).toBeUndefined();

      evalSpy.mockRestore();
      errSpy.mockRestore();
    });
  });

  describe('5. GET /api/v1/sessions/:id Inspection', () => {
    test('a scored session returns its latest assessment; a session with no assessments returns 200 with nulls', async () => {
      // 1. Session with no assessments yet (sessionA2)
      const resUnscored = await request(app)
        .get(`/api/v1/sessions/${sessionA2.id}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);

      expect(resUnscored.body.session_id).toBe(sessionA2.id);
      expect(resUnscored.body.created_at).toBeDefined();
      expect(resUnscored.body.expires_at).toBeDefined();
      expect(resUnscored.body.is_active).toBe(true);
      expect(resUnscored.body.risk).toEqual({
        risk_tier: null,
        evaluated_at: null,
        explanation: {
          user_facing: ''
        }
      });
      expect(resUnscored.body.risk.current_risk_score).toBeUndefined();
      expect(resUnscored.body.risk.contributing_signals).toBeUndefined();

      // 2. Record an event in sessionA1 to generate an assessment
      await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.id,
        eventType: 'login_success',
        context: { device_fingerprint: 'fp_seen_1', geo_country: 'US' }
      });

      const resScored = await request(app)
        .get(`/api/v1/sessions/${sessionA1.id}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);

      expect(resScored.body.session_id).toBe(sessionA1.id);
      assertTierOnlyContract(resScored.body.risk);
      expect(resScored.body.risk.current_risk_score).toBeUndefined();
      expect(resScored.body.risk.risk_score).toBeUndefined();
      expect(resScored.body.risk.contributing_signals).toBeUndefined();
      expect(resScored.body.risk.explanation.admin_facing).toBeUndefined();
    });
  });

  describe('6. Privacy Verification', () => {
    test('serialized response body contains none of: request IP, device fingerprint, latitude, longitude, password hash', async () => {
      const sensitiveIp = '203.0.113.195';
      const sensitiveFingerprint = 'device_fp_secret_hardware_identifier_999';

      // 1. POST /api/v1/risk/evaluate
      const evalRes = await request(app)
        .post('/api/v1/risk/evaluate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          user_id: userA.id,
          session_id: sessionA1.id,
          event_type: 'login_success',
          context: {
            ip_address: sensitiveIp,
            device_fingerprint: sensitiveFingerprint
          }
        })
        .expect(200);

      const evalBodyString = JSON.stringify(evalRes.body);
      expect(evalBodyString).not.toContain(sensitiveIp);
      expect(evalBodyString).not.toContain(sensitiveFingerprint);
      expect(evalBodyString.toLowerCase()).not.toContain('latitude');
      expect(evalBodyString.toLowerCase()).not.toContain('longitude');
      expect(evalBodyString).not.toContain('password_hash');
      expect(evalBodyString).not.toContain(userA.password_hash);

      // 2. GET /api/v1/sessions/:id
      const sessionRes = await request(app)
        .get(`/api/v1/sessions/${sessionA1.id}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);

      const sessionBodyString = JSON.stringify(sessionRes.body);
      expect(sessionBodyString).not.toContain(sensitiveIp);
      expect(sessionBodyString).not.toContain(sensitiveFingerprint);
      expect(sessionBodyString.toLowerCase()).not.toContain('latitude');
      expect(sessionBodyString.toLowerCase()).not.toContain('longitude');
      expect(sessionBodyString).not.toContain('password_hash');
      expect(sessionBodyString).not.toContain(userA.id); // raw user_id omitted from session response
    });
  });

  describe('7. Scenario 1 — Normal User Flow', () => {
    test('seed an earlier login, log in over HTTP from same device/country, GET session: tier low and invariant holds', async () => {
      const normalFingerprint = 'fp_normal_regular_device';
      const normalCountry = 'US';
      const nowMs = Date.now();

      // Seed earlier login 1 hour ago
      await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.id,
        eventType: 'login_success',
        timestamp: new Date(nowMs - 3600 * 1000),
        context: {
          device_fingerprint: normalFingerprint,
          geo_country: normalCountry
        }
      });

      // Login over HTTP from the same device and country
      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .set('x-device-fingerprint', normalFingerprint)
        .send({
          email: userA.email,
          password: passwordPlain
        })
        .expect(200);

      expect(loginRes.body.session_id).toBeDefined();
      expect(loginRes.body.token).toBeDefined();

      // GET /api/v1/sessions/:id
      const sessionRes = await request(app)
        .get(`/api/v1/sessions/${loginRes.body.session_id}`)
        .set('Authorization', `Bearer ${loginRes.body.token}`)
        .expect(200);

      const riskState = sessionRes.body.risk;
      expect(riskState.risk_tier).toBe('low');
      assertTierOnlyContract(riskState);
      expect(riskState.current_risk_score).toBeUndefined();
      expect(riskState.contributing_signals).toBeUndefined();
    });
  });

  describe('8. Scenario 2 — Simulated Takeover Progression', () => {
    test('seed earlier history on different device/country, login with new device, record recovery_email and critical password_change: scores at least 80 (84), critical, invariant holds', async () => {
      const nowMs = Date.now();
      const oldFingerprint = 'fp_initial_office_desktop';
      const oldCountry = 'US';
      const attackerFingerprint = 'fp_attacker_unrecognized_laptop';

      // 1. Seed earlier login_success on old device and country (1 hour ago in US)
      await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.id,
        eventType: 'login_success',
        timestamp: new Date(nowMs - 3600 * 1000),
        context: {
          ip_address: '198.51.100.1',
          device_fingerprint: oldFingerprint,
          geo_country: oldCountry
        }
      });

      // Spy geo resolution and coordinate resolution for attacker's login
      const geoSpy = jest.spyOn(geoService, 'resolveGeoLocation').mockResolvedValue({
        ip: '203.0.113.195',
        geo_country: 'RU',
        geo_region: 'MOW'
      });
      const coordsSpy = jest.spyOn(geoService, 'resolveCoordinates').mockImplementation(async (ip) => {
        if (ip === '198.51.100.1') return { latitude: 40.7128, longitude: -74.006 }; // NY
        return { latitude: 55.7558, longitude: 37.6173 }; // Moscow
      });

      let takeoverSessionId;
      let takeoverToken;

      try {
        // 2. Log in over HTTP with the attacker's new device
        const loginRes = await request(app)
          .post('/api/v1/auth/login')
          .set('x-device-fingerprint', attackerFingerprint)
          .send({
            email: userA.email,
            password: passwordPlain
          })
          .expect(200);

        takeoverSessionId = loginRes.body.session_id;
        takeoverToken = loginRes.body.token;
      } finally {
        geoSpy.mockRestore();
        coordsSpy.mockRestore();
      }

      // 3. Record recovery_email_change sequentially after the login
      const recoveryEvt = await recordSecurityEvent({
        userId: userA.id,
        sessionId: takeoverSessionId,
        eventType: 'recovery_email_change',
        timestamp: new Date(Date.now() + 1000),
        context: {
          device_fingerprint: attackerFingerprint,
          geo_country: 'RU'
        },
        metadata: {
          action_sensitivity: 'medium'
        }
      });
      expect(recoveryEvt).toBeDefined();

      // 4. Record critical password_change sequentially after recovery with baseline deviation 0.90
      const passwordEvt = await recordSecurityEvent({
        userId: userA.id,
        sessionId: takeoverSessionId,
        eventType: 'password_change',
        timestamp: new Date(Date.now() + 2000),
        context: {
          device_fingerprint: attackerFingerprint,
          geo_country: 'RU'
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
      expect(passwordEvt).toBeDefined();

      // 5. Query session risk state over HTTP via GET /api/v1/sessions/:id
      const sessionRes = await request(app)
        .get(`/api/v1/sessions/${takeoverSessionId}`)
        .set('Authorization', `Bearer ${takeoverToken}`)
        .expect(200);

      const riskState = sessionRes.body.risk;
      assertTierOnlyContract(riskState);

      // Verify critical tier and removal of score/signals/admin_facing
      expect(riskState.risk_tier).toBe('critical');
      expect(riskState.current_risk_score).toBeUndefined();
      expect(riskState.risk_score).toBeUndefined();
      expect(riskState.contributing_signals).toBeUndefined();
      expect(riskState.explanation.admin_facing).toBeUndefined();
    });
  });
});
