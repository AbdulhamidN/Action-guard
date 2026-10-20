const request = require('supertest');
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
const { recordSecurityEvent } = require('../src/services/eventService');
const { invalidateSequenceCache } = require('../src/services/sequenceCacheService');
const { getLatestRiskAssessment } = require('../src/services/riskEngineService');
const { tierForScore } = require('../src/utils/riskScoring');
const sequenceGroupingService = require('../src/services/sequenceGroupingService');
const riskEngineService = require('../src/services/riskEngineService');

function assertRiskInvariant(result) {
  expect(result).toBeDefined();
  expect(Number.isInteger(result.risk_score)).toBe(true);
  expect(result.risk_score).toBeGreaterThanOrEqual(0);
  expect(result.risk_score).toBeLessThanOrEqual(100);

  // Exact arithmetic invariant: sum of weights === risk_score
  const computedSum = result.contributing_signals.reduce((acc, s) => acc + s.weight, 0);
  expect(computedSum).toBe(result.risk_score);

  // Tier consistency
  expect(tierForScore(result.risk_score)).toBe(result.risk_tier);
}

describe('Module 6.3b — Live Event Pipeline Wiring', () => {
  let userA;
  let userB;
  let sessionA;
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
      email: 'pipeline-user-a@example.com',
      password_hash: passwordHash
    });

    userB = await User.create({
      email: 'pipeline-user-b@example.com',
      password_hash: passwordHash
    });

    sessionA = await Session.create({
      user_id: userA.id,
      expires_at: new Date(Date.now() + 3600000)
    });
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

  describe('1. Hook Execution & Return Shape', () => {
    test('recording a login_success creates a sequence membership and a risk_assessments row', async () => {
      const recorded = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA.id,
        eventType: 'login_success',
        context: { device_fingerprint: 'fp_live_1', geo_country: 'US' }
      });

      expect(recorded).toBeDefined();
      expect(recorded.event_id).toBeDefined();
      expect(recorded.user_id).toBe(userA.id);

      // Verify sequence membership
      const membership = await SequenceEvent.findOne({
        where: { event_id: recorded.event_id }
      });
      expect(membership).not.toBeNull();
      expect(membership.step_order).toBe(1);

      // Verify risk_assessments row
      const assessment = await RiskAssessment.findOne({
        where: { event_id: recorded.event_id }
      });
      expect(assessment).not.toBeNull();
      expect(assessment.user_id).toBe(userA.id);
      expect(assessment.risk_score).toBeDefined();
      assertRiskInvariant(assessment);
    });

    test('session_created is correlated but produces no assessment; session_terminated likewise', async () => {
      const createdEvent = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA.id,
        eventType: 'session_created',
        context: { ip_address: '1.2.3.4' }
      });

      // Sequence membership exists
      const createdMembership = await SequenceEvent.findOne({
        where: { event_id: createdEvent.event_id }
      });
      expect(createdMembership).not.toBeNull();

      // No risk assessment
      const createdAssessment = await RiskAssessment.findOne({
        where: { event_id: createdEvent.event_id }
      });
      expect(createdAssessment).toBeNull();

      const termEvent = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA.id,
        eventType: 'session_terminated',
        context: { ip_address: '1.2.3.4' }
      });

      // Sequence membership exists
      const termMembership = await SequenceEvent.findOne({
        where: { event_id: termEvent.event_id }
      });
      expect(termMembership).not.toBeNull();

      // No risk assessment
      const termAssessment = await RiskAssessment.findOne({
        where: { event_id: termEvent.event_id }
      });
      expect(termAssessment).toBeNull();
    });

    test('return value of recordSecurityEvent is identical in shape to before the change', async () => {
      const event = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA.id,
        eventType: 'login_success',
        context: { device_fingerprint: 'fp_shape' },
        metadata: { action_sensitivity: 'low' }
      });

      expect(event instanceof SecurityEvent).toBe(true);
      expect(event.event_id).toMatch(/^evt_/);
      expect(event.user_id).toBe(userA.id);
      expect(event.session_id).toBe(sessionA.id);
      expect(event.event_type).toBe('login_success');
      expect(event.timestamp instanceof Date).toBe(true);
      expect(event.context).toEqual({ device_fingerprint: 'fp_shape' });
      expect(event.metadata).toEqual({ action_sensitivity: 'low' });
    });
  });

  describe('2. Isolation & Failure Resilience', () => {
    test('correlation stubbed to throw: recordSecurityEvent still resolves and returns event, event exists, and scoring still runs and includes current event', async () => {
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      const correlateSpy = jest
        .spyOn(sequenceGroupingService, 'correlateEventIntoSequence')
        .mockRejectedValue(new Error('Simulated correlation failure'));

      const event = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA.id,
        eventType: 'login_success',
        context: { device_fingerprint: 'fp_correlate_throw', geo_country: 'US' }
      });

      expect(event).toBeDefined();
      expect(event.event_id).toBeDefined();

      // Event row exists in DB
      const dbEvent = await SecurityEvent.findByPk(event.event_id);
      expect(dbEvent).not.toBeNull();

      // Warning logged for correlation failure
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('[EventPipeline] Sequence correlation failed:'),
        'Simulated correlation failure'
      );

      // Scoring still ran and produced an assessment!
      const assessment = await RiskAssessment.findOne({
        where: { event_id: event.event_id }
      });
      expect(assessment).not.toBeNull();
      expect(assessment.risk_score).toBeDefined();
      assertRiskInvariant(assessment);

      correlateSpy.mockRestore();
      warnSpy.mockRestore();
    });

    test('scoring stubbed to throw: recordSecurityEvent still resolves, event row and sequence membership exist, no assessment row written', async () => {
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      const scoreSpy = jest
        .spyOn(riskEngineService, 'evaluateAndStoreRiskForEvent')
        .mockRejectedValue(new Error('Simulated scoring failure'));

      const event = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA.id,
        eventType: 'login_success',
        context: { device_fingerprint: 'fp_score_throw', geo_country: 'US' }
      });

      expect(event).toBeDefined();
      expect(event.event_id).toBeDefined();

      // Event exists
      const dbEvent = await SecurityEvent.findByPk(event.event_id);
      expect(dbEvent).not.toBeNull();

      // Sequence membership exists
      const membership = await SequenceEvent.findOne({
        where: { event_id: event.event_id }
      });
      expect(membership).not.toBeNull();

      // Warning logged
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('[EventPipeline] Risk evaluation failed:'),
        'Simulated scoring failure'
      );

      // No assessment row
      const assessment = await RiskAssessment.findOne({
        where: { event_id: event.event_id }
      });
      expect(assessment).toBeNull();

      scoreSpy.mockRestore();
      warnSpy.mockRestore();
    });

    test('no user_id: no sequence, no assessment, and console.warn is not called', async () => {
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

      await expect(
        recordSecurityEvent({
          userId: null,
          eventType: 'login_failed'
        })
      ).rejects.toThrow('user_id is required to record a security event');

      expect(warnSpy).not.toHaveBeenCalled();
      const countSeqs = await SequenceEvent.count();
      const countAssessments = await RiskAssessment.count();
      expect(countSeqs).toBe(0);
      expect(countAssessments).toBe(0);

      warnSpy.mockRestore();
    });
  });

  describe('3. Real HTTP Authentication Flow', () => {
    test('three wrong-password logins then a correct login: assessment includes seq_auth_failure_burst and invariant holds', async () => {
      // 1. Three consecutive failed logins for userA
      for (let i = 0; i < 3; i++) {
        await request(app)
          .post('/api/v1/auth/login')
          .send({
            email: userA.email,
            password: 'WrongPassword123!'
          })
          .expect(401);
      }

      // 2. Successful login for userA
      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .set('x-device-fingerprint', 'fp_valid_test_client')
        .send({
          email: userA.email,
          password: passwordPlain
        })
        .expect(200);

      expect(loginRes.body.token).toBeDefined();

      // Find the latest risk assessment for userA
      const latestAssessment = await getLatestRiskAssessment(userA.id);
      expect(latestAssessment).not.toBeNull();
      assertRiskInvariant(latestAssessment);

      // Assessment must include seq_auth_failure_burst
      const signals = latestAssessment.contributing_signals;
      const burstSignal = signals.find((s) => s.signal === 'seq_auth_failure_burst');
      expect(burstSignal).toBeDefined();
      expect(burstSignal.weight).toBe(15);
    });
  });

  describe('4. Live Pipeline Scenario B End-to-End', () => {
    test('Scenario B through the pipeline only: scores exactly 84, critical, invariant holds', async () => {
      const nowMs = Date.now();

      // Seed earlier login_success history on a different device and country (1 hour ago)
      await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA.id,
        eventType: 'login_success',
        timestamp: new Date(nowMs - 3600 * 1000),
        context: {
          device_fingerprint: 'fp_historic_device',
          geo_country: 'US'
        }
      });

      // 1. Impossible-travel login with new device (timestamp: now - 5 minutes)
      const loginEvt = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA.id,
        eventType: 'login_success',
        timestamp: new Date(nowMs - 300 * 1000),
        context: {
          device_fingerprint: 'fp_attacker_device',
          geo_country: 'RU'
        },
        metadata: {
          travel_anomaly: { impossible_travel: true }
        }
      });
      expect(loginEvt).toBeDefined();

      // 2. recovery_email_change (timestamp: now - 3 minutes)
      const recoveryEvt = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA.id,
        eventType: 'recovery_email_change',
        timestamp: new Date(nowMs - 180 * 1000),
        context: {
          device_fingerprint: 'fp_attacker_device',
          geo_country: 'RU'
        },
        metadata: {
          action_sensitivity: 'medium'
        }
      });
      expect(recoveryEvt).toBeDefined();

      // 3. critical password_change (timestamp: now - 1 minute)
      const passwordEvt = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA.id,
        eventType: 'password_change',
        timestamp: new Date(nowMs - 60 * 1000),
        context: {
          device_fingerprint: 'fp_attacker_device',
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

      // Look up assessment for password_change
      const assessment = await RiskAssessment.findOne({
        where: { event_id: passwordEvt.event_id }
      });
      expect(assessment).not.toBeNull();
      assertRiskInvariant(assessment);

      // Verify exact score 84 and critical tier
      expect(assessment.risk_score).toBe(84);
      expect(assessment.risk_tier).toBe('critical');

      // Verify exact contributing signals
      const signals = assessment.contributing_signals;
      expect(signals.some((s) => s.signal === 'base_action_password_change' && s.weight === 20)).toBe(true);
      expect(signals.some((s) => s.signal === 'action_sensitivity_critical' && s.weight === 5)).toBe(true);
      expect(signals.some((s) => s.signal === 'seq_rapid_credential_cascade' && s.weight === 20)).toBe(true);
      expect(signals.some((s) => s.signal === 'behavioral_baseline_deviation' && s.weight === 14)).toBe(true);
    });
  });
});
