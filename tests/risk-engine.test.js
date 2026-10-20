const bcrypt = require('bcrypt');
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
const migration005 = require('../src/database/migrations/005_risk_assessments');
const migration006 = require('../src/database/migrations/006_datetime_millisecond_precision');
const { recordSecurityEvent } = require('../src/services/eventService');
const riskConfig = require('../src/config/riskConfig');
const {
  assembleEvaluationContext,
  evaluateRisk,
  evaluateAndStoreRiskForEvent,
  getLatestRiskAssessment,
  deriveNoveltyFlags
} = require('../src/services/riskEngineService');
const { tierForScore } = require('../src/utils/riskScoring');
const { correlateEventIntoSequence } = require('../src/services/sequenceGroupingService');
const { invalidateSequenceCache } = require('../src/services/sequenceCacheService');

function assertRiskInvariant(result) {
  expect(result).toBeDefined();
  expect(result.status).toBe('ok');
  expect(Number.isInteger(result.risk_score)).toBe(true);
  expect(result.risk_score).toBeGreaterThanOrEqual(0);
  expect(result.risk_score).toBeLessThanOrEqual(100);

  // Exact arithmetic invariant: sum of weights === risk_score
  const computedSum = result.contributing_signals.reduce((acc, s) => acc + s.weight, 0);
  expect(computedSum).toBe(result.risk_score);

  // Tier consistency
  expect(tierForScore(result.risk_score)).toBe(result.risk_tier);
}

describe('Module 6.3a — Risk Assessment Persistence & Engine Coordinator', () => {
  let userA;
  let userB;
  let sessionA;
  let sessionB;
  const baseTime = 1770000000000; // deterministic epoch ms

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

    const passwordHash = await bcrypt.hash('TestPassword123!', 10);

    userA = await User.create({
      email: 'risk-user-a@example.com',
      password_hash: passwordHash
    });

    userB = await User.create({
      email: 'risk-user-b@example.com',
      password_hash: passwordHash
    });

    sessionA = await Session.create({
      user_id: userA.id,
      expires_at: new Date(Date.now() + 3600000)
    });

    sessionB = await Session.create({
      user_id: userB.id,
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

  describe('1. Migration up, down, re-apply & Foreign Key Cascade Behaviors', () => {
    test('migration up, down, and re-apply completes cleanly', async () => {
      const queryInterface = sequelize.getQueryInterface();

      // Down drops risk_assessments
      await migration005.down(queryInterface);
      const tablesAfterDown = await queryInterface.showAllTables();
      const namesAfterDown = tablesAfterDown.map((t) => (typeof t === 'string' ? t : t.tableName || Object.values(t)[0]));
      expect(namesAfterDown.includes('risk_assessments')).toBe(false);

      // Up recreates risk_assessments
      await migration005.up(queryInterface);
      const tablesAfterUp = await queryInterface.showAllTables();
      const namesAfterUp = tablesAfterUp.map((t) => (typeof t === 'string' ? t : t.tableName || Object.values(t)[0]));
      expect(namesAfterUp.includes('risk_assessments')).toBe(true);

      const indexes = await queryInterface.showIndex('risk_assessments');
      const indexNames = indexes.map((idx) => idx.name);
      expect(indexNames).toContain('idx_risk_user_time');
      expect(indexNames).toContain('idx_risk_session_time');
      expect(indexNames).toContain('idx_risk_event');
    });

    test('migration 006 up, down, and re-apply completes cleanly', async () => {
      const queryInterface = sequelize.getQueryInterface();

      // Down reverts to DATETIME(0)
      await migration006.down(queryInterface);
      const [colsDown] = await sequelize.query(`
        SELECT TABLE_NAME, COLUMN_NAME, DATETIME_PRECISION 
        FROM INFORMATION_SCHEMA.COLUMNS 
        WHERE TABLE_SCHEMA = DATABASE() 
          AND TABLE_NAME IN ('action_sequences', 'sequence_events', 'risk_assessments', 'security_events')
          AND COLUMN_NAME IN ('started_at', 'last_event_at', 'added_at', 'evaluated_at', 'timestamp')
      `);
      for (const col of colsDown) {
        expect(col.DATETIME_PRECISION).toBe(0);
      }

      // Up promotes to DATETIME(3)
      await migration006.up(queryInterface);
      const [colsUp] = await sequelize.query(`
        SELECT TABLE_NAME, COLUMN_NAME, DATETIME_PRECISION 
        FROM INFORMATION_SCHEMA.COLUMNS 
        WHERE TABLE_SCHEMA = DATABASE() 
          AND TABLE_NAME IN ('action_sequences', 'sequence_events', 'risk_assessments', 'security_events')
          AND COLUMN_NAME IN ('started_at', 'last_event_at', 'added_at', 'evaluated_at', 'timestamp')
      `);
      for (const col of colsUp) {
        expect(col.DATETIME_PRECISION).toBe(3);
      }
    });

    test('the 40 ms repro lands in one sequence', async () => {
      const baseMs = new Date('2026-06-01T12:00:00.000Z').getTime();
      const t1 = new Date(baseMs + 600);
      const t2 = new Date(baseMs + 640);

      const event1 = await recordSecurityEvent({
        userId: userA.id,
        eventType: 'login_success',
        timestamp: t1
      });

      const event2 = await recordSecurityEvent({
        userId: userA.id,
        eventType: 'session_created',
        timestamp: t2
      });

      const sequences = await ActionSequence.findAll({ where: { user_id: userA.id } });
      expect(sequences.length).toBe(1);
      expect(sequences[0].event_count).toBe(2);

      const sequenceEvents = await SequenceEvent.findAll({
        where: { sequence_id: sequences[0].id },
        order: [['step_order', 'ASC']]
      });
      expect(sequenceEvents.length).toBe(2);
      expect(sequenceEvents[0].event_id).toBe(event1.event_id);
      expect(sequenceEvents[1].event_id).toBe(event2.event_id);
    });

    test('getLatestRiskAssessment returns the later of two assessments recorded in the same wall-clock second with different milliseconds', async () => {
      const baseMs = new Date('2026-06-01T12:00:00.000Z').getTime();
      const earlierDate = new Date(baseMs + 100);
      const laterDate = new Date(baseMs + 500);

      // Create earlier assessment
      await RiskAssessment.create({
        event_id: null,
        user_id: userA.id,
        session_id: null,
        risk_score: 10,
        risk_tier: 'low',
        contributing_signals: [{ signal: 'test_earlier', weight: 10, category: 'base_action' }],
        explanation: { user_facing: 'Earlier', admin_facing: 'Earlier' },
        evaluated_at: earlierDate
      });

      // Create later assessment
      const laterAssessment = await RiskAssessment.create({
        event_id: null,
        user_id: userA.id,
        session_id: null,
        risk_score: 45,
        risk_tier: 'medium',
        contributing_signals: [{ signal: 'test_later', weight: 45, category: 'base_action' }],
        explanation: { user_facing: 'Later', admin_facing: 'Later' },
        evaluated_at: laterDate
      });

      const latest = await getLatestRiskAssessment(userA.id);
      expect(latest).not.toBeNull();
      expect(latest.id).toBe(laterAssessment.id);
      expect(latest.risk_score).toBe(45);
      expect(new Date(latest.evaluated_at).getTime()).toBe(laterDate.getTime());
    });

    test('deleting an event leaves the risk assessment with event_id NULL', async () => {
      const event = await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'login_success',
        timestamp: new Date()
      });

      const assessment = await RiskAssessment.create({
        event_id: event.event_id,
        user_id: userA.id,
        session_id: sessionA.id,
        risk_score: 5,
        risk_tier: 'low',
        contributing_signals: [{ signal: 'base_action_login_success', category: 'base_action', weight: 5 }],
        explanation: { user_facing: 'Normal', admin_facing: 'Normal' }
      });

      expect(assessment.event_id).toBe(event.event_id);

      await event.destroy();

      const reloaded = await RiskAssessment.findByPk(assessment.id);
      expect(reloaded).not.toBeNull();
      expect(reloaded.event_id).toBeNull();
      expect(reloaded.user_id).toBe(userA.id);
    });

    test('deleting a session leaves the risk assessment with session_id NULL', async () => {
      const tempSession = await Session.create({
        user_id: userA.id,
        expires_at: new Date(Date.now() + 3600000)
      });

      const assessment = await RiskAssessment.create({
        user_id: userA.id,
        session_id: tempSession.id,
        risk_score: 10,
        risk_tier: 'low',
        contributing_signals: [{ signal: 'base_action_new_device', category: 'base_action', weight: 10 }],
        explanation: { user_facing: 'Normal', admin_facing: 'Normal' }
      });

      await tempSession.destroy();

      const reloaded = await RiskAssessment.findByPk(assessment.id);
      expect(reloaded).not.toBeNull();
      expect(reloaded.session_id).toBeNull();
    });

    test('deleting a user cascades and deletes all their risk assessments', async () => {
      const tempUser = await User.create({
        email: 'temp-cascade-user@example.com',
        password_hash: 'hash'
      });

      const assessment = await RiskAssessment.create({
        user_id: tempUser.id,
        risk_score: 5,
        risk_tier: 'low',
        contributing_signals: [],
        explanation: {}
      });

      await tempUser.destroy();

      const reloaded = await RiskAssessment.findByPk(assessment.id);
      expect(reloaded).toBeNull();
    });
  });

  describe('2. Model Validations & Round-Trip Persistence', () => {
    test('enforces score range [0, 100] and valid risk tier', async () => {
      await expect(RiskAssessment.create({
        user_id: userA.id,
        risk_score: -1,
        risk_tier: 'low',
        contributing_signals: [],
        explanation: {}
      })).rejects.toThrow();

      await expect(RiskAssessment.create({
        user_id: userA.id,
        risk_score: 101,
        risk_tier: 'low',
        contributing_signals: [],
        explanation: {}
      })).rejects.toThrow();

      await expect(RiskAssessment.create({
        user_id: userA.id,
        risk_score: 50,
        risk_tier: 'invalid_tier',
        contributing_signals: [],
        explanation: {}
      })).rejects.toThrow();
    });

    test('persists row and round-trips signals and explanation, stored weights sum to risk_score', async () => {
      const event = await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'login_success',
        timestamp: new Date()
      });

      const stored = await evaluateAndStoreRiskForEvent(event);
      expect(stored).not.toBeNull();
      expect(stored.id).toMatch(/^rsk_/);
      expect(stored.event_id).toBe(event.event_id);
      expect(stored.user_id).toBe(userA.id);
      expect(stored.session_id).toBe(sessionA.id);

      const reloaded = await RiskAssessment.findByPk(stored.id);
      expect(Array.isArray(reloaded.contributing_signals)).toBe(true);
      expect(reloaded.explanation).toBeDefined();

      const sumWeights = reloaded.contributing_signals.reduce((acc, s) => acc + s.weight, 0);
      expect(sumWeights).toBe(reloaded.risk_score);
    });
  });

  describe('3. Context Assembly & Novelty Rules', () => {
    test('first-ever login emits NO novelty signals (unrecognized_device = false, unrecognized_country = false)', async () => {
      const event = {
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime),
        context: {
          device_fingerprint: 'fp_first_ever',
          geo_country: 'US'
        }
      };

      const ctx = await assembleEvaluationContext(event);
      expect(ctx.context.unrecognized_device).toBe(false);
      expect(ctx.context.unrecognized_country).toBe(false);
    });

    test('first-sighting device on subsequent login is unrecognized; previously seen device is not', async () => {
      // Seed prior login_success
      await SecurityEvent.create({
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime),
        context: {
          device_fingerprint: 'fp_known',
          geo_country: 'US'
        }
      });

      // Event 2: new device fingerprint -> unrecognized_device = true
      const eventNewDevice = {
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime + 10000),
        context: {
          device_fingerprint: 'fp_brand_new',
          geo_country: 'US'
        }
      };
      const ctxNew = await assembleEvaluationContext(eventNewDevice);
      expect(ctxNew.context.unrecognized_device).toBe(true);
      expect(ctxNew.context.unrecognized_country).toBe(false);

      // Event 3: known device fingerprint -> unrecognized_device = false
      const eventKnownDevice = {
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime + 20000),
        context: {
          device_fingerprint: 'fp_known',
          geo_country: 'US'
        }
      };
      const ctxKnown = await assembleEvaluationContext(eventKnownDevice);
      expect(ctxKnown.context.unrecognized_device).toBe(false);
    });

    test('is_trusted false on a previously seen device adds NO risk (is_trusted is never used)', async () => {
      // Device table row exists with is_trusted: false
      await Device.create({
        user_id: userA.id,
        fingerprint: 'fp_untrusted_device',
        is_trusted: false,
        first_seen_at: new Date(baseTime - 10000)
      });

      // Seed prior login_success with this fingerprint
      await SecurityEvent.create({
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime),
        context: {
          device_fingerprint: 'fp_untrusted_device',
          geo_country: 'US'
        }
      });

      // Routine login with the same fingerprint
      const event = {
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime + 10000),
        context: {
          device_fingerprint: 'fp_untrusted_device',
          geo_country: 'US'
        }
      };

      const ctx = await assembleEvaluationContext(event);
      expect(ctx.context.unrecognized_device).toBe(false);

      const evaluation = await evaluateRisk(event);
      expect(evaluation.status).toBe('ok');
      expect(evaluation.risk_score).toBe(5); // base_action_login_success only
      expect(evaluation.risk_tier).toBe('low');
      const hasDeviceSignal = evaluation.contributing_signals.some((s) => s.signal === 'unrecognized_device');
      expect(hasDeviceSignal).toBe(false);
    });

    test('failed logins carrying a fingerprint do not make that device recognized on a later success', async () => {
      // Seed prior login_success on fp_1
      await SecurityEvent.create({
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime),
        context: {
          device_fingerprint: 'fp_1',
          geo_country: 'US'
        }
      });

      // Record a failed login on fp_2
      await SecurityEvent.create({
        user_id: userA.id,
        event_type: 'login_failed',
        timestamp: new Date(baseTime + 5000),
        context: {
          device_fingerprint: 'fp_2',
          geo_country: 'US'
        }
      });

      // Subsequent login_success with fp_2: must still be considered unrecognized!
      const event = {
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime + 10000),
        context: {
          device_fingerprint: 'fp_2',
          geo_country: 'US'
        }
      };

      const ctx = await assembleEvaluationContext(event);
      expect(ctx.context.unrecognized_device).toBe(true);
    });

    test('null country and null fingerprint emit no signal', async () => {
      // Seed prior login
      await SecurityEvent.create({
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime),
        context: {
          device_fingerprint: 'fp_1',
          geo_country: 'US'
        }
      });

      const event = {
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime + 10000),
        context: {
          device_fingerprint: null,
          geo_country: null
        }
      };

      const ctx = await assembleEvaluationContext(event);
      expect(ctx.context.unrecognized_device).toBe(false);
      expect(ctx.context.unrecognized_country).toBe(false);
    });

    test('events inserted directly with no Device row evaluate correctly', async () => {
      // Clean Device table
      await Device.destroy({ where: { user_id: userA.id }, force: true });

      await SecurityEvent.create({
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime),
        context: {
          device_fingerprint: 'fp_nodevice_model',
          geo_country: 'CA'
        }
      });

      const event = {
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime + 10000),
        context: {
          device_fingerprint: 'fp_nodevice_model',
          geo_country: 'CA'
        }
      };

      const ctx = await assembleEvaluationContext(event);
      expect(ctx.context.unrecognized_device).toBe(false);
      expect(ctx.context.unrecognized_country).toBe(false);
    });

    test('geo recognized and unrecognized', async () => {
      await SecurityEvent.create({
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime),
        context: {
          device_fingerprint: 'fp_1',
          geo_country: 'US'
        }
      });

      const eventKnown = {
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime + 10000),
        context: {
          device_fingerprint: 'fp_1',
          geo_country: 'US'
        }
      };
      const ctxKnown = await assembleEvaluationContext(eventKnown);
      expect(ctxKnown.context.unrecognized_country).toBe(false);

      const eventNewCountry = {
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime + 20000),
        context: {
          device_fingerprint: 'fp_1',
          geo_country: 'FR'
        }
      };
      const ctxNewCountry = await assembleEvaluationContext(eventNewCountry);
      expect(ctxNewCountry.context.unrecognized_country).toBe(true);
    });

    test('travel is inherited from same-session login_success and NOT from another session', async () => {
      // Session A login has travel anomaly = true
      await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime),
        metadata: {
          travel_anomaly: { impossible_travel: true }
        }
      });

      // Session B login has travel anomaly = false
      await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionB.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime + 1000),
        metadata: {
          travel_anomaly: { impossible_travel: false }
        }
      });

      // Event in Session A (e.g. password_change) with no explicit metadata.travel_anomaly
      const eventSessionA = {
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'password_change',
        timestamp: new Date(baseTime + 5000),
        metadata: {}
      };

      const ctxA = await assembleEvaluationContext(eventSessionA);
      expect(ctxA.context.impossible_travel).toBe(true);

      // Event in Session B with no explicit travel_anomaly
      const eventSessionB = {
        user_id: userA.id,
        session_id: sessionB.id,
        event_type: 'password_change',
        timestamp: new Date(baseTime + 6000),
        metadata: {}
      };

      const ctxB = await assembleEvaluationContext(eventSessionB);
      expect(ctxB.context.impossible_travel).toBe(false);
    });

    test('bot timing is ignored on non-login events', async () => {
      const event = {
        user_id: userA.id,
        event_type: 'password_change',
        timestamp: new Date(baseTime),
        metadata: {
          bot_detection: { automation_suspected: true }
        }
      };

      const ctx = await assembleEvaluationContext(event);
      expect(ctx.timing.automation_suspected).toBe(false);

      const loginEvent = {
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime),
        metadata: {
          bot_detection: { automation_suspected: true }
        }
      };

      const ctxLogin = await assembleEvaluationContext(loginEvent);
      expect(ctxLogin.timing.automation_suspected).toBe(true);
    });

    test('insufficient baseline history gives weight-0 signal; evaluated baseline gives scaled signal', async () => {
      const eventNoHistory = {
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime),
        metadata: {
          behavioral_deviation: {
            is_evaluated: false,
            has_sufficient_history: false,
            deviation_score: null
          }
        }
      };

      const evalNoHistory = await evaluateRisk(eventNoHistory);
      expect(evalNoHistory.status).toBe('ok');
      const bSig0 = evalNoHistory.contributing_signals.find((s) => s.category === 'baseline');
      expect(bSig0).toBeDefined();
      expect(bSig0.signal).toBe('baseline_insufficient_history');
      expect(bSig0.weight).toBe(0);

      const eventWithHistory = {
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime),
        metadata: {
          behavioral_deviation: {
            is_evaluated: true,
            has_sufficient_history: true,
            deviation_score: 0.8
          }
        }
      };

      const evalWithHistory = await evaluateRisk(eventWithHistory);
      expect(evalWithHistory.status).toBe('ok');
      const bSig = evalWithHistory.contributing_signals.find((s) => s.category === 'baseline');
      expect(bSig).toBeDefined();
      expect(bSig.signal).toBe('behavioral_baseline_deviation');
      // Math.round(0.8 * 15) = 12
      expect(bSig.weight).toBe(12);
    });
  });

  describe('4. Step-up Verification Scoping', () => {
    test('verification in Session A gives no discount to Session B; null session gives none; older than 900s gives none', async () => {
      const now = new Date(baseTime);

      // Record verification_success in Session A 100 seconds ago
      await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'verification_success',
        timestamp: new Date(baseTime - 100 * 1000)
      });

      // Event in Session A
      const eventSessionA = {
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'password_change',
        timestamp: now
      };
      const ctxA = await assembleEvaluationContext(eventSessionA);
      expect(ctxA.verification).not.toBeNull();
      expect(ctxA.verification.elapsed_seconds).toBe(100);

      // Event in Session B
      const eventSessionB = {
        user_id: userA.id,
        session_id: sessionB.id,
        event_type: 'password_change',
        timestamp: now
      };
      const ctxB = await assembleEvaluationContext(eventSessionB);
      expect(ctxB.verification).toBeNull();

      // Event with null session
      const eventNullSession = {
        user_id: userA.id,
        session_id: null,
        event_type: 'password_change',
        timestamp: now
      };
      const ctxNull = await assembleEvaluationContext(eventNullSession);
      expect(ctxNull.verification).toBeNull();

      // Event 1000 seconds after verification (window is 900s)
      const eventExpired = {
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'password_change',
        timestamp: new Date(baseTime + 1000 * 1000)
      };
      const ctxExpired = await assembleEvaluationContext(eventExpired);
      expect(ctxExpired.verification).toBeNull();
    });
  });

  describe('5. Scenario A & Scenario B End-to-End Evaluation', () => {
    test('Scenario A: routine login from previously seen device scores 5, tier low, one signal', async () => {
      // Seed prior login
      await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime),
        context: {
          device_fingerprint: 'fp_routine',
          geo_country: 'US'
        }
      });

      const routineLogin = await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime + 10000),
        context: {
          device_fingerprint: 'fp_routine',
          geo_country: 'US'
        }
      });

      const result = await evaluateRisk(routineLogin);
      assertRiskInvariant(result);
      expect(result.risk_score).toBe(5);
      expect(result.risk_tier).toBe('low');
      // signals: base_action_login_success (5), baseline_insufficient_history (0)
      const activeSignals = result.contributing_signals.filter((s) => s.weight !== 0);
      expect(activeSignals.length).toBe(1);
      expect(activeSignals[0].signal).toBe('base_action_login_success');
      expect(activeSignals[0].weight).toBe(5);
    });

    test('Scenario B (live-pipeline version): impossible-travel login with new device, then recovery_email_change, then critical password_change scores exactly 84', async () => {
      // Rulings requirement 5: Seed earlier login_success on a different device and country first, so novelty is real
      await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime - 3600 * 1000),
        context: {
          device_fingerprint: 'fp_old_original',
          geo_country: 'US'
        }
      });

      // 1. Impossible-travel login with new device & new country
      const loginEvt = await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime),
        context: {
          device_fingerprint: 'fp_attacker_device',
          geo_country: 'RU'
        },
        metadata: {
          travel_anomaly: { impossible_travel: true }
        }
      });
      await correlateEventIntoSequence(loginEvt);

      // 2. recovery_email_change 2 minutes later
      const recoveryEvt = await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'recovery_email_change',
        timestamp: new Date(baseTime + 2 * 60 * 1000),
        context: {
          device_fingerprint: 'fp_attacker_device',
          geo_country: 'RU'
        },
        metadata: {
          action_sensitivity: 'medium'
        }
      });
      await correlateEventIntoSequence(recoveryEvt);

      // 3. critical password_change 4 minutes later with baseline deviation 0.90
      const passwordEvt = await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'password_change',
        timestamp: new Date(baseTime + 4 * 60 * 1000),
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
      await correlateEventIntoSequence(passwordEvt);

      // Evaluate risk for the password change event
      const result = await evaluateRisk(passwordEvt);
      assertRiskInvariant(result);

      // Detailed expectations for 84:
      // Base: password_change (20) + sensitivity_critical (5) = 25 (capped at 25)
      // Context: unrecognized_device (10) + unrecognized_country (10) + impossible_travel (20) = 40, capped at 25 (-15 adjustment)
      // Sequence: seq_rapid_credential_cascade (20)
      // Timing: 0
      // Baseline: Math.round(0.90 * 15) = 14
      // Total: 25 + 25 + 20 + 0 + 14 = 84
      expect(result.risk_score).toBe(84);
      expect(result.risk_tier).toBe('critical');

      // Persistence test: store it
      const stored = await evaluateAndStoreRiskForEvent(passwordEvt);
      expect(stored).not.toBeNull();
      expect(stored.risk_score).toBe(84);
      expect(stored.risk_tier).toBe('critical');

      // Read back with getLatestRiskAssessment
      const latest = await getLatestRiskAssessment(userA.id, sessionA.id);
      expect(latest).not.toBeNull();
      expect(latest.id).toBe(stored.id);
      expect(latest.risk_score).toBe(84);
    });
  });

  describe('6. Advisory Scoring Path', () => {
    test('proposedEvent changes score vs without it, and persists nothing', async () => {
      // Seed prior login
      await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'login_success',
        timestamp: new Date(baseTime),
        context: {
          device_fingerprint: 'fp_1',
          geo_country: 'US'
        }
      });

      const recoveryEvt = await SecurityEvent.create({
        user_id: userA.id,
        session_id: sessionA.id,
        event_type: 'recovery_email_change',
        timestamp: new Date(baseTime + 60 * 1000),
        metadata: { action_sensitivity: 'medium' }
      });
      await correlateEventIntoSequence(recoveryEvt);

      // Score without proposed event
      const resultBefore = await evaluateRisk(recoveryEvt);

      // Propose follow-up password_change within cascade window
      const proposed = {
        event_type: 'password_change',
        timestamp: new Date(baseTime + 120 * 1000).toISOString(),
        action_sensitivity: 'high'
      };

      const countAssessmentsBefore = await RiskAssessment.count();
      const countSequencesBefore = await ActionSequence.count();

      const resultWithProposal = await evaluateRisk(recoveryEvt, { proposedEvent: proposed });

      // Risk score should be higher or rules triggered due to cascade with proposed event
      expect(resultWithProposal.status).toBe('ok');
      const cascadeSignal = resultWithProposal.contributing_signals.find((s) => s.signal === 'seq_rapid_credential_cascade');
      expect(cascadeSignal).toBeDefined();

      // Check DB remained completely unmutated
      const countAssessmentsAfter = await RiskAssessment.count();
      const countSequencesAfter = await ActionSequence.count();
      expect(countAssessmentsAfter).toBe(countAssessmentsBefore);
      expect(countSequencesAfter).toBe(countSequencesBefore);
    });
  });

  describe('7. Failure Handling & Boundaries', () => {
    test('forced internal error returns unavailable object and persists nothing, evaluateAndStoreRiskForEvent does not throw', async () => {
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

      // Pass an invalid object causing internal error
      const brokenEvent = {
        user_id: userA.id,
        event_type: 'invalid_event_type_that_will_throw_RiskInputError',
        timestamp: new Date()
      };

      const result = await evaluateRisk(brokenEvent);
      expect(result).toEqual({
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

      // evaluateAndStoreRiskForEvent resolves without throwing and returns null
      const stored = await evaluateAndStoreRiskForEvent(brokenEvent);
      expect(stored).toBeNull();

      expect(warnSpy).toHaveBeenCalled();
      warnSpy.mockRestore();
    });

    test('unavailable explanation never leaks internal error messages or stack traces', async () => {
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

      const internalErrorMessage = 'SECRET_DATABASE_INTERNAL_EXCEPTION_XYZ';
      // Pass an event with a broken getter or invalid structure that throws a sensitive error
      const sensitiveBrokenEvent = {
        user_id: userA.id,
        get event_type() {
          throw new Error(internalErrorMessage);
        },
        timestamp: new Date()
      };

      const result = await evaluateRisk(sensitiveBrokenEvent);
      expect(result.status).toBe('unavailable');
      expect(result.error_code).toBe('risk_evaluation_failed');
      expect(result.explanation.user_facing).not.toContain(internalErrorMessage);
      expect(result.explanation.admin_facing).not.toContain(internalErrorMessage);
      expect(result.explanation.user_facing).toBe('Security risk evaluation is temporarily unavailable.');
      expect(result.explanation.admin_facing).toBe('Risk engine failed to evaluate context: risk_evaluation_failed.');

      warnSpy.mockRestore();
    });

    test('event with no user_id is skipped silently (console.warn not called)', async () => {
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

      const anonymousEvent = {
        event_type: 'login_failed',
        timestamp: new Date()
      };

      const stored = await evaluateAndStoreRiskForEvent(anonymousEvent);
      expect(stored).toBeNull();
      expect(warnSpy).not.toHaveBeenCalled();

      warnSpy.mockRestore();
    });
  });
});
