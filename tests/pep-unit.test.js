'use strict';

const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const { runMigrations } = require('../src/database/migrate');
const {
  User,
  Session,
  SecurityEvent,
  RiskAssessment,
  PolicyDecision
} = require('../src/database/models');
const { createSession } = require('../src/services/sessionService');
const {
  grantElevation,
  checkElevation,
  createMockVerificationTicket
} = require('../src/services/elevationService');
const riskEngineService = require('../src/services/riskEngineService');
const redisStorage = require('../src/storage/redis');
const { JWT_SECRET, authenticateToken, requireElevation } = require('../src/middleware/auth');
const { enforce } = require('../src/middleware/pep');
const accountActionsRouter = require('../src/routes/accountActions');

describe('Module 10b — PEP Middleware Unit & Boundary Verification', () => {
  let user;
  let session;
  let token;

  beforeAll(async () => {
    await runMigrations();
  });

  beforeEach(async () => {
    user = await User.create({
      email: `pep-unit-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`,
      password_hash: 'hashed_pw'
    });
    session = await createSession(user.id, user.email, 900, {
      device_fingerprint: 'fp_trusted_server_0001'
    });
    token = jwt.sign(
      { id: user.id, email: user.email, session_id: session.sessionId },
      JWT_SECRET,
      { expiresIn: '15m' }
    );
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  // T10b-01 (FR-30, FR-37, NFR-12)
  test('T10b-01 (FR-30, FR-37, NFR-12): PEP maps allow, monitor, reverify, delay, and block decisions accurately and persists PolicyDecision with policy_id@schema_version', async () => {
    const testApp = express();
    testApp.use(express.json());

    let handlerExecutions = 0;
    testApp.post(
      '/test/phone',
      authenticateToken,
      enforce('phone_number_change', { sensitivity: 'medium', scope: 'account_recovery' }),
      (req, res) => {
        handlerExecutions++;
        res.status(200).json({ ok: true, decision_id: req.policyDecision.id });
      }
    );

    testApp.post(
      '/test/password',
      authenticateToken,
      enforce('password_change', { sensitivity: 'high', scope: 'credential_change' }),
      (req, res) => {
        handlerExecutions++;
        res.status(200).json({ ok: true, decision_id: req.policyDecision.id });
      }
    );

    testApp.post(
      '/test/high-impact',
      authenticateToken,
      enforce('high_impact_action', { sensitivity: 'critical', scope: 'sensitive_action' }),
      (req, res) => {
        handlerExecutions++;
        res.status(200).json({ ok: true, decision_id: req.policyDecision.id });
      }
    );

    // 1. allow (low risk + medium sensitivity -> allow)
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 0,
      risk_tier: 'low',
      contributing_signals: [{ signal: 'action_sensitivity_weight', category: 'sensitivity', weight: 0 }],
      explanation: { user_facing: 'Normal activity.', admin_facing: 'Score 0.' }
    });

    const allowRes = await request(testApp)
      .post('/test/phone')
      .set('Authorization', `Bearer ${token}`)
      .send({})
      .expect(200);
    expect(allowRes.body.ok).toBe(true);
    const allowDec = await PolicyDecision.findByPk(allowRes.body.decision_id);
    expect(allowDec.recommended_decision).toBe('allow');
    expect(allowDec.effective_decision).toBe('allow');
    expect(allowDec.enforcement_outcome).toBe('allowed');
    expect(allowDec.policy_version).toBe('default-v1@1.0.0');

    // 2. monitor (low risk + high sensitivity -> monitor)
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 10,
      risk_tier: 'low',
      contributing_signals: [{ signal: 'action_sensitivity_weight', category: 'sensitivity', weight: 10 }],
      explanation: { user_facing: 'Monitored activity.', admin_facing: 'Score 10.' }
    });

    const monitorRes = await request(testApp)
      .post('/test/password')
      .set('Authorization', `Bearer ${token}`)
      .send({})
      .expect(200);
    const monitorDec = await PolicyDecision.findByPk(monitorRes.body.decision_id);
    expect(monitorDec.recommended_decision).toBe('monitor');
    expect(monitorDec.effective_decision).toBe('monitor');
    expect(monitorDec.enforcement_outcome).toBe('monitored');

    // 3. reverify (medium risk + high sensitivity -> reverify)
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 35,
      risk_tier: 'medium',
      contributing_signals: [{ signal: 'unrecognized_device', category: 'device', weight: 35 }],
      explanation: { user_facing: 'Unrecognized device.', admin_facing: 'Score 35.' }
    });

    const reverifyRes = await request(testApp)
      .post('/test/password')
      .set('Authorization', `Bearer ${token}`)
      .send({})
      .expect(403);
    expect(reverifyRes.body.error.code).toBe('step_up_required');
    expect(reverifyRes.body.error.decision).toBe('reverify');
    expect(reverifyRes.body.error.required_scope).toBe('credential_change');
    expect(reverifyRes.body.error.challenge_endpoint).toBe(
      `/api/v1/sessions/${session.sessionId}/step-up/challenge`
    );

    const reverifyDec = await PolicyDecision.findByPk(reverifyRes.body.error.decision_id);
    expect(reverifyDec.recommended_decision).toBe('reverify');
    expect(reverifyDec.effective_decision).toBe('reverify');
    expect(reverifyDec.enforcement_outcome).toBe('step_up_challenged');

    // 4. delay (high risk + high sensitivity -> delay)
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 60,
      risk_tier: 'high',
      contributing_signals: [{ signal: 'impossible_travel', category: 'location', weight: 60 }],
      explanation: { user_facing: 'Suspicious location change.', admin_facing: 'Score 60.' }
    });

    const delayRes = await request(testApp)
      .post('/test/password')
      .set('Authorization', `Bearer ${token}`)
      .send({})
      .expect(403);
    expect(delayRes.body.error.code).toBe('action_delayed');
    expect(delayRes.body.error.decision).toBe('delay');
    expect(delayRes.body.error.retry_after_seconds).toBe(300);

    const delayDec = await PolicyDecision.findByPk(delayRes.body.error.decision_id);
    expect(delayDec.recommended_decision).toBe('delay');
    expect(delayDec.effective_decision).toBe('delay');
    expect(delayDec.enforcement_outcome).toBe('delayed');

    // 5. block (high risk + critical sensitivity -> block)
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 65,
      risk_tier: 'high',
      contributing_signals: [{ signal: 'impossible_travel', category: 'location', weight: 65 }],
      explanation: { user_facing: 'High risk critical action.', admin_facing: 'Score 65.' }
    });

    const blockRes = await request(testApp)
      .post('/test/high-impact')
      .set('Authorization', `Bearer ${token}`)
      .send({})
      .expect(403);
    expect(blockRes.body.error.code).toBe('action_blocked');
    expect(blockRes.body.error.decision).toBe('block');
    expect(blockRes.body.error.session_contained).toBe(false);

    const blockDec = await PolicyDecision.findByPk(blockRes.body.error.decision_id);
    expect(blockDec.recommended_decision).toBe('block');
    expect(blockDec.effective_decision).toBe('block');
    expect(blockDec.enforcement_outcome).toBe('blocked');

    // Handler only ran for allow and monitor
    expect(handlerExecutions).toBe(2);
  });

  // T10b-02 (FR-3, FR-7)
  test('T10b-02 (FR-3, FR-7): PEP ignores client-supplied context, timestamp, and action_sensitivity in req.body and req.query', async () => {
    const testApp = express();
    testApp.use(express.json());
    testApp.post(
      '/test/critical-action',
      authenticateToken,
      enforce('high_impact_action', { sensitivity: 'critical', scope: 'sensitive_action' }),
      (req, res) => {
        res.status(200).json({ decision: req.policyDecision });
      }
    );

    const beforeMs = Date.now();
    const res = await request(testApp)
      .post('/test/critical-action?action_sensitivity=low&ip_address=1.1.1.1')
      .set('Authorization', `Bearer ${token}`)
      .set('User-Agent', 'ServerTrustedAgent/1.0')
      .send({
        action_sensitivity: 'low',
        sensitivity: 'low',
        timestamp: '2020-01-01T00:00:00.000Z',
        context: {
          ip_address: '8.8.8.8',
          geo_country: 'AQ',
          device_fingerprint: 'spoofed_body_fp_99999999'
        }
      })
      .expect(200);
    const afterMs = Date.now();

    const decision = await PolicyDecision.findByPk(res.body.decision.id);
    expect(decision.action_sensitivity).toBe('critical');

    const secEvent = await SecurityEvent.findByPk(decision.event_id);
    expect(secEvent.metadata.action_sensitivity).toBe('critical');
    expect(secEvent.context.ip_address).not.toBe('8.8.8.8');
    expect(secEvent.context.ip_address).not.toBe('1.1.1.1');
    expect(secEvent.context.geo_country).not.toBe('AQ');
    expect(secEvent.context.device_fingerprint).toBe('fp_trusted_server_0001');
    expect(secEvent.context.user_agent).toBe('ServerTrustedAgent/1.0');

    const eventTimeMs = new Date(secEvent.timestamp).getTime();
    expect(eventTimeMs).toBeGreaterThanOrEqual(beforeMs - 50);
    expect(eventTimeMs).toBeLessThanOrEqual(afterMs + 50);
  });

  // T10b-03 (FR-24, FR-30)
  test('T10b-03 (FR-24, FR-30): Elevation satisfies reverify only for matching scope and never bypasses delay or block', async () => {
    const testApp = express();
    testApp.use(express.json());
    testApp.post(
      '/test/password',
      authenticateToken,
      enforce('password_change', { sensitivity: 'high', scope: 'credential_change' }),
      (req, res) => {
        res.status(200).json({ ok: true, decision_id: req.policyDecision.id });
      }
    );

    // Grant 'account_recovery' scope (wrong scope for password_change which requires 'credential_change')
    const wrongScopeTicket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'account_recovery'
    });
    await grantElevation({
      sessionId: session.sessionId,
      userId: user.id,
      scope: 'account_recovery',
      verificationTicket: wrongScopeTicket,
      grantedAtRiskTier: 'high'
    });

    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 35,
      risk_tier: 'medium',
      contributing_signals: [{ signal: 'unrecognized_device', category: 'device', weight: 35 }],
      explanation: { user_facing: 'Verify identity.', admin_facing: 'Medium risk.' }
    });

    const wrongScopeRes = await request(testApp)
      .post('/test/password')
      .set('Authorization', `Bearer ${token}`)
      .send({})
      .expect(403);
    expect(wrongScopeRes.body.error.code).toBe('step_up_required');

    // Now grant the required 'credential_change' scope at 'high' tier
    const rightScopeTicket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'credential_change'
    });
    await grantElevation({
      sessionId: user.id ? session.sessionId : '',
      userId: user.id,
      scope: 'credential_change',
      verificationTicket: rightScopeTicket,
      grantedAtRiskTier: 'high'
    });

    // 1. Satisfies 'reverify' at medium risk
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 35,
      risk_tier: 'medium',
      contributing_signals: [{ signal: 'unrecognized_device', category: 'device', weight: 35 }],
      explanation: { user_facing: 'Verify identity.', admin_facing: 'Medium risk.' }
    });

    const elevatedRes = await request(testApp)
      .post('/test/password')
      .set('Authorization', `Bearer ${token}`)
      .send({})
      .expect(200);
    const elevatedDec = await PolicyDecision.findByPk(elevatedRes.body.decision_id);
    expect(elevatedDec.recommended_decision).toBe('reverify');
    expect(elevatedDec.effective_decision).toBe('allow');
    expect(elevatedDec.enforcement_outcome).toBe('elevated_allowed');

    // 2. Does NOT bypass 'delay' (high risk + high sensitivity -> delay)
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 60,
      risk_tier: 'high',
      contributing_signals: [{ signal: 'impossible_travel', category: 'location', weight: 60 }],
      explanation: { user_facing: 'Delayed.', admin_facing: 'High risk.' }
    });

    const delayRes = await request(testApp)
      .post('/test/password')
      .set('Authorization', `Bearer ${token}`)
      .send({})
      .expect(403);
    expect(delayRes.body.error.code).toBe('action_delayed');

    // 3. Does NOT bypass 'block' (critical risk + high sensitivity -> block)
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 85,
      risk_tier: 'critical',
      contributing_signals: [{ signal: 'impossible_travel', category: 'location', weight: 85 }],
      explanation: { user_facing: 'Blocked.', admin_facing: 'Critical risk.' }
    });

    const blockRes = await request(testApp)
      .post('/test/password')
      .set('Authorization', `Bearer ${token}`)
      .send({})
      .expect(403);
    expect(blockRes.body.error.code).toBe('action_blocked');
  });

  // T10b-04 (FR-30, NFR-7)
  test('T10b-04 (FR-30, NFR-7): PEP enforces fail-safe challenge/block when Risk Engine is unavailable and fails closed (503) when PolicyDecision persistence fails', async () => {
    const testApp = express();
    testApp.use(express.json());

    let handlerCalled = false;
    testApp.post(
      '/test/phone',
      authenticateToken,
      enforce('phone_number_change', { sensitivity: 'medium', scope: 'account_recovery' }),
      (req, res) => {
        handlerCalled = true;
        res.status(200).json({ ok: true });
      }
    );

    testApp.post(
      '/test/high-impact',
      authenticateToken,
      enforce('high_impact_action', { sensitivity: 'critical', scope: 'sensitive_action' }),
      (req, res) => {
        handlerCalled = true;
        res.status(200).json({ ok: true });
      }
    );

    // 1. Risk Engine unavailable on medium sensitivity -> upgraded to reverify (fail_safe_challenged)
    jest.spyOn(riskEngineService, 'evaluateAndStoreRiskForEvent').mockResolvedValueOnce(null);

    const medFailSafeRes = await request(testApp)
      .post('/test/phone')
      .set('Authorization', `Bearer ${token}`)
      .send({})
      .expect(403);
    expect(medFailSafeRes.body.error.code).toBe('step_up_required');
    const medDec = await PolicyDecision.findByPk(medFailSafeRes.body.error.decision_id);
    expect(medDec.enforcement_outcome).toBe('fail_safe_challenged');
    expect(handlerCalled).toBe(false);

    // 2. Risk Engine unavailable on critical sensitivity -> fail_safe_blocked
    jest.spyOn(riskEngineService, 'evaluateAndStoreRiskForEvent').mockResolvedValueOnce(null);

    const critFailSafeRes = await request(testApp)
      .post('/test/high-impact')
      .set('Authorization', `Bearer ${token}`)
      .send({})
      .expect(403);
    expect(critFailSafeRes.body.error.code).toBe('action_blocked');
    const critDec = await PolicyDecision.findByPk(critFailSafeRes.body.error.decision_id);
    expect(critDec.enforcement_outcome).toBe('fail_safe_blocked');
    expect(handlerCalled).toBe(false);

    // 3. PolicyDecision.create throws DB error -> PEP fails closed with 503 and never invokes handler
    jest.spyOn(PolicyDecision, 'create').mockRejectedValueOnce(new Error('Simulated DB write failure'));

    const dbFailRes = await request(testApp)
      .post('/test/phone')
      .set('Authorization', `Bearer ${token}`)
      .send({})
      .expect(503);
    expect(dbFailRes.body.error.code).toBe('policy_enforcement_unavailable');
    expect(handlerCalled).toBe(false);
  });

  // T10b-05 (FR-8, FR-30)
  test('T10b-05 (FR-8, FR-30): checkElevation and requireElevation fail closed when Redis read fails, and PEP fails closed (503) on Redis error during reverify', async () => {
    const ticket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'credential_change'
    });
    await grantElevation({
      sessionId: session.sessionId,
      userId: user.id,
      scope: 'credential_change',
      verificationTicket: ticket
    });

    const client = redisStorage.getRedisClient();
    const originalGet = client.get.bind(client);

    // Simulate Redis failure on elevation key read
    jest.spyOn(client, 'get').mockImplementation(async (key) => {
      if (String(key).startsWith('elevation:session:')) {
        throw new Error('Simulated Redis ECONNRESET during elevation check');
      }
      return originalGet(key);
    });

    // 1. Direct checkElevation fails closed (elevated: false)
    const directStatus = await checkElevation({
      sessionId: session.sessionId,
      scope: 'credential_change'
    });
    expect(directStatus.elevated).toBe(false);

    // 2. Module 10a requireElevation middleware fails closed (403 step_up_required)
    const testApp = express();
    testApp.use(express.json());
    testApp.post(
      '/test/require-elev',
      authenticateToken,
      requireElevation('credential_change'),
      (req, res) => res.status(200).json({ ok: true })
    );
    const reqElevRes = await request(testApp)
      .post('/test/require-elev')
      .set('Authorization', `Bearer ${token}`)
      .send({})
      .expect(403);
    expect(reqElevRes.body.error.code).toBe('elevation_required');

    // 3. Module 10b PEP enforce middleware fails closed (503) when Redis throws during reverify check
    testApp.post(
      '/test/pep-redis-err',
      authenticateToken,
      enforce('password_change', { sensitivity: 'high', scope: 'credential_change' }),
      (req, res) => res.status(200).json({ ok: true })
    );
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 35,
      risk_tier: 'medium',
      contributing_signals: [{ signal: 'unrecognized_device', category: 'device', weight: 35 }],
      explanation: { user_facing: 'Verify.', admin_facing: 'Medium.' }
    });

    const pepErrRes = await request(testApp)
      .post('/test/pep-redis-err')
      .set('Authorization', `Bearer ${token}`)
      .send({})
      .expect(503);
    expect(pepErrRes.body.error.code).toBe('policy_enforcement_unavailable');
  });

  // T10b-06 (FR-3, FR-7, FR-37)
  test('T10b-06 (FR-3, FR-7, FR-37): Programmatic route-coverage check confirms all 5 sensitive account routes enforce authenticateToken and pepMiddleware before handler', () => {
    const registry = accountActionsRouter.SENSITIVE_ROUTE_REGISTRY;
    expect(Array.isArray(registry)).toBe(true);
    expect(registry).toHaveLength(5);

    const routeLayers = accountActionsRouter.stack.filter((layer) => layer.route);
    expect(routeLayers).toHaveLength(5);

    for (const expected of registry) {
      const matchingLayer = routeLayers.find(
        (layer) =>
          layer.route.path === expected.path &&
          Boolean(layer.route.methods[expected.method.toLowerCase()])
      );
      expect(matchingLayer).toBeDefined();

      const handlers = matchingLayer.route.stack.map((s) => s.name);
      // Every sensitive route must run authenticateToken first, pepMiddleware second, and route handler third
      expect(handlers.length).toBeGreaterThanOrEqual(3);
      expect(handlers[0]).toBe('authenticateToken');
      expect(handlers[1]).toBe('pepMiddleware');
    }
  });
});
