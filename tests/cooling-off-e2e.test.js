'use strict';

const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { runMigrations } = require('../src/database/migrate');
const {
  User,
  Session,
  SecurityEvent,
  PolicyDecision,
  DelayedAction
} = require('../src/database/models');
const { createSession } = require('../src/services/sessionService');
const riskEngineService = require('../src/services/riskEngineService');
const redisStorage = require('../src/storage/redis');
const { JWT_SECRET } = require('../src/middleware/auth');
const { setDelayHandler } = require('../src/middleware/pep');
const coolingOffService = require('../src/services/coolingOffService');
const coolingOffWorker = require('../src/jobs/coolingOffWorker');
const accountActionsRouter = require('../src/routes/accountActions');
const coolingOffRouter = require('../src/routes/coolingOff');
const eventBus = require('../src/events/eventBus');

describe('Module 10c — Cooling-Off End-to-End & Worker Verification (FR-32)', () => {
  let app;
  let user;
  let session;
  let token;

  beforeAll(async () => {
    await runMigrations();
  });

  beforeEach(async () => {
    setDelayHandler(coolingOffService.coolingOffDelayHandler);

    app = express();
    app.use(express.json());
    app.use('/api/v1/account', accountActionsRouter);
    app.use('/api/v1/cooling-off', coolingOffRouter);

    user = await User.create({
      email: `cooling-e2e-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`,
      password_hash: 'hashed_pw'
    });
    session = await createSession(user.id, user.email, 900, {
      device_fingerprint: 'fp_e2e_cooling_01'
    });
    token = jwt.sign(
      { id: user.id, email: user.email, session_id: session.sessionId },
      JWT_SECRET,
      { expiresIn: '15m' }
    );
  });

  afterEach(async () => {
    coolingOffWorker.stopCoolingOffWorker();
    coolingOffService.resetActionExecutors();
    setDelayHandler(coolingOffService.coolingOffDelayHandler);
    jest.restoreAllMocks();
  });

  // T10c-08 (FR-32)
  test('T10c-08 (FR-32): Sensitive route triggers PEP delay outcome -> enqueues action in MySQL and Redis, prevents immediate mutation, and returns cancellation token and cooling-off endpoints', async () => {
    const emittedScheduled = [];
    const onScheduled = (payload) => emittedScheduled.push(payload);
    eventBus.on('cooling_off:scheduled', onScheduled);

    // Mock risk engine to return medium risk (40) with impossible_travel + unrecognized_device on critical route -> triggers 'delay' via esc_travel_and_novelty
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 40,
      risk_tier: 'medium',
      contributing_signals: [
        { signal: 'impossible_travel', category: 'location', weight: 25 },
        { signal: 'unrecognized_device', category: 'device', weight: 15 }
      ],
      explanation: { user_facing: 'Suspicious location and device change.', admin_facing: 'Score 40 -> delay via esc_travel_and_novelty.' }
    });

    const res = await request(app)
      .post('/api/v1/account/high-impact')
      .set('Authorization', `Bearer ${token}`)
      .send({
        operation: 'delete_organization_workspace',
        target: 'org_prod_99'
      });

    eventBus.off('cooling_off:scheduled', onScheduled);

    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('action_delayed');
    expect(res.body.error.decision_id).toMatch(/^dec_/);
    expect(res.body.error.pending_action_id).toMatch(/^cact_/);
    expect(res.body.error.cooling_off_seconds).toBe(300);
    expect(res.body.error.retry_after_seconds).toBe(300);
    expect(res.body.error.cancellation_token).toMatch(/^ctkn_[a-f0-9]{64}$/);
    expect(res.body.error.cancel_endpoint).toBe(
      `/api/v1/cooling-off/actions/${res.body.error.pending_action_id}/cancel`
    );
    expect(res.body.error.status_endpoint).toBe(
      `/api/v1/cooling-off/actions/${res.body.error.pending_action_id}`
    );

    // Verify DelayedAction persisted in MySQL
    const dbAction = await DelayedAction.findByPk(res.body.error.pending_action_id);
    expect(dbAction).not.toBeNull();
    expect(dbAction.status).toBe('pending');
    expect(dbAction.action_type).toBe('high_impact_action');
    expect(dbAction.user_id).toBe(user.id);
    expect(dbAction.decision_id).toBe(res.body.error.decision_id);

    // Verify SecurityEvent remains 'delayed' (immediate mutation prevented)
    const secEvent = await SecurityEvent.findByPk(dbAction.event_id);
    expect(secEvent).not.toBeNull();
    expect(secEvent.metadata.action_status).toBe('delayed');

    // Verify eventBus notification fired
    expect(emittedScheduled).toHaveLength(1);
    expect(emittedScheduled[0].action_id).toBe(dbAction.id);
  });

  // T10c-09 (FR-32)
  test('T10c-09 (FR-32): GET /api/v1/cooling-off/actions lists user pending actions and GET /actions/:id enforces strict user ownership isolation (403 for wrong user)', async () => {
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 40,
      risk_tier: 'medium',
      contributing_signals: [
        { signal: 'impossible_travel', category: 'location', weight: 25 },
        { signal: 'unrecognized_device', category: 'device', weight: 15 }
      ],
      explanation: { user_facing: 'Suspicious location change.', admin_facing: 'Score 40.' }
    });

    const scheduleRes = await request(app)
      .post('/api/v1/account/high-impact')
      .set('Authorization', `Bearer ${token}`)
      .send({ operation: 'bulk_key_rotation', target: 'kms_all' });

    const actionId = scheduleRes.body.error.pending_action_id;

    // 1. List pending actions for owner
    const listRes = await request(app)
      .get('/api/v1/cooling-off/actions?status=pending')
      .set('Authorization', `Bearer ${token}`);

    expect(listRes.status).toBe(200);
    expect(listRes.body.count).toBeGreaterThanOrEqual(1);
    const listed = listRes.body.actions.find((a) => a.id === actionId);
    expect(listed).toBeDefined();
    expect(listed.status).toBe('pending');
    expect(listed.cancellation_token_hash).toBeUndefined();

    // 2. Get specific action details for owner
    const detailRes = await request(app)
      .get(`/api/v1/cooling-off/actions/${actionId}`)
      .set('Authorization', `Bearer ${token}`);

    expect(detailRes.status).toBe(200);
    expect(detailRes.body.action.id).toBe(actionId);
    expect(detailRes.body.action.action_payload.operation).toBe('bulk_key_rotation');

    // 3. Another user cannot view this user's delayed action (403 Forbidden)
    const otherUser = await User.create({
      email: `other-cooling-${Date.now()}@example.com`,
      password_hash: 'hashed_pw'
    });
    const otherSession = await createSession(otherUser.id, otherUser.email, 900);
    const otherToken = jwt.sign(
      { id: otherUser.id, email: otherUser.email, session_id: otherSession.sessionId },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    const forbiddenRes = await request(app)
      .get(`/api/v1/cooling-off/actions/${actionId}`)
      .set('Authorization', `Bearer ${otherToken}`);

    expect(forbiddenRes.status).toBe(403);
    expect(forbiddenRes.body.error.code).toBe('forbidden');
  });

  // T10c-10 (FR-32)
  test('T10c-10 (FR-32): POST /api/v1/cooling-off/actions/:id/cancel cancels pending action with valid token, updates SecurityEvent to cancelled, and rejects token reuse', async () => {
    const emittedCancelled = [];
    const onCancelled = (payload) => emittedCancelled.push(payload);
    eventBus.on('cooling_off:cancelled', onCancelled);

    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 40,
      risk_tier: 'medium',
      contributing_signals: [
        { signal: 'impossible_travel', category: 'location', weight: 25 },
        { signal: 'unrecognized_device', category: 'device', weight: 15 }
      ],
      explanation: { user_facing: 'Suspicious location change.', admin_facing: 'Score 40.' }
    });

    const scheduleRes = await request(app)
      .post('/api/v1/account/high-impact')
      .set('Authorization', `Bearer ${token}`)
      .send({ operation: 'transfer_ownership', target: 'ext_admin_01' });

    const actionId = scheduleRes.body.error.pending_action_id;
    const cancelToken = scheduleRes.body.error.cancellation_token;

    // 1. Wrong cancellation token is rejected with 403
    const wrongTokenRes = await request(app)
      .post(`/api/v1/cooling-off/actions/${actionId}/cancel`)
      .set('Authorization', `Bearer ${token}`)
      .send({
        cancellation_token: `ctkn_${'a'.repeat(64)}`,
        reason: 'Attempt with wrong token'
      });
    expect(wrongTokenRes.status).toBe(403);
    expect(wrongTokenRes.body.error.code).toBe('invalid_cancellation_token');

    // 2. Valid cancellation token cancels the pending action
    const cancelRes = await request(app)
      .post(`/api/v1/cooling-off/actions/${actionId}/cancel`)
      .set('Authorization', `Bearer ${token}`)
      .send({
        cancellation_token: cancelToken,
        reason: 'User did not initiate this request'
      });

    eventBus.off('cooling_off:cancelled', onCancelled);

    expect(cancelRes.status).toBe(200);
    expect(cancelRes.body.status).toBe('cancelled');
    expect(cancelRes.body.action_id).toBe(actionId);

    // Verify DB state and SecurityEvent audit status
    const dbAction = await DelayedAction.findByPk(actionId);
    expect(dbAction.status).toBe('cancelled');
    expect(dbAction.cancelled_by).toBe(user.id);

    const secEvent = await SecurityEvent.findByPk(dbAction.event_id);
    expect(secEvent.metadata.action_status).toBe('cancelled');

    expect(emittedCancelled).toHaveLength(1);
    expect(emittedCancelled[0].action_id).toBe(actionId);

    // 3. Reusing the single-use cancellation token on an already-cancelled action fails with 409
    const replayRes = await request(app)
      .post(`/api/v1/cooling-off/actions/${actionId}/cancel`)
      .set('Authorization', `Bearer ${token}`)
      .send({
        cancellation_token: cancelToken
      });
    expect(replayRes.status).toBe(409);
    expect(replayRes.body.error.code).toBe('action_already_cancelled');
  });

  // T10c-11 (FR-32)
  test('T10c-11 (FR-32): POST /api/v1/cooling-off/actions/:id/execute rejects early execution with 409, executes mutation after cooling-off elapses, and updates SecurityEvent to completed', async () => {
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 40,
      risk_tier: 'medium',
      contributing_signals: [
        { signal: 'impossible_travel', category: 'location', weight: 25 },
        { signal: 'unrecognized_device', category: 'device', weight: 15 }
      ],
      explanation: { user_facing: 'Suspicious location change.', admin_facing: 'Score 40.' }
    });

    const scheduleRes = await request(app)
      .post('/api/v1/account/high-impact')
      .set('Authorization', `Bearer ${token}`)
      .send({ operation: 'archive_audit_vault', target: 'vault_2025' });

    const actionId = scheduleRes.body.error.pending_action_id;

    // 1. Attempting execution before cooling-off period elapses returns 409 Conflict
    const earlyRes = await request(app)
      .post(`/api/v1/cooling-off/actions/${actionId}/execute`)
      .set('Authorization', `Bearer ${token}`);

    expect(earlyRes.status).toBe(409);
    expect(earlyRes.body.error.code).toBe('action_still_cooling_off');
    expect(earlyRes.body.error.remaining_seconds).toBeGreaterThan(0);

    // 2. Fast-forward execute_at to the past to simulate cooling-off completion
    await DelayedAction.update(
      { execute_at: new Date(Date.now() - 5000) },
      { where: { id: actionId } }
    );

    // Mock risk engine for Zero Trust pre-execution recheck (benign low risk)
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 0,
      risk_tier: 'low',
      contributing_signals: [],
      explanation: { user_facing: 'Normal.', admin_facing: 'Low risk.' }
    });

    const execRes = await request(app)
      .post(`/api/v1/cooling-off/actions/${actionId}/execute`)
      .set('Authorization', `Bearer ${token}`);

    expect(execRes.status).toBe(200);
    expect(execRes.body.status).toBe('completed');
    expect(execRes.body.execution_result.executed).toBe(true);
    expect(execRes.body.execution_result.operation).toBe('archive_audit_vault');

    // Verify DB & SecurityEvent updated to 'completed'
    const dbAction = await DelayedAction.findByPk(actionId);
    expect(dbAction.status).toBe('completed');

    const secEvent = await SecurityEvent.findByPk(dbAction.event_id);
    expect(secEvent.metadata.action_status).toBe('completed');
  });

  // T10c-12 (FR-32)
  test('T10c-12 (FR-32): Background worker processOverdueActions executes ready actions, respects distributed Redis worker lock, and auto-expires abandoned actions', async () => {
    // 1. Create an overdue action ready for worker execution
    const pastScheduled = new Date(Date.now() - 400 * 1000);
    const pastExecuteAt = new Date(Date.now() - 20 * 1000);
    const futureExpiresAt = new Date(Date.now() + 1800 * 1000);

    const readyAction = await DelayedAction.create({
      id: `cact_${crypto.randomUUID()}`,
      user_id: user.id,
      session_id: session.sessionId,
      action_type: 'high_impact_action',
      action_sensitivity: 'critical',
      route_path: '/api/v1/account/high-impact',
      route_method: 'POST',
      action_payload: { operation: 'worker_scheduled_task', target: 'cluster_a' },
      scheduled_at_risk_tier: 'medium',
      cooling_off_seconds: 300,
      status: 'pending',
      cancellation_token_hash: crypto.createHash('sha256').update('tok1').digest('hex'),
      scheduled_at: pastScheduled,
      execute_at: pastExecuteAt,
      expires_at: futureExpiresAt
    });

    // 2. Create an abandoned action whose expires_at is already in the past
    const abandonedAction = await DelayedAction.create({
      id: `cact_${crypto.randomUUID()}`,
      user_id: user.id,
      session_id: session.sessionId,
      action_type: 'high_impact_action',
      action_sensitivity: 'critical',
      route_path: '/api/v1/account/high-impact',
      route_method: 'POST',
      action_payload: { operation: 'abandoned_task', target: 'cluster_b' },
      scheduled_at_risk_tier: 'medium',
      cooling_off_seconds: 300,
      status: 'pending',
      cancellation_token_hash: crypto.createHash('sha256').update('tok2').digest('hex'),
      scheduled_at: new Date(Date.now() - 5000 * 1000),
      execute_at: new Date(Date.now() - 4700 * 1000),
      expires_at: new Date(Date.now() - 100 * 1000)
    });

    // Mock risk engine for readyAction pre-execution recheck
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValue({
      status: 'ok',
      risk_score: 0,
      risk_tier: 'low',
      contributing_signals: [],
      explanation: { user_facing: 'Low risk.', admin_facing: 'Low risk.' }
    });

    const summary = await coolingOffWorker.processOverdueActions();
    expect(summary.skipped).toBe(false);
    expect(summary.executedCount).toBeGreaterThanOrEqual(1);
    expect(summary.expiredCount).toBeGreaterThanOrEqual(1);

    const updatedReady = await DelayedAction.findByPk(readyAction.id);
    expect(updatedReady.status).toBe('completed');

    const updatedAbandoned = await DelayedAction.findByPk(abandonedAction.id);
    expect(updatedAbandoned.status).toBe('expired');

    // 3. Verify distributed lock contention skips concurrent worker tick cleanly
    const rawRedis = redisStorage.getRedisClient();
    await rawRedis.set('cooling_off:worker_lock', 'locked_by_other_instance', 'EX', 15);

    const lockedSummary = await coolingOffWorker.processOverdueActions();
    expect(lockedSummary.skipped).toBe(true);
    expect(lockedSummary.reason).toBe('lock_held');

    await rawRedis.del('cooling_off:worker_lock');
  });

  // T10c-13 (FR-32)
  test('T10c-13 (FR-32): Fail-closed resilience: if DelayedAction persistence fails during PEP delay handling, request is denied with 503 policy_enforcement_unavailable and route handler never executes', async () => {
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 40,
      risk_tier: 'medium',
      contributing_signals: [
        { signal: 'impossible_travel', category: 'location', weight: 25 },
        { signal: 'unrecognized_device', category: 'device', weight: 15 }
      ],
      explanation: { user_facing: 'Suspicious location change.', admin_facing: 'Score 40.' }
    });

    // Simulate database failure during DelayedAction.create
    jest.spyOn(DelayedAction, 'create').mockRejectedValueOnce(new Error('DB write failure'));

    const res = await request(app)
      .post('/api/v1/account/high-impact')
      .set('Authorization', `Bearer ${token}`)
      .send({ operation: 'should_fail_closed', target: 'prod_db' });

    expect(res.status).toBe(503);
    expect(res.body.error.code).toBe('policy_enforcement_unavailable');
  });

  // T10c-19 (FR-32 / C-01, C-02, C-03)
  test('T10c-19 (FR-32 / C-01, C-02, C-03): E2E delayed password_change verifies current_password, hides password hash from GET /actions/:id, mutates password and revokes sessions on execute, and returns 410 action_expired when cancelling expired actions', async () => {
    const bcrypt = require('bcrypt');
    const currentPw = 'InitialSecurePassword!111';
    const newPw = 'DelayedUpdatedPassword!222';
    await user.update({ password_hash: await bcrypt.hash(currentPw, 10) });

    // 1. Trigger PEP delay on /api/v1/account/password with WRONG current_password -> rejected with 401
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 65,
      risk_tier: 'high',
      contributing_signals: [{ signal: 'impossible_travel', category: 'location', weight: 65 }]
    });

    const wrongPwRes = await request(app)
      .post('/api/v1/account/password')
      .set('Authorization', `Bearer ${token}`)
      .send({
        current_password: 'WrongPassword!000',
        new_password: newPw
      });
    expect(wrongPwRes.status).toBe(401);
    expect(wrongPwRes.body.error.code).toBe('invalid_credentials');

    // 2. Trigger PEP delay on /api/v1/account/password with VALID current_password -> 403 action_delayed
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 65,
      risk_tier: 'high',
      contributing_signals: [{ signal: 'impossible_travel', category: 'location', weight: 65 }]
    });

    const delayedPwRes = await request(app)
      .post('/api/v1/account/password')
      .set('Authorization', `Bearer ${token}`)
      .send({
        current_password: currentPw,
        new_password: newPw
      });
    expect(delayedPwRes.status).toBe(403);
    expect(delayedPwRes.body.error.code).toBe('action_delayed');

    const pwActionId = delayedPwRes.body.error.pending_action_id;

    // 3. GET /api/v1/cooling-off/actions/:id never exposes new_password or new_password_hash
    const detailRes = await request(app)
      .get(`/api/v1/cooling-off/actions/${pwActionId}`)
      .set('Authorization', `Bearer ${token}`);
    expect(detailRes.status).toBe(200);
    expect(detailRes.body.action.action_payload).toEqual({ password_change_requested: true });
    expect(JSON.stringify(detailRes.body)).not.toContain(newPw);
    expect(JSON.stringify(detailRes.body)).not.toContain('$2b$');

    // 4. Advance execute_at and execute via POST /api/v1/cooling-off/actions/:id/execute
    await DelayedAction.update(
      { execute_at: new Date(Date.now() - 5000) },
      { where: { id: pwActionId } }
    );

    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 0,
      risk_tier: 'low',
      contributing_signals: []
    });

    const execPwRes = await request(app)
      .post(`/api/v1/cooling-off/actions/${pwActionId}/execute`)
      .set('Authorization', `Bearer ${token}`);
    expect(execPwRes.status).toBe(200);
    expect(execPwRes.body.status).toBe('completed');
    expect(execPwRes.body.execution_result.action).toBe('password_change');
    expect(execPwRes.body.execution_result.reauthentication_required).toBe(true);

    const refreshedUser = await User.findByPk(user.id);
    expect(await bcrypt.compare(newPw, refreshedUser.password_hash)).toBe(true);

    const oldSess = await Session.findByPk(session.sessionId);
    expect(oldSess.is_active).toBe(false);

    // 5. Create a new session and verify POST /api/v1/cooling-off/actions/:id/cancel returns 410 action_expired past expires_at
    const nextSession = await createSession(user.id, user.email, 900);
    const nextToken = jwt.sign(
      { id: user.id, email: user.email, session_id: nextSession.sessionId },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 40,
      risk_tier: 'medium',
      contributing_signals: [
        { signal: 'impossible_travel', category: 'location', weight: 25 },
        { signal: 'unrecognized_device', category: 'device', weight: 15 }
      ]
    });

    const schedExpRes = await request(app)
      .post('/api/v1/account/high-impact')
      .set('Authorization', `Bearer ${nextToken}`)
      .send({ operation: 'expire_before_cancel' });

    const expActionId = schedExpRes.body.error.pending_action_id;
    const expCancelToken = schedExpRes.body.error.cancellation_token;

    await DelayedAction.update(
      {
        execute_at: new Date(Date.now() - 4000 * 1000),
        expires_at: new Date(Date.now() - 10 * 1000)
      },
      { where: { id: expActionId } }
    );

    const cancelExpiredRes = await request(app)
      .post(`/api/v1/cooling-off/actions/${expActionId}/cancel`)
      .set('Authorization', `Bearer ${nextToken}`)
      .send({ cancellation_token: expCancelToken });

    expect(cancelExpiredRes.status).toBe(410);
    expect(cancelExpiredRes.body.error.code).toBe('action_expired');
  });

  // T10c-20 (FR-32 / C-04, C-07)
  test('T10c-20 (FR-32 / C-04, C-07): Atomic Redis lock release prevents deleting another worker lock and processOverdueActions reconciles stale executing actions', async () => {
    const rawRedis = redisStorage.getRedisClient();
    const lockKey = 'cooling_off:test_atomic_lock';

    // 1. Acquire lock for Worker A, then simulate expiry and acquisition by Worker B
    await rawRedis.set(lockKey, 'worker_B_owner', 'EX', 30);

    // Worker A attempting to release with its own stale token must NOT delete Worker B's lock
    const wrongOwnerRelease = await redisStorage.executeReleaseLock(lockKey, 'worker_A_stale_owner');
    expect(Number(wrongOwnerRelease)).toBe(0);
    expect(await rawRedis.get(lockKey)).toBe('worker_B_owner');

    // Worker B releasing with matching owner token deletes the lock atomically
    const rightOwnerRelease = await redisStorage.executeReleaseLock(lockKey, 'worker_B_owner');
    expect(Number(rightOwnerRelease)).toBe(1);
    expect(await rawRedis.get(lockKey)).toBeNull();

    // 2. Worker processOverdueActions reconciles stale 'executing' rows
    const stuckAction = await DelayedAction.create({
      id: `cact_${crypto.randomUUID()}`,
      user_id: user.id,
      session_id: session.sessionId,
      action_type: 'high_impact_action',
      action_sensitivity: 'critical',
      route_path: '/api/v1/account/high-impact',
      route_method: 'POST',
      action_payload: { operation: 'stuck_worker_task' },
      scheduled_at_risk_tier: 'medium',
      cooling_off_seconds: 300,
      status: 'executing',
      cancellation_token_hash: crypto.createHash('sha256').update('stuck_tok').digest('hex'),
      scheduled_at: new Date(Date.now() - 600 * 1000),
      execute_at: new Date(Date.now() - 300 * 1000),
      expires_at: new Date(Date.now() + 1800 * 1000)
    });

    await DelayedAction.update(
      { updated_at: new Date(Date.now() - 60 * 1000) },
      { where: { id: stuckAction.id } }
    );

    const summary = await coolingOffWorker.processOverdueActions({ staleTimeoutMs: 10000 });
    expect(summary.skipped).toBe(false);
    expect(summary.reconciledStaleCount).toBeGreaterThanOrEqual(1);

    const refreshedStuck = await DelayedAction.findByPk(stuckAction.id);
    expect(refreshedStuck.status).toBe('failed');
    expect(refreshedStuck.failure_reason).toBe('worker_execution_timeout_or_crash');
  });
});

