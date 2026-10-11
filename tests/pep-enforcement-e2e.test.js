'use strict';

const http = require('http');
const bcrypt = require('bcrypt');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const { io: ioClient } = require('socket.io-client');
const app = require('../src/app');
const { runMigrations } = require('../src/database/migrate');
const {
  User,
  Session,
  SecurityEvent,
  RiskAssessment,
  PolicyDecision,
  ElevationAuditLog
} = require('../src/database/models');
const { createSession } = require('../src/services/sessionService');
const {
  grantElevation,
  checkElevation,
  createMockVerificationTicket
} = require('../src/services/elevationService');
const { getTestChallengeOtp } = require('../src/services/stepUpService');
const { recordSecurityEvent } = require('../src/services/eventService');
const policyLoader = require('../src/services/policyLoader');
const sessionService = require('../src/services/sessionService');
const redisStorage = require('../src/storage/redis');
const { initSocketServer, closeSocketServer } = require('../src/realtime/socketServer');
const { JWT_SECRET } = require('../src/middleware/auth');
const { REDIS_PREFIXES } = require('../src/config/sessionConfig');

const TEST_ADMIN_KEY_VALID = 'admin_secret_key_with_at_least_32_characters_12345';

async function waitForCondition(predicate, timeoutMs = 3000, intervalMs = 20) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await predicate()) return true;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return false;
}

describe('Module 10b — PEP End-to-End Enforcement, Containment, Account Lock & Real-Time Broadcasts', () => {
  let user;
  let session;
  let token;
  const plainPassword = 'CorrectHorseBatteryStaple1!';

  beforeAll(async () => {
    await runMigrations();
  });

  beforeEach(async () => {
    const passwordHash = await bcrypt.hash(plainPassword, 10);
    user = await User.create({
      email: `pep-e2e-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`,
      password_hash: passwordHash
    });
    session = await createSession(user.id, user.email, 900, {
      device_fingerprint: 'fp_known_e2e_device_01'
    });
    token = jwt.sign(
      { id: user.id, email: user.email, session_id: session.sessionId },
      JWT_SECRET,
      { expiresIn: '15m' }
    );
  });

  afterEach(async () => {
    jest.restoreAllMocks();
    policyLoader.resetActivePolicy();
    await closeSocketServer();
  });

  // T10b-13 (FR-3, FR-7)
  test('T10b-13 (FR-3, FR-7): All 5 sensitive account routes execute real mutations when allowed, and password change invalidates all sessions and elevations for the user', async () => {
    // 1. POST /api/v1/account/phone (low risk -> allow)
    const phoneRes = await request(app)
      .post('/api/v1/account/phone')
      .set('Authorization', `Bearer ${token}`)
      .send({ phone_number: '+14155552671' })
      .expect(200);
    expect(phoneRes.body.status).toBe('completed');
    expect(phoneRes.body.phone_number).toBe('+14155552671');

    // Note: phone_number_change was account modification #1.
    // A second account modification within 10 minutes will match seq_rapid_credential_cascade (-> reverify).
    // Grant elevations on the active session so we can test all remaining route mutations and then verify
    // that password change purges all sessions and elevations!
    for (const scope of ['account_recovery', 'credential_change', 'sensitive_action']) {
      const tkt = createMockVerificationTicket({
        userId: user.id,
        sessionId: session.sessionId,
        scope
      });
      await grantElevation({
        sessionId: session.sessionId,
        userId: user.id,
        scope,
        verificationTicket: tkt,
        grantedAtRiskTier: 'high'
      });
    }

    // 2. POST /api/v1/account/recovery-email
    const recRes = await request(app)
      .post('/api/v1/account/recovery-email')
      .set('Authorization', `Bearer ${token}`)
      .send({ recovery_email: 'NewRecovery@Example.com' })
      .expect(200);
    expect(recRes.body.status).toBe('completed');
    expect(recRes.body.recovery_email).toBe('newrecovery@example.com');

    // 3. POST /api/v1/account/mfa
    const mfaRes = await request(app)
      .post('/api/v1/account/mfa')
      .set('Authorization', `Bearer ${token}`)
      .send({ mfa_enabled: true })
      .expect(200);
    expect(mfaRes.body.status).toBe('completed');
    expect(mfaRes.body.mfa_enabled).toBe(true);

    // 4. POST /api/v1/account/high-impact
    const hiRes = await request(app)
      .post('/api/v1/account/high-impact')
      .set('Authorization', `Bearer ${token}`)
      .send({ operation: 'export_full_account_archive', target: 's3://vault/export' })
      .expect(200);
    expect(hiRes.body.status).toBe('completed');
    expect(hiRes.body.operation).toBe('export_full_account_archive');

    // Create a second concurrent session for the same user with its own elevation
    const session2 = await createSession(user.id, user.email, 900);
    const token2 = jwt.sign(
      { id: user.id, email: user.email, session_id: session2.sessionId },
      JWT_SECRET,
      { expiresIn: '15m' }
    );
    const tkt2 = createMockVerificationTicket({
      userId: user.id,
      sessionId: session2.sessionId,
      scope: 'credential_change'
    });
    await grantElevation({
      sessionId: session2.sessionId,
      userId: user.id,
      scope: 'credential_change',
      verificationTicket: tkt2,
      grantedAtRiskTier: 'high'
    });

    // 5. POST /api/v1/account/password -> updates password_hash and invalidates ALL sessions & elevations
    const newPassword = 'UpdatedStrongPassword99!';
    const pwRes = await request(app)
      .post('/api/v1/account/password')
      .set('Authorization', `Bearer ${token}`)
      .send({
        current_password: plainPassword,
        new_password: newPassword
      })
      .expect(200);

    expect(pwRes.body.status).toBe('completed');
    expect(pwRes.body.reauthentication_required).toBe(true);
    expect(pwRes.body.sessions_terminated).toBeGreaterThanOrEqual(2);

    // Verify all user columns persisted in MySQL
    const updatedUser = await User.findByPk(user.id);
    expect(updatedUser.phone_number).toBe('+14155552671');
    expect(updatedUser.recovery_email).toBe('newrecovery@example.com');
    expect(updatedUser.mfa_enabled).toBe(true);
    expect(await bcrypt.compare(newPassword, updatedUser.password_hash)).toBe(true);

    // Verify both Session 1 (caller) and Session 2 are invalidated and their elevations purged
    const elev1 = await checkElevation({ sessionId: session.sessionId, scope: 'credential_change' });
    const elev2 = await checkElevation({ sessionId: session2.sessionId, scope: 'credential_change' });
    expect(elev1.elevated).toBe(false);
    expect(elev2.elevated).toBe(false);

    await request(app)
      .get('/api/v1/me')
      .set('Authorization', `Bearer ${token}`)
      .expect(401);

    await request(app)
      .get('/api/v1/me')
      .set('Authorization', `Bearer ${token2}`)
      .expect(401);
  });

  // T10b-14 (FR-3, FR-24, FR-30, NFR-12)
  test('T10b-14 (FR-3, FR-24, FR-30, NFR-12): End-to-end step-up re-verification flow — 403 step_up_required -> challenge -> verify -> 200 completed (elevated_allowed)', async () => {
    // Establish prior baseline login on known device/country so current session login from a new device + country raises risk to medium
    const earlierTime = new Date(Date.now() - 3600 * 1000);
    await recordSecurityEvent({
      userId: user.id,
      eventType: 'login_success',
      timestamp: earlierTime,
      context: {
        ip_address: '8.8.8.8',
        geo_country: 'US',
        device_fingerprint: 'fp_historical_device_01'
      }
    });

    // Record login for current session with a new device fingerprint -> +10 unrecognized_device
    // So recovery_email_change (base 18 + high sensitivity 3 + unrecognized_device 10 = 31 -> medium tier -> reverify!)
    await recordSecurityEvent({
      userId: user.id,
      sessionId: session.sessionId,
      eventType: 'login_success',
      timestamp: new Date(Date.now() - 10 * 1000),
      context: {
        ip_address: '8.8.8.8',
        geo_country: 'US',
        device_fingerprint: 'fp_brand_new_device_02'
      }
    });

    // 1. Attempt recovery-email change without elevation -> 403 step_up_required
    const haltedRes = await request(app)
      .post('/api/v1/account/recovery-email')
      .set('Authorization', `Bearer ${token}`)
      .set('x-device-fingerprint', 'fp_brand_new_device_02')
      .send({ recovery_email: 'verified-recovery@example.com' })
      .expect(403);

    expect(haltedRes.body.error.code).toBe('step_up_required');
    expect(haltedRes.body.error.required_scope).toBe('account_recovery');

    // Verify recovery_email was NOT mutated while halted
    const unchangedUser = await User.findByPk(user.id);
    expect(unchangedUser.recovery_email).toBeNull();

    // 2. Request step-up challenge on the returned challenge_endpoint
    const challengeRes = await request(app)
      .post(haltedRes.body.error.challenge_endpoint)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: haltedRes.body.error.required_scope })
      .expect(200);

    const otp = getTestChallengeOtp(challengeRes.body.challenge_id);

    // 3. Verify step-up OTP on the returned verify_endpoint
    const verifyRes = await request(app)
      .post(haltedRes.body.error.verify_endpoint)
      .set('Authorization', `Bearer ${token}`)
      .send({
        challenge_id: challengeRes.body.challenge_id,
        code: otp
      })
      .expect(200);
    expect(verifyRes.body.elevated).toBe(true);

    // 4. Retry recovery-email change -> now succeeds (200 completed)
    const retryRes = await request(app)
      .post('/api/v1/account/recovery-email')
      .set('Authorization', `Bearer ${token}`)
      .set('x-device-fingerprint', 'fp_brand_new_device_02')
      .send({ recovery_email: 'verified-recovery@example.com' })
      .expect(200);

    expect(retryRes.body.status).toBe('completed');
    expect(retryRes.body.recovery_email).toBe('verified-recovery@example.com');

    const updatedUser = await User.findByPk(user.id);
    expect(updatedUser.recovery_email).toBe('verified-recovery@example.com');
  });

  // T10b-15 (FR-3, FR-17, FR-18, FR-30)
  test('T10b-15 (FR-3, FR-17, FR-18, FR-30): Halted attempts never mutate user state, record action_status: halted, and correlate into active sequences to trigger escalation', async () => {
    // Establish prior baseline login so new device raises risk to medium on recovery-email attempt
    await recordSecurityEvent({
      userId: user.id,
      eventType: 'login_success',
      timestamp: new Date(Date.now() - 7200 * 1000),
      context: {
        ip_address: '8.8.8.8',
        geo_country: 'US',
        device_fingerprint: 'fp_baseline_device_01'
      }
    });

    // 1. Attempt POST /api/v1/account/recovery-email from unrecognized device -> score 18 + 3 + 10 = 31 (medium -> halted with 403 step_up_required)
    const firstRes = await request(app)
      .post('/api/v1/account/recovery-email')
      .set('Authorization', `Bearer ${token}`)
      .set('x-device-fingerprint', 'fp_unrecognized_device_02')
      .send({ recovery_email: 'attacker@evil.example' })
      .expect(403);
    expect(firstRes.body.error.code).toBe('step_up_required');

    const firstDecision = await PolicyDecision.findByPk(firstRes.body.error.decision_id);
    const firstEvent = await SecurityEvent.findByPk(firstDecision.event_id);
    expect(firstEvent.metadata.action_status).toBe('halted');
    expect(firstEvent.metadata.enforcement_outcome).toBe('step_up_challenged');

    // Verify recovery_email was NOT mutated by the halted attempt
    let dbUser = await User.findByPk(user.id);
    expect(dbUser.recovery_email).toBeNull();

    // 2. Now attempt POST /api/v1/account/password within 10 minutes:
    // Even though recovery_email_change was halted, it was correlated into the active sequence,
    // so recovery_email_change -> password_change triggers seq_rapid_credential_cascade (+20 points)!
    const secondRes = await request(app)
      .post('/api/v1/account/password')
      .set('Authorization', `Bearer ${token}`)
      .set('x-device-fingerprint', 'fp_unrecognized_device_02')
      .send({
        current_password: plainPassword,
        new_password: 'AttackerNewPassword99!'
      })
      .expect(403);

    expect(secondRes.body.error.code).toBe('step_up_required');

    const secondDecision = await PolicyDecision.findByPk(secondRes.body.error.decision_id);
    expect(secondDecision.risk_tier).toBe('medium');
    expect(secondDecision.enforcement_outcome).toBe('step_up_challenged');
    const signalNames = secondDecision.contributing_signals.map((s) => s.signal);
    expect(signalNames).toContain('seq_rapid_credential_cascade');

    const secondEvent = await SecurityEvent.findByPk(secondDecision.event_id);
    expect(secondEvent.metadata.action_status).toBe('halted');

    // Verify password_hash was NOT mutated by the halted attempt
    dbUser = await User.findByPk(user.id);
    expect(await bcrypt.compare(plainPassword, dbUser.password_hash)).toBe(true);
  });

  // T10b-16 (FR-4, FR-28, FR-29, FR-30)
  test('T10b-16 (FR-4, FR-28, FR-29, FR-30): Critical takeover progression triggers session containment and 15-minute account lock, blocks login across Redis restarts, unlocks after expiry, and fails closed if invalidation fails', async () => {
    // Establish historical login so new device login is detected as is_new_device: true
    await recordSecurityEvent({
      userId: user.id,
      eventType: 'login_success',
      timestamp: new Date(Date.now() - 7200 * 1000),
      context: {
        ip_address: '8.8.8.8',
        geo_country: 'US',
        device_fingerprint: 'fp_old_device_100'
      }
    });

    // Position i: untrusted login_success on new device + impossible_travel
    await recordSecurityEvent({
      userId: user.id,
      sessionId: session.sessionId,
      eventType: 'login_success',
      timestamp: new Date(Date.now() - 40 * 1000),
      context: {
        ip_address: '198.51.100.77',
        geo_country: 'DE',
        device_fingerprint: 'fp_attacker_device_999'
      },
      metadata: {
        travel_anomaly: {
          impossible_travel: true
        }
      }
    });

    // Position j: account modification event in sequence
    await recordSecurityEvent({
      userId: user.id,
      sessionId: session.sessionId,
      eventType: 'recovery_email_change',
      timestamp: new Date(Date.now() - 20 * 1000),
      context: {
        ip_address: '198.51.100.77',
        geo_country: 'DE',
        device_fingerprint: 'fp_attacker_device_999'
      },
      metadata: {
        action_sensitivity: 'high',
        action_status: 'halted'
      }
    });

    // Position k: POST /api/v1/account/high-impact matches seq_takeover_progression (i < j < k) -> critical block + containment!
    // First verify fail-closed containment invariant: if invalidateSession throws during containment,
    // PEP must NOT report session_contained: true and must fail closed with 503
    jest
      .spyOn(sessionService, 'invalidateSession')
      .mockRejectedValueOnce(new Error('Simulated Redis failure during session invalidation'));

    const failedContainmentRes = await request(app)
      .post('/api/v1/account/high-impact')
      .set('Authorization', `Bearer ${token}`)
      .set('x-device-fingerprint', 'fp_attacker_device_999')
      .send({
        operation: 'export_full_account_archive'
      })
      .expect(503);
    expect(failedContainmentRes.body.error.code).toBe('policy_enforcement_unavailable');
    expect(failedContainmentRes.body.error.session_contained).toBeUndefined();

    // Now allow invalidateSession to run normally -> triggers full containment + 15-minute account lock
    const blockRes = await request(app)
      .post('/api/v1/account/high-impact')
      .set('Authorization', `Bearer ${token}`)
      .set('x-device-fingerprint', 'fp_attacker_device_999')
      .send({
        operation: 'export_full_account_archive'
      })
      .expect(403);

    expect(blockRes.body.error.code).toBe('action_blocked');
    expect(blockRes.body.error.session_contained).toBe(true);
    expect(blockRes.body.error.account_locked).toBe(true);
    expect(blockRes.body.error.locked_until).toBeDefined();

    // 1. Subsequent request with the old session token is rejected with 401
    await request(app)
      .get('/api/v1/me')
      .set('Authorization', `Bearer ${token}`)
      .expect(401);

    // 2. Login with valid credentials while locked returns 403 account_temporarily_locked
    const lockedLoginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: user.email, password: plainPassword })
      .expect(403);
    expect(lockedLoginRes.body.error.code).toBe('account_temporarily_locked');
    expect(lockedLoginRes.body.error.retry_after_seconds).toBeGreaterThan(0);

    // 3. Consistency across Redis restart/flush: delete the Redis account_lock key while MySQL locked_until is still in the future
    const client = redisStorage.getRedisClient();
    await client.del(`${REDIS_PREFIXES.ACCOUNT_LOCK}${user.id}`);

    const afterFlushLoginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: user.email, password: plainPassword })
      .expect(403);
    expect(afterFlushLoginRes.body.error.code).toBe('account_temporarily_locked');

    // Verify Redis key was automatically re-warmed from MySQL locked_until
    const rewarmed = await client.get(`${REDIS_PREFIXES.ACCOUNT_LOCK}${user.id}`);
    expect(rewarmed).not.toBeNull();

    // 4. Once locked_until expires, login succeeds and clears stale locked_until
    await User.update(
      { locked_until: new Date(Date.now() - 1000) },
      { where: { id: user.id } }
    );
    await client.del(`${REDIS_PREFIXES.ACCOUNT_LOCK}${user.id}`);

    const unlockedLoginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: user.email, password: plainPassword })
      .expect(200);
    expect(unlockedLoginRes.body.token).toBeDefined();

    const unlockedUser = await User.findByPk(user.id);
    expect(unlockedUser.locked_until).toBeNull();
  });

  // T10b-17 (FR-30, FR-36)
  test('T10b-17 (FR-30, FR-36): recommend_only enforcement mode logs recommended_decision without blocking and allows action execution', async () => {
    const basePolicy = policyLoader.getActivePolicy();
    const recommendOnlyPolicy = {
      ...basePolicy,
      policy_id: 'recommend-only-v1',
      ENFORCEMENT_MODE_BY_DECISION: {
        allow: 'recommend_only',
        monitor: 'recommend_only',
        reverify: 'recommend_only',
        delay: 'recommend_only',
        block: 'recommend_only'
      }
    };
    jest.spyOn(policyLoader, 'getActivePolicy').mockReturnValue(recommendOnlyPolicy);

    // Create takeover progression sequence (new_device -> mfa_change -> high_impact_action)
    // In automatic mode this is 'block' via esc_takeover_progression, but in recommend_only mode it logs and allows!
    await recordSecurityEvent({
      userId: user.id,
      sessionId: session.sessionId,
      eventType: 'new_device',
      timestamp: new Date(Date.now() - 20 * 1000),
      context: { ip_address: '198.51.100.99' }
    });
    await recordSecurityEvent({
      userId: user.id,
      sessionId: session.sessionId,
      eventType: 'mfa_change',
      timestamp: new Date(Date.now() - 10 * 1000),
      context: { ip_address: '198.51.100.99' }
    });

    const res = await request(app)
      .post('/api/v1/account/high-impact')
      .set('Authorization', `Bearer ${token}`)
      .send({ operation: 'delete_production_cluster' })
      .expect(200);

    expect(res.body.status).toBe('completed');
    const decision = await PolicyDecision.findByPk(res.body.decision_id);
    expect(decision.recommended_decision).toBe('block');
    expect(decision.effective_decision).toBe('monitor');
    expect(decision.enforcement_outcome).toBe('recommend_only_allowed');
    expect(decision.enforcement_mode).toBe('recommend_only');
    expect(decision.policy_version).toBe('recommend-only-v1@1.0.0');
  });

  // T10b-18 (FR-26, FR-30, FR-32)
  test('T10b-18 (FR-26, FR-30, FR-32): Real-time Socket.IO decision:recorded broadcast delivers sanitized payload to user room and full breakdown to admin:stream', async () => {
    process.env.ACTIONGUARD_ADMIN_API_KEY = TEST_ADMIN_KEY_VALID;
    const httpServer = http.createServer(app);
    initSocketServer(httpServer);

    await new Promise((resolve) => httpServer.listen(0, resolve));
    const port = httpServer.address().port;

    const userSocket = ioClient(`http://localhost:${port}`, {
      transports: ['websocket'],
      auth: { token }
    });
    const adminSocket = ioClient(`http://localhost:${port}`, {
      transports: ['websocket'],
      auth: { apiKey: TEST_ADMIN_KEY_VALID }
    });

    const userDecisions = [];
    const adminDecisions = [];
    userSocket.on('decision:recorded', (payload) => userDecisions.push(payload));
    adminSocket.on('decision:recorded', (payload) => adminDecisions.push(payload));

    try {
      await Promise.all([
        new Promise((resolve, reject) => {
          userSocket.on('connect', resolve);
          userSocket.on('connect_error', reject);
        }),
        new Promise((resolve, reject) => {
          adminSocket.on('connect', resolve);
          adminSocket.on('connect_error', reject);
        })
      ]);

      await request(app)
        .post('/api/v1/account/mfa')
        .set('Authorization', `Bearer ${token}`)
        .send({ mfa_enabled: true })
        .expect(200);

      const receivedBoth = await waitForCondition(
        () => userDecisions.length >= 1 && adminDecisions.length >= 1
      );
      expect(receivedBoth).toBe(true);

      const userPayload = userDecisions[0];
      expect(userPayload.decision_id).toMatch(/^dec_/);
      expect(userPayload.action_type).toBe('mfa_change');
      expect(userPayload.decision).toBe('monitor');
      expect(userPayload.enforcement_outcome).toBe('monitored');
      expect(userPayload.explanation.user_facing).toBeDefined();
      // User payload must NEVER expose internal/admin fields
      expect(userPayload.user_id).toBeUndefined();
      expect(userPayload.risk_score).toBeUndefined();
      expect(userPayload.contributing_signals).toBeUndefined();
      expect(userPayload.reasons).toBeUndefined();
      expect(userPayload.policy_version).toBeUndefined();
      expect(userPayload.explanation.admin_facing).toBeUndefined();

      const adminPayload = adminDecisions.find((d) => d.decision_id === userPayload.decision_id);
      expect(adminPayload).toBeDefined();
      expect(adminPayload.user_id).toBe(user.id);
      expect(typeof adminPayload.risk_score).toBe('number');
      expect(Array.isArray(adminPayload.contributing_signals)).toBe(true);
      expect(Array.isArray(adminPayload.reasons)).toBe(true);
      expect(adminPayload.policy_version).toBe('default-v1@1.0.0');
      expect(adminPayload.explanation.admin_facing).toContain("Policy decision 'monitor'");
    } finally {
      userSocket.disconnect();
      adminSocket.disconnect();
      await closeSocketServer();
      await new Promise((resolve) => httpServer.close(resolve));
    }
  });

  // T10b-21 (F-02, F-05, FR-3, FR-17, FR-30, FR-37)
  test('T10b-21 (F-02, F-05, FR-3, FR-17, FR-30, FR-37): Action lifecycle distinguishes authorized, rejected, failed_execution, and completed states; rejects malformed schemas before recording events; and includes action_status in sequence projections', async () => {
    const { loadActiveSequenceForUser } = require('../src/services/riskEngineService');

    // 1. Malformed payloads (short password, unchanged password, missing '+' on phone, invalid email)
    //    are rejected BEFORE recording a SecurityEvent or PolicyDecision
    await request(app)
      .post('/api/v1/account/password')
      .set('Authorization', `Bearer ${token}`)
      .send({ current_password: plainPassword, new_password: 'short' })
      .expect(400);

    await request(app)
      .post('/api/v1/account/password')
      .set('Authorization', `Bearer ${token}`)
      .send({ current_password: plainPassword, new_password: plainPassword })
      .expect(400);

    await request(app)
      .post('/api/v1/account/phone')
      .set('Authorization', `Bearer ${token}`)
      .send({ phone_number: '14155552671' }) // missing leading '+'
      .expect(400);

    const eventsAfterMalformed = await SecurityEvent.findAll({
      where: { user_id: user.id }
    });
    expect(eventsAfterMalformed).toHaveLength(0);

    // 2. Wrong current_password passes schema validation & PEP authorization, then is marked 'rejected' (never 'completed')
    const wrongPwRes = await request(app)
      .post('/api/v1/account/password')
      .set('Authorization', `Bearer ${token}`)
      .send({
        current_password: 'WrongCurrentPassword999!',
        new_password: 'ValidNewPassword999!'
      })
      .expect(401);
    expect(wrongPwRes.body.error.code).toBe('invalid_credentials');

    const rejectedEvents = await SecurityEvent.findAll({
      where: { user_id: user.id, event_type: 'password_change' }
    });
    expect(rejectedEvents).toHaveLength(1);
    expect(rejectedEvents[0].metadata.action_status).toBe('rejected');
    expect(rejectedEvents[0].metadata.rejection_reason).toBe('invalid_current_password');

    // 3. Recovery email matching primary registration email is marked 'rejected'
    const sameEmailRes = await request(app)
      .post('/api/v1/account/recovery-email')
      .set('Authorization', `Bearer ${token}`)
      .send({ recovery_email: user.email })
      .expect(400);
    expect(sameEmailRes.body.error.code).toBe('invalid_request');

    const sameEmailEvents = await SecurityEvent.findAll({
      where: { user_id: user.id, event_type: 'recovery_email_change' }
    });
    expect(sameEmailEvents).toHaveLength(1);
    expect(sameEmailEvents[0].metadata.action_status).toBe('rejected');
    expect(sameEmailEvents[0].metadata.rejection_reason).toBe('recovery_email_matches_primary');

    // 4. Database exception inside route handler marks event as 'failed_execution' (never 'completed')
    const elevTicket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'account_recovery'
    });
    await grantElevation({
      sessionId: session.sessionId,
      userId: user.id,
      scope: 'account_recovery',
      verificationTicket: elevTicket,
      grantedAtRiskTier: 'high'
    });

    jest
      .spyOn(User.prototype, 'update')
      .mockRejectedValueOnce(new Error('Simulated MySQL write failure during phone update'));

    await request(app)
      .post('/api/v1/account/phone')
      .set('Authorization', `Bearer ${token}`)
      .send({ phone_number: '+14155550199' })
      .expect(500);

    const failedPhoneEvents = await SecurityEvent.findAll({
      where: { user_id: user.id, event_type: 'phone_number_change' }
    });
    expect(failedPhoneEvents).toHaveLength(1);
    expect(failedPhoneEvents[0].metadata.action_status).toBe('failed_execution');
    expect(failedPhoneEvents[0].metadata.failure_reason).toContain('Simulated MySQL write failure');

    // 5. Sequence projection includes action_status for each event in the active sequence
    const projectedSequence = await loadActiveSequenceForUser(user.id);
    expect(projectedSequence.length).toBeGreaterThanOrEqual(3);
    const statusesByType = Object.fromEntries(
      projectedSequence.map((ev) => [ev.event_type, ev.action_status])
    );
    expect(statusesByType.password_change).toBe('rejected');
    expect(statusesByType.recovery_email_change).toBe('rejected');
    expect(statusesByType.phone_number_change).toBe('failed_execution');
  });

  // T10b-22 (F-03, FR-4, FR-28, FR-29, FR-30, NFR-7)
  test('T10b-22 (F-03, FR-4, FR-28, FR-29, FR-30, NFR-7): Truthful containment — when invalidateSession returns false or Redis lock write fails, PEP fails closed (503), rolls back MySQL locked_until, and never persists or broadcasts contained_and_blocked', async () => {
    const eventBus = require('../src/events/eventBus');

    // Set up takeover progression sequence so POST /api/v1/account/high-impact qualifies for critical containment
    await recordSecurityEvent({
      userId: user.id,
      eventType: 'login_success',
      timestamp: new Date(Date.now() - 7200 * 1000),
      context: { ip_address: '8.8.8.8', geo_country: 'US', device_fingerprint: 'fp_known_01' }
    });
    await recordSecurityEvent({
      userId: user.id,
      sessionId: session.sessionId,
      eventType: 'login_success',
      timestamp: new Date(Date.now() - 40 * 1000),
      context: { ip_address: '198.51.100.88', geo_country: 'DE', device_fingerprint: 'fp_attacker_02' },
      metadata: { travel_anomaly: { impossible_travel: true } }
    });
    await recordSecurityEvent({
      userId: user.id,
      sessionId: session.sessionId,
      eventType: 'mfa_change',
      timestamp: new Date(Date.now() - 20 * 1000),
      context: { ip_address: '198.51.100.88', geo_country: 'DE', device_fingerprint: 'fp_attacker_02' }
    });

    const broadcastedDecisions = [];
    const onDecisionRecorded = (payload) => {
      if (payload && payload.decision && payload.decision.user_id === user.id) {
        broadcastedDecisions.push(payload.decision);
      }
    };
    eventBus.on('policy:decision_recorded', onDecisionRecorded);

    try {
      // Case 1: invalidateSession returns false (without throwing) -> must fail closed (503) and NOT claim contained_and_blocked
      jest.spyOn(sessionService, 'invalidateSession').mockResolvedValueOnce(false);

      const falseInvRes = await request(app)
        .post('/api/v1/account/high-impact')
        .set('Authorization', `Bearer ${token}`)
        .set('x-device-fingerprint', 'fp_attacker_02')
        .send({ operation: 'delete_all_backups' })
        .expect(503);
      expect(falseInvRes.body.error.code).toBe('policy_enforcement_unavailable');

      // Verify no PolicyDecision row claims 'contained_and_blocked' and no broadcast was emitted
      const decisionsAfterFalse = await PolicyDecision.findAll({
        where: { user_id: user.id }
      });
      expect(decisionsAfterFalse).toHaveLength(1);
      expect(decisionsAfterFalse[0].enforcement_outcome).toBe('blocked');
      expect(broadcastedDecisions).toHaveLength(0);

      // Case 2: Redis lock write throws AFTER MySQL User.update({ locked_until }) ->
      //         must roll back users.locked_until, fail closed (503), and NOT claim contained_and_blocked
      // Keep session active for the retry by mocking invalidateSession to return true once while we fail Redis lock write
      jest.spyOn(sessionService, 'invalidateSession').mockResolvedValueOnce(true);

      const client = redisStorage.getRedisClient();
      const origSet = client.set.bind(client);
      jest.spyOn(client, 'set').mockImplementation(async (key, ...rest) => {
        if (String(key).startsWith(REDIS_PREFIXES.ACCOUNT_LOCK)) {
          throw new Error('Simulated Redis write failure on account_lock key');
        }
        return origSet(key, ...rest);
      });

      const redisLockFailRes = await request(app)
        .post('/api/v1/account/high-impact')
        .set('Authorization', `Bearer ${token}`)
        .set('x-device-fingerprint', 'fp_attacker_02')
        .send({ operation: 'delete_all_backups' })
        .expect(503);
      expect(redisLockFailRes.body.error.code).toBe('policy_enforcement_unavailable');

      // Verify MySQL locked_until was compensated back to null (no contradictory lock state)
      const userAfterRedisFail = await User.findByPk(user.id);
      expect(userAfterRedisFail.locked_until).toBeNull();

      // Verify no PolicyDecision claims 'contained_and_blocked' and no broadcast was emitted
      const decisionsAfterRedisFail = await PolicyDecision.findAll({
        where: { user_id: user.id }
      });
      expect(
        decisionsAfterRedisFail.every((d) => d.enforcement_outcome !== 'contained_and_blocked')
      ).toBe(true);
      expect(broadcastedDecisions).toHaveLength(0);
    } finally {
      eventBus.removeListener('policy:decision_recorded', onDecisionRecorded);
    }
  });
});

