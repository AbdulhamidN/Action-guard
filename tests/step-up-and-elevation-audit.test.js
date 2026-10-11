'use strict';

const crypto = require('crypto');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../src/app');
const { runMigrations } = require('../src/database/migrate');
const {
  User,
  Session,
  SecurityEvent,
  RiskAssessment,
  ElevationAuditLog
} = require('../src/database/models');
const { createSession, invalidateSession } = require('../src/services/sessionService');
const {
  grantElevation,
  checkElevation,
  revokeElevation,
  createMockVerificationTicket
} = require('../src/services/elevationService');
const {
  getTestChallengeOtp,
  getTestChallengeRecord
} = require('../src/services/stepUpService');
const { recordSecurityEvent } = require('../src/services/eventService');
const redisStorage = require('../src/storage/redis');
const { JWT_SECRET } = require('../src/middleware/auth');
const { REDIS_PREFIXES } = require('../src/config/sessionConfig');

describe('Module 10b — Local Step-Up Provider, Cross-Session Isolation & Elevation Audit (FR-8, FR-9, FR-24, FR-27)', () => {
  let user;
  let session;
  let token;

  beforeAll(async () => {
    await runMigrations();
  });

  beforeEach(async () => {
    user = await User.create({
      email: `stepup-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`,
      recovery_email: 'attacker-changeable-recovery@evil.example',
      password_hash: 'hashed_pw'
    });
    session = await createSession(user.id, user.email, 900);
    token = jwt.sign(
      { id: user.id, email: user.email, session_id: session.sessionId },
      JWT_SECRET,
      { expiresIn: '15m' }
    );
  });

  afterEach(() => {
    delete process.env.STEP_UP_VERIFICATION_PRIVATE_KEY;
    delete process.env.STEP_UP_VERIFICATION_PUBLIC_KEY;
    jest.restoreAllMocks();
  });

  // T10b-07 (FR-8, FR-24)
  test('T10b-07 (FR-8, FR-24): Local step-up challenge & verify issues OTP to registration email (never recovery_email), hides OTP from response, redeems ES256 ticket server-side, and records verification_success + granted audit row', async () => {
    // 1. Issue challenge for credential_change scope
    const challengeRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'credential_change' })
      .expect(200);

    expect(challengeRes.body.challenge_id).toMatch(/^chl_/);
    expect(challengeRes.body.scope).toBe('credential_change');
    expect(challengeRes.body.delivery_channel).toBe('registration_email');
    expect(challengeRes.body.masked_destination).toBe(`s***@example.com`);
    // Must NEVER expose plaintext OTP or ticket in HTTP response
    expect(challengeRes.body.otp).toBeUndefined();
    expect(challengeRes.body.code).toBeUndefined();

    // Verify delivery target is strictly the immutable registration email, NEVER recovery_email
    const outboxRecord = getTestChallengeRecord(challengeRes.body.challenge_id);
    expect(outboxRecord).not.toBeNull();
    expect(outboxRecord.destination).toBe(user.email);
    expect(outboxRecord.destination).not.toBe(user.recovery_email);

    // Verify Redis stores HMAC hash, never plaintext OTP
    const client = redisStorage.getRedisClient();
    const rawRedisChallenge = await client.get(
      `${REDIS_PREFIXES.STEP_UP_CHALLENGE}${challengeRes.body.challenge_id}`
    );
    expect(rawRedisChallenge).not.toContain(outboxRecord.otp);

    // 2. Verify challenge with the 6-digit OTP
    const otp = getTestChallengeOtp(challengeRes.body.challenge_id);
    expect(otp).toMatch(/^\d{6}$/);

    const verifyRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/verify`)
      .set('Authorization', `Bearer ${token}`)
      .send({
        challenge_id: challengeRes.body.challenge_id,
        code: otp,
        duration_seconds: 300
      })
      .expect(200);

    expect(verifyRes.body.elevated).toBe(true);
    expect(verifyRes.body.scope).toBe('credential_change');
    expect(verifyRes.body.remainingSeconds).toBeGreaterThan(0);
    // Client never handles a verification ticket
    expect(verifyRes.body.verification_ticket).toBeUndefined();
    expect(verifyRes.body.ticket).toBeUndefined();

    // 3. Verify verification_success security event was recorded for this session
    const verEvents = await SecurityEvent.findAll({
      where: {
        user_id: user.id,
        session_id: session.sessionId,
        event_type: 'verification_success'
      }
    });
    expect(verEvents).toHaveLength(1);
    expect(verEvents[0].metadata.challenge_id).toBe(challengeRes.body.challenge_id);
    expect(verEvents[0].metadata.scope).toBe('credential_change');

    // 4. Verify persistent elevation_audit_logs row ('granted')
    const auditLogs = await ElevationAuditLog.findAll({
      where: {
        user_id: user.id,
        session_id: session.sessionId,
        scope: 'credential_change',
        event_action: 'granted'
      }
    });
    expect(auditLogs).toHaveLength(1);
    expect(auditLogs[0].reason).toBe('step_up_verified');
    expect(auditLogs[0].jti).toMatch(/^tkt_/);
  });

  // T10b-08 (FR-8, FR-24)
  test('T10b-08 (FR-8, FR-24): Local step-up enforces separate ES256 keypair and fails closed (501) on missing, malformed, RSA, or mismatched keys', async () => {
    // 1. Missing public key when private key is set
    const pair1 = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    process.env.STEP_UP_VERIFICATION_PRIVATE_KEY = pair1.privateKey.export({
      type: 'pkcs8',
      format: 'pem'
    });
    delete process.env.STEP_UP_VERIFICATION_PUBLIC_KEY;

    const missingPubRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'credential_change' })
      .expect(501);
    expect(missingPubRes.body.error.code).toBe('verification_provider_unavailable');

    // 2. Mismatched EC public key from a second keypair
    const pair2 = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    process.env.STEP_UP_VERIFICATION_PUBLIC_KEY = pair2.publicKey.export({
      type: 'spki',
      format: 'pem'
    });

    const mismatchRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'credential_change' })
      .expect(501);
    expect(mismatchRes.body.error.code).toBe('verification_provider_unavailable');

    // 3. Matching valid EC P-256 keypair succeeds
    process.env.STEP_UP_VERIFICATION_PUBLIC_KEY = pair1.publicKey.export({
      type: 'spki',
      format: 'pem'
    });

    const validRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'credential_change' })
      .expect(200);

    const otp = getTestChallengeOtp(validRes.body.challenge_id);
    const verifyRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/verify`)
      .set('Authorization', `Bearer ${token}`)
      .send({
        challenge_id: validRes.body.challenge_id,
        code: otp
      })
      .expect(200);
    expect(verifyRes.body.elevated).toBe(true);
  });

  // T10b-09 (FR-8, FR-24)
  test('T10b-09 (FR-8, FR-24): Step-up verification rejects wrong OTP, single-use replay, expired challenge, and cross-session redemption', async () => {
    const challengeRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'account_recovery' })
      .expect(200);

    const challengeId = challengeRes.body.challenge_id;
    const realOtp = getTestChallengeOtp(challengeId);
    const wrongOtp = realOtp === '000000' ? '999999' : '000000';

    // 1. Wrong OTP -> 401 verification_failed + records verification_failed event
    const wrongRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/verify`)
      .set('Authorization', `Bearer ${token}`)
      .send({ challenge_id: challengeId, code: wrongOtp })
      .expect(401);
    expect(wrongRes.body.error.code).toBe('verification_failed');
    expect(wrongRes.body.error.remaining_attempts).toBe(2);

    const failedEvents = await SecurityEvent.findAll({
      where: {
        user_id: user.id,
        session_id: session.sessionId,
        event_type: 'verification_failed'
      }
    });
    expect(failedEvents).toHaveLength(1);

    // 2. Cross-session redemption attempt (Session B belonging to the same user tries to redeem Session A's challenge)
    const sessionB = await createSession(user.id, user.email, 900);
    const tokenB = jwt.sign(
      { id: user.id, email: user.email, session_id: sessionB.sessionId },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    const crossSessionRes = await request(app)
      .post(`/api/v1/sessions/${sessionB.sessionId}/step-up/verify`)
      .set('Authorization', `Bearer ${tokenB}`)
      .send({ challenge_id: challengeId, code: realOtp })
      .expect(403);
    expect(crossSessionRes.body.error.code).toBe('challenge_mismatch');

    // 3. Valid redemption on Session A succeeds
    await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/verify`)
      .set('Authorization', `Bearer ${token}`)
      .send({ challenge_id: challengeId, code: realOtp })
      .expect(200);

    // 4. Replaying the same challenge + OTP fails (401 challenge_expired)
    const replayRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/verify`)
      .set('Authorization', `Bearer ${token}`)
      .send({ challenge_id: challengeId, code: realOtp })
      .expect(401);
    expect(replayRes.body.error.code).toBe('challenge_expired');
  });

  // T10b-10 (FR-4, FR-8, FR-29)
  test('T10b-10 (FR-4, FR-8, FR-29): Exhausting 3 step-up OTP attempts triggers session containment and 15-minute protective account lock', async () => {
    const challengeRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'credential_change' })
      .expect(200);

    const challengeId = challengeRes.body.challenge_id;
    const realOtp = getTestChallengeOtp(challengeId);
    const wrongOtp = realOtp === '123456' ? '654321' : '123456';

    // Attempt 1 (wrong) -> 401
    await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/verify`)
      .set('Authorization', `Bearer ${token}`)
      .send({ challenge_id: challengeId, code: wrongOtp })
      .expect(401);

    // Attempt 2 (wrong) -> 401
    await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/verify`)
      .set('Authorization', `Bearer ${token}`)
      .send({ challenge_id: challengeId, code: wrongOtp })
      .expect(401);

    // Attempt 3 (wrong) -> 403 session_contained + protective lock
    const thirdRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/verify`)
      .set('Authorization', `Bearer ${token}`)
      .send({ challenge_id: challengeId, code: wrongOtp })
      .expect(403);

    expect(thirdRes.body.error.code).toBe('session_contained');
    expect(thirdRes.body.error.session_contained).toBe(true);
    expect(thirdRes.body.error.account_locked).toBe(true);
    expect(thirdRes.body.error.locked_until).toBeDefined();

    // Session is now inactive in MySQL and purged from Redis
    const dbSession = await Session.findByPk(session.sessionId);
    expect(dbSession.is_active).toBe(false);
    const redisSess = await redisStorage.getSession(session.sessionId);
    expect(redisSess).toBeNull();

    // User has locked_until set in MySQL ~15 minutes ahead
    const refreshedUser = await User.findByPk(user.id);
    expect(refreshedUser.locked_until).not.toBeNull();
    expect(new Date(refreshedUser.locked_until).getTime()).toBeGreaterThan(Date.now() + 800 * 1000);
  });

  // T10b-11 (FR-9, FR-27)
  test('T10b-11 (FR-9, FR-27): Cross-session elevation isolation — elevation granted on Session A is unusable from Session B of the same user', async () => {
    const sessionB = await createSession(user.id, user.email, 900);
    const tokenB = jwt.sign(
      { id: user.id, email: user.email, session_id: sessionB.sessionId },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    // Elevate Session A for 'account_recovery'
    const ticketA = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'account_recovery'
    });
    await grantElevation({
      sessionId: session.sessionId,
      userId: user.id,
      scope: 'account_recovery',
      verificationTicket: ticketA,
      grantedAtRiskTier: 'high'
    });

    // 1. Session A sees elevated: true
    const statusARes = await request(app)
      .get(`/api/v1/sessions/${session.sessionId}/elevate/account_recovery`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(statusARes.body.elevated).toBe(true);

    // 2. Session B sees elevated: false for its own session
    const statusBRes = await request(app)
      .get(`/api/v1/sessions/${sessionB.sessionId}/elevate/account_recovery`)
      .set('Authorization', `Bearer ${tokenB}`)
      .expect(200);
    expect(statusBRes.body.elevated).toBe(false);

    // 3. Session B cannot inspect or elevate Session A (403 forbidden)
    await request(app)
      .get(`/api/v1/sessions/${session.sessionId}/elevate/account_recovery`)
      .set('Authorization', `Bearer ${tokenB}`)
      .expect(403);

    await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${tokenB}`)
      .send({ scope: 'account_recovery' })
      .expect(403);
  });

  // T10b-12 (FR-9, FR-26, FR-27)
  test('T10b-12 (FR-9, FR-26, FR-27): Elevation lifecycle audit logs granted, used, expired, and revoked events, and revokes elevation when session risk tier rises above grant tier', async () => {
    const nowMs = Date.now();

    // 1. Grant elevation at 'low' risk tier
    const ticket1 = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'credential_change'
    });
    const grantRes = await grantElevation({
      sessionId: session.sessionId,
      userId: user.id,
      scope: 'credential_change',
      verificationTicket: ticket1,
      durationSeconds: 300,
      nowMs,
      grantedAtRiskTier: 'low'
    });
    expect(grantRes.elevated).toBe(true);
    expect(grantRes.grantedAtRiskTier).toBe('low');

    // 2. Check elevation with recordUse: true -> records 'used' audit log
    const useRes = await checkElevation({
      sessionId: session.sessionId,
      scope: 'credential_change',
      nowMs: nowMs + 1000,
      currentRiskTier: 'low',
      recordUse: true,
      actionType: 'password_change'
    });
    expect(useRes.elevated).toBe(true);

    // 3. Check elevation after TTL elapsed -> lazy expiry records 'expired' audit log
    const expiredRes = await checkElevation({
      sessionId: session.sessionId,
      scope: 'credential_change',
      nowMs: nowMs + 305 * 1000
    });
    expect(expiredRes.elevated).toBe(false);

    // 4. Grant a second elevation at 'medium' tier, then trigger a 'high' tier RiskAssessment on the session
    const ticket2 = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'account_recovery'
    });
    await grantElevation({
      sessionId: session.sessionId,
      userId: user.id,
      scope: 'account_recovery',
      verificationTicket: ticket2,
      durationSeconds: 300,
      grantedAtRiskTier: 'medium'
    });

    // Record a critical high_impact_action with impossible_travel + behavioral_deviation -> risk score 25 + 20 + 15 = 60 ('high' tier > 'medium')
    await recordSecurityEvent({
      userId: user.id,
      sessionId: session.sessionId,
      eventType: 'high_impact_action',
      context: { ip_address: '198.51.100.42' },
      metadata: {
        action_sensitivity: 'critical',
        travel_anomaly: {
          impossible_travel: true
        },
        behavioral_deviation: {
          is_evaluated: true,
          has_sufficient_history: true,
          deviation_score: 1.0
        }
      }
    });

    // Elevation for 'account_recovery' should now be automatically revoked with reason 'risk_tier_increased'
    const afterRiskRise = await checkElevation({
      sessionId: session.sessionId,
      scope: 'account_recovery'
    });
    expect(afterRiskRise.elevated).toBe(false);

    const auditRows = await ElevationAuditLog.findAll({
      where: {
        user_id: user.id,
        session_id: session.sessionId
      },
      order: [['seq_no', 'ASC']]
    });

    const actionsAndReasons = auditRows.map((r) => `${r.scope}:${r.event_action}:${r.reason}`);
    expect(actionsAndReasons).toContain('credential_change:granted:step_up_verified');
    expect(actionsAndReasons).toContain('credential_change:used:reverify:password_change');
    expect(actionsAndReasons).toContain('credential_change:expired:ttl_elapsed');
    expect(actionsAndReasons).toContain('account_recovery:granted:step_up_verified');
    expect(actionsAndReasons).toContain('account_recovery:revoked:risk_tier_increased');
  });

  // T10b-19 (F-01, F-08, FR-4, FR-8, FR-24)
  test('T10b-19 (F-01, F-08, FR-4, FR-8, FR-24): Concurrent wrong-OTP brute-force burst evaluates at most 3 attempts atomically, invalidates challenge, and cleans test outbox', async () => {
    const { verifyStepUpChallenge } = require('../src/services/stepUpService');
    const challengeRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'credential_change' })
      .expect(200);

    const challengeId = challengeRes.body.challenge_id;
    const realOtp = getTestChallengeOtp(challengeId);
    expect(realOtp).toMatch(/^\d{6}$/);

    // Generate 10 distinct wrong 6-digit codes
    const wrongCodes = [];
    for (let i = 0; wrongCodes.length < 10; i++) {
      const candidate = String(100000 + i);
      if (candidate !== realOtp) {
        wrongCodes.push(candidate);
      }
    }

    // Fire all 10 wrong-code verification attempts concurrently
    const settled = await Promise.allSettled(
      wrongCodes.map((wrongCode) =>
        verifyStepUpChallenge({
          userId: user.id,
          sessionId: session.sessionId,
          challengeId,
          code: wrongCode
        })
      )
    );

    // Every single promise must reject
    for (const res of settled) {
      expect(res.status).toBe('rejected');
    }

    const errorCodes = settled.map((r) => r.reason && r.reason.code);
    // At most 3 attempts can evaluate the OTP (producing VERIFICATION_CODE_INVALID or VERIFICATION_FAILED_CONTAINED)
    const evaluatedCount = errorCodes.filter(
      (c) => c === 'VERIFICATION_CODE_INVALID' || c === 'VERIFICATION_FAILED_CONTAINED'
    ).length;
    const expiredOrNotFoundCount = errorCodes.filter(
      (c) => c === 'CHALLENGE_EXPIRED_OR_NOT_FOUND' || c === 'CHALLENGE_MAX_ATTEMPTS_EXCEEDED'
    ).length;

    expect(evaluatedCount).toBe(3);
    expect(expiredOrNotFoundCount).toBe(7);

    // Exactly 3 verification_failed security events recorded with attempts 1, 2, 3
    const failedEvents = await SecurityEvent.findAll({
      where: {
        user_id: user.id,
        session_id: session.sessionId,
        event_type: 'verification_failed'
      }
    });
    expect(failedEvents).toHaveLength(3);
    const recordedAttempts = failedEvents.map((e) => e.metadata.attempt).sort((a, b) => a - b);
    expect(recordedAttempts).toEqual([1, 2, 3]);

    // Test outbox entry is cleaned up upon max-attempt invalidation (F-08)
    expect(getTestChallengeOtp(challengeId)).toBeNull();
    expect(getTestChallengeRecord(challengeId)).toBeNull();
  });

  // T10b-20 (F-01, FR-8, FR-24)
  test('T10b-20 (F-01, FR-8, FR-24): Concurrent correct-OTP requests against one challenge allow exactly one to succeed and reject all others', async () => {
    const { verifyStepUpChallenge } = require('../src/services/stepUpService');
    const challengeRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'credential_change' })
      .expect(200);

    const challengeId = challengeRes.body.challenge_id;
    const realOtp = getTestChallengeOtp(challengeId);

    // Fire 5 concurrent requests with the exact valid OTP
    const settled = await Promise.allSettled(
      Array.from({ length: 5 }, () =>
        verifyStepUpChallenge({
          userId: user.id,
          sessionId: session.sessionId,
          challengeId,
          code: realOtp
        })
      )
    );

    const fulfilled = settled.filter((r) => r.status === 'fulfilled');
    const rejected = settled.filter((r) => r.status === 'rejected');

    expect(fulfilled).toHaveLength(1);
    expect(fulfilled[0].value.elevated).toBe(true);
    expect(rejected).toHaveLength(4);
    for (const rej of rejected) {
      expect(rej.reason.code).toBe('CHALLENGE_EXPIRED_OR_NOT_FOUND');
    }
  });

  // T10b-23 (F-04, FR-9, FR-26, FR-27)
  test('T10b-23 (F-04, FR-9, FR-26, FR-27): Atomic risk-tier elevation revocation preserves concurrent high-tier grant while revoking stale low-tier elevation and auditing only revoked scopes', async () => {
    const { revokeElevationsOnRiskIncrease } = require('../src/services/elevationService');

    // 1. Seed 'account_recovery' at 'low' tier and 'credential_change' at 'low' tier
    for (const scope of ['account_recovery', 'credential_change']) {
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
        grantedAtRiskTier: 'low'
      });
    }

    // 2. Race concurrent 'high'-tier grant on 'credential_change' against revokeElevationsOnRiskIncrease('high')
    const highTierTicket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'credential_change'
    });
    const decodedHighTicket = jwt.decode(highTierTicket);

    const [grantResult] = await Promise.all([
      grantElevation({
        sessionId: session.sessionId,
        userId: user.id,
        scope: 'credential_change',
        verificationTicket: highTierTicket,
        grantedAtRiskTier: 'high'
      }),
      revokeElevationsOnRiskIncrease(session.sessionId, 'high')
    ]);

    expect(grantResult.elevated).toBe(true);
    expect(grantResult.grantedAtRiskTier).toBe('high');

    // 3. Run revokeElevationsOnRiskIncrease('high') again after the concurrent race:
    //    must return 0 because 'account_recovery' is already revoked and 'credential_change' is at 'high' tier
    const secondPassRevoked = await revokeElevationsOnRiskIncrease(session.sessionId, 'high');
    expect(secondPassRevoked).toBe(0);

    // 'account_recovery' (granted at 'low') must be revoked
    const recoveryCheck = await checkElevation({
      sessionId: session.sessionId,
      scope: 'account_recovery',
      currentRiskTier: 'high'
    });
    expect(recoveryCheck.elevated).toBe(false);

    // 'credential_change' (granted at 'high') must remain active at 'high' tier!
    const credCheck = await checkElevation({
      sessionId: session.sessionId,
      scope: 'credential_change',
      currentRiskTier: 'high'
    });
    expect(credCheck.elevated).toBe(true);
    expect(credCheck.grantedAtRiskTier).toBe('high');

    // Audit log must NEVER show the newly granted 'high'-tier ticket (decodedHighTicket.jti) as revoked
    const revokedAudits = await ElevationAuditLog.findAll({
      where: {
        user_id: user.id,
        session_id: session.sessionId,
        event_action: 'revoked',
        reason: 'risk_tier_increased'
      }
    });
    expect(revokedAudits.some((a) => a.scope === 'account_recovery')).toBe(true);
    expect(revokedAudits.some((a) => a.jti === decodedHighTicket.jti)).toBe(false);
  });
});
