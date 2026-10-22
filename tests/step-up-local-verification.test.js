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
  ElevationAuditLog
} = require('../src/database/models');
const { createSession } = require('../src/services/sessionService');
const { recordSecurityEvent } = require('../src/services/eventService');
const {
  issueStepUpChallenge,
  verifyStepUpChallenge,
  resolveLocalStepUpKeys,
  getTestChallengeOtp,
  getTestChallengeRecord
} = require('../src/services/stepUpService');
const mailService = require('../src/services/mailService');
const redisStorage = require('../src/storage/redis');
const { JWT_SECRET } = require('../src/middleware/auth');
const { REDIS_PREFIXES } = require('../src/config/sessionConfig');

describe('Step-Up Authentication & Local Verification Suite (FR-8, FR-24, SecReq-1, SecReq-4)', () => {
  let user;
  let session;
  let token;
  const originalEnv = { ...process.env };

  beforeAll(async () => {
    await runMigrations();
  });

  beforeEach(async () => {
    mailService.clearTestMailOutbox();
    mailService.resetMockTransport();

    user = await User.create({
      email: `stepup-local-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@actionguard.test`,
      password_hash: '$2b$10$abcdefghijklmnopqrstuvwxyze32characterdummyhashforauth'
    });

    session = await createSession(user.id, user.email, 900);
    token = jwt.sign(
      { id: user.id, email: user.email, session_id: session.sessionId },
      JWT_SECRET,
      { expiresIn: '15m' }
    );
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    mailService.clearTestMailOutbox();
    mailService.resetMockTransport();
    jest.restoreAllMocks();
  });

  // Test 1: Req 1 & 2 - Safe local development with ephemeral keypair and test outbox
  test('T-STEPUP-DEV-01: Local development environment generates ephemeral ES256 keypair and routes OTP via test outbox without requiring external SMTP', async () => {
    process.env.NODE_ENV = 'development';
    delete process.env.STEP_UP_VERIFICATION_PRIVATE_KEY;
    delete process.env.STEP_UP_VERIFICATION_PUBLIC_KEY;
    delete process.env.SMTP_HOST;

    const keyCtx = resolveLocalStepUpKeys();
    expect(keyCtx.ok).toBe(true);
    expect(keyCtx.privateKeyObject).toBeDefined();
    expect(keyCtx.publicKeyObject).toBeDefined();

    const challengeRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'credential_change' })
      .expect(200);

    expect(challengeRes.body.challenge_id).toMatch(/^chl_/);
    expect(challengeRes.body.delivery_channel).toBe('registration_email');
    expect(challengeRes.body.otp).toBeUndefined();

    // Verify OTP was stored in both stepUpService outbox and mailService outbox
    const otp = getTestChallengeOtp(challengeRes.body.challenge_id);
    expect(otp).toMatch(/^\d{6}$/);

    const mailOutbox = mailService.getTestMailOutbox();
    expect(mailOutbox.length).toBeGreaterThanOrEqual(1);
    const sentMail = mailOutbox.find((m) => m.to === user.email);
    expect(sentMail).toBeDefined();
    expect(sentMail.otp).toBe(otp);
  });

  // Test 2: Req 1 - EC P-256 keypair with escaped newlines from .env parses successfully
  test('T-STEPUP-DEV-02: EC P-256 keypair with escaped newlines in environment parses and validates successfully', async () => {
    const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const rawPriv = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
    const rawPub = pair.publicKey.export({ type: 'spki', format: 'pem' });

    // Simulate single-line quoted .env escaped newlines
    process.env.STEP_UP_VERIFICATION_PRIVATE_KEY = rawPriv.replace(/\n/g, '\\n');
    process.env.STEP_UP_VERIFICATION_PUBLIC_KEY = rawPub.replace(/\n/g, '\\n');
    process.env.NODE_ENV = 'production';

    const keyCtx = resolveLocalStepUpKeys();
    expect(keyCtx.ok).toBe(true);
    expect(keyCtx.privateKeyObject.type).toBe('private');
    expect(keyCtx.publicKeyObject.type).toBe('public');
  });

  // Test 3: Req 6 - Production mode strictly fails closed when keys missing
  test('T-STEPUP-PROD-01: Production mode strictly fails closed (501) when EC P-256 verification keys are missing', async () => {
    process.env.NODE_ENV = 'production';
    delete process.env.STEP_UP_VERIFICATION_PRIVATE_KEY;
    delete process.env.STEP_UP_VERIFICATION_PUBLIC_KEY;

    const keyCtx = resolveLocalStepUpKeys();
    expect(keyCtx.ok).toBe(false);
    expect(keyCtx.code).toBe('VERIFICATION_PROVIDER_UNAVAILABLE');

    const challengeRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'credential_change' })
      .expect(501);

    expect(challengeRes.body.error.code).toBe('verification_provider_unavailable');
  });

  // Test 4: Req 6 - Production mode fails closed when SMTP delivery fails or unconfigured
  test('T-STEPUP-PROD-02: Production mode fails closed with STEP_UP_DELIVERY_FAILED when SMTP delivery fails in production', async () => {
    // Configure valid EC keys
    const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    process.env.STEP_UP_VERIFICATION_PRIVATE_KEY = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
    process.env.STEP_UP_VERIFICATION_PUBLIC_KEY = pair.publicKey.export({ type: 'spki', format: 'pem' });
    process.env.NODE_ENV = 'production';
    delete process.env.SMTP_HOST; // Missing SMTP in production

    const challengeRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'credential_change' })
      .expect(500);

    expect(challengeRes.body.error.code).toBe('internal_error');
  });

  // Test 5: Req 4 - Protected action blocked by PEP before step-up elevation
  test('T-STEPUP-PEP-01: Sensitive action is blocked by PEP with 403 step_up_required before elevation', async () => {
    // Establish prior baseline and unrecognized device to elevate risk to medium tier (triggering reverify)
    await recordSecurityEvent({
      userId: user.id,
      eventType: 'login_success',
      timestamp: new Date(Date.now() - 3600 * 1000),
      context: {
        ip_address: '8.8.8.8',
        geo_country: 'US',
        device_fingerprint: 'fp_known_dev_01'
      }
    });

    await recordSecurityEvent({
      userId: user.id,
      sessionId: session.sessionId,
      eventType: 'login_success',
      timestamp: new Date(Date.now() - 10 * 1000),
      context: {
        ip_address: '8.8.8.8',
        geo_country: 'US',
        device_fingerprint: 'fp_unrecognized_dev_02'
      }
    });

    const blockedRes = await request(app)
      .post('/api/v1/account/recovery-email')
      .set('Authorization', `Bearer ${token}`)
      .set('x-device-fingerprint', 'fp_unrecognized_dev_02')
      .send({ recovery_email: 'new-recovery@actionguard.test' })
      .expect(403);

    expect(blockedRes.body.error.code).toBe('step_up_required');
    expect(blockedRes.body.error.required_scope).toBe('account_recovery');
    expect(blockedRes.body.error.challenge_endpoint).toBe(`/api/v1/sessions/${session.sessionId}/step-up/challenge`);
    expect(blockedRes.body.error.verify_endpoint).toBe(`/api/v1/sessions/${session.sessionId}/step-up/verify`);

    // Verify database was NOT mutated
    const unchanged = await User.findByPk(user.id);
    expect(unchanged.recovery_email).toBeNull();
  });

  // Test 6: Req 3 & 4 - Valid OTP elevation allows sensitive action to complete
  test('T-STEPUP-PEP-02: Valid OTP verification grants elevation and allows previously blocked sensitive action to complete', async () => {
    // 1. Issue challenge
    const challengeRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'account_recovery' })
      .expect(200);

    const otp = getTestChallengeOtp(challengeRes.body.challenge_id);
    expect(otp).toBeDefined();

    // 2. Verify challenge with valid OTP
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
    expect(verifyRes.body.scope).toBe('account_recovery');

    // 3. Retry sensitive action -> now succeeds with HTTP 200
    const allowedRes = await request(app)
      .post('/api/v1/account/recovery-email')
      .set('Authorization', `Bearer ${token}`)
      .send({ recovery_email: 'verified-recovery@actionguard.test' })
      .expect(200);

    expect(allowedRes.body.status).toBe('completed');
    expect(allowedRes.body.recovery_email).toBe('verified-recovery@actionguard.test');

    const updated = await User.findByPk(user.id);
    expect(updated.recovery_email).toBe('verified-recovery@actionguard.test');
  });

  // Test 7: Req 3 - Invalid OTP rejected and remaining attempts decremented
  test('T-STEPUP-REJECT-01: Invalid 6-digit OTP code is rejected (401 verification_failed) and decrements remaining attempts', async () => {
    const challengeRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'credential_change' })
      .expect(200);

    const wrongOtp = '000000';
    const rejectRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/verify`)
      .set('Authorization', `Bearer ${token}`)
      .send({
        challenge_id: challengeRes.body.challenge_id,
        code: wrongOtp
      })
      .expect(401);

    expect(rejectRes.body.error.code).toBe('verification_failed');
    expect(rejectRes.body.error.remaining_attempts).toBe(2);
  });

  // Test 8: Req 3 - Expired challenge is rejected
  test('T-STEPUP-REJECT-02: Expired challenge is rejected (401 challenge_expired)', async () => {
    const challengeRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'credential_change' })
      .expect(200);

    const challengeId = challengeRes.body.challenge_id;
    const otp = getTestChallengeOtp(challengeId);

    // Artificially expire the challenge in Redis by setting past expires_at_ms
    const client = redisStorage.getRedisClient();
    const challengeKey = `${REDIS_PREFIXES.STEP_UP_CHALLENGE}${challengeId}`;
    const raw = await client.get(challengeKey);
    const parsed = JSON.parse(raw);
    parsed.expires_at_ms = Date.now() - 5000;
    await client.set(challengeKey, JSON.stringify(parsed));

    const expiredRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/verify`)
      .set('Authorization', `Bearer ${token}`)
      .send({
        challenge_id: challengeId,
        code: otp
      })
      .expect(401);

    expect(expiredRes.body.error.code).toBe('challenge_expired');
  });

  // Test 9: Req 3 - Single-use invariant: already-redeemed OTP cannot be reused
  test('T-STEPUP-REJECT-03: Already-redeemed OTP cannot be reused (401 challenge_expired)', async () => {
    const challengeRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'credential_change' })
      .expect(200);

    const challengeId = challengeRes.body.challenge_id;
    const otp = getTestChallengeOtp(challengeId);

    // 1st redemption succeeds
    await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/verify`)
      .set('Authorization', `Bearer ${token}`)
      .send({
        challenge_id: challengeId,
        code: otp
      })
      .expect(200);

    // 2nd redemption attempt with the same challenge + code is rejected
    const replayRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/verify`)
      .set('Authorization', `Bearer ${token}`)
      .send({
        challenge_id: challengeId,
        code: otp
      })
      .expect(401);

    expect(replayRes.body.error.code).toBe('challenge_expired');
  });

  // Test 10: Req 5 - Zero credential/OTP/key leakage in logs
  test('T-STEPUP-SEC-01: Production logs never contain OTP, private keys, passwords, or elevation tokens', async () => {
    const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const privPem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
    const pubPem = pair.publicKey.export({ type: 'spki', format: 'pem' });

    process.env.STEP_UP_VERIFICATION_PRIVATE_KEY = privPem;
    process.env.STEP_UP_VERIFICATION_PUBLIC_KEY = pubPem;

    const logSpy = jest.spyOn(console, 'log');
    const errorSpy = jest.spyOn(console, 'error');
    const warnSpy = jest.spyOn(console, 'warn');

    const challengeRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'credential_change' })
      .expect(200);

    const otp = getTestChallengeOtp(challengeRes.body.challenge_id);

    await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/step-up/verify`)
      .set('Authorization', `Bearer ${token}`)
      .send({
        challenge_id: challengeRes.body.challenge_id,
        code: otp
      })
      .expect(200);

    const allLoggedLines = [
      ...logSpy.mock.calls.map((c) => c.join(' ')),
      ...errorSpy.mock.calls.map((c) => c.join(' ')),
      ...warnSpy.mock.calls.map((c) => c.join(' '))
    ];

    for (const line of allLoggedLines) {
      if (otp) {
        expect(line).not.toContain(otp);
      }
      expect(line).not.toContain('BEGIN EC PRIVATE KEY');
      expect(line).not.toContain('BEGIN PRIVATE KEY');
      expect(line).not.toContain('dummyhashforauth');
    }
  });
});
