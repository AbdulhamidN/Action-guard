'use strict';

const crypto = require('crypto');
const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../src/app');
const { User, Session } = require('../src/database/models');
const {
  createSession,
  invalidateSession,
  terminateAllUserSessions
} = require('../src/services/sessionService');
const {
  grantElevation,
  checkElevation,
  revokeElevation,
  createMockVerificationTicket,
  verifyVerificationTicket,
  ALLOWLISTED_ELEVATION_SCOPES,
  TEST_VERIFICATION_TICKET_SECRET
} = require('../src/services/elevationService');
const { getSession, getRedisClient, executeGrantElevation } = require('../src/storage/redis');
const { JWT_SECRET, authenticateToken, requireElevation } = require('../src/middleware/auth');
const { REDIS_PREFIXES } = require('../src/config/sessionConfig');

describe('Module 10a — Scoped Temporary Elevation & Revocation (FR-8, FR-9 & FR-27)', () => {
  let user;
  let session;
  let token;

  beforeEach(async () => {
    user = await User.create({
      email: `elev-test-${Date.now()}-${Math.random().toString(36).substring(7)}@example.com`,
      password_hash: 'dummyhash'
    });

    session = await createSession(user.id, user.email, 900, null, 28800);

    token = jwt.sign(
      { id: user.id, email: user.email, session_id: session.sessionId },
      JWT_SECRET,
      { expiresIn: '15m' }
    );
  });

  // T9 (FR-8): Missing, fabricated, untrusted, expired, future iat, >60s lifetime, missing claims, disallowed alg, key-type mismatch, or production-unconfigured tickets are rejected
  test('T9 (FR-8): Missing, fabricated, untrusted, expired, >60s lifetime, disallowed alg, or incorrectly bound tickets are rejected', async () => {
    // 1. Missing ticket
    const resNoTicket = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/elevate`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'sensitive_action' })
      .expect(400);
    expect(resNoTicket.body.error.code).toBe('invalid_request');

    // 2. Fabricated / untrusted ticket signed with wrong secret (or normal session JWT_SECRET)
    const sessionSecretTicket = jwt.sign(
      {
        sub: user.id,
        session_id: session.sessionId,
        scope: 'sensitive_action',
        purpose: 'step_up_verification'
      },
      JWT_SECRET,
      { jwtid: 'tkt_wrong_secret', expiresIn: '60s' }
    );
    const resFabricated = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/elevate`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'sensitive_action', verification_ticket: sessionSecretTicket })
      .expect(401);
    expect(resFabricated.body.error.code).toBe('invalid_ticket');

    // 3. Expired ticket & deterministic expiration boundary (F-2)
    const fixedNowMs = 1760000000000;
    const fixedNowSec = Math.floor(fixedNowMs / 1000);
    const boundaryExpiredTicket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'sensitive_action',
      iat: fixedNowSec - 60,
      exp: fixedNowSec
    });
    const boundaryExpiredRes = await verifyVerificationTicket(
      boundaryExpiredTicket,
      user.id,
      session.sessionId,
      'sensitive_action',
      { nowMs: fixedNowMs }
    );
    expect(boundaryExpiredRes.valid).toBe(false);
    expect(boundaryExpiredRes.code).toBe('TICKET_EXPIRED');

    // 4. Exact 60s allowed lifetime boundary vs 61s first rejected lifetime (F-2)
    const exact60sTicket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'sensitive_action',
      iat: fixedNowSec,
      exp: fixedNowSec + 60
    });
    const exact60sRes = await verifyVerificationTicket(
      exact60sTicket,
      user.id,
      session.sessionId,
      'sensitive_action',
      { nowMs: fixedNowMs }
    );
    expect(exact60sRes.valid).toBe(true);

    const rejected61sTicket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'sensitive_action',
      iat: fixedNowSec,
      exp: fixedNowSec + 61
    });
    const rejected61sRes = await verifyVerificationTicket(
      rejected61sTicket,
      user.id,
      session.sessionId,
      'sensitive_action',
      { nowMs: fixedNowMs }
    );
    expect(rejected61sRes.valid).toBe(false);
    expect(rejected61sRes.code).toBe('INVALID_TICKET');

    // 5. Future iat rejection (F-2): ticket issued materially in the future (even with exp - iat <= 60)
    const futureIatTicket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'sensitive_action',
      iat: fixedNowSec + 6, // 1s past the 5s clock-skew allowance
      exp: fixedNowSec + 66
    });
    const futureIatRes = await verifyVerificationTicket(
      futureIatTicket,
      user.id,
      session.sessionId,
      'sensitive_action',
      { nowMs: fixedNowMs, maxClockSkewSeconds: 5 }
    );
    expect(futureIatRes.valid).toBe(false);
    expect(futureIatRes.code).toBe('INVALID_TICKET');

    // 6. Missing exp, missing iat, or missing jti claims (F-2)
    const noExpTicket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'sensitive_action',
      expiresInSeconds: null
    });
    const resNoExp = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/elevate`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'sensitive_action', verification_ticket: noExpTicket })
      .expect(401);
    expect(resNoExp.body.error.code).toBe('invalid_ticket');

    const noIatTicket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'sensitive_action',
      noTimestamp: true,
      exp: fixedNowSec + 30
    });
    const noIatRes = await verifyVerificationTicket(
      noIatTicket,
      user.id,
      session.sessionId,
      'sensitive_action',
      { nowMs: fixedNowMs }
    );
    expect(noIatRes.valid).toBe(false);
    expect(noIatRes.code).toBe('INVALID_TICKET');

    const noJtiTicket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'sensitive_action',
      jti: null
    });
    const noJtiRes = await verifyVerificationTicket(
      noJtiTicket,
      user.id,
      session.sessionId,
      'sensitive_action'
    );
    expect(noJtiRes.valid).toBe(false);
    expect(noJtiRes.code).toBe('INVALID_TICKET');

    // 7. Disallowed algorithm (HS512) and user/scope mismatches
    const hs512Ticket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'sensitive_action',
      algorithm: 'HS512'
    });
    const resBadAlg = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/elevate`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'sensitive_action', verification_ticket: hs512Ticket })
      .expect(401);
    expect(resBadAlg.body.error.code).toBe('invalid_ticket');

    const otherUserTicket = createMockVerificationTicket({
      userId: 'different_user_id',
      sessionId: session.sessionId,
      scope: 'sensitive_action'
    });
    const resUserMismatch = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/elevate`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'sensitive_action', verification_ticket: otherUserTicket })
      .expect(401);
    expect(resUserMismatch.body.error.code).toBe('invalid_ticket');

    const scopeMismatchTicket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'credential_change'
    });
    const resScopeMismatch = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/elevate`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'sensitive_action', verification_ticket: scopeMismatchTicket })
      .expect(401);
    expect(resScopeMismatch.body.error.code).toBe('invalid_ticket');

    // 8. Production & asymmetric key verification (F-1):
    //    - Valid RSA public key accepts RS256, rejects ES256 and HS256 (including key-confusion HMAC)
    //    - Valid EC P-256 public key accepts ES256, rejects RS256 and HS256
    //    - Malformed key or unsupported curve fails closed (INVALID_VERIFICATION_KEY -> 501)
    //    - Missing key in production fails closed (VERIFICATION_PROVIDER_UNAVAILABLE -> 501)
    const rsaPairs = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    const ecP256Pairs = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    const ecP384Pairs = crypto.generateKeyPairSync('ec', {
      namedCurve: 'secp384r1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    const validHs256TestTicket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'sensitive_action'
    });
    const validRs256Ticket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'sensitive_action',
      secret: rsaPairs.privateKey,
      algorithm: 'RS256'
    });
    const validEs256Ticket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'sensitive_action',
      secret: ecP256Pairs.privateKey,
      algorithm: 'ES256'
    });

    const prevNodeEnv = process.env.NODE_ENV;
    const prevPubKey = process.env.STEP_UP_VERIFICATION_PUBLIC_KEY;
    try {
      process.env.NODE_ENV = 'production';

      // (a) Unconfigured provider in production -> 501 verification_provider_unavailable
      delete process.env.STEP_UP_VERIFICATION_PUBLIC_KEY;
      expect(() =>
        createMockVerificationTicket({
          userId: user.id,
          sessionId: session.sessionId,
          scope: 'sensitive_action'
        })
      ).toThrow(/strictly forbidden outside test environment/);

      const resProd501 = await request(app)
        .post(`/api/v1/sessions/${session.sessionId}/elevate`)
        .set('Authorization', `Bearer ${token}`)
        .send({ scope: 'sensitive_action', verification_ticket: validHs256TestTicket })
        .expect(501);
      expect(resProd501.body.error.code).toBe('verification_provider_unavailable');

      // (b) Malformed public key in production -> never becomes HMAC secret, fails closed with 501
      process.env.STEP_UP_VERIFICATION_PUBLIC_KEY = 'malformed_non_pem_secret_value';
      const hmacForgedWithMalformedKey = jwt.sign(
        {
          sub: user.id,
          session_id: session.sessionId,
          scope: 'sensitive_action',
          purpose: 'step_up_verification'
        },
        'malformed_non_pem_secret_value',
        { algorithm: 'HS256', jwtid: 'tkt_forged_hmac', expiresIn: '60s' }
      );
      const malformedKeyRes = await verifyVerificationTicket(
        hmacForgedWithMalformedKey,
        user.id,
        session.sessionId,
        'sensitive_action'
      );
      expect(malformedKeyRes.valid).toBe(false);
      expect(malformedKeyRes.code).toBe('INVALID_VERIFICATION_KEY');

      const resMalformed501 = await request(app)
        .post(`/api/v1/sessions/${session.sessionId}/elevate`)
        .set('Authorization', `Bearer ${token}`)
        .send({ scope: 'sensitive_action', verification_ticket: hmacForgedWithMalformedKey })
        .expect(501);
      expect(resMalformed501.body.error.code).toBe('verification_provider_unavailable');

      // (c) Incompatible EC curve (P-384 instead of P-256) -> fails closed
      process.env.STEP_UP_VERIFICATION_PUBLIC_KEY = ecP384Pairs.publicKey;
      const badCurveRes = await verifyVerificationTicket(
        validEs256Ticket,
        user.id,
        session.sessionId,
        'sensitive_action'
      );
      expect(badCurveRes.valid).toBe(false);
      expect(badCurveRes.code).toBe('INVALID_VERIFICATION_KEY');

      // (d) Valid RSA public key configured in production -> accepts RS256, rejects HS256 & ES256
      process.env.STEP_UP_VERIFICATION_PUBLIC_KEY = rsaPairs.publicKey;
      const rsaAcceptRes = await verifyVerificationTicket(
        validRs256Ticket,
        user.id,
        session.sessionId,
        'sensitive_action'
      );
      expect(rsaAcceptRes.valid).toBe(true);

      const rsaRejectHs256 = await verifyVerificationTicket(
        validHs256TestTicket,
        user.id,
        session.sessionId,
        'sensitive_action'
      );
      expect(rsaRejectHs256.valid).toBe(false);
      expect(rsaRejectHs256.code).toBe('INVALID_TICKET');

      const rsaRejectEs256 = await verifyVerificationTicket(
        validEs256Ticket,
        user.id,
        session.sessionId,
        'sensitive_action'
      );
      expect(rsaRejectEs256.valid).toBe(false);
      expect(rsaRejectEs256.code).toBe('INVALID_TICKET');

      // (e) Valid EC P-256 public key configured in production -> accepts ES256, rejects RS256 & HS256
      process.env.STEP_UP_VERIFICATION_PUBLIC_KEY = ecP256Pairs.publicKey;
      const ecAcceptRes = await verifyVerificationTicket(
        validEs256Ticket,
        user.id,
        session.sessionId,
        'sensitive_action'
      );
      expect(ecAcceptRes.valid).toBe(true);

      const ecRejectRs256 = await verifyVerificationTicket(
        validRs256Ticket,
        user.id,
        session.sessionId,
        'sensitive_action'
      );
      expect(ecRejectRs256.valid).toBe(false);
      expect(ecRejectRs256.code).toBe('INVALID_TICKET');
    } finally {
      process.env.NODE_ENV = prevNodeEnv;
      if (prevPubKey === undefined) {
        delete process.env.STEP_UP_VERIFICATION_PUBLIC_KEY;
      } else {
        process.env.STEP_UP_VERIFICATION_PUBLIC_KEY = prevPubKey;
      }
    }
  });

  // T10 (FR-8, FR-25): Valid test-issued ticket grants only requested scope, clamps duration, and sets index TTL
  test('T10 (FR-8, FR-25): A valid test-issued ticket grants elevation, clamps duration to session lifetime, and sets Set index TTL', async () => {
    const validTicket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'sensitive_action'
    });

    const res = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/elevate`)
      .set('Authorization', `Bearer ${token}`)
      .send({
        scope: 'sensitive_action',
        verification_ticket: validTicket,
        duration_seconds: 300
      })
      .expect(200);

    expect(res.body.elevated).toBe(true);
    expect(res.body.scope).toBe('sensitive_action');
    expect(res.body.remainingSeconds).toBe(300);

    // Verify Set index key has a bounded TTL in Redis so it cannot leak indefinitely
    const client = getRedisClient();
    const indexTtl = await client.ttl(`${REDIS_PREFIXES.SESSION_ELEVATIONS_INDEX}${session.sessionId}`);
    expect(indexTtl).toBeGreaterThan(0);

    // Verify GET endpoint confirms elevated status
    const statusRes = await request(app)
      .get(`/api/v1/sessions/${session.sessionId}/elevate/sensitive_action`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(statusRes.body.elevated).toBe(true);
    expect(statusRes.body.scope).toBe('sensitive_action');

    // Verify duration clamping to parent session remaining lifetime
    const shortSession = await createSession(user.id, user.email, 900, null, 60); // 60s max session lifetime
    const shortTicket = createMockVerificationTicket({
      userId: user.id,
      sessionId: shortSession.sessionId,
      scope: 'sensitive_action'
    });
    const clampedGrant = await grantElevation({
      sessionId: shortSession.sessionId,
      userId: user.id,
      scope: 'sensitive_action',
      verificationTicket: shortTicket,
      durationSeconds: 600, // requested 10m
      maxSessionExpiresAt: shortSession.maxExpiresAt.getTime()
    });
    expect(clampedGrant.remainingSeconds).toBeLessThanOrEqual(60);
  });

  // T11 (FR-8): Single-use ticket cannot be replayed under concurrent or subsequent attempts, and failed parent-session check does not burn ticket
  test('T11 (FR-8): A verification ticket cannot be replayed under concurrent Promise.all or subsequent attempts', async () => {
    const client = getRedisClient();

    // 1. Verify atomic parent-session check in GRANT_ELEVATION_LUA does NOT consume ticket if parent session is missing/expired (F-3)
    const unburnedJti = `tkt_unburned_${crypto.randomUUID()}`;
    const luaMissingParentRes = await executeGrantElevation({
      sessionKey: `${REDIS_PREFIXES.SESSION}sess_missing_parent`,
      claimKey: `${REDIS_PREFIXES.TICKET_CLAIM}${unburnedJti}`,
      indexKey: `${REDIS_PREFIXES.SESSION_ELEVATIONS_INDEX}sess_missing_parent`,
      elevationKey: `${REDIS_PREFIXES.ELEVATION}sess_missing_parent:sensitive_action`,
      nowMs: Date.now(),
      userId: user.id,
      claimTtlSec: 120,
      scope: 'sensitive_action',
      payloadJson: '{}',
      elevationTtlSec: 300,
      indexTtlSec: 300
    });
    expect(Number(luaMissingParentRes[0])).toBe(-1);
    // Ticket claim key must NOT have been set when parent session check failed
    expect(await client.get(`${REDIS_PREFIXES.TICKET_CLAIM}${unburnedJti}`)).toBeNull();
    expect(await client.get(`${REDIS_PREFIXES.ELEVATION}sess_missing_parent:sensitive_action`)).toBeNull();

    // 2. Concurrent Promise.allSettled replay test with valid active parent session
    const ticket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'sensitive_action'
    });

    const results = await Promise.allSettled([
      grantElevation({
        sessionId: session.sessionId,
        userId: user.id,
        scope: 'sensitive_action',
        verificationTicket: ticket
      }),
      grantElevation({
        sessionId: session.sessionId,
        userId: user.id,
        scope: 'sensitive_action',
        verificationTicket: ticket
      })
    ]);

    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    const rejected = results.filter((r) => r.status === 'rejected');

    expect(fulfilled.length).toBe(1);
    expect(rejected.length).toBe(1);
    expect(rejected[0].reason.code).toBe('VERIFICATION_TICKET_ALREADY_USED');

    // 3. Subsequent HTTP replay attempt also fails with 409
    const replayRes = await request(app)
      .post(`/api/v1/sessions/${session.sessionId}/elevate`)
      .set('Authorization', `Bearer ${token}`)
      .send({ scope: 'sensitive_action', verification_ticket: ticket })
      .expect(409);
    expect(replayRes.body.error.code).toBe('ticket_already_used');
  });

  // T12 (FR-8): Ungranted scope remains denied and requireElevation middleware enforces scope isolation
  test('T12 (FR-8): An ungranted scope remains denied and requireElevation(scope) middleware enforces exact scope', async () => {
    const ticket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'sensitive_action'
    });

    // Build isolated Express test app wired with authenticateToken + requireElevation
    const testApp = express();
    testApp.use(express.json());
    testApp.post(
      '/test-sensitive',
      authenticateToken,
      requireElevation('sensitive_action'),
      (req, res) => res.status(200).json({ ok: true, elevation: req.elevation })
    );
    testApp.post(
      '/test-admin',
      authenticateToken,
      requireElevation('admin_action'),
      (req, res) => res.status(200).json({ ok: true })
    );

    // 1. Before elevation grant -> 403 elevation_required
    const deniedBefore = await request(testApp)
      .post('/test-sensitive')
      .set('Authorization', `Bearer ${token}`)
      .expect(403);
    expect(deniedBefore.body.error.code).toBe('elevation_required');

    // 2. Grant elevation for 'sensitive_action'
    await grantElevation({
      sessionId: session.sessionId,
      userId: user.id,
      scope: 'sensitive_action',
      verificationTicket: ticket
    });

    // 3. Matching scope route succeeds (200)
    const allowedRes = await request(testApp)
      .post('/test-sensitive')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(allowedRes.body.ok).toBe(true);
    expect(allowedRes.body.elevation.scope).toBe('sensitive_action');

    // 4. Different scope ('admin_action') remains denied (403)
    const deniedOtherScope = await request(testApp)
      .post('/test-admin')
      .set('Authorization', `Bearer ${token}`)
      .expect(403);
    expect(deniedOtherScope.body.error.code).toBe('elevation_required');
  });

  // T13 (FR-9): Elevation expires naturally at its expiration boundary while base session remains active
  test('T13 (FR-9): Elevation expires naturally at its expiration boundary while the base session remains active', async () => {
    const ticket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'sensitive_action'
    });

    const grantRes = await grantElevation({
      sessionId: session.sessionId,
      userId: user.id,
      scope: 'sensitive_action',
      verificationTicket: ticket,
      durationSeconds: 60
    });

    const expiresAtMs = new Date(grantRes.expiresAt).getTime();

    // 1. Check 1ms before expiration -> still elevated
    const beforeExpiryCheck = await checkElevation({
      sessionId: session.sessionId,
      scope: 'sensitive_action',
      nowMs: expiresAtMs - 1
    });
    expect(beforeExpiryCheck.elevated).toBe(true);

    // 2. Check at exact expiration boundary (nowMs === expiresAtMs) -> expired and cleaned up!
    const atExpiryCheck = await checkElevation({
      sessionId: session.sessionId,
      scope: 'sensitive_action',
      nowMs: expiresAtMs
    });
    expect(atExpiryCheck.elevated).toBe(false);

    // Confirm Redis key and index entry were automatically cleaned up upon boundary expiration
    const client = getRedisClient();
    expect(await client.get(`${REDIS_PREFIXES.ELEVATION}${session.sessionId}:sensitive_action`)).toBeNull();
    expect(await client.smembers(`${REDIS_PREFIXES.SESSION_ELEVATIONS_INDEX}${session.sessionId}`)).toEqual([]);

    // 3. Base session remains completely active and operational
    const activeSession = await getSession(session.sessionId);
    expect(activeSession).not.toBeNull();
    expect(activeSession.is_active).toBe(true);

    await request(app)
      .get('/api/v1/me')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
  });

  // T14 (FR-8): Redis failure, forged parentSession, or missing/expired parent session returns elevated: false (fail-closed)
  test('T14 (FR-8): Redis exception, invalid parentSession, or missing parent session fails closed with elevated: false', async () => {
    // 1. Missing parent session
    const statusMissingSession = await checkElevation({
      sessionId: 'sess_non_existent',
      scope: 'sensitive_action'
    });
    expect(statusMissingSession.elevated).toBe(false);

    // 2. Grant valid elevation
    const ticket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'sensitive_action'
    });
    await grantElevation({
      sessionId: session.sessionId,
      userId: user.id,
      scope: 'sensitive_action',
      verificationTicket: ticket
    });

    // 3. Caller supplies untrusted/inactive or mismatched parentSession -> fails closed
    const inactiveParentCheck = await checkElevation({
      sessionId: session.sessionId,
      scope: 'sensitive_action',
      parentSession: { session_id: session.sessionId, user_id: user.id, is_active: false }
    });
    expect(inactiveParentCheck.elevated).toBe(false);

    const wrongUserParentCheck = await checkElevation({
      sessionId: session.sessionId,
      scope: 'sensitive_action',
      parentSession: { session_id: session.sessionId, user_id: 'other_user', is_active: true }
    });
    expect(wrongUserParentCheck.elevated).toBe(false);

    // 4. Inject actual Redis exception during checkElevation -> fails closed without throwing
    const client = getRedisClient();
    const originalGet = client.get.bind(client);
    client.get = jest.fn().mockRejectedValue(new Error('Simulated Redis read failure'));
    try {
      const redisFailureCheck = await checkElevation({
        sessionId: session.sessionId,
        scope: 'sensitive_action',
        parentSession: { session_id: session.sessionId, user_id: user.id, is_active: true }
      });
      expect(redisFailureCheck.elevated).toBe(false);
    } finally {
      client.get = originalGet;
    }

    // 5. Invalidate parent session -> subsequent elevation check fails closed
    await invalidateSession(session.sessionId);
    const statusAfterSessionRevocation = await checkElevation({
      sessionId: session.sessionId,
      scope: 'sensitive_action'
    });
    expect(statusAfterSessionRevocation.elevated).toBe(false);
  });

  // T15 (FR-27): Logout revokes all elevations without wildcard key scans
  test('T15 (FR-27): Logout revokes all elevations via deterministic Set index without wildcard scans', async () => {
    const ticket1 = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'sensitive_action'
    });
    const ticket2 = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'export_data'
    });

    await grantElevation({
      sessionId: session.sessionId,
      userId: user.id,
      scope: 'sensitive_action',
      verificationTicket: ticket1
    });

    await grantElevation({
      sessionId: session.sessionId,
      userId: user.id,
      scope: 'export_data',
      verificationTicket: ticket2
    });

    expect((await checkElevation({ sessionId: session.sessionId, scope: 'sensitive_action' })).elevated).toBe(true);
    expect((await checkElevation({ sessionId: session.sessionId, scope: 'export_data' })).elevated).toBe(true);

    // User logs out via POST /auth/logout
    await request(app)
      .post('/api/v1/auth/logout')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    // Confirm session and both elevations are purged in Redis
    const client = getRedisClient();
    const elev1 = await client.get(`${REDIS_PREFIXES.ELEVATION}${session.sessionId}:sensitive_action`);
    const elev2 = await client.get(`${REDIS_PREFIXES.ELEVATION}${session.sessionId}:export_data`);
    const index = await client.smembers(`${REDIS_PREFIXES.SESSION_ELEVATIONS_INDEX}${session.sessionId}`);

    expect(elev1).toBeNull();
    expect(elev2).toBeNull();
    expect(index.length).toBe(0);
  });

  // T16 (FR-27): Credential changes revoke sessions and elevations across devices
  test('T16 (FR-27): Credential changes / bulk termination revokes all sessions and elevations across devices', async () => {
    const session2 = await createSession(user.id, user.email, 900, { device_id: 'dev_mobile' }, 28800);

    const ticket1 = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'credential_change'
    });
    const ticket2 = createMockVerificationTicket({
      userId: user.id,
      sessionId: session2.sessionId,
      scope: 'credential_change'
    });

    await grantElevation({
      sessionId: session.sessionId,
      userId: user.id,
      scope: 'credential_change',
      verificationTicket: ticket1
    });
    await grantElevation({
      sessionId: session2.sessionId,
      userId: user.id,
      scope: 'credential_change',
      verificationTicket: ticket2
    });

    const termRes = await terminateAllUserSessions(user.id, 'password_change');
    expect(termRes.terminatedCount).toBeGreaterThanOrEqual(2);

    expect(await getSession(session.sessionId)).toBeNull();
    expect(await getSession(session2.sessionId)).toBeNull();

    const activeSessionsInDb = await Session.findAll({
      where: { user_id: user.id, is_active: true }
    });
    expect(activeSessionsInDb.length).toBe(0);

    expect((await checkElevation({ sessionId: session.sessionId, scope: 'credential_change' })).elevated).toBe(false);
    expect((await checkElevation({ sessionId: session2.sessionId, scope: 'credential_change' })).elevated).toBe(false);
  });
});
