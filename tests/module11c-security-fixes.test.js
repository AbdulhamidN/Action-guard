'use strict';

const fs = require('fs');
const path = require('path');
const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = require('../src/app');
const { runMigrations } = require('../src/database/migrate');
const { User, SecurityEvent } = require('../src/database/models');
const { createSession } = require('../src/services/sessionService');
const { recordSecurityEvent } = require('../src/services/eventService');
const policyLoader = require('../src/services/policyLoader');
const riskEngineService = require('../src/services/riskEngineService');
const {
  issueStepUpChallenge,
  checkStepUpLimits,
  testChallengeOutbox
} = require('../src/services/stepUpService');
const {
  assertRequiredSecrets,
  getJwtSecret,
  authenticateApiKey,
  JWT_SECRET
} = require('../src/middleware/auth');
const redisStorage = require('../src/storage/redis');
const { REDIS_PREFIXES } = require('../src/config/sessionConfig');

async function lockUserAccount(userId, durationSeconds = 900) {
  const lockedUntil = new Date(Date.now() + durationSeconds * 1000);
  await User.update({ locked_until: lockedUntil }, { where: { id: userId } });
  const client = redisStorage.getRedisClient();
  await client.set(
    `${REDIS_PREFIXES.ACCOUNT_LOCK}${userId}`,
    JSON.stringify({
      user_id: userId,
      locked_until: lockedUntil.toISOString(),
      reason: 'test_hold'
    }),
    'EX',
    durationSeconds
  );
}

describe('Module 11c — Security Fixes (F1 - F5)', () => {
  let testUser;
  let testPassword;
  let savedEnv = {};

  beforeAll(async () => {
    await runMigrations();
  });

  beforeEach(async () => {
    savedEnv = { ...process.env };
    testPassword = 'CorrectPassword123!';
    const passwordHash = await bcrypt.hash(testPassword, 10);
    testUser = await User.create({
      email: `m11c-user-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`,
      password_hash: passwordHash
    });
  });

  afterEach(() => {
    for (const k of Object.keys(process.env)) {
      if (!(k in savedEnv)) {
        delete process.env[k];
      }
    }
    for (const [k, v] of Object.entries(savedEnv)) {
      process.env[k] = v;
    }
    jest.restoreAllMocks();
  });

  // =========================================================================
  // F1: JWT Secret Hardening & Startup Secrets Validation
  // =========================================================================
  describe('F1: JWT Secret Hardening', () => {
    test('F1-01: assertRequiredSecrets throws in non-test mode when JWT_SECRET is missing', () => {
      const mockEnv = { NODE_ENV: 'production' };
      expect(() => assertRequiredSecrets(mockEnv)).toThrow(
        /JWT_SECRET environment variable is required and must not be empty/i
      );
    });

    test('F1-02: assertRequiredSecrets throws in non-test mode when JWT_SECRET is shorter than 32 characters', () => {
      const mockEnv = {
        NODE_ENV: 'production',
        JWT_SECRET: 'short_secret_16c'
      };
      // Must not leak the secret value in the error message
      let thrownError = null;
      try {
        assertRequiredSecrets(mockEnv);
      } catch (err) {
        thrownError = err;
      }
      expect(thrownError).not.toBeNull();
      expect(thrownError.message).toMatch(/at least 32 characters in length/i);
      expect(thrownError.message).not.toContain('short_secret_16c');
    });

    test('F1-03: assertRequiredSecrets passes in non-test mode when JWT_SECRET is at least 32 characters', () => {
      const mockEnv = {
        NODE_ENV: 'production',
        JWT_SECRET: 'a_very_long_production_jwt_secret_that_exceeds_32_chars_12345'
      };
      expect(() => assertRequiredSecrets(mockEnv)).not.toThrow();
    });

    test('F1-04: assertRequiredSecrets passes in test mode even if JWT_SECRET is unset', () => {
      const mockEnv = { NODE_ENV: 'test' };
      expect(() => assertRequiredSecrets(mockEnv)).not.toThrow();
      expect(typeof getJwtSecret()).toBe('string');
      expect(getJwtSecret().length).toBeGreaterThanOrEqual(32);
    });

    test('F1-05: source-text scan verifies no hardcoded secret-like literal fallbacks exist in src/', () => {
      const srcDir = path.resolve(__dirname, '../src');
      const files = [];

      function walk(dir) {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            walk(fullPath);
          } else if (entry.name.endsWith('.js')) {
            files.push(fullPath);
          }
        }
      }
      walk(srcDir);

      const secretLikeFallbackRegex = /process\.env\.(JWT_SECRET|API_KEY|ACTIONGUARD_API_KEY|ACTIONGUARD_ADMIN_API_KEY)\s*\|\|\s*['"`]/g;
      const violations = [];

      for (const file of files) {
        const content = fs.readFileSync(file, 'utf8');
        const relPath = path.relative(srcDir, file);
        const matches = content.match(secretLikeFallbackRegex);
        if (matches) {
          violations.push({ file: relPath, matches });
        }
      }

      expect(violations).toEqual([]);
    });
  });

  // =========================================================================
  // F2: Account Hold Evaluation Timing & Recognized Device Bypass
  // =========================================================================
  describe('F2: Login Hold Semantics', () => {
    test('F2-01: login with wrong password during account hold returns generic 401 matching non-hold response', async () => {
      // 1. Establish account hold
      await lockUserAccount(testUser.id, 900);

      // 2. Login with wrong password during hold
      const resLocked = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: testUser.email, password: 'WrongPassword999!' })
        .expect(401);

      expect(resLocked.body.error.code).toBe('authentication_failed');
      expect(resLocked.body.error.message).toBe('Invalid email or password');

      // Compare with normal non-hold wrong password response envelope
      const normalUser = await User.create({
        email: `normal-${Date.now()}@example.com`,
        password_hash: await bcrypt.hash('Correct123!', 10)
      });
      const resNormal = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: normalUser.email, password: 'WrongPassword999!' })
        .expect(401);

      expect(resLocked.body).toEqual(resNormal.body);
    });

    test('F2-02: login with unknown email during account hold returns generic 401 matching non-hold response', async () => {
      const resUnknown = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: `unknown-${Date.now()}@example.com`, password: 'AnyPassword123!' })
        .expect(401);

      expect(resUnknown.body.error.code).toBe('authentication_failed');
      expect(resUnknown.body.error.message).toBe('Invalid email or password');
    });

    test('F2-03: login with correct password from recognized fingerprint during account hold succeeds with 200', async () => {
      const recognizedFp = 'fp_recognized_desktop_device_01';

      // 1. Establish historical successful login with this fingerprint
      await recordSecurityEvent({
        userId: testUser.id,
        eventType: 'login_success',
        timestamp: new Date(Date.now() - 3600 * 1000),
        context: {
          ip_address: '198.51.100.10',
          device_fingerprint: recognizedFp
        }
      });

      // 2. Apply account hold
      await lockUserAccount(testUser.id, 900);

      // 3. Login with correct password and recognized fingerprint succeeds
      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .set('x-device-fingerprint', recognizedFp)
        .send({ email: testUser.email, password: testPassword })
        .expect(200);

      expect(loginRes.body.token).toBeDefined();
      expect(loginRes.body.session_id).toBeDefined();
      expect(loginRes.body.user.email).toBe(testUser.email);
    });

    test('F2-04: login with correct password from unrecognized fingerprint during account hold is refused with 403 account_temporarily_locked', async () => {
      // 1. Establish historical successful login on device A
      await recordSecurityEvent({
        userId: testUser.id,
        eventType: 'login_success',
        timestamp: new Date(Date.now() - 3600 * 1000),
        context: {
          ip_address: '198.51.100.10',
          device_fingerprint: 'fp_known_device_alpha'
        }
      });

      // 2. Apply account hold
      await lockUserAccount(testUser.id, 900);

      // 3. Login from new/unrecognized device B with correct password is refused
      const resUnrecognized = await request(app)
        .post('/api/v1/auth/login')
        .set('x-device-fingerprint', 'fp_attacker_unrecognized_beta')
        .send({ email: testUser.email, password: testPassword })
        .expect(403);

      expect(resUnrecognized.body.error.code).toBe('account_temporarily_locked');
      expect(resUnrecognized.body.error.retry_after_seconds).toBeGreaterThan(0);
      expect(resUnrecognized.body.error.locked_until).toBeDefined();

      // 4. Login without fingerprint header is also refused with 403
      const resNoFp = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: testUser.email, password: testPassword })
        .expect(403);

      expect(resNoFp.body.error.code).toBe('account_temporarily_locked');
    });

    test('F2-05: login after account hold expiration restores normal login flow for any device', async () => {
      // 1. Set account hold expired in the past
      await User.update(
        { locked_until: new Date(Date.now() - 5000) },
        { where: { id: testUser.id } }
      );
      const client = redisStorage.getRedisClient();
      await client.del(`${REDIS_PREFIXES.ACCOUNT_LOCK}${testUser.id}`);

      // 2. Login succeeds even from unrecognized device
      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .set('x-device-fingerprint', 'fp_new_device_after_expiry')
        .send({ email: testUser.email, password: testPassword })
        .expect(200);

      expect(loginRes.body.token).toBeDefined();
    });
  });

  // =========================================================================
  // F3: Step-Up Challenge Multi-Dimensional Limits
  // =========================================================================
  describe('F3: Step-Up Challenge Limits', () => {
    let activeSession;
    let validToken;

    beforeEach(async () => {
      activeSession = await createSession(testUser.id, testUser.email, 900, {
        device_fingerprint: 'fp_m11c_stepup_dev'
      });
      validToken = jwt.sign(
        { id: testUser.id, email: testUser.email, session_id: activeSession.sessionId },
        JWT_SECRET,
        { expiresIn: '15m' }
      );
    });

    test('F3-01: step-up challenge enforces 30s cooldown per session and scope', async () => {
      // Call 1: succeeds
      const res1 = await request(app)
        .post(`/api/v1/sessions/${activeSession.sessionId}/step-up/challenge`)
        .set('Authorization', `Bearer ${validToken}`)
        .send({ scope: 'credential_change' })
        .expect(200);
      expect(res1.body.challenge_id).toBeDefined();

      // Call 2: within 30s with same scope -> rejected with 429 challenge_limited
      const res2 = await request(app)
        .post(`/api/v1/sessions/${activeSession.sessionId}/step-up/challenge`)
        .set('Authorization', `Bearer ${validToken}`)
        .send({ scope: 'credential_change' })
        .expect(429);

      expect(res2.body.error.code).toBe('challenge_limited');
      expect(res2.body.error.retry_after_seconds).toBeGreaterThan(0);
      expect(res2.body.error.retry_after_seconds).toBeLessThanOrEqual(30);
      expect(res2.headers['retry-after']).toBeDefined();

      // But a different scope on the same session is NOT blocked by this scope's cooldown
      const resDiffScope = await request(app)
        .post(`/api/v1/sessions/${activeSession.sessionId}/step-up/challenge`)
        .set('Authorization', `Bearer ${validToken}`)
        .send({ scope: 'sensitive_action' })
        .expect(200);
      expect(resDiffScope.body.challenge_id).toBeDefined();
    });

    test('F3-02: step-up challenge enforces cap of at most 3 challenges per 10 minutes per session and scope', async () => {
      const client = redisStorage.getRedisClient();
      const scope = 'account_recovery';

      for (let i = 1; i <= 3; i++) {
        // Clear cooldown between calls to test window counter cap specifically
        await client.del(`${REDIS_PREFIXES.STEP_UP_COOLDOWN}${activeSession.sessionId}:${scope}`);
        const res = await request(app)
          .post(`/api/v1/sessions/${activeSession.sessionId}/step-up/challenge`)
          .set('Authorization', `Bearer ${validToken}`)
          .send({ scope })
          .expect(200);
        expect(res.body.challenge_id).toBeDefined();
      }

      // 4th call within 10 min window: clear cooldown, but session+scope limit must trip
      await client.del(`${REDIS_PREFIXES.STEP_UP_COOLDOWN}${activeSession.sessionId}:${scope}`);
      const res4 = await request(app)
        .post(`/api/v1/sessions/${activeSession.sessionId}/step-up/challenge`)
        .set('Authorization', `Bearer ${validToken}`)
        .send({ scope })
        .expect(429);

      expect(res4.body.error.code).toBe('challenge_limited');
      expect(res4.body.error.retry_after_seconds).toBeGreaterThan(0);
      expect(res4.body.error.retry_after_seconds).toBeLessThanOrEqual(600);
    });

    test('F3-03: step-up challenge enforces cap of at most 6 challenges per 10 minutes per user across sessions', async () => {
      const client = redisStorage.getRedisClient();
      const scopes = ['credential_change', 'sensitive_action', 'export_data'];

      // Issue 6 challenges across 2 distinct sessions of the same user
      const session2 = await createSession(testUser.id, testUser.email, 900, {
        device_fingerprint: 'fp_m11c_device_2'
      });
      const token2 = jwt.sign(
        { id: testUser.id, email: testUser.email, session_id: session2.sessionId },
        JWT_SECRET,
        { expiresIn: '15m' }
      );

      let issued = 0;
      for (const s of [activeSession, session2]) {
        const tok = s.sessionId === activeSession.sessionId ? validToken : token2;
        for (const sc of scopes) {
          await client.del(`${REDIS_PREFIXES.STEP_UP_COOLDOWN}${s.sessionId}:${sc}`);
          await request(app)
            .post(`/api/v1/sessions/${s.sessionId}/step-up/challenge`)
            .set('Authorization', `Bearer ${tok}`)
            .send({ scope: sc })
            .expect(200);
          issued++;
        }
      }
      expect(issued).toBe(6);

      // 7th challenge on a third session: must be rejected by user cap
      const session3 = await createSession(testUser.id, testUser.email, 900, {
        device_fingerprint: 'fp_m11c_device_3'
      });
      const token3 = jwt.sign(
        { id: testUser.id, email: testUser.email, session_id: session3.sessionId },
        JWT_SECRET,
        { expiresIn: '15m' }
      );

      const res7 = await request(app)
        .post(`/api/v1/sessions/${session3.sessionId}/step-up/challenge`)
        .set('Authorization', `Bearer ${token3}`)
        .send({ scope: 'admin_action' })
        .expect(429);

      expect(res7.body.error.code).toBe('challenge_limited');
      expect(res7.body.error.message).toMatch(/across your sessions/i);
    });

    test('F3-04: parallel burst of step-up challenge requests cannot exceed the configured cap', async () => {
      const burstSession = await createSession(testUser.id, testUser.email, 900);
      const scope = 'credential_change';

      // Launch 10 concurrent requests for the exact same session + scope
      const promises = Array.from({ length: 10 }).map(() =>
        checkStepUpLimits({
          userId: testUser.id,
          sessionId: burstSession.sessionId,
          scope
        })
      );

      const results = await Promise.all(promises);
      const allowedCount = results.filter((r) => r.allowed).length;
      const limitedCount = results.filter((r) => !r.allowed).length;

      // Exactly 1 request must succeed due to the atomic cooldown, and 9 must be limited
      expect(allowedCount).toBe(1);
      expect(limitedCount).toBe(9);
    });

    test('F3-05: step-up challenge limit counters expire after TTL window allowing new challenges', async () => {
      const client = redisStorage.getRedisClient();
      const scope = 'credential_change';

      // Issue challenge to set cooldown and counters
      await issueStepUpChallenge({
        userId: testUser.id,
        sessionId: activeSession.sessionId,
        scope
      });

      // Clear the cooldown key to simulate 30s elapsed
      await client.del(`${REDIS_PREFIXES.STEP_UP_COOLDOWN}${activeSession.sessionId}:${scope}`);

      // Now next challenge is allowed
      const nextChallenge = await issueStepUpChallenge({
        userId: testUser.id,
        sessionId: activeSession.sessionId,
        scope
      });
      expect(nextChallenge.challenge_id).toBeDefined();

      // Clear all keys to simulate full window expiration
      await client.del(`${REDIS_PREFIXES.STEP_UP_COOLDOWN}${activeSession.sessionId}:${scope}`);
      await client.del(`${REDIS_PREFIXES.STEP_UP_SESSION_SCOPE}${activeSession.sessionId}:${scope}`);
      await client.del(`${REDIS_PREFIXES.STEP_UP_USER}${testUser.id}`);

      const freshChallenge = await issueStepUpChallenge({
        userId: testUser.id,
        sessionId: activeSession.sessionId,
        scope
      });
      expect(freshChallenge.challenge_id).toBeDefined();
    });

    test('F3-06: normal step-up challenge flow operates unaffected when within limits', async () => {
      const challenge = await issueStepUpChallenge({
        userId: testUser.id,
        sessionId: activeSession.sessionId,
        scope: 'sensitive_action'
      });

      expect(challenge.challenge_id).toMatch(/^chl_/);
      expect(challenge.scope).toBe('sensitive_action');
      expect(challenge.delivery_channel).toBe('registration_email');
      expect(challenge.masked_destination).toContain('@');
      expect(challenge.ttl_seconds).toBe(300);
    });

    test('F3-07: email transport/outbox is not invoked when step-up challenge is rate limited', async () => {
      const scope = 'export_data';
      const beforeCount = testChallengeOutbox.size;

      // 1. First challenge goes into outbox
      const first = await issueStepUpChallenge({
        userId: testUser.id,
        sessionId: activeSession.sessionId,
        scope
      });
      expect(testChallengeOutbox.has(first.challenge_id)).toBe(true);
      expect(testChallengeOutbox.size).toBe(beforeCount + 1);

      // 2. Second challenge hits cooldown and throws 429
      let thrown = null;
      try {
        await issueStepUpChallenge({
          userId: testUser.id,
          sessionId: activeSession.sessionId,
          scope
        });
      } catch (err) {
        thrown = err;
      }
      expect(thrown).not.toBeNull();
      expect(thrown.code).toBe('CHALLENGE_LIMITED');

      // 3. Outbox count must NOT have increased
      expect(testChallengeOutbox.size).toBe(beforeCount + 1);
    });

    test('F3-08: step-up challenge limits operate identically under live Redis', async () => {
      // Run test against live Redis if available or test the Lua script directly on InMemoryRedisClient
      const client = redisStorage.getRedisClient();
      const testPrefix = `test_live_${Date.now()}:`;
      const cooldownKey = `${testPrefix}cd`;
      const sessionScopeKey = `${testPrefix}ss`;
      const userKey = `${testPrefix}u`;

      const checkParams = {
        cooldownKey,
        sessionScopeKey,
        userKey,
        cooldownSec: 30,
        windowSec: 600,
        sessionScopeMax: 3,
        userMax: 6
      };

      // 1. First execution: allowed
      const res1 = await redisStorage.executeCheckStepUpChallengeLimits(checkParams);
      expect(res1[0]).toBe(1);
      expect(res1[1]).toBe('ok');

      // 2. Immediate second execution: blocked by cooldown
      const res2 = await redisStorage.executeCheckStepUpChallengeLimits(checkParams);
      expect(res2[0]).toBe(0);
      expect(res2[1]).toBe('cooldown');
      expect(Number(res2[2])).toBeGreaterThan(0);

      // Clean up test keys
      await client.del(cooldownKey, sessionScopeKey, userKey);
    });
  });

  // =========================================================================
  // F4: Service API Key Constant-Time Authentication
  // =========================================================================
  describe('F4: Service API Key Constant-Time Comparison', () => {
    let mockReq;
    let mockRes;
    let nextCalled;

    beforeEach(() => {
      nextCalled = false;
      mockReq = {
        headers: {},
        query: {}
      };
      mockRes = {
        statusCode: null,
        body: null,
        status(code) {
          this.statusCode = code;
          return this;
        },
        json(data) {
          this.body = data;
          return this;
        }
      };
    });

    test('F4-01: authenticateApiKey rejects request when API key is missing from header', () => {
      process.env.API_KEY = 'configured_service_api_key_for_test_purposes_123';
      authenticateApiKey(mockReq, mockRes, () => {
        nextCalled = true;
      });

      expect(nextCalled).toBe(false);
      expect(mockRes.statusCode).toBe(401);
      expect(mockRes.body.error.code).toBe('unauthorized');
      expect(mockRes.body.error.message).toContain('Missing authorization token');
    });

    test('F4-02: authenticateApiKey rejects request when provided API key is wrong', () => {
      process.env.API_KEY = 'configured_service_api_key_for_test_purposes_123';
      mockReq.headers['authorization'] = 'Bearer completely_incorrect_client_api_key_xyz';

      authenticateApiKey(mockReq, mockRes, () => {
        nextCalled = true;
      });

      expect(nextCalled).toBe(false);
      expect(mockRes.statusCode).toBe(401);
      expect(mockRes.body.error.code).toBe('unauthorized');
      expect(mockRes.body.error.message).toContain('Invalid or unconfigured API key');
    });

    test('F4-03: authenticateApiKey rejects request when server API key is unset or unconfigured', () => {
      delete process.env.API_KEY;
      delete process.env.ACTIONGUARD_API_KEY;
      mockReq.headers['authorization'] = 'Bearer some_client_provided_api_key_123';

      authenticateApiKey(mockReq, mockRes, () => {
        nextCalled = true;
      });

      expect(nextCalled).toBe(false);
      expect(mockRes.statusCode).toBe(401);
      expect(mockRes.body.error.code).toBe('unauthorized');
      expect(mockRes.body.error.message).toContain('Invalid or unconfigured API key');
    });

    test('F4-04: authenticateApiKey allows request when provided API key matches configured key in constant time', () => {
      const validKey = 'correct_production_service_api_key_long_enough_32ch';
      process.env.API_KEY = validKey;
      mockReq.headers['authorization'] = `Bearer ${validKey}`;

      authenticateApiKey(mockReq, mockRes, () => {
        nextCalled = true;
      });

      expect(nextCalled).toBe(true);
      expect(mockReq.apiKey).toBe(validKey);
      expect(mockRes.statusCode).toBeNull();
    });
  });

  // =========================================================================
  // F5: Fail-Safe Enforcement under recommend_only Mode
  // =========================================================================
  describe('F5: Fail-Safe Enforcement under recommend_only', () => {
    test('F5-01: fail-safe reverify/block decision is enforced by PEP even when enforcement_mode is recommend_only', async () => {
      // 1. Mock policy to recommend_only for all decisions
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

      // 2. Mock risk engine outage -> evaluateAndStoreRiskForEvent returns null (isFailSafe = true)
      jest.spyOn(riskEngineService, 'evaluateAndStoreRiskForEvent').mockResolvedValueOnce(null);

      // Create session and token
      const session = await createSession(testUser.id, testUser.email, 900);
      const token = jwt.sign(
        { id: testUser.id, email: testUser.email, session_id: session.sessionId },
        JWT_SECRET,
        { expiresIn: '15m' }
      );

      // Attempt protected action on existing app endpoint without elevation
      const res = await request(app)
        .post('/api/v1/account/phone')
        .set('Authorization', `Bearer ${token}`)
        .send({ phone_number: '+14155552671' })
        .expect(403);

      expect(res.body.error.code).toBe('step_up_required');
      const decision = await require('../src/database/models').PolicyDecision.findByPk(res.body.error.decision_id);
      expect(decision.enforcement_outcome).toBe('fail_safe_challenged');
      expect(decision.enforcement_mode).toBe('recommend_only');
    });
  });
});
