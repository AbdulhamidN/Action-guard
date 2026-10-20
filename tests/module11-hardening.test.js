'use strict';

const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../src/app');
const { runMigrations } = require('../src/database/migrate');
const { User } = require('../src/database/models');
const { createSession } = require('../src/services/sessionService');
const redisStorage = require('../src/storage/redis');
const {
  JWT_SECRET,
  authenticateApiKey,
  authenticateAdminApiKey,
  constantTimeKeyMatch
} = require('../src/middleware/auth');
const { createRateLimiter } = require('../src/middleware/rateLimiter');

describe('Module 11.1 — Stage 1: Production Security Hardening', () => {
  let testUser;
  let testSession;
  let validToken;
  const savedEnv = {};

  beforeAll(async () => {
    await runMigrations();
  });

  beforeEach(async () => {
    for (const k of [
      'API_KEY',
      'ACTIONGUARD_API_KEY',
      'ACTIONGUARD_ADMIN_API_KEY',
      'RATE_LIMIT_AUTH_MAX',
      'RATE_LIMIT_AUTH_WINDOW_MS',
      'RATE_LIMIT_STEP_UP_MAX',
      'RATE_LIMIT_STEP_UP_WINDOW_MS',
      'RATE_LIMIT_SENSITIVE_MAX',
      'RATE_LIMIT_SENSITIVE_WINDOW_MS',
      'RATE_LIMIT_API_MAX',
      'RATE_LIMIT_API_WINDOW_MS',
      'RATE_LIMIT_ENFORCE_IN_TESTS'
    ]) {
      savedEnv[k] = process.env[k];
    }

    testUser = await User.create({
      email: `m11-hardening-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`,
      password_hash: '$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234'
    });
    testSession = await createSession(testUser.id, testUser.email, 900, {
      device_fingerprint: 'fp_m11_stage1_device_01'
    });
    validToken = jwt.sign(
      { id: testUser.id, email: testUser.email, session_id: testSession.sessionId },
      JWT_SECRET,
      { expiresIn: '15m' }
    );
  });

  afterEach(() => {
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) {
        delete process.env[k];
      } else {
        process.env[k] = v;
      }
    }
    jest.restoreAllMocks();
  });

  // T11.1-01 (NFR-5, Module 11 Stage 1.4): Helmet security headers on API responses
  test('T11.1-01: Express app sets hardened Helmet security headers and hides X-Powered-By across API responses', async () => {
    const res = await request(app).get('/health').expect(200);

    expect(res.headers['x-powered-by']).toBeUndefined();
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
    expect(res.headers['x-dns-prefetch-control']).toBe('off');
    expect(res.headers['x-download-options']).toBe('noopen');
    expect(res.headers['x-permitted-cross-domain-policies']).toBe('none');
    expect(res.headers['cross-origin-opener-policy']).toBe('same-origin');
    expect(res.headers['cross-origin-resource-policy']).toBe('same-origin');
    expect(res.headers['strict-transport-security']).toContain('max-age=31536000');
    expect(res.headers['content-security-policy']).toContain("default-src 'none'");
    expect(res.headers['content-security-policy']).toContain("frame-ancestors 'none'");
  });

  // T11.1-02 (NFR-5, Module 11 Stage 1.2): Tiered rate-limit enforcement, headers, and 429 error envelope
  test('T11.1-02: Tiered rate limiters enforce configured thresholds across auth, step-up, sensitive account, and general API routes with standard headers and 429 envelope', async () => {
    process.env.RATE_LIMIT_AUTH_MAX = '2';
    process.env.RATE_LIMIT_AUTH_WINDOW_MS = '60000';
    process.env.RATE_LIMIT_STEP_UP_MAX = '2';
    process.env.RATE_LIMIT_STEP_UP_WINDOW_MS = '60000';
    process.env.RATE_LIMIT_SENSITIVE_MAX = '2';
    process.env.RATE_LIMIT_SENSITIVE_WINDOW_MS = '60000';
    process.env.RATE_LIMIT_API_MAX = '2';
    process.env.RATE_LIMIT_API_WINDOW_MS = '60000';

    const client = redisStorage.getRedisClient();
    await client.del('rate_limit:auth:127.0.0.1');
    await client.del('rate_limit:step_up:127.0.0.1');
    await client.del('rate_limit:sensitive_action:127.0.0.1');
    await client.del('rate_limit:api:127.0.0.1');

    // 1. Auth tier (/api/v1/auth/login)
    const auth1 = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'nobody@example.com', password: 'password123' })
      .expect(401);
    expect(auth1.headers['x-ratelimit-limit']).toBe('2');
    expect(auth1.headers['x-ratelimit-remaining']).toBe('1');
    expect(Number(auth1.headers['x-ratelimit-reset'])).toBeGreaterThan(0);

    const auth2 = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'nobody@example.com', password: 'password123' })
      .expect(401);
    expect(auth2.headers['x-ratelimit-remaining']).toBe('0');

    const auth3 = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'nobody@example.com', password: 'password123' })
      .expect(429);
    expect(auth3.body.error.code).toBe('rate_limited');
    expect(auth3.body.error.status).toBe(429);
    expect(auth3.body.error.tier).toBe('auth');
    expect(Number(auth3.body.error.retry_after_seconds)).toBeGreaterThan(0);
    expect(Number(auth3.headers['retry-after'])).toBeGreaterThan(0);
    expect(auth3.headers['x-ratelimit-remaining']).toBe('0');

    // 2. Step-up tier (/api/v1/sessions/:id/step-up/challenge)
    await request(app)
      .post(`/api/v1/sessions/${testSession.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${validToken}`)
      .send({ scope: 'credential_change' })
      .expect(200);
    await request(app)
      .post(`/api/v1/sessions/${testSession.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${validToken}`)
      .send({ scope: 'sensitive_action' })
      .expect(200);
    const stepUp3 = await request(app)
      .post(`/api/v1/sessions/${testSession.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${validToken}`)
      .send({ scope: 'credential_change' })
      .expect(429);
    expect(stepUp3.body.error.code).toBe('rate_limited');
    expect(stepUp3.body.error.tier).toBe('step_up');

    // 3. Sensitive action tier (/api/v1/account/phone)
    await request(app)
      .post('/api/v1/account/phone')
      .set('Authorization', `Bearer ${validToken}`)
      .send({ phone_number: '+14155552671' });
    await request(app)
      .post('/api/v1/account/phone')
      .set('Authorization', `Bearer ${validToken}`)
      .send({ phone_number: '+14155552671' });
    const sens3 = await request(app)
      .post('/api/v1/account/phone')
      .set('Authorization', `Bearer ${validToken}`)
      .send({ phone_number: '+14155552671' })
      .expect(429);
    expect(sens3.body.error.code).toBe('rate_limited');
    expect(sens3.body.error.tier).toBe('sensitive_action');

    // 4. General API tier (/api/v1/me)
    await request(app)
      .get('/api/v1/me')
      .set('Authorization', `Bearer ${validToken}`)
      .expect(200);
    await request(app)
      .get('/api/v1/me')
      .set('Authorization', `Bearer ${validToken}`)
      .expect(200);
    const api3 = await request(app)
      .get('/api/v1/me')
      .set('Authorization', `Bearer ${validToken}`)
      .expect(429);
    expect(api3.body.error.code).toBe('rate_limited');
    expect(api3.body.error.tier).toBe('api');

    await client.del('rate_limit:auth:127.0.0.1');
    await client.del('rate_limit:step_up:127.0.0.1');
    await client.del('rate_limit:sensitive_action:127.0.0.1');
    await client.del('rate_limit:api:127.0.0.1');
  });

  // T11.1-03 (NFR-5, Module 11 Stage 1.2): Rate-limit window reset and fail-closed Redis outage handling
  test('T11.1-03: Rate limiter resets counter deterministically after window expiration and fails closed (503) when Redis throws', async () => {
    let simulatedNowMs = Date.now();
    const tierId = `test_reset_${Date.now()}`;
    const testApp = express();
    testApp.use(
      createRateLimiter({
        tier: tierId,
        windowMs: 2000,
        max: 2,
        nowFn: () => simulatedNowMs
      })
    );
    testApp.get('/ping', (_req, res) => res.status(200).json({ ok: true }));

    await request(testApp).get('/ping').expect(200);
    await request(testApp).get('/ping').expect(200);
    const blocked = await request(testApp).get('/ping').expect(429);
    expect(blocked.body.error.code).toBe('rate_limited');
    expect(blocked.body.error.retry_after_seconds).toBe(2);

    // Advance clock past the 2000ms window
    simulatedNowMs += 2001;
    const afterReset = await request(testApp).get('/ping').expect(200);
    expect(afterReset.headers['x-ratelimit-remaining']).toBe('1');

    // Simulate Redis error -> fail closed with 503 rate_limit_unavailable
    const client = redisStorage.getRedisClient();
    jest.spyOn(client, 'eval').mockRejectedValueOnce(new Error('Simulated Redis rate-limit outage'));
    const outageRes = await request(testApp).get('/ping').expect(503);
    expect(outageRes.body.error.code).toBe('rate_limit_unavailable');
  });

  // T11.1-04 (NFR-5, Module 11 Stage 1.2): Concurrent rate-limit requests proving atomic counting
  test('T11.1-04: Concurrent requests against Redis rate limiter increment atomically without race conditions', async () => {
    const concurrentTier = `concurrent_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const maxAllowed = 7;
    const totalConcurrent = 20;

    const testApp = express();
    testApp.use(
      createRateLimiter({
        tier: concurrentTier,
        windowMs: 60000,
        max: maxAllowed
      })
    );
    testApp.get('/atomic', (_req, res) => res.status(200).json({ ok: true }));

    const responses = await Promise.all(
      Array.from({ length: totalConcurrent }, () => request(testApp).get('/atomic'))
    );

    const status200 = responses.filter((r) => r.status === 200);
    const status429 = responses.filter((r) => r.status === 429);

    expect(status200).toHaveLength(maxAllowed);
    expect(status429).toHaveLength(totalConcurrent - maxAllowed);

    const remainingValues = status200
      .map((r) => Number(r.headers['x-ratelimit-remaining']))
      .sort((a, b) => a - b);
    expect(remainingValues).toEqual([0, 1, 2, 3, 4, 5, 6]);
  });

  // T11.1-05 (NFR-5, Module 11 Stage 1.1): Constant-time API key and Admin API key authentication
  test('T11.1-05: authenticateApiKey and authenticateAdminApiKey enforce constant-time comparison and reject missing, malformed, unequal-length, unconfigured, short, or query-string keys', async () => {
    const testApp = express();
    testApp.get('/service-only', authenticateApiKey, (_req, res) => {
      res.status(200).json({ ok: true });
    });
    testApp.get('/admin-only', authenticateAdminApiKey, (_req, res) => {
      res.status(200).json({ ok: true, isAdmin: true });
    });

    // 1. Unconfigured API_KEY -> 401
    delete process.env.API_KEY;
    delete process.env.ACTIONGUARD_API_KEY;
    await request(testApp)
      .get('/service-only')
      .set('Authorization', 'Bearer any_key_value')
      .expect(401);

    // 2. Configured API_KEY -> test missing, malformed, unequal-length, query-string, and valid
    process.env.ACTIONGUARD_API_KEY = 'service_secret_key_for_integration_testing_01';

    await request(testApp).get('/service-only').expect(401);
    await request(testApp)
      .get('/service-only')
      .set('Authorization', 'Basic dXNlcjpwYXNz')
      .expect(401);
    await request(testApp)
      .get('/service-only')
      .set('Authorization', 'Bearer short')
      .expect(401);
    await request(testApp)
      .get('/service-only')
      .set(
        'Authorization',
        'Bearer a_much_longer_incorrect_key_than_the_configured_service_secret_key_value_99999'
      )
      .expect(401);
    await request(testApp)
      .get('/service-only?apiKey=service_secret_key_for_integration_testing_01')
      .set('Authorization', 'Bearer service_secret_key_for_integration_testing_01')
      .expect(401);
    await request(testApp)
      .get('/service-only')
      .set('Authorization', 'Bearer service_secret_key_for_integration_testing_01')
      .expect(200);

    // 3. Admin API key: unconfigured or < 32 chars fails closed with 401
    delete process.env.ACTIONGUARD_ADMIN_API_KEY;
    await request(testApp)
      .get('/admin-only')
      .set('Authorization', 'Bearer a_valid_length_admin_key_at_least_32_bytes_long')
      .expect(401);

    process.env.ACTIONGUARD_ADMIN_API_KEY = 'too_short_admin_key_under_32';
    await request(testApp)
      .get('/admin-only')
      .set('Authorization', 'Bearer too_short_admin_key_under_32')
      .expect(401);

    // 4. Valid >= 32-char Admin API key: test Bearer, X-Admin-Api-Key, conflicting headers, query rejection, and unequal length
    const validAdminKey = 'admin_super_secret_key_at_least_32_characters_long_001';
    process.env.ACTIONGUARD_ADMIN_API_KEY = validAdminKey;

    await request(testApp)
      .get('/admin-only')
      .set('Authorization', 'Bearer short_wrong_key')
      .expect(401);
    await request(testApp)
      .get(`/admin-only?apiKey=${validAdminKey}`)
      .set('Authorization', `Bearer ${validAdminKey}`)
      .expect(401);
    await request(testApp)
      .get('/admin-only')
      .set('Authorization', `Bearer ${validAdminKey}`)
      .set('X-Admin-Api-Key', 'different_admin_key_in_second_header_value_000000')
      .expect(401);
    await request(testApp)
      .get('/admin-only')
      .set('Authorization', `Bearer ${validAdminKey}`)
      .expect(200);
    await request(testApp)
      .get('/admin-only')
      .set('X-Admin-Api-Key', validAdminKey)
      .expect(200);

    // Unit verification of constantTimeKeyMatch helper
    expect(constantTimeKeyMatch('', '')).toBe(false);
    expect(constantTimeKeyMatch(null, 'valid')).toBe(false);
    expect(constantTimeKeyMatch('valid', undefined)).toBe(false);
    expect(constantTimeKeyMatch('short', 'much_longer_secret_value')).toBe(false);
    expect(constantTimeKeyMatch(validAdminKey, validAdminKey)).toBe(true);
  });

  // T11.1-06 (NFR-5, Module 11 Stage 1.3): Malformed JSON and oversized payload (>64KB) handling
  test('T11.1-06: Express body parser rejects malformed JSON with 400 invalid_request and payloads exceeding 64KB with 413 payload_too_large', async () => {
    // 1. Malformed JSON syntax
    const badJsonRes = await request(app)
      .post('/api/v1/auth/login')
      .set('Content-Type', 'application/json')
      .send('{"email": "broken@example.com", "password": ')
      .expect(400);
    expect(badJsonRes.body.error.code).toBe('invalid_request');
    expect(badJsonRes.body.error.status).toBe(400);

    // 2. Oversized payload (> 64KB)
    const oversizedString = 'A'.repeat(70 * 1024);
    const largeRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'user@example.com', padding: oversizedString })
      .expect(413);
    expect(largeRes.body.error.code).toBe('payload_too_large');
    expect(largeRes.body.error.status).toBe(413);
  });

  // T11.1-07 (NFR-5, Module 11 Stage 1.3): Non-object bodies and prototype-pollution key rejection
  test('T11.1-07: Global request envelope validator rejects array/primitive JSON bodies and nested prototype-pollution keys (__proto__, constructor, prototype)', async () => {
    // 1. JSON array body on POST endpoint
    const arrRes = await request(app)
      .post('/api/v1/auth/login')
      .set('Content-Type', 'application/json')
      .send(JSON.stringify([{ email: 'a@example.com', password: 'password123' }]))
      .expect(400);
    expect(arrRes.body.error.code).toBe('invalid_request');

    // 2. JSON primitive body
    const primRes = await request(app)
      .post('/api/v1/auth/login')
      .set('Content-Type', 'application/json')
      .send('"just_a_string"')
      .expect(400);
    expect(primRes.body.error.code).toBe('invalid_request');

    // 3. Root-level __proto__ in raw JSON body
    const protoRootRes = await request(app)
      .post('/api/v1/auth/login')
      .set('Content-Type', 'application/json')
      .send('{"email":"a@example.com","password":"password123","__proto__":{"isAdmin":true}}')
      .expect(400);
    expect(protoRootRes.body.error.code).toBe('invalid_request');
    expect(({}).isAdmin).toBeUndefined();

    // 4. Deeply nested constructor.prototype in JSON body
    const nestedConstructorRes = await request(app)
      .post('/api/v1/account/high-impact')
      .set('Authorization', `Bearer ${validToken}`)
      .set('Content-Type', 'application/json')
      .send(
        '{"operation":"export_all","nested":{"items":[{"constructor":{"prototype":{"polluted":true}}}]}}'
      )
      .expect(400);
    expect(nestedConstructorRes.body.error.code).toBe('invalid_request');
    expect(({}).polluted).toBeUndefined();

    // 5. Prototype-pollution key in query string
    const queryProtoRes = await request(app)
      .get('/api/v1/events?__proto__[polluted]=true')
      .set('Authorization', `Bearer ${validToken}`)
      .expect(400);
    expect(queryProtoRes.body.error.code).toBe('invalid_request');
  });

  // T11.1-08 (NFR-5, Module 11 Stage 1.3): Bounded string lengths and route :id parameter validation
  test('T11.1-08: Sensitive endpoints reject unbounded passwords (>256 chars), oversized emails, oversized tokens/scopes, and invalid route :id parameters', async () => {
    const longPassword = 'P'.repeat(257);
    const longEmail = `${'a'.repeat(250)}@example.com`;
    const longId = 'x'.repeat(130);

    // 1. Signup and login reject password > 256 chars (bcrypt DoS protection) and email > 254 chars
    const signupLongPw = await request(app)
      .post('/api/v1/auth/signup')
      .send({ email: 'valid@example.com', password: longPassword })
      .expect(400);
    expect(signupLongPw.body.error.code).toBe('invalid_request');

    const signupLongEmail = await request(app)
      .post('/api/v1/auth/signup')
      .send({ email: longEmail, password: 'ValidPassword123!' })
      .expect(400);
    expect(signupLongEmail.body.error.code).toBe('invalid_request');

    const loginLongPw = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: testUser.email, password: longPassword })
      .expect(400);
    expect(loginLongPw.body.error.code).toBe('invalid_request');

    // 2. Account password change rejects password > 256 chars before PEP/controller execution
    const acctLongPw = await request(app)
      .post('/api/v1/account/password')
      .set('Authorization', `Bearer ${validToken}`)
      .send({ current_password: 'OldPassword123!', new_password: longPassword })
      .expect(400);
    expect(acctLongPw.body.error.code).toBe('invalid_request');

    // 3. Step-up and elevation endpoints reject oversized scope, challenge_id, code, and route :id
    const badIdStepUp = await request(app)
      .post(`/api/v1/sessions/${longId}/step-up/challenge`)
      .set('Authorization', `Bearer ${validToken}`)
      .send({ scope: 'credential_change' })
      .expect(400);
    expect(badIdStepUp.body.error.code).toBe('invalid_request');

    const longScopeStepUp = await request(app)
      .post(`/api/v1/sessions/${testSession.sessionId}/step-up/challenge`)
      .set('Authorization', `Bearer ${validToken}`)
      .send({ scope: 's'.repeat(65) })
      .expect(400);
    expect(longScopeStepUp.body.error.code).toBe('invalid_request');

    const longCodeVerify = await request(app)
      .post(`/api/v1/sessions/${testSession.sessionId}/step-up/verify`)
      .set('Authorization', `Bearer ${validToken}`)
      .send({ challenge_id: 'ch_valid_123', code: '1'.repeat(17) })
      .expect(400);
    expect(longCodeVerify.body.error.code).toBe('invalid_request');

    // 4. Cooling-off routes reject oversized :id parameter and oversized cancellation_token
    const badIdCoolingOff = await request(app)
      .get(`/api/v1/cooling-off/actions/${longId}`)
      .set('Authorization', `Bearer ${validToken}`)
      .expect(400);
    expect(badIdCoolingOff.body.error.code).toBe('invalid_request');

    const longTokenCancel = await request(app)
      .post('/api/v1/cooling-off/actions/valid_id_123/cancel')
      .set('Authorization', `Bearer ${validToken}`)
      .send({ cancellation_token: 't'.repeat(513) })
      .expect(400);
    expect(longTokenCancel.body.error.code).toBe('invalid_request');
  });
});
