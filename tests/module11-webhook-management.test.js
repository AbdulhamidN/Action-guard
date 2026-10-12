'use strict';

const crypto = require('crypto');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../src/app');
const {
  sequelize,
  User,
  Session,
  WebhookEndpoint,
  WebhookDeliveryLog
} = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const { createSession } = require('../src/services/sessionService');
const { grantElevation } = require('../src/services/elevationService');
const authMiddleware = require('../src/middleware/auth');
const { JWT_SECRET } = authMiddleware;
const redisStorage = require('../src/storage/redis');
const eventBus = require('../src/events/eventBus');
const {
  decryptWebhookSecret,
  encryptWebhookSecret,
  resetEphemeralTestEncryptionKey
} = require('../src/utils/webhookCrypto');

const TEST_ADMIN_API_KEY =
  'whk_admin_test_secret_key_with_more_than_32_characters_001';
const TEST_SERVICE_API_KEY =
  'whk_service_integration_key_with_more_than_32_chars_002';
const TEST_ENCRYPTION_KEY_HEX =
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

describe('Module 11.2c Stage 1 — Secure Webhook Endpoint Management (/api/v1/webhooks)', () => {
  let testUser;
  let testSession;
  let validUserJwt;
  const savedEnv = {};

  const ENV_KEYS = [
    'NODE_ENV',
    'API_KEY',
    'ACTIONGUARD_API_KEY',
    'ACTIONGUARD_ADMIN_API_KEY',
    'WEBHOOK_SECRET_ENCRYPTION_KEY',
    'WEBHOOK_ENCRYPTION_KEY',
    'REQUIRE_WEBHOOK_ENCRYPTION_KEY',
    'ALLOW_INSECURE_HTTP_WEBHOOKS',
    'ALLOW_LOCAL_WEBHOOK_TARGETS',
    'RATE_LIMIT_SENSITIVE_MAX',
    'RATE_LIMIT_SENSITIVE_WINDOW_MS',
    'RATE_LIMIT_ENFORCE_IN_TESTS'
  ];

  beforeAll(async () => {
    for (const k of ENV_KEYS) {
      savedEnv[k] = process.env[k];
    }
    await runMigrations();
  });

  beforeEach(async () => {
    for (const k of ENV_KEYS) {
      if (savedEnv[k] === undefined) {
        delete process.env[k];
      } else {
        process.env[k] = savedEnv[k];
      }
    }

    process.env.ACTIONGUARD_ADMIN_API_KEY = TEST_ADMIN_API_KEY;
    process.env.API_KEY = TEST_SERVICE_API_KEY;
    process.env.WEBHOOK_SECRET_ENCRYPTION_KEY = TEST_ENCRYPTION_KEY_HEX;

    const redisClient = redisStorage.getRedisClient();
    if (redisClient) {
      await redisClient.del('rate_limit:sensitive_action:127.0.0.1');
    }

    await WebhookDeliveryLog.destroy({ where: {} });
    await WebhookEndpoint.destroy({ where: {} });

    testUser = await User.create({
      email: `whk-user-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`,
      password_hash: '$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234'
    });

    testSession = await createSession(testUser.id, testUser.email, 900, {
      device_fingerprint: 'fp_whk_mgmt_test_device_01'
    });

    validUserJwt = jwt.sign(
      {
        id: testUser.id,
        email: testUser.email,
        session_id: testSession.sessionId
      },
      JWT_SECRET,
      { expiresIn: '15m' }
    );
  });

  afterEach(async () => {
    jest.restoreAllMocks();
    const redisClient = redisStorage.getRedisClient();
    if (redisClient) {
      await redisClient.del('rate_limit:sensitive_action:127.0.0.1');
      if (testSession && testSession.sessionId) {
        await redisStorage.deleteSession(testSession.sessionId);
      }
    }
    if (testUser) {
      await Session.destroy({ where: { user_id: testUser.id } });
      await User.destroy({ where: { id: testUser.id } });
      testUser = null;
      testSession = null;
    }
  });

  afterAll(async () => {
    await WebhookDeliveryLog.destroy({ where: {} });
    await WebhookEndpoint.destroy({ where: {} });
    for (const k of ENV_KEYS) {
      if (savedEnv[k] === undefined) {
        delete process.env[k];
      } else {
        process.env[k] = savedEnv[k];
      }
    }
  });

  test('T11.2c-01: registers webhook endpoints with server-generated ID and encrypted secret, and lists endpoints with filtering and pagination', async () => {
    // 1. Register first endpoint with explicit subscribed_events and description
    const createRes1 = await request(app)
      .post('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send({
        url: 'https://siem.example.com/webhooks/actionguard',
        subscribed_events: ['decision.recorded'],
        description: 'Primary SIEM Receiver'
      })
      .expect(201);

    const wh1 = createRes1.body.webhook;
    expect(wh1).toBeDefined();
    expect(wh1.id).toMatch(/^whk_[0-9a-f-]{36}$/i);
    expect(wh1.url).toBe('https://siem.example.com/webhooks/actionguard');
    expect(wh1.subscribed_events).toEqual(['decision.recorded']);
    expect(wh1.description).toBe('Primary SIEM Receiver');
    expect(wh1.secret_prefix).toMatch(/^whsec_[0-9a-f]{8}$/);
    expect(wh1.is_active).toBe(true);
    expect(new Date(wh1.created_at).getTime()).toBeGreaterThan(0);
    expect(new Date(wh1.updated_at).getTime()).toBeGreaterThan(0);

    // 2. Register second endpoint using X-Admin-Api-Key header, default subscribed_events, and is_active=false
    const createRes2 = await request(app)
      .post('/api/v1/webhooks')
      .set('X-Admin-Api-Key', TEST_ADMIN_API_KEY)
      .send({
        url: 'https://soc.example.org/hooks/alerts',
        is_active: false
      })
      .expect(201);

    const wh2 = createRes2.body.webhook;
    expect(wh2.id).toMatch(/^whk_[0-9a-f-]{36}$/i);
    expect(wh2.id).not.toBe(wh1.id);
    expect(wh2.subscribed_events).toEqual([
      'event.processed',
      'decision.recorded'
    ]);
    expect(wh2.description).toBeNull();
    expect(wh2.is_active).toBe(false);

    // 3. List all endpoints
    const listAll = await request(app)
      .get('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .expect(200);

    expect(listAll.body.total).toBe(2);
    expect(listAll.body.count).toBe(2);
    expect(listAll.body.webhooks).toHaveLength(2);

    // 4. Filter by is_active=true and is_active=false
    const listActive = await request(app)
      .get('/api/v1/webhooks?is_active=true')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .expect(200);
    expect(listActive.body.total).toBe(1);
    expect(listActive.body.webhooks[0].id).toBe(wh1.id);

    const listInactive = await request(app)
      .get('/api/v1/webhooks?is_active=false')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .expect(200);
    expect(listInactive.body.total).toBe(1);
    expect(listInactive.body.webhooks[0].id).toBe(wh2.id);

    // 5. Pagination via limit & offset
    const page1 = await request(app)
      .get('/api/v1/webhooks?limit=1&offset=0')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .expect(200);
    expect(page1.body.count).toBe(1);
    expect(page1.body.total).toBe(2);
  });

  test('T11.2c-02: retrieves, updates, deactivates, reactivates, and deletes webhook endpoints with CASCADE cleanup of delivery logs', async () => {
    const regRes = await request(app)
      .post('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send({
        url: 'https://initial.example.com/webhook',
        subscribed_events: ['event.processed'],
        description: 'Initial endpoint'
      })
      .expect(201);

    const endpointId = regRes.body.webhook.id;
    const originalSecretPrefix = regRes.body.webhook.secret_prefix;

    // 1. Retrieve by ID
    const getRes = await request(app)
      .get(`/api/v1/webhooks/${endpointId}`)
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .expect(200);
    expect(getRes.body.webhook.id).toBe(endpointId);
    expect(getRes.body.webhook.url).toBe('https://initial.example.com/webhook');
    expect(getRes.body.webhook.secret_prefix).toBe(originalSecretPrefix);

    // 2. Update URL, subscribed_events, and description via PATCH
    const patchRes = await request(app)
      .patch(`/api/v1/webhooks/${endpointId}`)
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send({
        url: 'https://updated.example.com/webhook/v2',
        subscribed_events: ['event.processed', 'decision.recorded'],
        description: 'Updated SIEM endpoint'
      })
      .expect(200);

    expect(patchRes.body.webhook.url).toBe('https://updated.example.com/webhook/v2');
    expect(patchRes.body.webhook.subscribed_events).toEqual([
      'event.processed',
      'decision.recorded'
    ]);
    expect(patchRes.body.webhook.description).toBe('Updated SIEM endpoint');
    expect(patchRes.body.webhook.secret_prefix).toBe(originalSecretPrefix);

    // 3. Deactivate via POST /:id/deactivate (preserves delivery logs)
    const deliveryLog = await WebhookDeliveryLog.create({
      webhook_id: endpointId,
      event_type: 'event.processed',
      source_event_id: 'evt_sample_001',
      status: 'delivered',
      attempt_count: 1,
      http_status: 200,
      delivered_at: new Date()
    });

    const deactRes = await request(app)
      .post(`/api/v1/webhooks/${endpointId}/deactivate`)
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .expect(200);
    expect(deactRes.body.webhook.is_active).toBe(false);

    // Delivery log remains intact while endpoint is deactivated
    const preservedLog = await WebhookDeliveryLog.findByPk(deliveryLog.id);
    expect(preservedLog).not.toBeNull();

    // 4. Reactivate via POST /:id/activate
    const actRes = await request(app)
      .post(`/api/v1/webhooks/${endpointId}/activate`)
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .expect(200);
    expect(actRes.body.webhook.is_active).toBe(true);

    // Also toggle is_active via PATCH
    const patchDeact = await request(app)
      .patch(`/api/v1/webhooks/${endpointId}`)
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send({ is_active: false })
      .expect(200);
    expect(patchDeact.body.webhook.is_active).toBe(false);

    // 5. Delete endpoint -> removes endpoint and CASCADE-deletes delivery logs
    const delRes = await request(app)
      .delete(`/api/v1/webhooks/${endpointId}`)
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .expect(200);
    expect(delRes.body).toEqual({
      deleted: true,
      id: endpointId
    });

    // Subsequent GET or DELETE returns 404 webhook_not_found
    const getAfterDel = await request(app)
      .get(`/api/v1/webhooks/${endpointId}`)
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .expect(404);
    expect(getAfterDel.body.error.code).toBe('webhook_not_found');

    // Associated delivery log was cascade-deleted
    const cascadedLog = await WebhookDeliveryLog.findByPk(deliveryLog.id);
    expect(cascadedLog).toBeNull();
  });

  test('T11.2c-03: rejects unauthenticated callers with 401 and non-administrator callers (user JWT, elevated session, service API key) with 403', async () => {
    const validBody = {
      url: 'https://siem.example.com/webhooks',
      subscribed_events: ['event.processed']
    };

    // 1. Unauthenticated (missing header) -> 401
    const noAuth = await request(app)
      .post('/api/v1/webhooks')
      .send(validBody)
      .expect(401);
    expect(noAuth.body.error.code).toBe('unauthorized');

    // 2. Invalid / wrong admin API key -> 401
    const wrongAdmin = await request(app)
      .get('/api/v1/webhooks')
      .set('Authorization', 'Bearer wrong_admin_key_that_is_over_32_characters_long_999')
      .expect(401);
    expect(wrongAdmin.body.error.code).toBe('unauthorized');

    // 3. Query-parameter credential -> 401
    const queryCred = await request(app)
      .get(`/api/v1/webhooks?admin_api_key=${TEST_ADMIN_API_KEY}`)
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .expect(401);
    expect(queryCred.body.error.code).toBe('unauthorized');

    // 4. Unconfigured or < 32-char ACTIONGUARD_ADMIN_API_KEY -> 401
    process.env.ACTIONGUARD_ADMIN_API_KEY = 'short_admin_key_under_32';
    const shortConfig = await request(app)
      .get('/api/v1/webhooks')
      .set('Authorization', 'Bearer short_admin_key_under_32')
      .expect(401);
    expect(shortConfig.body.error.code).toBe('unauthorized');
    process.env.ACTIONGUARD_ADMIN_API_KEY = TEST_ADMIN_API_KEY;

    // 5. Authenticated end-user session JWT -> 403 forbidden
    const userJwtRes = await request(app)
      .post('/api/v1/webhooks')
      .set('Authorization', `Bearer ${validUserJwt}`)
      .send(validBody)
      .expect(403);
    expect(userJwtRes.body.error.code).toBe('forbidden');

    // 6. Authenticated end-user session EVEN WITH `admin_action` temporary elevation -> 403 forbidden
    const { resolveLocalStepUpKeys } = require('../src/services/stepUpService');
    const keyCtx = resolveLocalStepUpKeys();
    const nowSec = Math.floor(Date.now() / 1000);
    const dummyTicketJwt = jwt.sign(
      {
        sub: testUser.id,
        session_id: testSession.sessionId,
        scope: 'admin_action',
        jti: `jti_whk_${crypto.randomUUID()}`,
        purpose: 'step_up_verification',
        iat: nowSec,
        exp: nowSec + 60
      },
      keyCtx.privateKeyObject,
      { algorithm: 'ES256' }
    );
    await grantElevation({
      sessionId: testSession.sessionId,
      userId: testUser.id,
      scope: 'admin_action',
      verificationTicket: dummyTicketJwt,
      publicKey: keyCtx.publicKeyObject
    });

    const elevatedUserRes = await request(app)
      .get('/api/v1/webhooks')
      .set('Authorization', `Bearer ${validUserJwt}`)
      .expect(403);
    expect(elevatedUserRes.body.error.code).toBe('forbidden');

    // 7. Authenticated service integration API key (API_KEY / ACTIONGUARD_API_KEY) -> 403 forbidden
    const serviceKeyRes = await request(app)
      .post('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_SERVICE_API_KEY}`)
      .send(validBody)
      .expect(403);
    expect(serviceKeyRes.body.error.code).toBe('forbidden');

    // 8. Misconfigured environment where ACTIONGUARD_ADMIN_API_KEY === API_KEY fails closed with 401
    process.env.ACTIONGUARD_ADMIN_API_KEY = TEST_SERVICE_API_KEY;
    const sameKeyRes = await request(app)
      .get('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_SERVICE_API_KEY}`)
      .expect(401);
    expect(sameKeyRes.body.error.code).toBe('unauthorized');
  });

  test('T11.2c-04: rejects invalid URLs, non-HTTPS production URLs, SSRF/local targets, unsupported or duplicate event types, and malformed requests', async () => {
    const invalidUrls = [
      '',
      'not-a-valid-url',
      'http://insecure.example.com/webhook',
      'ftp://files.example.com/webhook',
      'javascript:alert(1)',
      'https://user:password@siem.example.com/webhook',
      'https://siem.example.com/webhook#fragment',
      'https://localhost/webhook',
      'https://sub.localhost/webhook',
      'https://internal-service/webhook',
      'https://db.internal/webhook',
      'https://printer.local/webhook',
      'https://127.0.0.1/webhook',
      'https://10.0.0.1/webhook',
      'https://172.16.0.1/webhook',
      'https://192.168.1.1/webhook',
      'https://169.254.169.254/latest/meta-data/',
      'https://100.64.0.1/webhook',
      'https://[::1]/webhook',
      'https://[::ffff:127.0.0.1]/webhook',
      'https://[::ffff:169.254.169.254]/webhook',
      'https://[fc00::1]/webhook',
      'https://[fe80::1]/webhook',
      `https://siem.example.com/${'a'.repeat(510)}`
    ];

    for (const badUrl of invalidUrls) {
      const res = await request(app)
        .post('/api/v1/webhooks')
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .send({
          url: badUrl,
          subscribed_events: ['event.processed']
        })
        .expect(400);

      expect(res.body.error.code).toBe('invalid_webhook_url');
    }

    // Verify explicit non-production local-dev HTTP exception works ONLY outside production
    process.env.NODE_ENV = 'development';
    process.env.ALLOW_INSECURE_HTTP_WEBHOOKS = 'true';
    const devHttpRes = await request(app)
      .post('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send({
        url: 'http://dev-receiver.example.com/webhook',
        subscribed_events: ['event.processed']
      })
      .expect(201);
    expect(devHttpRes.body.webhook.url).toBe('http://dev-receiver.example.com/webhook');

    // In NODE_ENV=production, HTTP and local targets are NEVER allowed even if override flags are set
    process.env.NODE_ENV = 'production';
    process.env.ALLOW_INSECURE_HTTP_WEBHOOKS = 'true';
    process.env.ALLOW_LOCAL_WEBHOOK_TARGETS = 'true';

    const prodHttpRes = await request(app)
      .post('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send({
        url: 'http://siem.example.com/webhook',
        subscribed_events: ['event.processed']
      })
      .expect(400);
    expect(prodHttpRes.body.error.code).toBe('invalid_webhook_url');

    const prodLocalRes = await request(app)
      .post('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send({
        url: 'https://127.0.0.1/webhook',
        subscribed_events: ['event.processed']
      })
      .expect(400);
    expect(prodLocalRes.body.error.code).toBe('invalid_webhook_url');

    process.env.NODE_ENV = 'test';
    delete process.env.ALLOW_INSECURE_HTTP_WEBHOOKS;
    delete process.env.ALLOW_LOCAL_WEBHOOK_TARGETS;

    // Invalid subscribed_events (empty array, non-array, unsupported event, duplicate event)
    const invalidEventsPayloads = [
      [],
      'event.processed',
      ['unsupported.event'],
      ['event.processed', 'unknown.event'],
      ['event.processed', 'event.processed']
    ];

    for (const badEvents of invalidEventsPayloads) {
      const res = await request(app)
        .post('/api/v1/webhooks')
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .send({
          url: 'https://siem.example.com/webhook',
          subscribed_events: badEvents
        })
        .expect(400);

      expect(res.body.error.code).toBe('invalid_subscribed_events');
    }

    // Empty PATCH body or invalid is_active / description types
    const emptyPatch = await request(app)
      .patch(`/api/v1/webhooks/${devHttpRes.body.webhook.id}`)
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send({})
      .expect(400);
    expect(emptyPatch.body.error.code).toBe('invalid_request');

    const badActiveType = await request(app)
      .post('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send({
        url: 'https://siem.example.com/webhook',
        is_active: 'true'
      })
      .expect(400);
    expect(badActiveType.body.error.code).toBe('invalid_request');
  });

  test('T11.2c-05: rejects attempts to inject internal fields, custom IDs, plaintext secrets, encryption metadata, or privileged settings', async () => {
    const validBase = {
      url: 'https://siem.example.com/webhook',
      subscribed_events: ['event.processed']
    };

    const injectedCreatePayloads = [
      { id: 'whk_custom_attacker_id' },
      { secret: 'whsec_attacker_chosen_secret_0123456789abcdef' },
      { signing_secret: 'whsec_attacker_chosen_secret' },
      { encrypted_secret: 'deadbeef' },
      { secret_iv: '00112233445566778899aabb' },
      { secret_auth_tag: '00112233445566778899aabbccddeeff' },
      { secret_prefix: 'whsec_spoofed' },
      { created_at: '2020-01-01T00:00:00.000Z' },
      { updated_at: '2020-01-01T00:00:00.000Z' },
      { owner_id: 'usr_attacker' },
      { tenant_id: 'tenant_other' },
      { role: 'superadmin' },
      { isAdmin: true }
    ];

    for (const injection of injectedCreatePayloads) {
      const res = await request(app)
        .post('/api/v1/webhooks')
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .send({ ...validBase, ...injection })
        .expect(400);

      expect(res.body.error.code).toBe('invalid_request');
    }

    expect(await WebhookEndpoint.count()).toBe(0);

    // Create a legitimate endpoint and test field injection on PATCH, activate, deactivate, and GET query
    const created = await request(app)
      .post('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send(validBase)
      .expect(201);
    const id = created.body.webhook.id;

    for (const injection of injectedCreatePayloads) {
      const patchRes = await request(app)
        .patch(`/api/v1/webhooks/${id}`)
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .send({ description: 'Attempted overwrite', ...injection })
        .expect(400);

      expect(patchRes.body.error.code).toBe('invalid_request');
    }

    const actInjected = await request(app)
      .post(`/api/v1/webhooks/${id}/activate`)
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send({ secret_prefix: 'whsec_override' })
      .expect(400);
    expect(actInjected.body.error.code).toBe('invalid_request');

    const queryInjected = await request(app)
      .get('/api/v1/webhooks?encrypted_secret=leak')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .expect(400);
    expect(queryInjected.body.error.code).toBe('invalid_request');
  });

  test('T11.2c-06: preserves strict secret confidentiality across all API responses, database ciphertext storage, and audit/console logs', async () => {
    const auditEvents = [];
    const onAudit = (evt) => auditEvents.push(evt);
    eventBus.on('webhook:endpoint_audit', onAudit);

    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    const infoSpy = jest.spyOn(console, 'info').mockImplementation(() => {});
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    try {
      // 1. Register endpoint
      const postRes = await request(app)
        .post('/api/v1/webhooks')
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .send({
          url: 'https://siem.example.com/webhooks/confidentiality',
          subscribed_events: ['event.processed', 'decision.recorded'],
          description: 'Confidentiality Verification Endpoint'
        })
        .expect(201);

      const endpointId = postRes.body.webhook.id;

      // 2. Inspect raw database row to verify AES-256-GCM encryption at rest
      const dbRecord = await WebhookEndpoint.findByPk(endpointId);
      expect(dbRecord).not.toBeNull();
      expect(dbRecord.encrypted_secret).toMatch(/^[0-9a-f]+$/i);
      expect(dbRecord.secret_iv).toMatch(/^[0-9a-f]{24}$/i); // 12 bytes = 24 hex chars
      expect(dbRecord.secret_auth_tag).toMatch(/^[0-9a-f]{32}$/i); // 16 bytes = 32 hex chars

      // Decrypt secret using server key and verify prefix correspondence & non-plaintext storage
      const decryptedSecret = decryptWebhookSecret(dbRecord);
      expect(decryptedSecret).toMatch(/^whsec_[0-9a-f]{64}$/);
      expect(decryptedSecret.startsWith(dbRecord.secret_prefix)).toBe(true);
      expect(dbRecord.encrypted_secret).not.toContain(decryptedSecret);
      expect(dbRecord.encrypted_secret).not.toContain(decryptedSecret.slice(6));

      // 3. Perform GET list, GET by ID, PATCH, deactivate, activate, and DELETE
      const listRes = await request(app)
        .get('/api/v1/webhooks')
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .expect(200);

      const getRes = await request(app)
        .get(`/api/v1/webhooks/${endpointId}`)
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .expect(200);

      const patchRes = await request(app)
        .patch(`/api/v1/webhooks/${endpointId}`)
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .send({ description: 'Updated description' })
        .expect(200);

      const deactRes = await request(app)
        .post(`/api/v1/webhooks/${endpointId}/deactivate`)
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .expect(200);

      const actRes = await request(app)
        .post(`/api/v1/webhooks/${endpointId}/activate`)
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .expect(200);

      const delRes = await request(app)
        .delete(`/api/v1/webhooks/${endpointId}`)
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .expect(200);

      // 4. Verify ONLY the 201 Created registration response includes one-time `signing_secret`,
      // and NO subsequent response body contains `signing_secret`, plaintext secret, encrypted_secret,
      // secret_iv, secret_auth_tag, or admin/encryption keys.
      expect(postRes.body.webhook.signing_secret).toBe(decryptedSecret);
      expect(JSON.stringify(postRes.body)).not.toContain(dbRecord.encrypted_secret);
      expect(JSON.stringify(postRes.body)).not.toContain(dbRecord.secret_iv);
      expect(JSON.stringify(postRes.body)).not.toContain(dbRecord.secret_auth_tag);
      expect(JSON.stringify(postRes.body)).not.toContain(TEST_ADMIN_API_KEY);
      expect(JSON.stringify(postRes.body)).not.toContain(TEST_ENCRYPTION_KEY_HEX);
      expect(JSON.stringify(postRes.body)).not.toContain('"encrypted_secret"');
      expect(JSON.stringify(postRes.body)).not.toContain('"secret_iv"');
      expect(JSON.stringify(postRes.body)).not.toContain('"secret_auth_tag"');
      expect(JSON.stringify(postRes.body)).not.toContain('"secret"');

      const postCreationResponses = [
        listRes.body,
        getRes.body,
        patchRes.body,
        deactRes.body,
        actRes.body,
        delRes.body
      ];

      for (const body of postCreationResponses) {
        const serialized = JSON.stringify(body);
        expect(serialized).not.toContain(decryptedSecret);
        expect(serialized).not.toContain('"signing_secret"');
        expect(serialized).not.toContain(dbRecord.encrypted_secret);
        expect(serialized).not.toContain(dbRecord.secret_iv);
        expect(serialized).not.toContain(dbRecord.secret_auth_tag);
        expect(serialized).not.toContain(TEST_ADMIN_API_KEY);
        expect(serialized).not.toContain(TEST_ENCRYPTION_KEY_HEX);
        expect(serialized).not.toContain('"encrypted_secret"');
        expect(serialized).not.toContain('"secret_iv"');
        expect(serialized).not.toContain('"secret_auth_tag"');
        expect(serialized).not.toContain('"secret"');
      }

      // 5. Verify audit events and console logs contain zero secret material
      expect(auditEvents.length).toBe(5);
      const serializedAudit = JSON.stringify(auditEvents);
      expect(serializedAudit).not.toContain(decryptedSecret);
      expect(serializedAudit).not.toContain('"signing_secret"');
      expect(serializedAudit).not.toContain(dbRecord.encrypted_secret);
      expect(serializedAudit).not.toContain(TEST_ADMIN_API_KEY);
      expect(serializedAudit).not.toContain(TEST_ENCRYPTION_KEY_HEX);

      const consoleOutput = [
        ...logSpy.mock.calls,
        ...infoSpy.mock.calls,
        ...warnSpy.mock.calls,
        ...errorSpy.mock.calls
      ]
        .flat()
        .map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg)))
        .join(' ');

      expect(consoleOutput).not.toContain(decryptedSecret);
      expect(consoleOutput).not.toContain(dbRecord.encrypted_secret);
      expect(consoleOutput).not.toContain(TEST_ADMIN_API_KEY);
      expect(consoleOutput).not.toContain(TEST_ENCRYPTION_KEY_HEX);
    } finally {
      eventBus.off('webhook:endpoint_audit', onAudit);
    }
  });

  test('T11.2c-07: fails closed with 503 webhook_encryption_unavailable when encryption key is missing in production or invalid/corrupted', async () => {
    // 1. Missing WEBHOOK_SECRET_ENCRYPTION_KEY in production -> 503 webhook_encryption_unavailable
    process.env.NODE_ENV = 'production';
    delete process.env.WEBHOOK_SECRET_ENCRYPTION_KEY;
    delete process.env.WEBHOOK_ENCRYPTION_KEY;

    const missingProdRes = await request(app)
      .post('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send({
        url: 'https://siem.example.com/webhooks',
        subscribed_events: ['event.processed']
      })
      .expect(503);
    expect(missingProdRes.body.error.code).toBe('webhook_encryption_unavailable');
    expect(await WebhookEndpoint.count()).toBe(0);

    // 2. Weak / short WEBHOOK_SECRET_ENCRYPTION_KEY (< 32 chars) in any environment -> 503
    process.env.NODE_ENV = 'test';
    process.env.WEBHOOK_SECRET_ENCRYPTION_KEY = 'too_short_encryption_key_123';

    const shortKeyRes = await request(app)
      .post('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send({
        url: 'https://siem.example.com/webhooks',
        subscribed_events: ['event.processed']
      })
      .expect(503);
    expect(shortKeyRes.body.error.code).toBe('webhook_encryption_unavailable');
    expect(await WebhookEndpoint.count()).toBe(0);

    // 3. Verify AES-256-GCM authentication tag tamper detection in decryptWebhookSecret
    process.env.WEBHOOK_SECRET_ENCRYPTION_KEY = TEST_ENCRYPTION_KEY_HEX;
    const encrypted = encryptWebhookSecret('whsec_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
    const tamperedTag =
      (encrypted.secret_auth_tag[0] === 'a' ? 'b' : 'a') +
      encrypted.secret_auth_tag.slice(1);

    expect(() =>
      decryptWebhookSecret({
        ...encrypted,
        secret_auth_tag: tamperedTag
      })
    ).toThrow(/Unable to decrypt webhook signing secret/i);
  });

  test('T11.2c-08: rejects invalid endpoint IDs with 400, returns 404 for unknown endpoints, and masks database errors behind generic 500 responses', async () => {
    // 1. Invalid endpoint ID formats (non-whk_ prefix, oversized ID, special characters) -> 400 invalid_request
    const invalidIds = [
      'invalid_prefix_12345',
      '1234567890',
      `whk_${'a'.repeat(70)}`,
      'whk_invalid$char!'
    ];

    for (const badId of invalidIds) {
      const getBad = await request(app)
        .get(`/api/v1/webhooks/${badId}`)
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .expect(400);
      expect(getBad.body.error.code).toBe('invalid_request');

      const patchBad = await request(app)
        .patch(`/api/v1/webhooks/${badId}`)
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .send({ is_active: false })
        .expect(400);
      expect(patchBad.body.error.code).toBe('invalid_request');

      const delBad = await request(app)
        .delete(`/api/v1/webhooks/${badId}`)
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .expect(400);
      expect(delBad.body.error.code).toBe('invalid_request');
    }

    // 2. Valid whk_ ID that does not exist -> 404 webhook_not_found
    const missingId = `whk_${crypto.randomUUID()}`;
    await request(app)
      .get(`/api/v1/webhooks/${missingId}`)
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .expect(404);

    await request(app)
      .patch(`/api/v1/webhooks/${missingId}`)
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send({ is_active: false })
      .expect(404);

    await request(app)
      .post(`/api/v1/webhooks/${missingId}/activate`)
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .expect(404);

    await request(app)
      .delete(`/api/v1/webhooks/${missingId}`)
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .expect(404);

    // 3. Database error masking -> returns 500 internal_error without leaking SQL or table details
    jest
      .spyOn(WebhookEndpoint, 'findAndCountAll')
      .mockRejectedValueOnce(
        new Error(
          "ER_NO_SUCH_TABLE: Table 'actionguard.webhook_endpoints' doesn't exist in SQL SELECT * FROM webhook_endpoints"
        )
      );

    const dbErrRes = await request(app)
      .get('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .expect(500);

    expect(dbErrRes.body.error.code).toBe('internal_error');
    expect(JSON.stringify(dbErrRes.body)).not.toContain('ER_NO_SUCH_TABLE');
    expect(JSON.stringify(dbErrRes.body)).not.toContain('webhook_endpoints');
    expect(JSON.stringify(dbErrRes.body)).not.toContain('SELECT');
  });

  test('T11.2c-09: enforces sensitive_action rate limiting on /api/v1/webhooks and remains compatible with existing webhook models and associations', async () => {
    // 1. Verify compatibility with WebhookEndpoint <-> WebhookDeliveryLog associations on registered endpoint
    const regRes = await request(app)
      .post('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send({
        url: 'https://siem.example.com/webhooks/compat',
        subscribed_events: ['event.processed', 'decision.recorded']
      })
      .expect(201);

    const endpointId = regRes.body.webhook.id;
    const logEntry = await WebhookDeliveryLog.create({
      webhook_id: endpointId,
      event_type: 'decision.recorded',
      source_event_id: 'dec_compat_001',
      status: 'pending',
      attempt_count: 1
    });

    const loadedWithLogs = await WebhookEndpoint.findByPk(endpointId, {
      include: [{ model: WebhookDeliveryLog, as: 'deliveryLogs' }]
    });
    expect(loadedWithLogs.deliveryLogs).toHaveLength(1);
    expect(loadedWithLogs.deliveryLogs[0].id).toBe(logEntry.id);

    // 2. Verify sensitive_action rate limiting on /api/v1/webhooks
    const redisClient = redisStorage.getRedisClient();
    await redisClient.del('rate_limit:sensitive_action:127.0.0.1');

    process.env.RATE_LIMIT_SENSITIVE_MAX = '2';
    process.env.RATE_LIMIT_SENSITIVE_WINDOW_MS = '60000';

    const r1 = await request(app)
      .get('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .expect(200);
    expect(r1.headers['x-ratelimit-limit']).toBe('2');
    expect(r1.headers['x-ratelimit-remaining']).toBe('1');

    const r2 = await request(app)
      .get('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .expect(200);
    expect(r2.headers['x-ratelimit-remaining']).toBe('0');

    const r3 = await request(app)
      .get('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .expect(429);
    expect(r3.body.error.code).toBe('rate_limited');
    expect(r3.body.error.tier).toBe('sensitive_action');
    expect(Number(r3.headers['retry-after'])).toBeGreaterThan(0);
  });

  test('T11.2c-10: [F11.2c-01] discloses signing_secret only once in 201 Created response after persistence succeeds and never on failed registration or subsequent endpoints', async () => {
    const auditEvents = [];
    const onAudit = (evt) => auditEvents.push(evt);
    eventBus.on('webhook:endpoint_audit', onAudit);

    try {
      // 1. Simulated database write failure on POST /api/v1/webhooks must NOT disclose any secret or emit an audit event
      jest
        .spyOn(WebhookEndpoint, 'create')
        .mockRejectedValueOnce(new Error('Simulated DB write failure during registration'));

      const failedCreateRes = await request(app)
        .post('/api/v1/webhooks')
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .send({
          url: 'https://siem.example.com/webhooks/fail-write',
          subscribed_events: ['event.processed']
        })
        .expect(500);

      expect(failedCreateRes.body.error.code).toBe('internal_error');
      expect(JSON.stringify(failedCreateRes.body)).not.toContain('whsec_');
      expect(JSON.stringify(failedCreateRes.body)).not.toContain('signing_secret');
      expect(auditEvents).toHaveLength(0);

      // 2. Successful registration returns `signing_secret` once, matching the AES-256-GCM encrypted DB record
      const createRes = await request(app)
        .post('/api/v1/webhooks')
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .send({
          url: 'https://siem.example.com/webhooks/onetime',
          subscribed_events: ['event.processed', 'decision.recorded']
        })
        .expect(201);

      const createdWebhook = createRes.body.webhook;
      expect(createdWebhook.signing_secret).toMatch(/^whsec_[0-9a-f]{64}$/);
      expect(createdWebhook.signing_secret.startsWith(createdWebhook.secret_prefix)).toBe(true);

      const dbRow = await WebhookEndpoint.findByPk(createdWebhook.id);
      expect(dbRow).not.toBeNull();
      expect(decryptWebhookSecret(dbRow)).toBe(createdWebhook.signing_secret);

      // 3. Subsequent list, retrieve, update, deactivate, activate, and delete never return `signing_secret`
      const listRes = await request(app)
        .get('/api/v1/webhooks')
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .expect(200);
      expect(listRes.body.webhooks[0].signing_secret).toBeUndefined();
      expect(JSON.stringify(listRes.body)).not.toContain(createdWebhook.signing_secret);

      const getRes = await request(app)
        .get(`/api/v1/webhooks/${createdWebhook.id}`)
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .expect(200);
      expect(getRes.body.webhook.signing_secret).toBeUndefined();
      expect(JSON.stringify(getRes.body)).not.toContain(createdWebhook.signing_secret);

      const patchRes = await request(app)
        .patch(`/api/v1/webhooks/${createdWebhook.id}`)
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .send({ description: 'No secret returned on patch' })
        .expect(200);
      expect(patchRes.body.webhook.signing_secret).toBeUndefined();
      expect(JSON.stringify(patchRes.body)).not.toContain(createdWebhook.signing_secret);

      const deactRes = await request(app)
        .post(`/api/v1/webhooks/${createdWebhook.id}/deactivate`)
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .expect(200);
      expect(deactRes.body.webhook.signing_secret).toBeUndefined();

      const actRes = await request(app)
        .post(`/api/v1/webhooks/${createdWebhook.id}/activate`)
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .expect(200);
      expect(actRes.body.webhook.signing_secret).toBeUndefined();

      const delRes = await request(app)
        .delete(`/api/v1/webhooks/${createdWebhook.id}`)
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .expect(200);
      expect(JSON.stringify(delRes.body)).not.toContain(createdWebhook.signing_secret);
      expect(JSON.stringify(auditEvents)).not.toContain(createdWebhook.signing_secret);
    } finally {
      eventBus.off('webhook:endpoint_audit', onAudit);
    }
  });

  test('T11.2c-11: [F11.2c-02] validates administrator configuration before inspecting non-admin credentials and enforces consistent rules across headers', async () => {
    const verifyJwtSpy = jest.spyOn(authMiddleware, 'verifyUserAndSessionToken');
    const findAllSpy = jest.spyOn(WebhookEndpoint, 'findAndCountAll');

    // 1. Missing administrator configuration with a valid user JWT -> 401 without calling verifyUserAndSessionToken
    delete process.env.ACTIONGUARD_ADMIN_API_KEY;
    const missingAdminWithJwt = await request(app)
      .get('/api/v1/webhooks')
      .set('Authorization', `Bearer ${validUserJwt}`)
      .expect(401);
    expect(missingAdminWithJwt.body.error.code).toBe('unauthorized');
    expect(verifyJwtSpy).not.toHaveBeenCalled();
    expect(findAllSpy).not.toHaveBeenCalled();

    // 2. Too-short administrator configuration with a valid service key -> 401 (not 403)
    process.env.ACTIONGUARD_ADMIN_API_KEY = 'short_admin_key_under_32_chars';
    const shortAdminWithServiceBearer = await request(app)
      .get('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_SERVICE_API_KEY}`)
      .expect(401);
    expect(shortAdminWithServiceBearer.body.error.code).toBe('unauthorized');

    const shortAdminWithServiceHeader = await request(app)
      .get('/api/v1/webhooks')
      .set('X-Admin-Api-Key', TEST_SERVICE_API_KEY)
      .expect(401);
    expect(shortAdminWithServiceHeader.body.error.code).toBe('unauthorized');
    expect(findAllSpy).not.toHaveBeenCalled();

    // 3. Administrator key equal to the ordinary service key -> 401 in both header forms
    process.env.ACTIONGUARD_ADMIN_API_KEY = TEST_SERVICE_API_KEY;
    const equalKeyBearer = await request(app)
      .get('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_SERVICE_API_KEY}`)
      .expect(401);
    expect(equalKeyBearer.body.error.code).toBe('unauthorized');

    const equalKeyHeader = await request(app)
      .get('/api/v1/webhooks')
      .set('X-Admin-Api-Key', TEST_SERVICE_API_KEY)
      .expect(401);
    expect(equalKeyHeader.body.error.code).toBe('unauthorized');
    expect(findAllSpy).not.toHaveBeenCalled();

    // 4. Valid administrator configuration with ordinary service credentials in BOTH header forms -> 403 forbidden
    process.env.ACTIONGUARD_ADMIN_API_KEY = TEST_ADMIN_API_KEY;
    const serviceBearerRes = await request(app)
      .get('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_SERVICE_API_KEY}`)
      .expect(403);
    expect(serviceBearerRes.body.error.code).toBe('forbidden');

    const serviceHeaderRes = await request(app)
      .get('/api/v1/webhooks')
      .set('X-Admin-Api-Key', TEST_SERVICE_API_KEY)
      .expect(403);
    expect(serviceHeaderRes.body.error.code).toBe('forbidden');

    // Valid user JWT in X-Admin-Api-Key also receives 403 forbidden when admin config is valid
    const userJwtHeaderRes = await request(app)
      .get('/api/v1/webhooks')
      .set('X-Admin-Api-Key', validUserJwt)
      .expect(403);
    expect(userJwtHeaderRes.body.error.code).toBe('forbidden');
    expect(findAllSpy).not.toHaveBeenCalled();

    // 5. Valid administrator key and conflicting credentials -> 401 unauthorized
    const conflictingRes1 = await request(app)
      .get('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .set('X-Admin-Api-Key', TEST_ADMIN_API_KEY)
      .expect(401);
    expect(conflictingRes1.body.error.code).toBe('unauthorized');

    const conflictingRes2 = await request(app)
      .get('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_SERVICE_API_KEY}`)
      .set('X-Admin-Api-Key', TEST_ADMIN_API_KEY)
      .expect(401);
    expect(conflictingRes2.body.error.code).toBe('unauthorized');
    expect(findAllSpy).not.toHaveBeenCalled();

    // 6. Malformed headers and query-string credentials -> 401 unauthorized without reaching handlers
    const malformedCases = [
      { header: 'Authorization', value: `Basic ${TEST_ADMIN_API_KEY}` },
      { header: 'Authorization', value: 'Bearer' },
      { header: 'Authorization', value: 'Bearer   ' },
      { header: 'Authorization', value: `Bearer ${TEST_ADMIN_API_KEY} extra` },
      { header: 'X-Admin-Api-Key', value: '   ' },
      { header: 'X-Admin-Api-Key', value: `Bearer ${TEST_ADMIN_API_KEY}` }
    ];

    for (const tc of malformedCases) {
      const res = await request(app)
        .get('/api/v1/webhooks')
        .set(tc.header, tc.value)
        .expect(401);
      expect(res.body.error.code).toBe('unauthorized');
    }

    const queryKeys = ['apiKey', 'api_key', 'adminApiKey', 'admin_api_key', 'token', 'access_token'];
    for (const qk of queryKeys) {
      const res = await request(app)
        .get(`/api/v1/webhooks?${qk}=${TEST_ADMIN_API_KEY}`)
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .expect(401);
      expect(res.body.error.code).toBe('unauthorized');
    }
    expect(findAllSpy).not.toHaveBeenCalled();
  });

  test('T11.2c-12: [F11.2c-03] rejects IPv6 transition/special-purpose and IPv4 special-purpose SSRF destinations while allowing public IPv4 and IPv6 addresses', async () => {
    const prohibitedSpecialDestinations = [
      'https://[::127.0.0.1]/hook',
      'https://[::169.254.169.254]/hook',
      'https://[64:ff9b::127.0.0.1]/hook',
      'https://[64:ff9b:1::1]/hook',
      'https://[2002:7f00:0001::1]/hook',
      'https://[2001::1]/hook',
      'https://[2001:2::1]/hook',
      'https://[2001:db8::1]/hook',
      'https://[100::1]/hook',
      'https://[::ffff:127.0.0.1]/hook',
      'https://[0:0:0:0:0:ffff:127.0.0.1]/hook',
      'https://[::ffff:169.254.169.254]/hook',
      'https://[0:0:0:0:0:ffff:169.254.169.254]/hook',
      'https://192.0.0.1/hook',
      'https://192.0.2.1/hook',
      'https://192.88.99.1/hook',
      'https://198.18.0.1/hook',
      'https://198.19.255.254/hook',
      'https://198.51.100.1/hook',
      'https://203.0.113.1/hook'
    ];

    for (const forbiddenUrl of prohibitedSpecialDestinations) {
      const res = await request(app)
        .post('/api/v1/webhooks')
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .send({
          url: forbiddenUrl,
          subscribed_events: ['event.processed']
        })
        .expect(400);
      expect(res.body.error.code).toBe('invalid_webhook_url');
    }

    // Positive tests: ordinary public IPv4 and Global Unicast IPv6 addresses are accepted
    const publicIpv4Res = await request(app)
      .post('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send({
        url: 'https://93.184.216.34/webhooks/actionguard',
        subscribed_events: ['event.processed']
      })
      .expect(201);
    expect(publicIpv4Res.body.webhook.url).toBe('https://93.184.216.34/webhooks/actionguard');

    const publicIpv6Res = await request(app)
      .post('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send({
        url: 'https://[2606:4700:4700::1111]/webhooks/actionguard',
        subscribed_events: ['decision.recorded']
      })
      .expect(201);
    expect(publicIpv6Res.body.webhook.url).toBe(
      'https://[2606:4700:4700::1111]/webhooks/actionguard'
    );

    // Update endpoint to another public Global Unicast IPv6 (2001:4860:4860::8888) succeeds
    const patchPublicIpv6 = await request(app)
      .patch(`/api/v1/webhooks/${publicIpv6Res.body.webhook.id}`)
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send({
        url: 'https://[2001:4860:4860::8888]/webhooks/v2'
      })
      .expect(200);
    expect(patchPublicIpv6.body.webhook.url).toBe(
      'https://[2001:4860:4860::8888]/webhooks/v2'
    );

    // Updating an existing endpoint to any prohibited special-purpose IPv6/IPv4 is rejected consistently
    for (const forbiddenUrl of prohibitedSpecialDestinations.slice(0, 8)) {
      const badPatch = await request(app)
        .patch(`/api/v1/webhooks/${publicIpv6Res.body.webhook.id}`)
        .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
        .send({ url: forbiddenUrl })
        .expect(400);
      expect(badPatch.body.error.code).toBe('invalid_webhook_url');
    }
  });

  test('T11.2c-13: [F11.2c-04] requires explicit WEBHOOK_SECRET_ENCRYPTION_KEY outside test environment and decrypts persisted secrets across key-resolver reinitialization', async () => {
    // 1. In NODE_ENV=development, missing WEBHOOK_SECRET_ENCRYPTION_KEY fails closed with 503 (no silent ephemeral key)
    process.env.NODE_ENV = 'development';
    delete process.env.WEBHOOK_SECRET_ENCRYPTION_KEY;
    delete process.env.WEBHOOK_ENCRYPTION_KEY;

    const devMissingKeyRes = await request(app)
      .post('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send({
        url: 'https://siem.example.com/webhooks/dev-no-key',
        subscribed_events: ['event.processed']
      })
      .expect(503);
    expect(devMissingKeyRes.body.error.code).toBe('webhook_encryption_unavailable');
    expect(await WebhookEndpoint.count()).toBe(0);

    // 2. With an explicit WEBHOOK_SECRET_ENCRYPTION_KEY configured in development, registration succeeds
    process.env.WEBHOOK_SECRET_ENCRYPTION_KEY = TEST_ENCRYPTION_KEY_HEX;
    const devCreatedRes = await request(app)
      .post('/api/v1/webhooks')
      .set('Authorization', `Bearer ${TEST_ADMIN_API_KEY}`)
      .send({
        url: 'https://siem.example.com/webhooks/dev-with-key',
        subscribed_events: ['event.processed']
      })
      .expect(201);

    const disclosedSecret = devCreatedRes.body.webhook.signing_secret;
    const persistedRow = await WebhookEndpoint.findByPk(devCreatedRes.body.webhook.id);

    // 3. Reinitialize key-resolution state and re-require webhookCrypto to simulate an application restart / separate worker process
    resetEphemeralTestEncryptionKey();
    jest.resetModules();
    const reloadedCrypto = require('../src/utils/webhookCrypto');

    const decryptedAfterRestart = reloadedCrypto.decryptWebhookSecret(persistedRow, {
      NODE_ENV: 'development',
      WEBHOOK_SECRET_ENCRYPTION_KEY: TEST_ENCRYPTION_KEY_HEX
    });
    expect(decryptedAfterRestart).toBe(disclosedSecret);

    // 4. Attempting to decrypt in development when WEBHOOK_SECRET_ENCRYPTION_KEY is absent fails closed with 503
    expect(() =>
      reloadedCrypto.decryptWebhookSecret(persistedRow, {
        NODE_ENV: 'development'
      })
    ).toThrow(/Webhook secret encryption key is not configured/i);
  });

  test('T11.2c-14: [F11.2c-05] enforces destination URL validation at the WebhookEndpoint model layer even when bypassing webhookEndpointService', async () => {
    const baseModelFields = {
      subscribed_events: ['event.processed'],
      encrypted_secret: 'deadbeef0123456789abcdef',
      secret_iv: '00112233445566778899aabb',
      secret_auth_tag: 'ccddeeff00112233445566778899aabb',
      secret_prefix: 'whsec_12345678',
      is_active: true
    };

    const prohibitedModelUrls = [
      'http://insecure.example.com/hook',
      'https://127.0.0.1/hook',
      'https://[::127.0.0.1]/hook',
      'https://169.254.169.254/latest/meta-data/',
      'https://[64:ff9b::127.0.0.1]/hook',
      'https://localhost/hook',
      'https://internal-host/hook',
      'https://user:pass@siem.example.com/hook',
      'https://siem.example.com/hook#fragment'
    ];

    for (const badUrl of prohibitedModelUrls) {
      await expect(
        WebhookEndpoint.create({
          ...baseModelFields,
          url: badUrl
        })
      ).rejects.toThrow();
    }

    // Direct model creation with a valid public HTTPS URL succeeds
    const validRecord = await WebhookEndpoint.create({
      ...baseModelFields,
      url: 'https://siem.example.com/webhooks/direct-model'
    });
    expect(validRecord.id).toMatch(/^whk_/);

    // Direct model update to a prohibited URL is also rejected
    for (const badUrl of prohibitedModelUrls) {
      await expect(validRecord.update({ url: badUrl })).rejects.toThrow();
    }
  });
});
