'use strict';

const http = require('http');
const jwt = require('jsonwebtoken');
const request = require('supertest');
const app = require('../src/app');
const {
  User,
  Session,
  SecurityEvent,
  RiskAssessment,
  PolicyDecision,
  WebhookEndpoint,
  WebhookDeliveryLog
} = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const redisStorage = require('../src/storage/redis');
const authMiddleware = require('../src/middleware/auth');
const { JWT_SECRET } = authMiddleware;
const { createSession } = require('../src/services/sessionService');
const { recordSecurityEvent } = require('../src/services/eventService');
const eventBus = require('../src/events/eventBus');
const {
  verifyWebhookSignature
} = require('../src/utils/webhookCrypto');
const {
  enqueueWebhooksForEvent,
  reconcileMissingWebhookEnqueues
} = require('../src/services/webhookDeliveryService');
const {
  attachWebhookEventListeners,
  detachWebhookEventListeners,
  flushInFlightWebhookEnqueues,
  runWebhookWorkerCycle,
  startWebhookDeliveryWorker,
  stopWebhookDeliveryWorker,
  isWebhookDeliveryWorkerRunning
} = require('../src/jobs/webhookDeliveryWorker');

const TEST_ADMIN_API_KEY = 'adm_stage2b_worker_test_key_0123456789abcdef';
const TEST_SERVICE_API_KEY = 'svc_stage2b_worker_test_key_0123456789abcdef';
const TEST_ENCRYPTION_KEY_HEX =
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

/**
 * Polls an async predicate until it returns a truthy value or times out.
 */
async function waitForCondition(predicate, timeoutMs = 4000, intervalMs = 25) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() <= deadline) {
    try {
      const result = await predicate();
      if (result) {
        return result;
      }
    } catch (err) {
      lastError = err;
    }
    await new Promise((resolve) => {
      const timer = setTimeout(resolve, intervalMs);
      if (typeof timer.unref === 'function') {
        timer.unref();
      }
    });
  }
  if (lastError) {
    throw lastError;
  }
  throw new Error(`Condition not met within ${timeoutMs}ms`);
}

/**
 * Starts a local ephemeral HTTP receiver server on 127.0.0.1:0.
 */
function startEphemeralReceiver(handler) {
  const received = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const rawBody = Buffer.concat(chunks).toString('utf8');
      let parsedBody = null;
      try {
        parsedBody = JSON.parse(rawBody);
      } catch {
        parsedBody = null;
      }
      const entry = {
        method: req.method,
        url: req.url,
        headers: req.headers,
        rawBody,
        body: parsedBody
      };
      received.push(entry);
      if (typeof handler === 'function') {
        handler(entry, req, res);
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      }
    });
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const baseUrl = `http://127.0.0.1:${address.port}`;
      resolve({
        server,
        baseUrl,
        received,
        close: () =>
          new Promise((resClose) => {
            server.close(() => resClose());
          })
      });
    });
  });
}

describe('Module 11.2c Stage 2B — Webhook Delivery Worker & Integration', () => {
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
    'WEBHOOK_ALLOW_INSECURE_HTTP',
    'WEBHOOK_ALLOW_LOCAL_TARGETS'
  ];
  const activeServers = [];
  const createdUserIds = [];
  const createdSessionIds = [];

  async function createReceiver(handler) {
    const receiver = await startEphemeralReceiver(handler);
    activeServers.push(receiver);
    return receiver;
  }

  beforeAll(async () => {
    for (const k of ENV_KEYS) {
      savedEnv[k] = process.env[k];
    }
    await runMigrations();
  });

  beforeEach(async () => {
    await stopWebhookDeliveryWorker();
    detachWebhookEventListeners();

    for (const k of ENV_KEYS) {
      if (savedEnv[k] === undefined) {
        delete process.env[k];
      } else {
        process.env[k] = savedEnv[k];
      }
    }

    process.env.NODE_ENV = 'test';
    process.env.ACTIONGUARD_ADMIN_API_KEY = TEST_ADMIN_API_KEY;
    process.env.API_KEY = TEST_SERVICE_API_KEY;
    process.env.ACTIONGUARD_API_KEY = TEST_SERVICE_API_KEY;
    process.env.WEBHOOK_SECRET_ENCRYPTION_KEY = TEST_ENCRYPTION_KEY_HEX;
    process.env.ALLOW_INSECURE_HTTP_WEBHOOKS = 'true';
    process.env.ALLOW_LOCAL_WEBHOOK_TARGETS = 'true';
    process.env.WEBHOOK_ALLOW_INSECURE_HTTP = 'true';
    process.env.WEBHOOK_ALLOW_LOCAL_TARGETS = 'true';

    const redisClient = redisStorage.getRedisClient();
    if (redisClient) {
      await redisClient.del('rate_limit:sensitive_action:127.0.0.1');
    }

    await WebhookDeliveryLog.destroy({ where: {} });
    await WebhookEndpoint.destroy({ where: {} });
  });

  afterEach(async () => {
    await stopWebhookDeliveryWorker();
    detachWebhookEventListeners();

    while (activeServers.length > 0) {
      const srv = activeServers.pop();
      await srv.close();
    }

    const redisClient = redisStorage.getRedisClient();
    if (redisClient) {
      await redisClient.del('rate_limit:sensitive_action:127.0.0.1');
      while (createdSessionIds.length > 0) {
        const sid = createdSessionIds.pop();
        await redisStorage.deleteSession(sid);
      }
    }

    while (createdUserIds.length > 0) {
      const uid = createdUserIds.pop();
      await PolicyDecision.destroy({ where: { user_id: uid } });
      const userEvents = await SecurityEvent.findAll({
        where: { user_id: uid },
        attributes: ['event_id']
      });
      for (const evt of userEvents) {
        await RiskAssessment.destroy({ where: { event_id: evt.event_id } });
      }
      await SecurityEvent.destroy({ where: { user_id: uid } });
      await Session.destroy({ where: { user_id: uid } });
      await User.destroy({ where: { id: uid } });
    }
  });

  afterAll(async () => {
    await stopWebhookDeliveryWorker();
    detachWebhookEventListeners();
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

  async function seedUserAndSession(suffix = '1') {
    const user = await User.create({
      email: `stage2b_${suffix}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}@example.com`,
      password_hash: '$2b$10$abcdefghijklmnopqrstuv1234567890abcdefghijklmnopqrstu'
    });
    createdUserIds.push(user.id);

    const fp = `fp_stage2b_${suffix}_device_01`;
    const sessionInfo = await createSession(user.id, user.email, 900, {
      device_fingerprint: fp,
      ip_address: '198.51.100.42'
    });
    createdSessionIds.push(sessionInfo.sessionId);

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        session_id: sessionInfo.sessionId
      },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    return {
      user,
      session: {
        id: sessionInfo.sessionId,
        device_fingerprint: fp,
        ip_address: '198.51.100.42'
      },
      token
    };
  }

  describe('1. End-to-end event processing to webhook delivery and signature verification', () => {
    test('delivers signed event.processed webhook payload when pipeline:event_processed fires', async () => {
      const receiver = await createReceiver();

      const registerRes = await request(app)
        .post('/api/v1/webhooks')
        .set('X-Admin-Api-Key', TEST_ADMIN_API_KEY)
        .send({
          url: `${receiver.baseUrl}/hooks/events`,
          subscribed_events: ['event.processed'],
          description: 'E2E Event Receiver',
          is_active: true
        })
        .expect(201);

      const endpointId = registerRes.body.webhook.id;
      const signingSecret = registerRes.body.webhook.signing_secret;
      expect(signingSecret).toMatch(/^whsec_[0-9a-f]{64}$/);

      await startWebhookDeliveryWorker({
        pollIntervalMs: 40,
        reconcileIntervalMs: 60000
      });

      const { user, session } = await seedUserAndSession('evt_e2e');

      const event = await recordSecurityEvent({
        user_id: user.id,
        session_id: session.id,
        event_type: 'high_impact_action',
        context: {
          ip_address: '198.51.100.42',
          device_fingerprint: session.device_fingerprint,
          country: 'US',
          region: 'CA'
        },
        metadata: {
          operation: 'export_data',
          action_sensitivity: 'high'
        },
        timestamp: new Date()
      });
      const assessment = event._assessment;

      const deliveredReq = await waitForCondition(
        () => (receiver.received.length > 0 ? receiver.received[0] : null),
        4000,
        25
      );

      expect(deliveredReq.method).toBe('POST');
      expect(deliveredReq.url).toBe('/hooks/events');
      expect(deliveredReq.headers['x-actionguard-webhook-event']).toBe('event.processed');
      expect(deliveredReq.headers['x-actionguard-webhook-id']).toMatch(/^whdel_/);
      expect(deliveredReq.headers['x-actionguard-webhook-timestamp']).toMatch(/^\d+$/);
      expect(deliveredReq.headers['user-agent']).toBe('ActionGuard-Webhook/1.0');

      const sigHeader = deliveredReq.headers['x-actionguard-webhook-signature'];
      const tsHeader = deliveredReq.headers['x-actionguard-webhook-timestamp'];
      const verifiedSig = verifyWebhookSignature({
        secret: signingSecret,
        rawBody: deliveredReq.rawBody,
        signatureHeader: sigHeader,
        timestampHeader: tsHeader,
        nowSeconds: Math.floor(Date.now() / 1000)
      });
      expect(verifiedSig).toBe(true);

      expect(deliveredReq.body).toMatchObject({
        id: deliveredReq.headers['x-actionguard-webhook-id'],
        webhook_id: endpointId,
        event_type: 'event.processed',
        source_event_id: event.event_id,
        data: {
          event_id: event.event_id,
          user_id: user.id,
          session_id: session.id,
          event_type: 'high_impact_action',
          risk: {
            risk_score: assessment.risk_score,
            risk_tier: assessment.risk_tier
          }
        }
      });

      // Confirm sensitive fields are excluded from outbound payload
      expect(deliveredReq.body.data.ip_address).toBeUndefined();
      expect(deliveredReq.body.data.device_fingerprint).toBeUndefined();

      const deliveryRow = await waitForCondition(async () => {
        const row = await WebhookDeliveryLog.findOne({
          where: {
            webhook_id: endpointId,
            event_type: 'event.processed',
            source_event_id: event.event_id
          }
        });
        return row && row.status === 'delivered' ? row : null;
      });

      expect(deliveryRow.status).toBe('delivered');
      expect(deliveryRow.http_status).toBe(200);
      expect(deliveryRow.attempt_count).toBe(1);
    });
  });

  describe('2. End-to-end policy decision recording to webhook delivery and signature verification', () => {
    test('delivers signed decision.recorded webhook payload when policy:decision_recorded fires', async () => {
      const receiver = await createReceiver();

      const registerRes = await request(app)
        .post('/api/v1/webhooks')
        .set('X-Admin-Api-Key', TEST_ADMIN_API_KEY)
        .send({
          url: `${receiver.baseUrl}/hooks/decisions`,
          subscribed_events: ['decision.recorded'],
          description: 'E2E Decision Receiver',
          is_active: true
        })
        .expect(201);

      const endpointId = registerRes.body.webhook.id;
      const signingSecret = registerRes.body.webhook.signing_secret;

      await startWebhookDeliveryWorker({
        pollIntervalMs: 40,
        reconcileIntervalMs: 60000
      });

      const { user, session } = await seedUserAndSession('dec_e2e');
      const event = await recordSecurityEvent({
        user_id: user.id,
        session_id: session.id,
        event_type: 'password_change',
        context: {
          ip_address: '198.51.100.42',
          device_fingerprint: session.device_fingerprint
        },
        timestamp: new Date()
      });
      const assessment = event._assessment;

      const now = new Date();
      const decisionRecord = await PolicyDecision.create({
        id: `dec_stage2b_${Date.now()}`,
        event_id: event.event_id,
        risk_assessment_id: assessment.id,
        user_id: user.id,
        session_id: session.id,
        action_type: 'password_change',
        action_sensitivity: 'critical',
        risk_score: assessment.risk_score,
        risk_tier: assessment.risk_tier,
        recommended_decision: 'reverify',
        effective_decision: 'reverify',
        enforcement_outcome: 'step_up_challenged',
        enforcement_mode: 'automatic',
        reasons: [{ source: 'base_matrix', rule_id: 'test_rule', decision: 'reverify' }],
        contributing_signals: assessment.contributing_signals || [],
        explanation: {
          user_facing: 'Please verify your identity.',
          admin_facing: 'Sensitive action requires verification.'
        },
        policy_version: 'default-v1@1.0.0',
        decided_at: now
      });

      eventBus.safeEmit('policy:decision_recorded', {
        decision: decisionRecord.toJSON()
      });

      const deliveredReq = await waitForCondition(
        () => (receiver.received.length > 0 ? receiver.received[0] : null),
        4000,
        25
      );

      expect(deliveredReq.method).toBe('POST');
      expect(deliveredReq.url).toBe('/hooks/decisions');
      expect(deliveredReq.headers['x-actionguard-webhook-event']).toBe('decision.recorded');
      const verifiedSig = verifyWebhookSignature({
        secret: signingSecret,
        rawBody: deliveredReq.rawBody,
        signatureHeader: deliveredReq.headers['x-actionguard-webhook-signature'],
        timestampHeader: deliveredReq.headers['x-actionguard-webhook-timestamp'],
        nowSeconds: Math.floor(Date.now() / 1000)
      });
      expect(verifiedSig).toBe(true);

      expect(deliveredReq.body).toMatchObject({
        id: deliveredReq.headers['x-actionguard-webhook-id'],
        webhook_id: endpointId,
        event_type: 'decision.recorded',
        source_event_id: decisionRecord.id,
        data: {
          decision_id: decisionRecord.id,
          event_id: event.event_id,
          risk_assessment_id: assessment.id,
          user_id: user.id,
          session_id: session.id,
          action_type: 'password_change',
          effective_decision: 'reverify',
          enforcement_outcome: 'step_up_challenged'
        }
      });

      const deliveryRow = await waitForCondition(async () => {
        const row = await WebhookDeliveryLog.findOne({
          where: {
            webhook_id: endpointId,
            event_type: 'decision.recorded',
            source_event_id: decisionRecord.id
          }
        });
        return row && row.status === 'delivered' ? row : null;
      });

      expect(deliveryRow.status).toBe('delivered');
      expect(deliveryRow.http_status).toBe(200);
    });
  });

  describe('3. Inactive or unsubscribed endpoints not receiving events', () => {
    test('does not enqueue or deliver events to inactive or unsubscribed webhook endpoints', async () => {
      const activeSubscribedReceiver = await createReceiver();
      const inactiveReceiver = await createReceiver();
      const unsubscribedReceiver = await createReceiver();

      await request(app)
        .post('/api/v1/webhooks')
        .set('X-Admin-Api-Key', TEST_ADMIN_API_KEY)
        .send({
          url: `${activeSubscribedReceiver.baseUrl}/active`,
          subscribed_events: ['event.processed'],
          is_active: true
        })
        .expect(201);

      const inactiveRes = await request(app)
        .post('/api/v1/webhooks')
        .set('X-Admin-Api-Key', TEST_ADMIN_API_KEY)
        .send({
          url: `${inactiveReceiver.baseUrl}/inactive`,
          subscribed_events: ['event.processed'],
          is_active: false
        })
        .expect(201);

      const unsubscribedRes = await request(app)
        .post('/api/v1/webhooks')
        .set('X-Admin-Api-Key', TEST_ADMIN_API_KEY)
        .send({
          url: `${unsubscribedReceiver.baseUrl}/decision-only`,
          subscribed_events: ['decision.recorded'],
          is_active: true
        })
        .expect(201);

      attachWebhookEventListeners();

      const { user, session } = await seedUserAndSession('filter_sub');
      const event = await recordSecurityEvent({
        user_id: user.id,
        session_id: session.id,
        event_type: 'login_success',
        context: {
          ip_address: '198.51.100.42',
          device_fingerprint: session.device_fingerprint
        },
        timestamp: new Date()
      });

      await flushInFlightWebhookEnqueues();
      await runWebhookWorkerCycle();

      expect(activeSubscribedReceiver.received).toHaveLength(1);
      expect(inactiveReceiver.received).toHaveLength(0);
      expect(unsubscribedReceiver.received).toHaveLength(0);

      const allLogs = await WebhookDeliveryLog.findAll({
        where: { source_event_id: event.event_id }
      });
      expect(allLogs).toHaveLength(1);
      expect(allLogs[0].webhook_id).not.toBe(inactiveRes.body.webhook.id);
      expect(allLogs[0].webhook_id).not.toBe(unsubscribedRes.body.webhook.id);
    });
  });

  describe('4. Receiver failure not breaking core event processing or policy decisions', () => {
    test('core event ingestion and policy decision flow succeed even when webhook receiver returns 503', async () => {
      const failingReceiver = await createReceiver((_entry, _req, res) => {
        res.writeHead(503, { 'Content-Type': 'text/plain' });
        res.end('Downstream SIEM unavailable');
      });

      await request(app)
        .post('/api/v1/webhooks')
        .set('X-Admin-Api-Key', TEST_ADMIN_API_KEY)
        .send({
          url: `${failingReceiver.baseUrl}/failing`,
          subscribed_events: ['event.processed', 'decision.recorded'],
          is_active: true
        })
        .expect(201);

      attachWebhookEventListeners();

      const { user, session, token } = await seedUserAndSession('non_blocking');

      // Core event ingestion via POST /api/v1/events succeeds
      const ingestRes = await request(app)
        .post('/api/v1/events')
        .set('Authorization', `Bearer ${TEST_SERVICE_API_KEY}`)
        .send({
          idempotency_key: `idem_stage2b_${Date.now()}`,
          user_id: user.id,
          session_id: session.id,
          event_type: 'login_success',
          context: {
            ip_address: '198.51.100.42',
            device_fingerprint: session.device_fingerprint
          },
          timestamp: new Date().toISOString()
        });

      expect([200, 201]).toContain(ingestRes.status);
      expect(ingestRes.body.event_id).toBeDefined();

      // Core PEP protected action succeeds and records PolicyDecision
      const pepRes = await request(app)
        .post('/api/v1/account/phone')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Device-Fingerprint', session.device_fingerprint)
        .send({ phone_number: '+14155552671' });

      expect([200, 202, 403]).toContain(pepRes.status);

      await flushInFlightWebhookEnqueues();
      await runWebhookWorkerCycle();

      expect(failingReceiver.received.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('5. Worker retry and terminal failure behavior', () => {
    test('schedules retry with backoff on 5xx and transitions to terminal failed on 4xx or max attempts', async () => {
      let respondStatus = 502;
      const receiver = await createReceiver((_entry, _req, res) => {
        res.writeHead(respondStatus, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'simulated receiver error' }));
      });

      const registerRes = await request(app)
        .post('/api/v1/webhooks')
        .set('X-Admin-Api-Key', TEST_ADMIN_API_KEY)
        .send({
          url: `${receiver.baseUrl}/retry-test`,
          subscribed_events: ['event.processed'],
          is_active: true
        })
        .expect(201);

      const endpointId = registerRes.body.webhook.id;
      const { user, session } = await seedUserAndSession('retry_worker');
      const event = await recordSecurityEvent({
        user_id: user.id,
        session_id: session.id,
        event_type: 'login_success',
        context: {
          ip_address: '198.51.100.42',
          device_fingerprint: session.device_fingerprint
        },
        timestamp: new Date()
      });

      await enqueueWebhooksForEvent({
        eventType: 'event.processed',
        sourceEventId: event.event_id
      });

      // Attempt 1 -> 502 -> stays pending with attempt_count=1 and future next_attempt_at
      await runWebhookWorkerCycle();
      let row = await WebhookDeliveryLog.findOne({
        where: { webhook_id: endpointId, source_event_id: event.event_id }
      });
      expect(row.status).toBe('pending');
      expect(row.attempt_count).toBe(1);
      expect(row.http_status).toBe(502);
      expect(row.error_code).toBe('HTTP_502');
      expect(new Date(row.next_attempt_at).getTime()).toBeGreaterThan(Date.now());

      // Fast-forward next_attempt_at to now and switch receiver to non-retryable 400
      respondStatus = 400;
      await row.update({ next_attempt_at: new Date(Date.now() - 1000) });

      await runWebhookWorkerCycle();
      row = await WebhookDeliveryLog.findByPk(row.id);
      expect(row.status).toBe('failed');
      expect(row.attempt_count).toBe(2);
      expect(row.http_status).toBe(400);
      expect(row.error_code).toBe('HTTP_400');
      expect(row.next_attempt_at).toBeNull();
    });
  });

  describe('6. Missing-job reconciliation after a simulated crash between record commit and enqueue', () => {
    test('reconcileMissingWebhookEnqueues recovers missing event.processed and decision.recorded jobs and respects eligibility and endpoint created_at', async () => {
      const reconcileNow = new Date(Date.now() + 60 * 60 * 1000);
      const earlyEndpointTime = new Date(reconcileNow.getTime() - 120 * 1000);
      const eventTime = new Date(reconcileNow.getTime() - 60 * 1000);
      const lateEndpointTime = new Date(reconcileNow.getTime() - 10 * 1000);

      const receiver = await createReceiver();

      // Endpoint created BEFORE the event occurred -> eligible for reconciliation
      const earlyReg = await request(app)
        .post('/api/v1/webhooks')
        .set('X-Admin-Api-Key', TEST_ADMIN_API_KEY)
        .send({
          url: `${receiver.baseUrl}/early`,
          subscribed_events: ['event.processed', 'decision.recorded'],
          is_active: true
        })
        .expect(201);
      await WebhookEndpoint.update(
        { created_at: earlyEndpointTime, updated_at: earlyEndpointTime },
        { where: { id: earlyReg.body.webhook.id } }
      );

      // Endpoint created AFTER the event occurred -> must NOT receive historical backfills
      const lateReg = await request(app)
        .post('/api/v1/webhooks')
        .set('X-Admin-Api-Key', TEST_ADMIN_API_KEY)
        .send({
          url: `${receiver.baseUrl}/late`,
          subscribed_events: ['event.processed', 'decision.recorded'],
          is_active: true
        })
        .expect(201);
      await WebhookEndpoint.update(
        { created_at: lateEndpointTime, updated_at: lateEndpointTime },
        { where: { id: lateReg.body.webhook.id } }
      );

      const { user, session } = await seedUserAndSession('reconcile');

      // 1) Scored event WITH RiskAssessment committed, but webhook enqueue was skipped (simulated crash)
      const eligibleEvent = await SecurityEvent.create({
        event_id: `evt_reconcile_ok_${Date.now()}`,
        user_id: user.id,
        session_id: session.id,
        event_type: 'login_success',
        context: {
          ip_address: '198.51.100.42',
          device_fingerprint: session.device_fingerprint
        },
        metadata: {
          containment_status: 'not_applicable'
        },
        timestamp: eventTime,
        created_at: eventTime
      });
      const assessment = await RiskAssessment.create({
        id: `ass_reconcile_ok_${Date.now()}`,
        event_id: eligibleEvent.event_id,
        user_id: user.id,
        session_id: session.id,
        risk_score: 25,
        risk_tier: 'low',
        contributing_signals: [],
        explanation: { user_facing: 'Normal', admin_facing: 'Normal' },
        evaluated_at: eventTime
      });

      // 2) Scored event WITHOUT RiskAssessment (scoring failed) -> must NOT be enqueued
      const unscoredFailureEvent = await SecurityEvent.create({
        event_id: `evt_reconcile_no_ass_${Date.now()}`,
        user_id: user.id,
        session_id: session.id,
        event_type: 'login_failed',
        context: {
          ip_address: '198.51.100.42',
          device_fingerprint: session.device_fingerprint
        },
        metadata: {
          containment_status: 'not_applicable'
        },
        timestamp: eventTime,
        created_at: eventTime
      });

      // 3) PolicyDecision on eligible event -> must be enqueued
      const eligibleDecision = await PolicyDecision.create({
        id: `dec_reconcile_ok_${Date.now()}`,
        event_id: eligibleEvent.event_id,
        risk_assessment_id: assessment.id,
        user_id: user.id,
        session_id: session.id,
        action_type: 'phone_number_change',
        action_sensitivity: 'medium',
        risk_score: 25,
        risk_tier: 'low',
        recommended_decision: 'allow',
        effective_decision: 'allow',
        enforcement_outcome: 'allowed',
        enforcement_mode: 'automatic',
        reasons: [],
        contributing_signals: [],
        explanation: { user_facing: 'Allowed', admin_facing: 'Allowed' },
        policy_version: 'default-v1@1.0.0',
        decided_at: eventTime
      });

      // 4) PolicyDecision linked to a failed containment event -> must NOT be enqueued
      const failedContainmentEvent = await SecurityEvent.create({
        event_id: `evt_reconcile_fail_contain_${Date.now()}`,
        user_id: user.id,
        session_id: session.id,
        event_type: 'high_impact_action',
        context: {
          ip_address: '198.51.100.42',
          device_fingerprint: session.device_fingerprint
        },
        metadata: {
          containment_status: 'failed'
        },
        timestamp: eventTime,
        created_at: eventTime
      });
      const failedContainmentAssessment = await RiskAssessment.create({
        id: `ass_reconcile_fail_contain_${Date.now()}`,
        event_id: failedContainmentEvent.event_id,
        user_id: user.id,
        session_id: session.id,
        risk_score: 90,
        risk_tier: 'critical',
        contributing_signals: [],
        explanation: { user_facing: 'Blocked', admin_facing: 'Blocked' },
        evaluated_at: eventTime
      });
      const ineligibleDecision = await PolicyDecision.create({
        id: `dec_reconcile_ineligible_${Date.now()}`,
        event_id: failedContainmentEvent.event_id,
        risk_assessment_id: failedContainmentAssessment.id,
        user_id: user.id,
        session_id: session.id,
        action_type: 'high_impact_action',
        action_sensitivity: 'critical',
        risk_score: 90,
        risk_tier: 'critical',
        recommended_decision: 'block',
        effective_decision: 'block',
        enforcement_outcome: 'blocked',
        enforcement_mode: 'automatic',
        reasons: [],
        contributing_signals: [],
        explanation: { user_facing: 'Blocked', admin_facing: 'Blocked' },
        policy_version: 'default-v1@1.0.0',
        decided_at: eventTime
      });

      const firstPass = await reconcileMissingWebhookEnqueues({
        now: reconcileNow,
        lookbackMs: 5 * 60 * 1000
      });

      // eligibleEvent (event.processed) + failedContainmentEvent (event.processed) + eligibleDecision (decision.recorded) for earlyEndpoint only
      expect(firstPass.enqueuedCount).toBe(3);

      // Idempotent second pass creates no duplicates
      const secondPass = await reconcileMissingWebhookEnqueues({
        now: reconcileNow,
        lookbackMs: 5 * 60 * 1000
      });
      expect(secondPass.enqueuedCount).toBe(0);

      const earlyLogs = await WebhookDeliveryLog.findAll({
        where: { webhook_id: earlyReg.body.webhook.id }
      });
      expect(earlyLogs).toHaveLength(3);

      const lateLogs = await WebhookDeliveryLog.findAll({
        where: { webhook_id: lateReg.body.webhook.id }
      });
      expect(lateLogs).toHaveLength(0);

      const unscoredLogs = await WebhookDeliveryLog.findAll({
        where: { source_event_id: unscoredFailureEvent.event_id }
      });
      expect(unscoredLogs).toHaveLength(0);

      const ineligibleDecisionLogs = await WebhookDeliveryLog.findAll({
        where: { source_event_id: ineligibleDecision.id }
      });
      expect(ineligibleDecisionLogs).toHaveLength(0);
    });
  });

  describe('7. Delivery-history API authorization, pagination, filtering, 404 behavior, and secret-free projection', () => {
    test('enforces admin auth, returns 404 for unknown webhook, supports pagination and filtering, and projects only safe delivery fields', async () => {
      const receiver = await createReceiver();

      const regRes = await request(app)
        .post('/api/v1/webhooks')
        .set('X-Admin-Api-Key', TEST_ADMIN_API_KEY)
        .send({
          url: `${receiver.baseUrl}/history`,
          subscribed_events: ['event.processed', 'decision.recorded'],
          is_active: true
        })
        .expect(201);

      const webhookId = regRes.body.webhook.id;
      const baseTime = Date.now();

      await WebhookDeliveryLog.bulkCreate([
        {
          id: `whdel_hist_1_${baseTime}`,
          webhook_id: webhookId,
          event_type: 'event.processed',
          source_event_id: 'evt_hist_1',
          status: 'delivered',
          attempt_count: 1,
          http_status: 200,
          error_code: null,
          next_attempt_at: null,
          last_attempt_at: new Date(baseTime - 3000),
          locked_at: null,
          locked_by: null,
          delivered_at: new Date(baseTime - 3000),
          created_at: new Date(baseTime - 3000),
          updated_at: new Date(baseTime - 3000)
        },
        {
          id: `whdel_hist_2_${baseTime}`,
          webhook_id: webhookId,
          event_type: 'decision.recorded',
          source_event_id: 'dec_hist_2',
          status: 'failed',
          attempt_count: 5,
          http_status: 503,
          error_code: 'HTTP_503',
          next_attempt_at: null,
          last_attempt_at: new Date(baseTime - 2000),
          locked_at: null,
          locked_by: null,
          delivered_at: null,
          created_at: new Date(baseTime - 2000),
          updated_at: new Date(baseTime - 2000)
        },
        {
          id: `whdel_hist_3_${baseTime}`,
          webhook_id: webhookId,
          event_type: 'event.processed',
          source_event_id: 'evt_hist_3',
          status: 'pending',
          attempt_count: 1,
          http_status: 502,
          error_code: 'HTTP_502',
          next_attempt_at: new Date(baseTime + 30000),
          last_attempt_at: new Date(baseTime - 1000),
          locked_at: new Date(baseTime - 500),
          locked_by: 'internal_secret_worker_lock_token',
          delivered_at: null,
          created_at: new Date(baseTime - 1000),
          updated_at: new Date(baseTime - 1000)
        }
      ]);

      // Unauthenticated -> 401
      await request(app)
        .get(`/api/v1/webhooks/${webhookId}/deliveries`)
        .expect(401);

      // Service key -> 403
      await request(app)
        .get(`/api/v1/webhooks/${webhookId}/deliveries`)
        .set('Authorization', `Bearer ${TEST_SERVICE_API_KEY}`)
        .expect(403);

      // Non-existent parent endpoint -> 404
      const missingRes = await request(app)
        .get('/api/v1/webhooks/whk_00000000-0000-4000-8000-000000000000/deliveries')
        .set('X-Admin-Api-Key', TEST_ADMIN_API_KEY)
        .expect(404);
      expect(missingRes.body.error.code).toBe('webhook_not_found');

      // Invalid query parameters -> 400
      await request(app)
        .get(`/api/v1/webhooks/${webhookId}/deliveries?status=unknown`)
        .set('X-Admin-Api-Key', TEST_ADMIN_API_KEY)
        .expect(400);

      await request(app)
        .get(`/api/v1/webhooks/${webhookId}/deliveries?event_type=invalid.event`)
        .set('X-Admin-Api-Key', TEST_ADMIN_API_KEY)
        .expect(400);

      await request(app)
        .get(`/api/v1/webhooks/${webhookId}/deliveries?unexpected=1`)
        .set('X-Admin-Api-Key', TEST_ADMIN_API_KEY)
        .expect(400);

      // Pagination: limit=2, offset=0
      const pageRes = await request(app)
        .get(`/api/v1/webhooks/${webhookId}/deliveries?limit=2&offset=0`)
        .set('X-Admin-Api-Key', TEST_ADMIN_API_KEY)
        .expect(200);

      expect(pageRes.body.webhook_id).toBe(webhookId);
      expect(pageRes.body.count).toBe(2);
      expect(pageRes.body.total).toBe(3);
      expect(pageRes.body.deliveries[0].id).toBe(`whdel_hist_3_${baseTime}`);
      expect(pageRes.body.deliveries[1].id).toBe(`whdel_hist_2_${baseTime}`);

      // Verify safe projection: no locked_by, locked_at, signing_secret, encrypted_secret, payload, or response_body
      for (const item of pageRes.body.deliveries) {
        expect(Object.keys(item).sort()).toEqual(
          [
            'attempt_count',
            'created_at',
            'delivered_at',
            'error_code',
            'event_type',
            'http_status',
            'id',
            'last_attempt_at',
            'next_attempt_at',
            'source_event_id',
            'status',
            'updated_at',
            'webhook_id'
          ].sort()
        );
        expect(item.locked_by).toBeUndefined();
        expect(item.locked_at).toBeUndefined();
        expect(item.signing_secret).toBeUndefined();
        expect(item.encrypted_secret).toBeUndefined();
      }

      // Filter by status=failed and event_type=decision.recorded
      const filteredRes = await request(app)
        .get(
          `/api/v1/webhooks/${webhookId}/deliveries?status=failed&event_type=decision.recorded`
        )
        .set('X-Admin-Api-Key', TEST_ADMIN_API_KEY)
        .expect(200);

      expect(filteredRes.body.count).toBe(1);
      expect(filteredRes.body.total).toBe(1);
      expect(filteredRes.body.deliveries[0].id).toBe(`whdel_hist_2_${baseTime}`);
      expect(filteredRes.body.deliveries[0].status).toBe('failed');
      expect(filteredRes.body.deliveries[0].error_code).toBe('HTTP_503');
    });
  });

  describe('8. Clean worker startup/shutdown and no duplicate listener registration', () => {
    test('repeated startWebhookDeliveryWorker and attachWebhookEventListeners calls are idempotent and stopWebhookDeliveryWorker removes listeners cleanly', async () => {
      const baseEventListeners = eventBus.listenerCount('pipeline:event_processed');
      const baseDecisionListeners = eventBus.listenerCount('policy:decision_recorded');

      attachWebhookEventListeners();
      attachWebhookEventListeners();
      attachWebhookEventListeners();

      expect(eventBus.listenerCount('pipeline:event_processed')).toBe(
        baseEventListeners + 1
      );
      expect(eventBus.listenerCount('policy:decision_recorded')).toBe(
        baseDecisionListeners + 1
      );

      await startWebhookDeliveryWorker({
        pollIntervalMs: 100,
        reconcileIntervalMs: 60000
      });
      await startWebhookDeliveryWorker({
        pollIntervalMs: 100,
        reconcileIntervalMs: 60000
      });

      expect(isWebhookDeliveryWorkerRunning()).toBe(true);
      expect(eventBus.listenerCount('pipeline:event_processed')).toBe(
        baseEventListeners + 1
      );
      expect(eventBus.listenerCount('policy:decision_recorded')).toBe(
        baseDecisionListeners + 1
      );

      await stopWebhookDeliveryWorker();
      expect(isWebhookDeliveryWorkerRunning()).toBe(false);
      expect(eventBus.listenerCount('pipeline:event_processed')).toBe(
        baseEventListeners
      );
      expect(eventBus.listenerCount('policy:decision_recorded')).toBe(
        baseDecisionListeners
      );
    });
  });
});
