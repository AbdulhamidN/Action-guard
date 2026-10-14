'use strict';

const crypto = require('node:crypto');
const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');

const {
  sequelize,
  User,
  SecurityEvent,
  RiskAssessment,
  PolicyDecision,
  WebhookEndpoint,
  WebhookDeliveryLog
} = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const migration010 = require('../src/database/migrations/010_webhook_delivery_queue');
const { REDIS_PREFIXES } = require('../src/config/sessionConfig');
const {
  DEFAULT_SIGNATURE_TOLERANCE_SECONDS,
  generateWebhookSecret,
  encryptWebhookSecret,
  signWebhookPayload,
  verifyWebhookSignature
} = require('../src/utils/webhookCrypto');
const {
  DEFAULT_REQUEST_TIMEOUT_MS,
  DEFAULT_MAX_RESPONSE_BYTES,
  WebhookDeliveryError,
  clampRequestTimeoutMs,
  resolveAndValidateWebhookTarget,
  sendPinnedWebhookRequest
} = require('../src/utils/webhookHttpClient');
const {
  DEFAULT_MAX_ATTEMPTS,
  DEFAULT_BASE_BACKOFF_MS,
  DEFAULT_MAX_BACKOFF_MS,
  DEFAULT_MAX_RETRY_AFTER_MS,
  deriveDeterministicDeliveryId,
  parseRetryAfterMs,
  computeRetryDelayMs,
  classifyHttpResponseStatus,
  buildWebhookEventEnvelope,
  enqueueWebhooksForEvent,
  claimDeliveryJob,
  beginDeliveryAttempt,
  scheduleDeliveryRetry,
  executeWebhookDelivery,
  reconcileStaleLockedDeliveries,
  processPendingWebhookDeliveries
} = require('../src/services/webhookDeliveryService');

const TEST_MASTER_KEY_HEX = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
const TEST_ENV_WITH_KEY = Object.freeze({
  NODE_ENV: 'test',
  WEBHOOK_SECRET_ENCRYPTION_KEY: TEST_MASTER_KEY_HEX,
  WEBHOOK_ALLOW_LOCAL_TARGETS: 'true',
  WEBHOOK_ALLOW_INSECURE_HTTP: 'true'
});

/**
 * Builds a minimal valid DER/PEM self-signed X.509v3 certificate for a freshly
 * generated RSA keypair using pure Node.js buffers (no external CLI required).
 */
function createSelfSignedTlsCredentials(commonName = 'webhooks.example.com') {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1'
  });
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });

  function encodeLength(len) {
    if (len < 0x80) return Buffer.from([len]);
    const hex = len.toString(16).padStart(len > 0xff ? 4 : 2, '0');
    const bytes = Buffer.from(hex, 'hex');
    return Buffer.concat([Buffer.from([0x80 | bytes.length]), bytes]);
  }
  function asn1Tag(tag, content) {
    return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
  }
  function asn1Seq(...items) {
    return asn1Tag(0x30, Buffer.concat(items));
  }
  function asn1Set(...items) {
    return asn1Tag(0x31, Buffer.concat(items));
  }
  function asn1Int(buf) {
    const padded = buf[0] & 0x80 ? Buffer.concat([Buffer.from([0x00]), buf]) : buf;
    return asn1Tag(0x02, padded);
  }
  function asn1Oid(bytes) {
    return asn1Tag(0x06, Buffer.from(bytes));
  }
  function asn1Utf8(str) {
    return asn1Tag(0x0c, Buffer.from(str, 'utf8'));
  }
  function asn1UtcTime(date) {
    const yy = String(date.getUTCFullYear() % 100).padStart(2, '0');
    const mm = String(date.getUTCMonth() + 1).padStart(2, '0');
    const dd = String(date.getUTCDate()).padStart(2, '0');
    const hh = String(date.getUTCHours()).padStart(2, '0');
    const mi = String(date.getUTCMinutes()).padStart(2, '0');
    const ss = String(date.getUTCSeconds()).padStart(2, '0');
    return asn1Tag(0x17, Buffer.from(`${yy}${mm}${dd}${hh}${mi}${ss}Z`, 'ascii'));
  }

  // ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
  const sigAlg = asn1Seq(
    asn1Oid([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])
  );
  // CN=<commonName> (2.5.4.3)
  const name = asn1Seq(
    asn1Set(asn1Seq(asn1Oid([0x55, 0x04, 0x03]), asn1Utf8(commonName)))
  );
  const now = new Date();
  const validity = asn1Seq(
    asn1UtcTime(new Date(now.getTime() - 60_000)),
    asn1UtcTime(new Date(now.getTime() + 3600_000))
  );
  const version = asn1Tag(0xa0, asn1Int(Buffer.from([0x02])));
  const serial = asn1Int(crypto.randomBytes(8));

  // X.509v3 extensions: BasicConstraints (2.5.29.19, CA:TRUE) + SubjectAltName (2.5.29.17, DNS:<commonName>)
  const basicConstraintsExt = asn1Seq(
    asn1Oid([0x55, 0x1d, 0x13]),
    asn1Tag(0x04, asn1Seq(asn1Tag(0x01, Buffer.from([0xff]))))
  );
  const subjectAltNameExt = asn1Seq(
    asn1Oid([0x55, 0x1d, 0x11]),
    asn1Tag(0x04, asn1Seq(asn1Tag(0x82, Buffer.from(commonName, 'ascii'))))
  );
  const extensions = asn1Tag(0xa3, asn1Seq(basicConstraintsExt, subjectAltNameExt));

  const tbsCert = asn1Seq(
    version,
    serial,
    sigAlg,
    name,
    validity,
    name,
    spkiDer,
    extensions
  );

  const signature = crypto.sign('sha256', tbsCert, privateKey);
  const sigBitString = asn1Tag(
    0x03,
    Buffer.concat([Buffer.from([0x00]), signature])
  );
  const certDer = asn1Seq(tbsCert, sigAlg, sigBitString);
  const certPem = [
    '-----BEGIN CERTIFICATE-----',
    certDer.toString('base64').match(/.{1,64}/g).join('\n'),
    '-----END CERTIFICATE-----'
  ].join('\n');

  return {
    key: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    cert: certPem
  };
}

describe('Module 11.2c Stage 2A — Core Webhook Delivery Engine', () => {
  const activeServers = [];
  const createdEndpointIds = [];
  let dbTouched = false;
  let testUser;

  async function startHttpServer(handler) {
    const server = http.createServer(handler);
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    activeServers.push(server);
    const address = server.address();
    return {
      server,
      port: address.port,
      url: `http://siem.example.com:${address.port}/webhooks/receive`
    };
  }

  async function startHttpsServer(tlsOptions, handler) {
    const server = https.createServer(tlsOptions, handler);
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    activeServers.push(server);
    const address = server.address();
    return {
      server,
      port: address.port,
      url: `https://webhooks.example.com:${address.port}/webhooks/receive`
    };
  }

  async function createTestEndpoint({
    url = 'https://siem.example.com/webhooks/receive',
    subscribedEvents = ['event.processed', 'decision.recorded'],
    isActive = true,
    keyHex = TEST_MASTER_KEY_HEX
  } = {}) {
    dbTouched = true;
    const generated = generateWebhookSecret();
    const encrypted = encryptWebhookSecret(generated.secret, {
      NODE_ENV: 'test',
      WEBHOOK_SECRET_ENCRYPTION_KEY: keyHex
    });
    const endpoint = await WebhookEndpoint.create(
      {
        url,
        subscribed_events: subscribedEvents,
        description: 'Stage 2A Test Receiver',
        encrypted_secret: encrypted.encrypted_secret,
        secret_iv: encrypted.secret_iv,
        secret_auth_tag: encrypted.secret_auth_tag,
        secret_prefix: generated.secret_prefix,
        is_active: isActive
      },
      { validate: url.startsWith('https://') }
    );
    createdEndpointIds.push(endpoint.id);
    return { endpoint, secret: generated.secret };
  }

  async function createTestSecurityEventAndRisk({
    eventType = 'high_impact_action',
    riskScore = 82,
    riskTier = 'high'
  } = {}) {
    dbTouched = true;
    const event = await SecurityEvent.create({
      user_id: testUser.id,
      event_type: eventType,
      timestamp: new Date(),
      context: {
        ip_address: '198.51.100.42',
        country: 'US',
        device_id: 'dev_stage2a_test'
      },
      metadata: {
        action_name: 'role.assign_superadmin',
        action_sensitivity: 'critical'
      }
    });
    const assessment = await RiskAssessment.create({
      event_id: event.event_id,
      user_id: testUser.id,
      risk_score: riskScore,
      risk_tier: riskTier,
      contributing_signals: [
        { signal: 'action_sensitivity', score: 45 },
        { signal: 'new_device', score: 37 }
      ],
      explanation: {
        summary: 'High-impact privilege change from untrusted context'
      },
      evaluated_at: new Date()
    });
    return { event, assessment };
  }

  async function createTestPolicyDecision({
    decision = 'block',
    enforcementOutcome = 'blocked'
  } = {}) {
    dbTouched = true;
    const { event, assessment } = await createTestSecurityEventAndRisk({
      eventType: 'high_impact_action',
      riskScore: 94,
      riskTier: 'critical'
    });
    const policyDecision = await PolicyDecision.create({
      user_id: testUser.id,
      event_id: event.event_id,
      risk_assessment_id: assessment.id,
      action_type: 'treasury.wire_transfer',
      action_sensitivity: 'critical',
      risk_score: 94,
      risk_tier: 'critical',
      recommended_decision: decision,
      effective_decision: decision,
      enforcement_outcome: enforcementOutcome,
      enforcement_mode: 'automatic',
      policy_version: 'v1.0.0',
      reasons: ['Critical risk threshold exceeded on wire transfer'],
      contributing_signals: [{ signal: 'action_sensitivity', score: 50 }],
      explanation: { summary: 'Wire transfer blocked due to critical risk' },
      decided_at: new Date()
    });
    return { event, assessment, policyDecision };
  }

  beforeAll(async () => {
    await runMigrations();
    testUser = await User.create({
      email: `webhook-stage2a-${Date.now()}@example.com`,
      password_hash: 'hashed_password_placeholder',
      role: 'user',
      status: 'active'
    });
  });

  afterEach(async () => {
    while (activeServers.length > 0) {
      const srv = activeServers.pop();
      await new Promise((resolve) => srv.close(() => resolve()));
    }
    jest.restoreAllMocks();
    if (createdEndpointIds.length > 0) {
      const ids = createdEndpointIds.splice(0, createdEndpointIds.length);
      await WebhookDeliveryLog.destroy({ where: { webhook_id: ids } });
      await WebhookEndpoint.destroy({ where: { id: ids } });
    }
    if (dbTouched && testUser) {
      dbTouched = false;
      await PolicyDecision.destroy({ where: { user_id: testUser.id } });
      await RiskAssessment.destroy({ where: { user_id: testUser.id } });
      await SecurityEvent.destroy({ where: { user_id: testUser.id } });
    }
  });

  afterAll(async () => {
    if (testUser) {
      await User.destroy({ where: { id: testUser.id } });
    }
    await runMigrations();
  });

  // =========================================================================
  // 1. Signing & Verification Tests
  // =========================================================================

  test('T11.2d-01: signWebhookPayload computes deterministic HMAC-SHA256 v1=<64 lowercase hex> over exact raw body bytes and timestamp', () => {
    const secret = 'whsec_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const rawBody = Buffer.from('{"id":"whdel_test","type":"event.processed"}', 'utf8');
    const timestampSeconds = 1712345678;

    const signature = signWebhookPayload(rawBody, secret, timestampSeconds);

    const expectedHex = crypto
      .createHmac('sha256', Buffer.from(secret, 'utf8'))
      .update(`${timestampSeconds}.`, 'utf8')
      .update(rawBody)
      .digest('hex');

    expect(signature).toBe(`v1=${expectedHex}`);
    expect(signature).toMatch(/^v1=[0-9a-f]{64}$/);
  });

  test('T11.2d-02: verifyWebhookSignature succeeds for valid timestamp within tolerance and exact raw body bytes', () => {
    const { secret } = generateWebhookSecret();
    const rawBody = Buffer.from('{"id":"whdel_valid","type":"decision.recorded","data":{"ok":true}}', 'utf8');
    const nowSeconds = Math.floor(Date.now() / 1000);
    const signatureHeader = signWebhookPayload(rawBody, secret, nowSeconds - 120);

    expect(
      verifyWebhookSignature({
        rawBody,
        signatureHeader,
        timestampHeader: String(nowSeconds - 120),
        secret,
        toleranceSeconds: DEFAULT_SIGNATURE_TOLERANCE_SECONDS,
        nowSeconds
      })
    ).toBe(true);

    // Exact boundary (now - tolerance and now + tolerance) must also succeed
    const boundaryPastSig = signWebhookPayload(rawBody, secret, nowSeconds - 300);
    expect(
      verifyWebhookSignature({
        rawBody,
        signatureHeader: boundaryPastSig,
        timestampHeader: nowSeconds - 300,
        secret,
        toleranceSeconds: 300,
        nowSeconds
      })
    ).toBe(true);
  });

  test('T11.2d-03: verifyWebhookSignature fails when raw body bytes are modified (including whitespace changes)', () => {
    const { secret } = generateWebhookSecret();
    const originalBody = Buffer.from('{"id":"whdel_1","type":"event.processed"}', 'utf8');
    const modifiedBody = Buffer.from('{"id":"whdel_1", "type":"event.processed"}', 'utf8');
    const nowSeconds = Math.floor(Date.now() / 1000);
    const signatureHeader = signWebhookPayload(originalBody, secret, nowSeconds);

    expect(
      verifyWebhookSignature({
        rawBody: modifiedBody,
        signatureHeader,
        timestampHeader: String(nowSeconds),
        secret,
        nowSeconds
      })
    ).toBe(false);
  });

  test('T11.2d-04: verifyWebhookSignature fails for malformed, wrong-version, uppercase, or mismatched signature headers', () => {
    const { secret } = generateWebhookSecret();
    const { secret: otherSecret } = generateWebhookSecret();
    const rawBody = Buffer.from('{"id":"whdel_sig"}', 'utf8');
    const nowSeconds = Math.floor(Date.now() / 1000);
    const validSig = signWebhookPayload(rawBody, secret, nowSeconds);

    expect(
      verifyWebhookSignature({
        rawBody,
        signatureHeader: '',
        timestampHeader: String(nowSeconds),
        secret,
        nowSeconds
      })
    ).toBe(false);

    expect(
      verifyWebhookSignature({
        rawBody,
        signatureHeader: validSig.replace(/^v1=/, 'v2='),
        timestampHeader: String(nowSeconds),
        secret,
        nowSeconds
      })
    ).toBe(false);

    expect(
      verifyWebhookSignature({
        rawBody,
        signatureHeader: validSig.toUpperCase(),
        timestampHeader: String(nowSeconds),
        secret,
        nowSeconds
      })
    ).toBe(false);

    expect(
      verifyWebhookSignature({
        rawBody,
        signatureHeader: 'v1=deadbeef',
        timestampHeader: String(nowSeconds),
        secret,
        nowSeconds
      })
    ).toBe(false);

    expect(
      verifyWebhookSignature({
        rawBody,
        signatureHeader: signWebhookPayload(rawBody, otherSecret, nowSeconds),
        timestampHeader: String(nowSeconds),
        secret,
        nowSeconds
      })
    ).toBe(false);
  });

  test('T11.2d-05: verifyWebhookSignature fails for expired timestamps outside replay tolerance window', () => {
    const { secret } = generateWebhookSecret();
    const rawBody = Buffer.from('{"id":"whdel_expired"}', 'utf8');
    const nowSeconds = Math.floor(Date.now() / 1000);
    const expiredTs = nowSeconds - DEFAULT_SIGNATURE_TOLERANCE_SECONDS - 1;
    const signatureHeader = signWebhookPayload(rawBody, secret, expiredTs);

    expect(
      verifyWebhookSignature({
        rawBody,
        signatureHeader,
        timestampHeader: String(expiredTs),
        secret,
        toleranceSeconds: DEFAULT_SIGNATURE_TOLERANCE_SECONDS,
        nowSeconds
      })
    ).toBe(false);
  });

  test('T11.2d-06: verifyWebhookSignature fails for future timestamps outside replay tolerance window', () => {
    const { secret } = generateWebhookSecret();
    const rawBody = Buffer.from('{"id":"whdel_future"}', 'utf8');
    const nowSeconds = Math.floor(Date.now() / 1000);
    const futureTs = nowSeconds + DEFAULT_SIGNATURE_TOLERANCE_SECONDS + 1;
    const signatureHeader = signWebhookPayload(rawBody, secret, futureTs);

    expect(
      verifyWebhookSignature({
        rawBody,
        signatureHeader,
        timestampHeader: String(futureTs),
        secret,
        toleranceSeconds: DEFAULT_SIGNATURE_TOLERANCE_SECONDS,
        nowSeconds
      })
    ).toBe(false);
  });

  test('T11.2d-07: verifyWebhookSignature and signWebhookPayload reject malformed or non-positive timestamps', () => {
    const { secret } = generateWebhookSecret();
    const rawBody = Buffer.from('{"id":"whdel_ts"}', 'utf8');
    const nowSeconds = Math.floor(Date.now() / 1000);
    const validSig = signWebhookPayload(rawBody, secret, nowSeconds);

    for (const badTs of ['0', '-100', 'abc', '1712345678.5', '', null, undefined, NaN]) {
      expect(
        verifyWebhookSignature({
          rawBody,
          signatureHeader: validSig,
          timestampHeader: badTs,
          secret,
          nowSeconds
        })
      ).toBe(false);
    }

    expect(() => signWebhookPayload(rawBody, secret, 0)).toThrow(/positive integer/i);
    expect(() => signWebhookPayload(rawBody, secret, -5)).toThrow(/positive integer/i);
  });

  // =========================================================================
  // 2. Destination Security & SSRF-Safe HTTP Client Tests
  // =========================================================================

  test('T11.2d-08: Private IPv4/IPv6, IPv4-mapped IPv6 (::ffff:127.0.0.1), and NAT64 (64:ff9b::127.0.0.1) addresses are rejected at delivery time', async () => {
    const blockedResolvedIps = [
      { address: '127.0.0.1', family: 4 },
      { address: '10.0.0.15', family: 4 },
      { address: '169.254.169.254', family: 4 },
      { address: '::1', family: 6 },
      { address: '::ffff:127.0.0.1', family: 6 },
      { address: '::ffff:169.254.169.254', family: 6 },
      { address: '64:ff9b::127.0.0.1', family: 6 },
      { address: '64:ff9b::10.0.0.1', family: 6 }
    ];

    for (const record of blockedResolvedIps) {
      const lookupFn = jest.fn().mockResolvedValue([record]);
      await expect(
        resolveAndValidateWebhookTarget('https://siem.example.com/hook', {
          lookupFn,
          allowLocalTargets: false,
          env: { NODE_ENV: 'test' }
        })
      ).rejects.toMatchObject({
        name: 'WebhookDeliveryError',
        code: 'SSRF_BLOCKED_IP',
        retryable: false
      });
    }
  });

  test('T11.2d-09: Mixed public and private DNS answers are rejected with SSRF_BLOCKED_IP', async () => {
    const lookupFn = jest.fn().mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
      { address: '10.24.0.8', family: 4 }
    ]);

    await expect(
      resolveAndValidateWebhookTarget('https://siem.example.com/hook', {
        lookupFn,
        allowLocalTargets: false,
        env: { NODE_ENV: 'test' }
      })
    ).rejects.toMatchObject({
      name: 'WebhookDeliveryError',
      code: 'SSRF_BLOCKED_IP',
      retryable: false
    });
  });

  test('T11.2d-10: Empty or malformed DNS responses are rejected with DNS_RESOLUTION_FAILED', async () => {
    const emptyLookup = jest.fn().mockResolvedValue([]);
    await expect(
      resolveAndValidateWebhookTarget('https://siem.example.com/hook', {
        lookupFn: emptyLookup,
        env: { NODE_ENV: 'test' }
      })
    ).rejects.toMatchObject({
      name: 'WebhookDeliveryError',
      code: 'DNS_RESOLUTION_FAILED',
      retryable: true
    });

    const malformedLookup = jest.fn().mockResolvedValue([{ address: 'not-an-ip-address', family: 4 }]);
    await expect(
      resolveAndValidateWebhookTarget('https://siem.example.com/hook', {
        lookupFn: malformedLookup,
        env: { NODE_ENV: 'test' }
      })
    ).rejects.toMatchObject({
      name: 'WebhookDeliveryError',
      code: 'DNS_RESOLUTION_FAILED',
      retryable: true
    });
  });

  test('T11.2d-11: DNS lookup happens once for validation and socket connection uses the pinned IP without re-resolving DNS', async () => {
    let receivedRequestHeaders = null;
    let receivedBody = null;
    const { port, url } = await startHttpServer((req, res) => {
      receivedRequestHeaders = req.headers;
      const chunks = [];
      req.on('data', (chunk) => chunks.push(chunk));
      req.on('end', () => {
        receivedBody = Buffer.concat(chunks).toString('utf8');
        res.writeHead(202, { 'Content-Type': 'application/json' });
        res.end('{"accepted":true}');
      });
    });

    // If a second DNS lookup were ever performed during socket connection, it would fail or return 169.254.169.254
    const lookupFn = jest
      .fn()
      .mockResolvedValueOnce([{ address: '127.0.0.1', family: 4 }])
      .mockRejectedValue(new Error('Second DNS lookup must never occur'));

    const result = await sendPinnedWebhookRequest(url, {
      bodyBuffer: Buffer.from('{"id":"whdel_pinned"}', 'utf8'),
      headers: {
        'X-ActionGuard-Webhook-Event': 'event.processed',
        'X-ActionGuard-Webhook-Id': 'whdel_pinned'
      },
      lookupFn,
      allowLocalTargets: true,
      allowInsecureHttp: true,
      env: TEST_ENV_WITH_KEY
    });

    expect(lookupFn).toHaveBeenCalledTimes(1);
    expect(lookupFn).toHaveBeenCalledWith('siem.example.com', { all: true, verbatim: true });
    expect(result.httpStatus).toBe(202);
    expect(result.pinnedAddress).toBe('127.0.0.1');
    expect(receivedBody).toBe('{"id":"whdel_pinned"}');
    expect(receivedRequestHeaders.host).toBe(`siem.example.com:${port}`);
  });

  test('T11.2d-12: Production lockout ignores allowLocalTargets and allowInsecureHttp when NODE_ENV === production', async () => {
    const lookupFn = jest.fn().mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);

    // Local IP must be blocked in production even if allowLocalTargets=true and env flag is set
    await expect(
      resolveAndValidateWebhookTarget('https://siem.example.com/hook', {
        lookupFn,
        allowLocalTargets: true,
        allowInsecureHttp: true,
        env: {
          NODE_ENV: 'production',
          WEBHOOK_ALLOW_LOCAL_TARGETS: 'true',
          WEBHOOK_ALLOW_INSECURE_HTTP: 'true'
        }
      })
    ).rejects.toMatchObject({
      name: 'WebhookDeliveryError',
      code: 'SSRF_BLOCKED_IP',
      retryable: false
    });

    // Insecure http:// must be blocked in production even if allowInsecureHttp=true and env flag is set
    const publicLookup = jest.fn().mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
    await expect(
      resolveAndValidateWebhookTarget('http://siem.example.com/hook', {
        lookupFn: publicLookup,
        allowLocalTargets: true,
        allowInsecureHttp: true,
        env: {
          NODE_ENV: 'production',
          WEBHOOK_ALLOW_LOCAL_TARGETS: 'true',
          WEBHOOK_ALLOW_INSECURE_HTTP: 'true'
        }
      })
    ).rejects.toMatchObject({
      name: 'WebhookDeliveryError',
      code: 'INVALID_DESTINATION_URL',
      retryable: false
    });
  });

  test('T11.2d-13: TLS certificate and hostname verification remain enabled (untrusted self-signed certificate fails with TLS_VERIFICATION_FAILED)', async () => {
    const tlsCreds = createSelfSignedTlsCredentials('webhooks.example.com');
    const { url } = await startHttpsServer(tlsCreds, (_req, res) => {
      res.writeHead(200);
      res.end('ok');
    });

    const httpsRequestSpy = jest.spyOn(https, 'request');
    const lookupFn = jest.fn().mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);

    await expect(
      sendPinnedWebhookRequest(url, {
        bodyBuffer: Buffer.from('{"id":"whdel_tls"}', 'utf8'),
        lookupFn,
        allowLocalTargets: true,
        env: {
          NODE_ENV: 'test',
          WEBHOOK_ALLOW_LOCAL_TARGETS: 'true'
        }
      })
    ).rejects.toMatchObject({
      name: 'WebhookDeliveryError',
      code: 'TLS_VERIFICATION_FAILED',
      retryable: false
    });

    expect(httpsRequestSpy).toHaveBeenCalledTimes(1);
    const passedOptions = httpsRequestSpy.mock.calls[0][0];
    expect(passedOptions.rejectUnauthorized).toBe(true);
    expect(passedOptions.servername).toBe('webhooks.example.com');
    expect(passedOptions.agent).toBe(false);
    expect(typeof passedOptions.checkServerIdentity).toBe('function');

    const checkIdentitySpy = jest.spyOn(tls, 'checkServerIdentity').mockReturnValue(undefined);
    const dummyCert = { subject: { CN: 'webhooks.example.com' } };
    passedOptions.checkServerIdentity('127.0.0.1', dummyCert);
    expect(checkIdentitySpy).toHaveBeenCalledWith('webhooks.example.com', dummyCert);
  });

  test('T11.2d-14: 301, 302, 307, and 308 redirects are rejected with HTTP_REDIRECT_REJECTED without following Location', async () => {
    let redirectTargetHit = false;
    const targetServer = await startHttpServer((_req, res) => {
      redirectTargetHit = true;
      res.writeHead(200);
      res.end('should-never-be-called');
    });

    for (const statusCode of [301, 302, 307, 308]) {
      const redirectServer = await startHttpServer((_req, res) => {
        res.writeHead(statusCode, {
          Location: targetServer.url
        });
        res.end();
      });

      const lookupFn = jest.fn().mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);

      await expect(
        sendPinnedWebhookRequest(redirectServer.url, {
          bodyBuffer: Buffer.from('{"id":"whdel_redir"}', 'utf8'),
          lookupFn,
          allowLocalTargets: true,
          allowInsecureHttp: true,
          env: TEST_ENV_WITH_KEY
        })
      ).rejects.toMatchObject({
        name: 'WebhookDeliveryError',
        code: 'HTTP_REDIRECT_REJECTED',
        retryable: false,
        httpStatus: statusCode
      });
    }

    expect(redirectTargetHit).toBe(false);
  });

  test('T11.2d-15: Request timeouts abort cleanly with retryable REQUEST_TIMEOUT error', async () => {
    expect(clampRequestTimeoutMs(undefined)).toBe(DEFAULT_REQUEST_TIMEOUT_MS);
    expect(clampRequestTimeoutMs(100)).toBe(1_000);
    expect(clampRequestTimeoutMs(99_000)).toBe(15_000);

    const slowServer = await startHttpServer((_req, _res) => {
      // Intentionally do not respond so timeout fires
    });

    const lookupFn = jest.fn().mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);

    await expect(
      sendPinnedWebhookRequest(slowServer.url, {
        bodyBuffer: Buffer.from('{"id":"whdel_timeout"}', 'utf8'),
        lookupFn,
        timeoutMs: 1_000,
        allowLocalTargets: true,
        allowInsecureHttp: true,
        env: TEST_ENV_WITH_KEY
      })
    ).rejects.toMatchObject({
      name: 'WebhookDeliveryError',
      code: 'REQUEST_TIMEOUT',
      retryable: true
    });
  });

  test('T11.2d-16: Oversized responses (> 4096 bytes) are aborted with RESPONSE_TOO_LARGE and never persisted', async () => {
    const oversizedPayload = 'X'.repeat(DEFAULT_MAX_RESPONSE_BYTES + 512);
    const noisyServer = await startHttpServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(oversizedPayload);
    });

    const { endpoint } = await createTestEndpoint({
      url: noisyServer.url,
      subscribedEvents: ['event.processed']
    });
    const { event } = await createTestSecurityEventAndRisk();

    const { enqueued } = await enqueueWebhooksForEvent({
      eventType: 'event.processed',
      sourceEventId: event.event_id
    });
    const [job] = enqueued;

    const lookupFn = jest.fn().mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);

    const result = await executeWebhookDelivery(job.id, {
      lookupFn,
      allowLocalTargets: true,
      allowInsecureHttp: true,
      env: TEST_ENV_WITH_KEY
    });

    expect(result.error_code).toBe('RESPONSE_TOO_LARGE');
    expect(result.status).toBe('failed');

    const reloaded = await WebhookDeliveryLog.findByPk(job.id);
    expect(reloaded.error_code).toBe('RESPONSE_TOO_LARGE');
    expect(reloaded.http_status).toBe(200);
    expect(JSON.stringify(reloaded.toJSON())).not.toContain('XXXX');
    expect(endpoint.id).toBeDefined();
  });

  // =========================================================================
  // 3. Queue Semantics, Atomic Claims, Retries & Lease Recovery Tests
  // =========================================================================

  test('T11.2d-17: enqueueWebhooksForEvent matches only endpoints subscribed to the given eventType', async () => {
    const { endpoint: epEventOnly } = await createTestEndpoint({
      url: 'https://siem1.example.com/hook',
      subscribedEvents: ['event.processed']
    });
    const { endpoint: epDecisionOnly } = await createTestEndpoint({
      url: 'https://siem2.example.com/hook',
      subscribedEvents: ['decision.recorded']
    });
    const { endpoint: epBoth } = await createTestEndpoint({
      url: 'https://siem3.example.com/hook',
      subscribedEvents: ['event.processed', 'decision.recorded']
    });

    const { event } = await createTestSecurityEventAndRisk();

    const { enqueued: createdForEvent } = await enqueueWebhooksForEvent({
      eventType: 'event.processed',
      sourceEventId: event.event_id
    });

    const testScopeIds = new Set([epEventOnly.id, epDecisionOnly.id, epBoth.id]);
    const webhookIds = createdForEvent
      .map((row) => row.webhook_id)
      .filter((id) => testScopeIds.has(id))
      .sort();
    expect(webhookIds).toEqual([epEventOnly.id, epBoth.id].sort());
    expect(webhookIds).not.toContain(epDecisionOnly.id);
  });

  test('T11.2d-18: Inactive endpoints are excluded during enqueueWebhooksForEvent', async () => {
    const { endpoint: activeEp } = await createTestEndpoint({
      url: 'https://active.example.com/hook',
      subscribedEvents: ['event.processed'],
      isActive: true
    });
    const { endpoint: inactiveEp } = await createTestEndpoint({
      url: 'https://inactive.example.com/hook',
      subscribedEvents: ['event.processed'],
      isActive: false
    });

    const { event } = await createTestSecurityEventAndRisk();
    const { enqueued: allJobs } = await enqueueWebhooksForEvent({
      eventType: 'event.processed',
      sourceEventId: event.event_id
    });

    const jobs = allJobs.filter((j) =>
      [activeEp.id, inactiveEp.id].includes(j.webhook_id)
    );
    expect(jobs).toHaveLength(1);
    expect(jobs[0].webhook_id).toBe(activeEp.id);
    expect(jobs[0].attempt_count).toBe(0);
    expect(jobs[0].status).toBe('pending');
  });

  test('T11.2d-19: Duplicate enqueue calls do not create duplicate delivery jobs and migration 010 up/down is idempotent', async () => {
    const { endpoint } = await createTestEndpoint({
      url: 'https://dedup.example.com/hook',
      subscribedEvents: ['event.processed']
    });
    const { event } = await createTestSecurityEventAndRisk();

    const expectedId = deriveDeterministicDeliveryId(
      endpoint.id,
      'event.processed',
      event.event_id
    );
    expect(expectedId).toMatch(/^whdel_[0-9a-f]{32}$/);

    const firstBatch = await enqueueWebhooksForEvent({
      eventType: 'event.processed',
      sourceEventId: event.event_id
    });
    const secondBatch = await enqueueWebhooksForEvent({
      eventType: 'event.processed',
      sourceEventId: event.event_id
    });

    const firstForEp = firstBatch.enqueued.filter(
      (j) => j.webhook_id === endpoint.id
    );
    const secondEnqForEp = secondBatch.enqueued.filter(
      (j) => j.webhook_id === endpoint.id
    );
    const secondDupForEp = secondBatch.duplicates.filter(
      (j) => j.webhook_id === endpoint.id
    );

    expect(firstForEp).toHaveLength(1);
    expect(firstForEp[0].id).toBe(expectedId);
    expect(secondEnqForEp).toHaveLength(0);
    expect(secondDupForEp).toHaveLength(1);

    const allLogs = await WebhookDeliveryLog.findAll({
      where: {
        webhook_id: endpoint.id,
        event_type: 'event.processed',
        source_event_id: event.event_id
      }
    });
    expect(allLogs).toHaveLength(1);

    // Verify migration 010 idempotency on live schema and full down/up transition logic
    const queryInterface = sequelize.getQueryInterface();
    await migration010.up(queryInterface);

    const indexes = await queryInterface.showIndex('webhook_delivery_logs');
    const indexNames = indexes.map((idx) => idx.name);
    expect(indexNames).toContain('idx_webhook_delivery_logs_queue_schedule');
    expect(indexNames).toContain('uq_webhook_delivery_logs_endpoint_event');

    // Verify down() and up() DDL transitions in isolation without locking the shared table across parallel workers
    const stateCols = {
      id: { allowNull: false },
      webhook_id: { allowNull: false },
      next_attempt_at: { allowNull: true },
      last_attempt_at: { allowNull: true },
      locked_at: { allowNull: true },
      locked_by: { allowNull: true },
      updated_at: { allowNull: false }
    };
    const stateIdx = new Set([
      'idx_webhook_delivery_logs_queue_schedule',
      'uq_webhook_delivery_logs_endpoint_event'
    ]);
    const isolatedQi = {
      showAllTables: jest.fn().mockResolvedValue(['webhook_delivery_logs']),
      describeTable: jest.fn().mockImplementation(async () => ({ ...stateCols })),
      showIndex: jest.fn().mockImplementation(async () =>
        Array.from(stateIdx).map((name) => ({ name }))
      ),
      addIndex: jest.fn().mockImplementation(async (_table, _fields, opts) => {
        stateIdx.add(opts.name);
      }),
      removeIndex: jest.fn().mockImplementation(async (_table, name) => {
        stateIdx.delete(name);
      }),
      addColumn: jest.fn().mockImplementation(async (_table, col, spec) => {
        stateCols[col] = { allowNull: spec ? spec.allowNull : true };
      }),
      changeColumn: jest.fn().mockImplementation(async (_table, col, spec) => {
        stateCols[col] = { allowNull: spec ? spec.allowNull : false };
      }),
      removeColumn: jest.fn().mockImplementation(async (_table, col) => {
        delete stateCols[col];
      }),
      sequelize: {
        query: jest.fn().mockResolvedValue([[], 0])
      }
    };

    await migration010.down(isolatedQi);
    expect(stateIdx.has('idx_webhook_delivery_logs_webhook_id')).toBe(true);
    expect(stateIdx.has('uq_webhook_delivery_logs_endpoint_event')).toBe(false);
    expect(stateCols.updated_at).toBeUndefined();
    expect(stateCols.next_attempt_at).toBeUndefined();

    await migration010.up(isolatedQi);
    expect(stateCols.updated_at).toEqual({ allowNull: false });
    expect(stateCols.next_attempt_at).toBeDefined();
    expect(stateIdx.has('uq_webhook_delivery_logs_endpoint_event')).toBe(true);
    expect(stateIdx.has('idx_webhook_delivery_logs_queue_schedule')).toBe(true);

    // Simulate partial migration failure where updated_at was added (allowNull: true) but backfill/changeColumn failed
    stateCols.updated_at = { allowNull: true };
    isolatedQi.addColumn.mockClear();
    isolatedQi.changeColumn.mockClear();
    isolatedQi.sequelize.query.mockClear();

    await migration010.up(isolatedQi);
    expect(isolatedQi.addColumn).not.toHaveBeenCalledWith(
      'webhook_delivery_logs',
      'updated_at',
      expect.anything()
    );
    expect(isolatedQi.sequelize.query).toHaveBeenCalledTimes(1);
    expect(isolatedQi.changeColumn).toHaveBeenCalledWith(
      'webhook_delivery_logs',
      'updated_at',
      expect.objectContaining({ allowNull: false })
    );
    expect(stateCols.updated_at).toEqual({ allowNull: false });
  });

  test('T11.2d-20: Claiming is atomic under concurrent workers so only one worker claims a due job', async () => {
    await createTestEndpoint({
      url: 'https://atomic.example.com/hook',
      subscribedEvents: ['event.processed']
    });
    const { event } = await createTestSecurityEventAndRisk();

    const { enqueued } = await enqueueWebhooksForEvent({
      eventType: 'event.processed',
      sourceEventId: event.event_id
    });
    const [job] = enqueued;

    const claimPromises = Array.from({ length: 6 }, (_, idx) =>
      claimDeliveryJob(job.id, { ownerToken: `worker_concurrent_${idx}` })
    );
    const results = await Promise.all(claimPromises);
    const winners = results.filter((res) => res.claimed === true);

    expect(winners).toHaveLength(1);
    expect(winners[0].delivery.id).toBe(job.id);
    expect(winners[0].delivery.locked_by).toMatch(/^worker_concurrent_\d$/);
    expect(winners[0].delivery.attempt_count).toBe(0);
    await winners[0].releaseRedisLock();
  });

  test('T11.2d-21: Owner-token checks prevent a stale worker from starting an attempt or overwriting another worker state', async () => {
    await createTestEndpoint({
      url: 'https://owner-token.example.com/hook',
      subscribedEvents: ['event.processed']
    });
    const { event } = await createTestSecurityEventAndRisk();

    const { enqueued } = await enqueueWebhooksForEvent({
      eventType: 'event.processed',
      sourceEventId: event.event_id
    });
    const [job] = enqueued;

    // Worker A claims the job
    const claimedByA = await claimDeliveryJob(job.id, { ownerToken: 'worker_A' });
    expect(claimedByA.claimed).toBe(true);

    // Stale Worker B tries to begin attempt or reschedule using wrong ownerToken
    const attemptByB = await beginDeliveryAttempt(job.id, 'worker_B');
    expect(attemptByB).toEqual({ started: false, attemptCount: null });

    const retryByB = await scheduleDeliveryRetry(job.id, 'worker_B', {
      attemptCount: 1,
      httpStatus: 503,
      errorCode: 'HTTP_503'
    });
    expect(retryByB.updated).toBe(false);
    expect(retryByB.status).toBe('stale_owner');

    // Verify Worker A's claim and attempt_count remain intact
    const current = await WebhookDeliveryLog.findByPk(job.id);
    expect(current.locked_by).toBe('worker_A');
    expect(current.attempt_count).toBe(0);
    expect(current.status).toBe('pending');

    await claimedByA.releaseRedisLock();
  });

  test('T11.2d-22: attempt_count starts at 0, does not increment on claim, increments atomically on attempt start, and never exceeds MAX_ATTEMPTS', async () => {
    const { url } = await startHttpServer((_req, res) => {
      res.writeHead(502);
      res.end('bad gateway');
    });

    await createTestEndpoint({
      url,
      subscribedEvents: ['event.processed']
    });
    const { event } = await createTestSecurityEventAndRisk();

    const { enqueued } = await enqueueWebhooksForEvent({
      eventType: 'event.processed',
      sourceEventId: event.event_id
    });
    const [job] = enqueued;
    expect(job.attempt_count).toBe(0);

    const lookupFn = jest.fn().mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);
    let simulatedNow = new Date();

    for (let expectedAttempt = 1; expectedAttempt <= DEFAULT_MAX_ATTEMPTS; expectedAttempt += 1) {
      const ownerToken = `worker_step_${expectedAttempt}`;
      const claimRes = await claimDeliveryJob(job.id, {
        ownerToken,
        now: simulatedNow
      });
      expect(claimRes.claimed).toBe(true);
      // Claiming must NOT increment attempt_count
      expect(claimRes.delivery.attempt_count).toBe(expectedAttempt - 1);

      const outcome = await executeWebhookDelivery(job.id, {
        alreadyClaimed: true,
        ownerToken,
        now: simulatedNow,
        lookupFn,
        allowLocalTargets: true,
        allowInsecureHttp: true,
        randomFn: () => 0.5,
        env: TEST_ENV_WITH_KEY
      });
      await claimRes.releaseRedisLock();

      const reloaded = await WebhookDeliveryLog.findByPk(job.id);
      expect(reloaded.attempt_count).toBe(expectedAttempt);

      if (expectedAttempt < DEFAULT_MAX_ATTEMPTS) {
        expect(outcome.status).toBe('pending');
        expect(reloaded.status).toBe('pending');
        expect(reloaded.locked_by).toBeNull();
        simulatedNow = new Date(reloaded.next_attempt_at.getTime() + 1000);
      } else {
        expect(outcome.status).toBe('failed');
        expect(reloaded.status).toBe('failed');
        expect(reloaded.next_attempt_at).toBeNull();
        expect(reloaded.locked_by).toBeNull();
      }
    }

    // Even if forced back to pending at attempt_count = DEFAULT_MAX_ATTEMPTS, beginDeliveryAttempt refuses to increment past DEFAULT_MAX_ATTEMPTS
    await WebhookDeliveryLog.update(
      { status: 'pending', locked_by: 'worker_overflow', locked_at: new Date() },
      { where: { id: job.id } }
    );
    const overflowAttempt = await beginDeliveryAttempt(job.id, 'worker_overflow');
    expect(overflowAttempt).toEqual({ started: false, attemptCount: null });
    const finalRow = await WebhookDeliveryLog.findByPk(job.id);
    expect(finalRow.attempt_count).toBe(DEFAULT_MAX_ATTEMPTS);
  });

  test('T11.2d-23: Retryable vs permanent failure classification is enforced across HTTP status codes, network/DNS errors, and crypto errors', async () => {
    // 1. Direct unit classification checks
    expect(classifyHttpResponseStatus(200)).toEqual({
      outcome: 'delivered',
      errorCode: null
    });
    for (const retryableStatus of [408, 429, 500, 502, 503, 504]) {
      expect(classifyHttpResponseStatus(retryableStatus)).toEqual({
        outcome: 'retry',
        errorCode: `HTTP_${retryableStatus}`
      });
    }
    for (const permanentStatus of [400, 401, 403, 404, 410, 422]) {
      expect(classifyHttpResponseStatus(permanentStatus)).toEqual({
        outcome: 'permanent_failure',
        errorCode: `HTTP_${permanentStatus}`
      });
    }

    // 2. Permanent 404 HTTP status fails immediately on attempt 1 without retry
    const { url: url404 } = await startHttpServer((_req, res) => {
      res.writeHead(404);
      res.end('not found');
    });
    const { endpoint: ep404 } = await createTestEndpoint({
      url: url404,
      subscribedEvents: ['event.processed']
    });
    const { event } = await createTestSecurityEventAndRisk();
    const { enqueued: enq404 } = await enqueueWebhooksForEvent({
      eventType: 'event.processed',
      sourceEventId: event.event_id
    });
    const [job404] = enq404;
    const lookupFn = jest.fn().mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);

    const res404 = await executeWebhookDelivery(job404.id, {
      lookupFn,
      allowLocalTargets: true,
      allowInsecureHttp: true,
      env: TEST_ENV_WITH_KEY
    });
    expect(res404.status).toBe('failed');
    expect(res404.error_code).toBe('HTTP_404');
    expect(res404.attempt_count).toBe(1);

    // 3. Missing master encryption key is retryable (SECRET_DECRYPTION_UNAVAILABLE), whereas corrupted ciphertext is permanent (SECRET_DECRYPTION_FAILED)
    await WebhookEndpoint.destroy({ where: { id: ep404.id } });
    const { endpoint: epCrypto } = await createTestEndpoint({
      url: url404,
      subscribedEvents: ['decision.recorded']
    });
    const { policyDecision } = await createTestPolicyDecision();
    const { enqueued: enqCrypto } = await enqueueWebhooksForEvent({
      eventType: 'decision.recorded',
      sourceEventId: policyDecision.id
    });
    const [jobCrypto] = enqCrypto;

    const missingKeyRes = await executeWebhookDelivery(jobCrypto.id, {
      lookupFn,
      env: {
        NODE_ENV: 'test',
        REQUIRE_WEBHOOK_ENCRYPTION_KEY: 'true',
        WEBHOOK_SECRET_ENCRYPTION_KEY: ''
      }
    });
    expect(missingKeyRes.status).toBe('pending');
    expect(missingKeyRes.error_code).toBe('SECRET_DECRYPTION_UNAVAILABLE');
    expect(missingKeyRes.attempt_count).toBe(1);

    // Corrupt the auth tag on the endpoint -> permanent failure
    await WebhookEndpoint.update(
      { secret_auth_tag: '00000000000000000000000000000000' },
      { where: { id: epCrypto.id } }
    );
    const corruptRes = await executeWebhookDelivery(jobCrypto.id, {
      now: new Date(Date.now() + 60_000),
      lookupFn,
      env: TEST_ENV_WITH_KEY
    });
    expect(corruptRes.status).toBe('failed');
    expect(corruptRes.error_code).toBe('SECRET_DECRYPTION_FAILED');
    expect(corruptRes.attempt_count).toBe(2);
  });

  test('T11.2d-24: Retry-After delta-seconds and HTTP-date values are parsed, bounded, and respected', () => {
    const nowMs = Date.now();

    // Delta-seconds
    expect(parseRetryAfterMs('120', { nowMs })).toBe(120_000);
    expect(parseRetryAfterMs('999999', { nowMs })).toBe(DEFAULT_MAX_RETRY_AFTER_MS);
    expect(parseRetryAfterMs('-5', { nowMs })).toBeNull();
    expect(parseRetryAfterMs('invalid-header', { nowMs })).toBeNull();

    // HTTP-date
    const futureDateHeader = new Date(nowMs + 45_000).toUTCString();
    const parsedDateDelay = parseRetryAfterMs(futureDateHeader, { nowMs });
    expect(parsedDateDelay).toBeGreaterThanOrEqual(44_000);
    expect(parsedDateDelay).toBeLessThanOrEqual(46_000);

    // Exponential schedule without Retry-After (deterministic randomFn = 0.5 -> multiplier 1.0)
    expect(computeRetryDelayMs({ attemptCount: 1, nowMs, randomFn: () => 0.5 })).toBe(
      DEFAULT_BASE_BACKOFF_MS
    );
    expect(computeRetryDelayMs({ attemptCount: 2, nowMs, randomFn: () => 0.5 })).toBe(
      DEFAULT_BASE_BACKOFF_MS * 2
    );
    expect(computeRetryDelayMs({ attemptCount: 3, nowMs, randomFn: () => 0.5 })).toBe(
      DEFAULT_BASE_BACKOFF_MS * 4
    );

    // Retry-After on 429/503 larger than exponential backoff overrides base backoff (capped at DEFAULT_MAX_RETRY_AFTER_MS)
    expect(
      computeRetryDelayMs({
        attemptCount: 1,
        httpStatus: 429,
        retryAfterHeader: '90',
        nowMs,
        randomFn: () => 0.5
      })
    ).toBe(90_000);
    expect(
      computeRetryDelayMs({
        attemptCount: 1,
        httpStatus: 503,
        retryAfterHeader: '3600',
        nowMs,
        randomFn: () => 0.5
      })
    ).toBe(Math.max(DEFAULT_MAX_BACKOFF_MS, DEFAULT_MAX_RETRY_AFTER_MS));

    // Retry-After smaller than exponential backoff does not shrink backoff below exponential delay
    expect(
      computeRetryDelayMs({
        attemptCount: 3,
        httpStatus: 429,
        retryAfterHeader: '1',
        nowMs,
        randomFn: () => 0.5
      })
    ).toBe(DEFAULT_BASE_BACKOFF_MS * 4);
  });

  test('T11.2d-25: Stale-lease recovery (reconcileStaleLockedDeliveries) reschedules or fails rows without incrementing attempt_count a second time', async () => {
    const { endpoint } = await createTestEndpoint({
      url: 'https://lease.example.com/hook',
      subscribedEvents: ['event.processed', 'decision.recorded']
    });
    const { event } = await createTestSecurityEventAndRisk();
    const { policyDecision } = await createTestPolicyDecision();

    const { enqueued: enqReschedule } = await enqueueWebhooksForEvent({
      eventType: 'event.processed',
      sourceEventId: event.event_id
    });
    const [jobReschedule] = enqReschedule;

    const { enqueued: enqExhausted } = await enqueueWebhooksForEvent({
      eventType: 'decision.recorded',
      sourceEventId: policyDecision.id
    });
    const [jobExhausted] = enqExhausted;

    const staleLockTime = new Date(Date.now() - 120_000);

    // Simulate Worker crash AFTER beginDeliveryAttempt incremented attempt_count to 2
    await WebhookDeliveryLog.update(
      {
        status: 'pending',
        attempt_count: 2,
        locked_at: staleLockTime,
        locked_by: 'crashed_worker_1'
      },
      { where: { id: jobReschedule.id } }
    );

    // Simulate Worker crash AFTER beginDeliveryAttempt incremented attempt_count to DEFAULT_MAX_ATTEMPTS (5)
    await WebhookDeliveryLog.update(
      {
        status: 'pending',
        attempt_count: DEFAULT_MAX_ATTEMPTS,
        locked_at: staleLockTime,
        locked_by: 'crashed_worker_2'
      },
      { where: { id: jobExhausted.id } }
    );

    const summary = await reconcileStaleLockedDeliveries({
      now: new Date(),
      leaseTimeoutMs: 30_000
    });

    expect(summary).toEqual({
      reconciledCount: 2,
      rescheduledCount: 1,
      failedCount: 1
    });

    const reloadedRescheduled = await WebhookDeliveryLog.findByPk(jobReschedule.id);
    expect(reloadedRescheduled.status).toBe('pending');
    expect(reloadedRescheduled.attempt_count).toBe(2); // Must NOT increment a second time
    expect(reloadedRescheduled.locked_at).toBeNull();
    expect(reloadedRescheduled.locked_by).toBeNull();
    expect(reloadedRescheduled.error_code).toBe('WORKER_LEASE_EXPIRED');
    expect(reloadedRescheduled.next_attempt_at).toBeInstanceOf(Date);

    const reloadedExhausted = await WebhookDeliveryLog.findByPk(jobExhausted.id);
    expect(reloadedExhausted.status).toBe('failed');
    expect(reloadedExhausted.attempt_count).toBe(DEFAULT_MAX_ATTEMPTS); // Must NOT increment a second time
    expect(reloadedExhausted.locked_at).toBeNull();
    expect(reloadedExhausted.locked_by).toBeNull();
    expect(reloadedExhausted.next_attempt_at).toBeNull();
    expect(reloadedExhausted.error_code).toBe('WORKER_LEASE_EXPIRED');
    expect(endpoint.id).toBeDefined();
  });

  test('T11.2d-26: Missing source records fail safely with SOURCE_EVENT_NOT_FOUND without decrypting secrets or making outbound requests', async () => {
    let outboundHit = false;
    const { url } = await startHttpServer((_req, res) => {
      outboundHit = true;
      res.writeHead(200);
      res.end('ok');
    });

    await createTestEndpoint({
      url,
      subscribedEvents: ['event.processed']
    });
    const { event } = await createTestSecurityEventAndRisk();

    const { enqueued } = await enqueueWebhooksForEvent({
      eventType: 'event.processed',
      sourceEventId: event.event_id
    });
    const [job] = enqueued;

    // Remove the source SecurityEvent before delivery runs
    await RiskAssessment.destroy({ where: { event_id: event.event_id } });
    await SecurityEvent.destroy({ where: { event_id: event.event_id } });

    const lookupFn = jest.fn();
    const outcome = await executeWebhookDelivery(job.id, {
      lookupFn,
      // Even with an unconfigured encryption key, secret decryption must never be reached
      env: {
        NODE_ENV: 'test',
        REQUIRE_WEBHOOK_ENCRYPTION_KEY: 'true',
        WEBHOOK_SECRET_ENCRYPTION_KEY: ''
      }
    });

    expect(outcome.status).toBe('failed');
    expect(outcome.error_code).toBe('SOURCE_EVENT_NOT_FOUND');
    expect(outcome.attempt_count).toBe(0);
    expect(lookupFn).not.toHaveBeenCalled();
    expect(outboundHit).toBe(false);
  });

  test('T11.2d-27: Deactivated or deleted endpoints fail safely with ENDPOINT_INACTIVE / ENDPOINT_DELETED without decrypting secrets or making outbound requests', async () => {
    let outboundHit = false;
    const { url } = await startHttpServer((_req, res) => {
      outboundHit = true;
      res.writeHead(200);
      res.end('ok');
    });

    const { endpoint } = await createTestEndpoint({
      url,
      subscribedEvents: ['event.processed']
    });
    const { event } = await createTestSecurityEventAndRisk();

    const { enqueued } = await enqueueWebhooksForEvent({
      eventType: 'event.processed',
      sourceEventId: event.event_id
    });
    const [job] = enqueued;

    // Deactivate endpoint after enqueue
    await WebhookEndpoint.update(
      { is_active: false },
      { where: { id: endpoint.id } }
    );

    const lookupFn = jest.fn();
    const inactiveOutcome = await executeWebhookDelivery(job.id, {
      lookupFn,
      env: {
        NODE_ENV: 'test',
        REQUIRE_WEBHOOK_ENCRYPTION_KEY: 'true',
        WEBHOOK_SECRET_ENCRYPTION_KEY: ''
      }
    });

    expect(inactiveOutcome.status).toBe('failed');
    expect(inactiveOutcome.error_code).toBe('ENDPOINT_INACTIVE');
    expect(inactiveOutcome.attempt_count).toBe(0);
    expect(lookupFn).not.toHaveBeenCalled();
    expect(outboundHit).toBe(false);

    // Also verify deleted endpoint handling when the endpoint is deleted while a job is claimed
    const { endpoint: epToDelete } = await createTestEndpoint({
      url,
      subscribedEvents: ['decision.recorded']
    });
    const { policyDecision } = await createTestPolicyDecision();
    const { enqueued: enqDelete } = await enqueueWebhooksForEvent({
      eventType: 'decision.recorded',
      sourceEventId: policyDecision.id
    });
    const [jobDelete] = enqDelete;

    // Mock WebhookEndpoint.findByPk to return null right after claim to simulate concurrent deletion
    jest.spyOn(WebhookEndpoint, 'findByPk').mockResolvedValueOnce(null);
    const deletedOutcome = await executeWebhookDelivery(jobDelete.id, {
      lookupFn,
      env: {
        NODE_ENV: 'test',
        REQUIRE_WEBHOOK_ENCRYPTION_KEY: 'true',
        WEBHOOK_SECRET_ENCRYPTION_KEY: ''
      }
    });
    expect(deletedOutcome.error_code).toBe('ENDPOINT_NOT_FOUND');
    expect(deletedOutcome.status).toBe('failed');
    expect(epToDelete.id).toBeDefined();
  });

  // =========================================================================
  // 4. Regression & Secret / Response Body Redaction Tests
  // =========================================================================

  test('T11.2d-28: WebhookDeliveryLog has no payload column, DELIVERY_STATUSES is unchanged, and Redis prefixes are configured', () => {
    expect(WebhookDeliveryLog.DELIVERY_STATUSES).toEqual([
      'pending',
      'delivered',
      'failed'
    ]);
    expect(Object.isFrozen(WebhookDeliveryLog.DELIVERY_STATUSES)).toBe(true);

    const attributes = Object.keys(WebhookDeliveryLog.rawAttributes);
    expect(attributes).not.toContain('payload');
    expect(attributes).not.toContain('response_body');
    expect(attributes).not.toContain('secret');
    expect(attributes).not.toContain('encrypted_secret');
    expect(attributes).toEqual(
      expect.arrayContaining([
        'id',
        'webhook_id',
        'event_type',
        'source_event_id',
        'status',
        'attempt_count',
        'next_attempt_at',
        'last_attempt_at',
        'locked_at',
        'locked_by',
        'http_status',
        'error_code',
        'delivered_at',
        'created_at',
        'updated_at'
      ])
    );

    expect(REDIS_PREFIXES.WEBHOOK_DELIVERY_LOCK).toBe('webhook_delivery:lock:');
    expect(REDIS_PREFIXES.WEBHOOK_WORKER_LOCK).toBe('webhook_delivery:worker_lock');
  });

  test('T11.2d-29: End-to-end delivery verifies signed envelope headers/body and never leaks signing secret or encryption key in logs or records', async () => {
    let capturedHeaders = null;
    let capturedRawBody = null;

    const { url } = await startHttpServer((req, res) => {
      capturedHeaders = req.headers;
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        capturedRawBody = Buffer.concat(chunks);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"received":true}');
      });
    });

    const { endpoint, secret } = await createTestEndpoint({
      url,
      subscribedEvents: ['event.processed', 'decision.recorded']
    });
    const { event } = await createTestSecurityEventAndRisk();

    const envelopesBuilt = await buildWebhookEventEnvelope({
      id: 'whdel_preview0123456789abcdef012345',
      webhook_id: endpoint.id,
      event_type: 'event.processed',
      source_event_id: event.event_id,
      created_at: new Date()
    });
    expect(envelopesBuilt).toMatchObject({
      id: 'whdel_preview0123456789abcdef012345',
      webhook_id: endpoint.id,
      event_type: 'event.processed',
      source_event_id: event.event_id
    });
    expect(envelopesBuilt.data.event_id).toBe(event.event_id);
    expect(envelopesBuilt.data.risk.risk_score).toBe(82);

    await enqueueWebhooksForEvent({
      eventType: 'event.processed',
      sourceEventId: event.event_id
    });

    const lookupFn = jest.fn().mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);
    const summary = await processPendingWebhookDeliveries({
      lookupFn,
      allowLocalTargets: true,
      allowInsecureHttp: true,
      env: TEST_ENV_WITH_KEY
    });

    expect(summary).toMatchObject({
      processed: 1,
      deliveredCount: 1,
      retriedCount: 0,
      failedCount: 0
    });

    expect(capturedRawBody).toBeInstanceOf(Buffer);
    expect(capturedHeaders['content-type']).toBe('application/json; charset=utf-8');
    expect(capturedHeaders['user-agent']).toBe('ActionGuard-Webhook/1.0');
    expect(capturedHeaders['x-actionguard-webhook-event']).toBe('event.processed');
    expect(capturedHeaders['x-actionguard-webhook-id']).toMatch(/^whdel_[0-9a-f]{32}$/);

    // Receiver verifies signature using exact raw body bytes and timestamp header
    const isVerified = verifyWebhookSignature({
      rawBody: capturedRawBody,
      signatureHeader: capturedHeaders['x-actionguard-webhook-signature'],
      timestampHeader: capturedHeaders['x-actionguard-webhook-timestamp'],
      secret,
      nowSeconds: Number(capturedHeaders['x-actionguard-webhook-timestamp'])
    });
    expect(isVerified).toBe(true);

    const logRow = await WebhookDeliveryLog.findOne({
      where: { webhook_id: endpoint.id }
    });
    expect(logRow.status).toBe('delivered');
    expect(logRow.attempt_count).toBe(1);
    expect(logRow.http_status).toBe(200);
    expect(logRow.delivered_at).toBeInstanceOf(Date);
    expect(logRow.locked_at).toBeNull();
    expect(logRow.locked_by).toBeNull();

    const serializedRecord = JSON.stringify(logRow.toJSON());
    expect(serializedRecord).not.toContain(secret);
    expect(serializedRecord).not.toContain(TEST_MASTER_KEY_HEX);
  });

  test('T11.2d-30: Receiver response bodies never appear in delivery records or error properties on failure', async () => {
    const sensitiveReceiverBody = 'INTERNAL_RECEIVER_STACK_TRACE_SECRET_TOKEN_998877';
    const { url } = await startHttpServer((_req, res) => {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end(sensitiveReceiverBody);
    });

    const { endpoint } = await createTestEndpoint({
      url,
      subscribedEvents: ['decision.recorded']
    });
    const { policyDecision } = await createTestPolicyDecision();

    const { enqueued } = await enqueueWebhooksForEvent({
      eventType: 'decision.recorded',
      sourceEventId: policyDecision.id
    });
    const [job] = enqueued;

    const lookupFn = jest.fn().mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);
    const outcome = await executeWebhookDelivery(job.id, {
      lookupFn,
      allowLocalTargets: true,
      allowInsecureHttp: true,
      env: TEST_ENV_WITH_KEY
    });

    expect(outcome.status).toBe('pending');
    expect(outcome.error_code).toBe('HTTP_500');
    expect(outcome.http_status).toBe(500);

    const reloaded = await WebhookDeliveryLog.findByPk(job.id);
    const serialized = JSON.stringify(reloaded.toJSON());
    expect(serialized).not.toContain(sensitiveReceiverBody);
    expect(endpoint.id).toBeDefined();
  });

  test('T11.2d-31: Positive HTTPS delivery succeeds when using a trusted test CA and matching certificate hostname', async () => {
    const tlsCreds = createSelfSignedTlsCredentials('webhooks.example.com');
    let receivedHeaders = null;
    let receivedBody = null;

    const { url, port } = await startHttpsServer(tlsCreds, (req, res) => {
      receivedHeaders = req.headers;
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        receivedBody = Buffer.concat(chunks).toString('utf8');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"tls_ok":true}');
      });
    });

    const lookupFn = jest.fn().mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);
    const result = await sendPinnedWebhookRequest(url, {
      bodyBuffer: Buffer.from('{"id":"whdel_https_pos"}', 'utf8'),
      headers: {
        'X-ActionGuard-Webhook-Id': 'whdel_https_pos',
        'X-ActionGuard-Webhook-Event': 'event.processed'
      },
      lookupFn,
      allowLocalTargets: true,
      tlsOptions: {
        ca: tlsCreds.cert
      },
      env: {
        NODE_ENV: 'test',
        WEBHOOK_ALLOW_LOCAL_TARGETS: 'true'
      }
    });

    expect(result.httpStatus).toBe(200);
    expect(result.pinnedAddress).toBe('127.0.0.1');
    expect(receivedBody).toBe('{"id":"whdel_https_pos"}');
    expect(receivedHeaders.host).toBe(`webhooks.example.com:${port}`);
  });

  test('T11.2d-32: HTTPS hostname mismatch against trusted test CA fails permanently with TLS_VERIFICATION_FAILED', async () => {
    const tlsCreds = createSelfSignedTlsCredentials('webhooks.example.com');
    let receiverHit = false;

    const { port } = await startHttpsServer(tlsCreds, (_req, res) => {
      receiverHit = true;
      res.writeHead(200);
      res.end('should-never-reach');
    });

    const mismatchedUrl = `https://wrong-host.example.com:${port}/webhooks/receive`;
    const lookupFn = jest.fn().mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);

    await expect(
      sendPinnedWebhookRequest(mismatchedUrl, {
        bodyBuffer: Buffer.from('{"id":"whdel_https_mismatch"}', 'utf8'),
        lookupFn,
        allowLocalTargets: true,
        tlsOptions: {
          ca: tlsCreds.cert
        },
        env: {
          NODE_ENV: 'test',
          WEBHOOK_ALLOW_LOCAL_TARGETS: 'true'
        }
      })
    ).rejects.toMatchObject({
      name: 'WebhookDeliveryError',
      code: 'TLS_VERIFICATION_FAILED',
      retryable: false
    });

    expect(receiverHit).toBe(false);
  });

  test('T11.2d-33: Hung DNS lookup times out cleanly with retryable DNS_RESOLUTION_FAILED', async () => {
    const hungLookupFn = jest.fn(
      () =>
        new Promise(() => {
          // Intentionally never settles to simulate hung DNS resolver
        })
    );

    await expect(
      resolveAndValidateWebhookTarget('https://siem.example.com/hook', {
        lookupFn: hungLookupFn,
        dnsTimeoutMs: 50,
        env: { NODE_ENV: 'test' }
      })
    ).rejects.toMatchObject({
      name: 'WebhookDeliveryError',
      code: 'DNS_RESOLUTION_FAILED',
      retryable: true
    });

    expect(hungLookupFn).toHaveBeenCalledTimes(1);
  });

  test('T11.2d-34: Missing parent WebhookEndpoint permanently fails the delivery row with ENDPOINT_NOT_FOUND and handles FK cascade safely', async () => {
    const { url } = await startHttpServer((_req, res) => {
      res.writeHead(200);
      res.end('ok');
    });

    const { endpoint } = await createTestEndpoint({
      url,
      subscribedEvents: ['event.processed', 'decision.recorded']
    });
    const { event } = await createTestSecurityEventAndRisk();
    const { policyDecision } = await createTestPolicyDecision();

    const { enqueued: enqPre } = await enqueueWebhooksForEvent({
      eventType: 'event.processed',
      sourceEventId: event.event_id
    });
    const [jobPre] = enqPre;

    // 1. Pre-envelope check: WebhookEndpoint.findByPk returns null while delivery row still exists
    jest.spyOn(WebhookEndpoint, 'findByPk').mockResolvedValueOnce(null);
    const preOutcome = await executeWebhookDelivery(jobPre.id, {
      env: TEST_ENV_WITH_KEY
    });

    expect(preOutcome).toMatchObject({
      executed: false,
      status: 'failed',
      error_code: 'ENDPOINT_NOT_FOUND',
      attempt_count: 0
    });

    const reloadedPre = await WebhookDeliveryLog.findByPk(jobPre.id);
    expect(reloadedPre.status).toBe('failed');
    expect(reloadedPre.error_code).toBe('ENDPOINT_NOT_FOUND');
    expect(reloadedPre.locked_at).toBeNull();
    expect(reloadedPre.locked_by).toBeNull();
    expect(reloadedPre.next_attempt_at).toBeNull();

    // 2. Post-envelope check: first findByPk succeeds, second findByPk (after buildWebhookEventEnvelope) returns null
    const { enqueued: enqPost } = await enqueueWebhooksForEvent({
      eventType: 'decision.recorded',
      sourceEventId: policyDecision.id
    });
    const [jobPost] = enqPost;

    jest
      .spyOn(WebhookEndpoint, 'findByPk')
      .mockResolvedValueOnce(endpoint)
      .mockResolvedValueOnce(null);

    const postOutcome = await executeWebhookDelivery(jobPost.id, {
      env: TEST_ENV_WITH_KEY
    });

    expect(postOutcome).toMatchObject({
      executed: false,
      status: 'failed',
      error_code: 'ENDPOINT_NOT_FOUND',
      attempt_count: 0
    });

    const reloadedPost = await WebhookDeliveryLog.findByPk(jobPost.id);
    expect(reloadedPost.status).toBe('failed');
    expect(reloadedPost.error_code).toBe('ENDPOINT_NOT_FOUND');
    expect(reloadedPost.locked_at).toBeNull();
    expect(reloadedPost.locked_by).toBeNull();

    // 3. Real FK cascade deletion while job is already claimed in-memory: handles missing row safely without throwing
    const { endpoint: cascadeEp } = await createTestEndpoint({
      url,
      subscribedEvents: ['event.processed']
    });
    const { event: cascadeEvent } = await createTestSecurityEventAndRisk();
    const { enqueued: enqCascade } = await enqueueWebhooksForEvent({
      eventType: 'event.processed',
      sourceEventId: cascadeEvent.event_id
    });
    const jobCascade = enqCascade.find((j) => j.webhook_id === cascadeEp.id);
    expect(jobCascade).toBeDefined();

    const claimRes = await claimDeliveryJob(jobCascade.id, {
      ownerToken: 'worker_cascade_test'
    });
    expect(claimRes.claimed).toBe(true);

    // Delete parent endpoint in MySQL, which cascades to delete jobCascade row
    await WebhookEndpoint.destroy({ where: { id: cascadeEp.id } });
    jest.spyOn(WebhookDeliveryLog, 'findByPk').mockResolvedValueOnce(claimRes.delivery);

    const cascadeOutcome = await executeWebhookDelivery(jobCascade.id, {
      alreadyClaimed: true,
      ownerToken: 'worker_cascade_test',
      env: TEST_ENV_WITH_KEY
    });
    await claimRes.releaseRedisLock();

    expect(cascadeOutcome).toMatchObject({
      executed: false,
      status: 'deleted',
      error_code: 'ENDPOINT_NOT_FOUND'
    });
  });

  test('T11.2d-35: Expired lease at attempt_count === max_attempts cannot be claimed for an extra attempt and reconciliation fails the exhausted row', async () => {
    let outboundHit = false;
    const { url } = await startHttpServer((_req, res) => {
      outboundHit = true;
      res.writeHead(200);
      res.end('ok');
    });

    await createTestEndpoint({
      url,
      subscribedEvents: ['event.processed']
    });
    const { event } = await createTestSecurityEventAndRisk();

    const { enqueued } = await enqueueWebhooksForEvent({
      eventType: 'event.processed',
      sourceEventId: event.event_id
    });
    const [job] = enqueued;

    const expiredLockAt = new Date(Date.now() - 120_000);
    await WebhookDeliveryLog.update(
      {
        status: 'pending',
        attempt_count: DEFAULT_MAX_ATTEMPTS,
        locked_at: expiredLockAt,
        locked_by: 'crashed_worker_at_max'
      },
      { where: { id: job.id } }
    );

    // 1. Direct claimDeliveryJob must refuse to claim the exhausted row even though its lease is expired
    const claimAttempt = await claimDeliveryJob(job.id, {
      ownerToken: 'new_worker_takeover',
      leaseTimeoutMs: 30_000,
      maxAttempts: DEFAULT_MAX_ATTEMPTS
    });
    expect(claimAttempt.claimed).toBe(false);
    expect(claimAttempt.reason).toBe('not_claimable');

    // 2. Direct executeWebhookDelivery must also refuse to claim/execute a 6th attempt
    const execAttempt = await executeWebhookDelivery(job.id, {
      leaseTimeoutMs: 30_000,
      maxAttempts: DEFAULT_MAX_ATTEMPTS,
      allowLocalTargets: true,
      allowInsecureHttp: true,
      env: TEST_ENV_WITH_KEY
    });
    expect(execAttempt.executed).toBe(false);
    expect(outboundHit).toBe(false);

    // 3. processPendingWebhookDeliveries reconciles the expired lease first and fails the exhausted row without starting an attempt
    const batchSummary = await processPendingWebhookDeliveries({
      leaseTimeoutMs: 30_000,
      maxAttempts: DEFAULT_MAX_ATTEMPTS,
      allowLocalTargets: true,
      allowInsecureHttp: true,
      env: TEST_ENV_WITH_KEY
    });

    expect(batchSummary.reconciled).toEqual({
      reconciledCount: 1,
      rescheduledCount: 0,
      failedCount: 1
    });
    expect(batchSummary.processed).toBe(0);
    expect(outboundHit).toBe(false);

    const reloaded = await WebhookDeliveryLog.findByPk(job.id);
    expect(reloaded.status).toBe('failed');
    expect(reloaded.attempt_count).toBe(DEFAULT_MAX_ATTEMPTS);
    expect(reloaded.error_code).toBe('WORKER_LEASE_EXPIRED');
    expect(reloaded.locked_at).toBeNull();
    expect(reloaded.locked_by).toBeNull();
    expect(reloaded.next_attempt_at).toBeNull();
  });

  test('T11.2d-36: event.processed envelope builds and delivers cleanly with data.risk === null when RiskAssessment is absent', async () => {
    let capturedBody = null;
    const { url } = await startHttpServer((req, res) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        capturedBody = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      });
    });

    const { endpoint } = await createTestEndpoint({
      url,
      subscribedEvents: ['event.processed']
    });

    dbTouched = true;
    const eventWithoutRisk = await SecurityEvent.create({
      user_id: testUser.id,
      event_type: 'login_success',
      timestamp: new Date(),
      context: {
        ip_address: '198.51.100.77',
        country: 'US',
        device_id: 'dev_no_risk_test'
      },
      metadata: {
        action_name: 'session.login',
        action_sensitivity: 'low'
      }
    });

    const { enqueued } = await enqueueWebhooksForEvent({
      eventType: 'event.processed',
      sourceEventId: eventWithoutRisk.event_id
    });
    const [job] = enqueued;

    const lookupFn = jest.fn().mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);
    const outcome = await executeWebhookDelivery(job.id, {
      lookupFn,
      allowLocalTargets: true,
      allowInsecureHttp: true,
      env: TEST_ENV_WITH_KEY
    });

    expect(outcome.status).toBe('delivered');
    expect(outcome.http_status).toBe(200);
    expect(capturedBody).toBeDefined();
    expect(capturedBody.id).toBe(job.id);
    expect(capturedBody.webhook_id).toBe(endpoint.id);
    expect(capturedBody.event_type).toBe('event.processed');
    expect(capturedBody.source_event_id).toBe(eventWithoutRisk.event_id);
    expect(capturedBody.data.event_id).toBe(eventWithoutRisk.event_id);
    expect(capturedBody.data.risk).toBeNull();
  });
});
