const http = require('http');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { io: ioClient } = require('socket.io-client');

const app = require('../src/app');
const {
  sequelize,
  User,
  Session,
  Device,
  SecurityEvent,
  RiskAssessment,
  ActionSequence,
  SequenceEvent,
  BehavioralBaseline
} = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const { recordSecurityEvent } = require('../src/services/eventService');
const { createSession } = require('../src/services/sessionService');
const { invalidateSequenceCache } = require('../src/services/sequenceCacheService');
const geoService = require('../src/services/geoService');
const {
  initSocketServer,
  closeSocketServer
} = require('../src/realtime/socketServer');
const { JWT_SECRET } = require('../src/middleware/auth');

const TEST_ADMIN_KEY_VALID = 'admin_secret_key_with_at_least_32_characters_12345';

async function waitForCondition(predicate, timeoutMs = 4000, intervalMs = 25) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await predicate()) return true;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return false;
}

function createClient(port, options = {}) {
  return ioClient(`http://localhost:${port}`, {
    transports: ['websocket'],
    autoConnect: false,
    reconnection: false,
    ...options
  });
}

function connectClient(client) {
  return new Promise((resolve, reject) => {
    client.on('connect', () => resolve(client));
    client.on('connect_error', (err) => reject(err));
    client.connect();
  });
}

describe('Module 7.3 — Real-Time Scenario Tests & Documented Limitations', () => {
  let httpServer;
  let serverPort;
  let userA;
  let userB;
  let sessionA1;
  let sessionA2;
  let sessionB;
  let tokenA1;
  let tokenA2;
  let tokenB;
  const passwordPlain = 'Password123!';
  const activeClients = [];

  const originalAdminKey = process.env.ACTIONGUARD_ADMIN_API_KEY;

  beforeAll(async () => {
    await runMigrations();

    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await RiskAssessment.destroy({ where: {}, force: true });
    await SequenceEvent.destroy({ where: {}, force: true });
    await ActionSequence.destroy({ where: {}, force: true });
    await BehavioralBaseline.destroy({ where: {}, force: true });
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    const passwordHash = await bcrypt.hash(passwordPlain, 10);

    userA = await User.create({
      email: 'scenarios-user-a@example.com',
      password_hash: passwordHash
    });

    userB = await User.create({
      email: 'scenarios-user-b@example.com',
      password_hash: passwordHash
    });

    sessionA1 = await createSession(userA.id, userA.email);
    sessionA2 = await createSession(userA.id, userA.email);
    sessionB = await createSession(userB.id, userB.email);

    tokenA1 = jwt.sign(
      { id: userA.id, email: userA.email, session_id: sessionA1.sessionId },
      JWT_SECRET,
      { expiresIn: '900s' }
    );

    tokenA2 = jwt.sign(
      { id: userA.id, email: userA.email, session_id: sessionA2.sessionId },
      JWT_SECRET,
      { expiresIn: '900s' }
    );

    tokenB = jwt.sign(
      { id: userB.id, email: userB.email, session_id: sessionB.sessionId },
      JWT_SECRET,
      { expiresIn: '900s' }
    );
  });

  afterAll(async () => {
    process.env.ACTIONGUARD_ADMIN_API_KEY = originalAdminKey;

    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await RiskAssessment.destroy({ where: {}, force: true });
    await SequenceEvent.destroy({ where: {}, force: true });
    await ActionSequence.destroy({ where: {}, force: true });
    await BehavioralBaseline.destroy({ where: {}, force: true });
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');
  });

  beforeEach(async () => {
    process.env.ACTIONGUARD_ADMIN_API_KEY = TEST_ADMIN_KEY_VALID;

    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await RiskAssessment.destroy({ where: {}, force: true });
    await SequenceEvent.destroy({ where: {}, force: true });
    await ActionSequence.destroy({ where: {}, force: true });
    await SecurityEvent.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    await invalidateSequenceCache(userA.id);
    await invalidateSequenceCache(userB.id);

    httpServer = http.createServer(app);
    await new Promise((resolve) => {
      httpServer.listen(0, () => {
        serverPort = httpServer.address().port;
        resolve();
      });
    });

    initSocketServer(httpServer, {
      revalidationIntervalSeconds: 30
    });
  });

  afterEach(async () => {
    while (activeClients.length > 0) {
      const c = activeClients.pop();
      if (c && c.connected) {
        c.disconnect();
      }
    }

    await closeSocketServer();

    if (httpServer && httpServer.listening) {
      await new Promise((resolve) => httpServer.close(resolve));
    }

    jest.restoreAllMocks();
  });

  test('B1. Multi-session: user A has two sockets (two sessions), action on session 1 delivers event:recorded then risk:updated to both sockets exactly once each; user B receives nothing', async () => {
    // Connect User A on session 1 and session 2
    const clientA1 = createClient(serverPort, { auth: { token: tokenA1 } });
    const clientA2 = createClient(serverPort, { auth: { token: tokenA2 } });
    // Connect User B on session B
    const clientB = createClient(serverPort, { auth: { token: tokenB } });

    activeClients.push(clientA1, clientA2, clientB);

    await connectClient(clientA1);
    await connectClient(clientA2);
    await connectClient(clientB);

    const a1Messages = [];
    const a2Messages = [];
    const bMessages = [];

    clientA1.on('event:recorded', (d) => a1Messages.push({ event: 'event:recorded', d }));
    clientA1.on('risk:updated', (d) => a1Messages.push({ event: 'risk:updated', d }));

    clientA2.on('event:recorded', (d) => a2Messages.push({ event: 'event:recorded', d }));
    clientA2.on('risk:updated', (d) => a2Messages.push({ event: 'risk:updated', d }));

    clientB.on('event:recorded', (d) => bMessages.push({ event: 'event:recorded', d }));
    clientB.on('risk:updated', (d) => bMessages.push({ event: 'risk:updated', d }));

    // Action occurs on user A's session 1
    const event = await recordSecurityEvent({
      userId: userA.id,
      sessionId: sessionA1.sessionId,
      eventType: 'login_success',
      context: { device_fingerprint: 'fp_b1_multisess' }
    });

    const receivedBoth = await waitForCondition(
      () => a1Messages.length === 2 && a2Messages.length === 2,
      3000
    );
    expect(receivedBoth).toBe(true);

    // Verify ordering on client A1: event:recorded first, risk:updated second
    expect(a1Messages[0].event).toBe('event:recorded');
    expect(a1Messages[0].d.event_id).toBe(event.event_id);
    expect(a1Messages[1].event).toBe('risk:updated');
    expect(a1Messages[1].d.event_id).toBe(event.event_id);

    // Verify ordering on client A2: event:recorded first, risk:updated second
    expect(a2Messages[0].event).toBe('event:recorded');
    expect(a2Messages[0].d.event_id).toBe(event.event_id);
    expect(a2Messages[1].event).toBe('risk:updated');
    expect(a2Messages[1].d.event_id).toBe(event.event_id);

    // Give a brief window to confirm no duplicates arrive
    await new Promise((r) => setTimeout(r, 100));
    expect(a1Messages.length).toBe(2);
    expect(a2Messages.length).toBe(2);

    // User B receives absolutely nothing
    expect(bMessages.length).toBe(0);
  });

  test('B2. Attack timeline over sockets: legitimate user socket receives chronological tier-only payloads, final tier critical; admin receives full payloads with final score 84 and weights summing to 84; login has is_new_device and stubbed coarse location', async () => {
    const nowMs = Date.now();
    const legitimateDevice = 'fp_legit_office_workstation';
    const attackerDevice = 'fp_attacker_unrecognized_laptop';

    // 0. Seed historical login 1 hour ago in US
    await recordSecurityEvent({
      userId: userA.id,
      sessionId: sessionA1.sessionId,
      eventType: 'login_success',
      timestamp: new Date(nowMs - 3600 * 1000),
      context: {
        ip_address: '198.51.100.1',
        device_fingerprint: legitimateDevice,
        geo_country: 'US'
      }
    });

    // Connect legitimate user socket
    const userClient = createClient(serverPort, { auth: { token: tokenA1 } });
    // Connect admin socket
    const adminClient = createClient(serverPort, { auth: { apiKey: TEST_ADMIN_KEY_VALID } });
    activeClients.push(userClient, adminClient);

    await connectClient(userClient);
    await connectClient(adminClient);

    const userStream = [];
    const adminStream = [];

    userClient.on('event:recorded', (d) => userStream.push({ type: 'event:recorded', d }));
    userClient.on('risk:updated', (d) => userStream.push({ type: 'risk:updated', d }));

    adminClient.on('event:recorded', (d) => adminStream.push({ type: 'event:recorded', d }));
    adminClient.on('risk:updated', (d) => adminStream.push({ type: 'risk:updated', d }));

    // Geo resolution stubbing for attacker's login
    const geoSpy = jest.spyOn(geoService, 'resolveGeoLocation').mockResolvedValue({
      ip: '203.0.113.195',
      geo_country: 'RU',
      geo_region: 'MOW'
    });
    const coordsSpy = jest.spyOn(geoService, 'resolveCoordinates').mockImplementation(async (ip) => {
      if (ip === '198.51.100.1') return { latitude: 40.7128, longitude: -74.006 };
      return { latitude: 55.7558, longitude: 37.6173 };
    });

    let attackerSessionId;
    try {
      // 1. Attacker logs in over HTTP from unrecognized device and RU IP
      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .set('x-device-fingerprint', attackerDevice)
        .send({
          email: userA.email,
          password: passwordPlain
        })
        .expect(200);

      attackerSessionId = loginRes.body.session_id;
      expect(attackerSessionId).toBeDefined();
    } finally {
      geoSpy.mockRestore();
      coordsSpy.mockRestore();
    }

    // 2. Attacker performs recovery_email_change via pipeline
    const recoveryEvt = await recordSecurityEvent({
      userId: userA.id,
      sessionId: attackerSessionId,
      eventType: 'recovery_email_change',
      timestamp: new Date(Date.now() + 1000),
      context: {
        device_fingerprint: attackerDevice,
        geo_country: 'RU'
      },
      metadata: {
        action_sensitivity: 'medium'
      }
    });
    expect(recoveryEvt).toBeDefined();

    // 3. Attacker performs critical password_change with behavioral deviation 0.90 via pipeline
    const passwordEvt = await recordSecurityEvent({
      userId: userA.id,
      sessionId: attackerSessionId,
      eventType: 'password_change',
      timestamp: new Date(Date.now() + 2000),
      context: {
        device_fingerprint: attackerDevice,
        geo_country: 'RU'
      },
      metadata: {
        action_sensitivity: 'critical',
        behavioral_deviation: {
          is_evaluated: true,
          has_sufficient_history: true,
          deviation_score: 0.90
        }
      }
    });
    expect(passwordEvt).toBeDefined();

    // Wait for all messages across the attack timeline to arrive
    // Expected on user:
    //   login_success: event:recorded, risk:updated
    //   session_created: event:recorded (unscored)
    //   recovery_email_change: event:recorded, risk:updated
    //   password_change: event:recorded, risk:updated
    // Total = 7 messages
    const gotAll = await waitForCondition(
      () =>
        userStream.some((m) => m.type === 'risk:updated' && m.d.event_id === passwordEvt.event_id) &&
        adminStream.some((m) => m.type === 'risk:updated' && m.d.event_id === passwordEvt.event_id),
      5000
    );
    expect(gotAll).toBe(true);

    // 1. Assert chronological event arrival on legitimate user's socket
    const userRiskUpdates = userStream.filter((m) => m.type === 'risk:updated');
    const userEventRecords = userStream.filter((m) => m.type === 'event:recorded');

    expect(userEventRecords.length).toBeGreaterThanOrEqual(4);
    expect(userRiskUpdates.length).toBe(3);

    // Find the login_success event:recorded
    const loginRecorded = userEventRecords.find((m) => m.d.event_type === 'login_success');
    expect(loginRecorded).toBeDefined();
    expect(loginRecorded.d.is_new_device).toBe(true);
    expect(loginRecorded.d.coarse_location).toEqual({
      country: 'RU',
      region: 'MOW'
    });

    // All risk updates received by user must be tier-only and contain NO numeric scores or signal arrays
    for (const update of userRiskUpdates) {
      expect(typeof update.d.risk_tier).toBe('string');
      expect(update.d.risk_score).toBeUndefined();
      expect(update.d.contributing_signals).toBeUndefined();
      expect(update.d.user_id).toBeUndefined();
      expect(update.d.explanation.admin_facing).toBeUndefined();
      expect(typeof update.d.explanation.user_facing).toBe('string');
    }

    // Final risk update for password_change is tier 'critical'
    const finalUserRisk = userRiskUpdates.find((m) => m.d.event_id === passwordEvt.event_id);
    expect(finalUserRisk).toBeDefined();
    expect(finalUserRisk.d.risk_tier).toBe('critical');

    // 2. Assert admin socket receives full technical payloads
    const adminRiskUpdates = adminStream.filter((m) => m.type === 'risk:updated');
    const finalAdminRisk = adminRiskUpdates.find((m) => m.d.event_id === passwordEvt.event_id);

    expect(finalAdminRisk).toBeDefined();
    expect(finalAdminRisk.d.user_id).toBe(userA.id);
    expect(finalAdminRisk.d.risk_tier).toBe('critical');
    expect(finalAdminRisk.d.risk_score).toBe(84);

    const sumWeights = finalAdminRisk.d.contributing_signals.reduce((acc, s) => acc + s.weight, 0);
    expect(sumWeights).toBe(84);

    expect(typeof finalAdminRisk.d.explanation.admin_facing).toBe('string');
    expect(typeof finalAdminRisk.d.explanation.user_facing).toBe('string');
  });

  test('B3. Documented limitation: a second socket of the same account (a hijacker session) receives account-wide events too', async () => {
    // Legitimate user connected on session 1
    const legitSocket = createClient(serverPort, { auth: { token: tokenA1 } });

    // Attacker has hijacked or created a separate session for userA (session 2)
    const hijackerSocket = createClient(serverPort, { auth: { token: tokenA2 } });

    activeClients.push(legitSocket, hijackerSocket);

    await connectClient(legitSocket);
    await connectClient(hijackerSocket);

    const legitMessages = [];
    const hijackerMessages = [];

    legitSocket.on('event:recorded', (d) => legitMessages.push({ event: 'event:recorded', d }));
    legitSocket.on('risk:updated', (d) => legitMessages.push({ event: 'risk:updated', d }));

    hijackerSocket.on('event:recorded', (d) => hijackerMessages.push({ event: 'event:recorded', d }));
    hijackerSocket.on('risk:updated', (d) => hijackerMessages.push({ event: 'risk:updated', d }));

    // Legitimate user performs an action on session 1
    const event = await recordSecurityEvent({
      userId: userA.id,
      sessionId: sessionA1.sessionId,
      eventType: 'login_success',
      context: {
        device_fingerprint: 'fp_victim_phone',
        geo_country: 'US',
        geo_region: 'NY'
      }
    });

    const delivered = await waitForCondition(
      () => legitMessages.length >= 2 && hijackerMessages.length >= 2,
      3000
    );
    expect(delivered).toBe(true);

    // Documented limitation verification:
    // The hijacker's socket is bound to the same account room user:<userId>,
    // so it receives the account-wide event:recorded and risk:updated messages,
    // including the victim's coarse location and event metadata.
    const hijackerEvent = hijackerMessages.find((m) => m.event === 'event:recorded');
    const hijackerRisk = hijackerMessages.find((m) => m.event === 'risk:updated');

    expect(hijackerEvent).toBeDefined();
    expect(hijackerEvent.d.event_id).toBe(event.event_id);
    expect(hijackerEvent.d.coarse_location).toEqual({ country: 'US', region: 'NY' });

    expect(hijackerRisk).toBeDefined();
    expect(hijackerRisk.d.event_id).toBe(event.event_id);
  });
});
