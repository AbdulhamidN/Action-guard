const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
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
const eventBus = require('../src/events/eventBus');
const {
  initSocketServer,
  closeSocketServer
} = require('../src/realtime/socketServer');
const {
  buildUserRiskPayload,
  buildAdminRiskPayload,
  buildEventRecordedPayload
} = require('../src/realtime/payloads');
const { JWT_SECRET } = require('../src/middleware/auth');
const riskEngineService = require('../src/services/riskEngineService');

const TEST_ADMIN_KEY_VALID = 'admin_secret_key_with_at_least_32_characters_12345';

function deepFreeze(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  Object.freeze(obj);
  for (const key of Object.getOwnPropertyNames(obj)) {
    const val = obj[key];
    if (val !== null && typeof val === 'object') {
      deepFreeze(val);
    }
  }
  return obj;
}

async function waitForCondition(predicate, timeoutMs = 3000, intervalMs = 25) {
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

describe('Module 7.2 — Event Bus Pipeline Hook & Sanitized Broadcasts', () => {
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

    const passwordHash = await bcrypt.hash('Secret123!', 10);

    userA = await User.create({
      email: 'broadcaster-user-a@example.com',
      password_hash: passwordHash
    });

    userB = await User.create({
      email: 'broadcaster-user-b@example.com',
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

  describe('1. Pure Payload Builders & Immutability', () => {
    test('buildUserRiskPayload returns exact allowlisted keys and does not mutate frozen input', () => {
      const mockEvent = {
        event_id: 'evt_test_1',
        session_id: 'sess_1',
        user_id: 'usr_1',
        timestamp: new Date().toISOString()
      };
      const mockAssessment = {
        event_id: 'evt_test_1',
        user_id: 'usr_1',
        session_id: 'sess_1',
        risk_score: 84,
        risk_tier: 'critical',
        contributing_signals: [
          { signal: 'unrecognized_device', category: 'device', weight: 20 }
        ],
        evaluated_at: new Date().toISOString(),
        explanation: {
          user_facing: 'Elevated risk pattern observed across multiple security indicators.',
          admin_facing: 'Internal rule triggered'
        }
      };

      deepFreeze(mockEvent);
      deepFreeze(mockAssessment);

      const userPayload = buildUserRiskPayload(mockEvent, mockAssessment);

      expect(Object.keys(userPayload).sort()).toEqual(
        ['evaluated_at', 'event_id', 'explanation', 'risk_tier', 'session_id'].sort()
      );
      expect(Object.keys(userPayload.explanation)).toEqual(['user_facing']);
      expect(userPayload.risk_tier).toBe('critical');
      expect(userPayload.explanation.user_facing).toBe(
        'Elevated risk pattern observed across multiple security indicators.'
      );

      // Verify zero leakages
      expect(userPayload.user_id).toBeUndefined();
      expect(userPayload.risk_score).toBeUndefined();
      expect(userPayload.contributing_signals).toBeUndefined();
      expect(userPayload.explanation.admin_facing).toBeUndefined();
    });

    test('buildAdminRiskPayload returns exact allowlisted keys including admin explanation and signals', () => {
      const mockEvent = {
        event_id: 'evt_test_2',
        session_id: 'sess_2',
        user_id: 'usr_2',
        timestamp: new Date().toISOString()
      };
      const mockAssessment = {
        event_id: 'evt_test_2',
        user_id: 'usr_2',
        session_id: 'sess_2',
        risk_score: 45,
        risk_tier: 'medium',
        contributing_signals: [
          { signal: 'unrecognized_country', category: 'location', weight: 25 },
          { signal: 'base_action_login', category: 'action', weight: 20 }
        ],
        evaluated_at: new Date().toISOString(),
        explanation: {
          user_facing: 'Unusual activity attributes observed for this action.',
          admin_facing: 'Country novelty observed'
        }
      };

      deepFreeze(mockEvent);
      deepFreeze(mockAssessment);

      const adminPayload = buildAdminRiskPayload(mockEvent, mockAssessment);

      expect(Object.keys(adminPayload).sort()).toEqual(
        [
          'contributing_signals',
          'evaluated_at',
          'event_id',
          'explanation',
          'risk_score',
          'risk_tier',
          'session_id',
          'user_id'
        ].sort()
      );
      expect(Object.keys(adminPayload.explanation).sort()).toEqual(
        ['admin_facing', 'user_facing'].sort()
      );
      expect(adminPayload.risk_score).toBe(45);
      expect(adminPayload.risk_tier).toBe('medium');
      expect(adminPayload.contributing_signals).toHaveLength(2);
      expect(adminPayload.user_id).toBe('usr_2');
    });

    test('buildEventRecordedPayload with includeUserId=false and novelty signals present', () => {
      const mockEvent = {
        event_id: 'evt_test_3',
        session_id: 'sess_3',
        user_id: 'usr_3',
        event_type: 'login_success',
        timestamp: new Date().toISOString(),
        context: {
          device_fingerprint: 'fp_secret_123',
          geo_country: 'FR',
          geo_region: 'IDF',
          ip_address: '1.2.3.4'
        }
      };
      const mockAssessment = {
        contributing_signals: [
          { signal: 'unrecognized_device', category: 'device', weight: 20 },
          { signal: 'unrecognized_country', category: 'location', weight: 25 }
        ]
      };

      deepFreeze(mockEvent);
      deepFreeze(mockAssessment);

      const userPayload = buildEventRecordedPayload(mockEvent, mockAssessment, { includeUserId: false });

      expect(Object.keys(userPayload).sort()).toEqual(
        [
          'coarse_location',
          'event_id',
          'event_type',
          'is_new_country',
          'is_new_device',
          'session_id',
          'timestamp'
        ].sort()
      );
      expect(userPayload.user_id).toBeUndefined();
      expect(userPayload.is_new_device).toBe(true);
      expect(userPayload.is_new_country).toBe(true);
      expect(userPayload.coarse_location).toEqual({ country: 'FR', region: 'IDF' });

      // No sensitive details in payload
      expect(userPayload.ip_address).toBeUndefined();
      expect(userPayload.device_fingerprint).toBeUndefined();
    });

    test('buildEventRecordedPayload with includeUserId=true and recognized device/country omits novelty keys', () => {
      const mockEvent = {
        event_id: 'evt_test_4',
        session_id: 'sess_4',
        user_id: 'usr_4',
        event_type: 'login_success',
        timestamp: new Date().toISOString(),
        context: {}
      };
      const mockAssessment = {
        contributing_signals: []
      };

      deepFreeze(mockEvent);
      deepFreeze(mockAssessment);

      const adminPayload = buildEventRecordedPayload(mockEvent, mockAssessment, { includeUserId: true });

      expect(Object.keys(adminPayload).sort()).toEqual(
        ['coarse_location', 'event_id', 'event_type', 'session_id', 'timestamp', 'user_id'].sort()
      );
      expect(adminPayload.user_id).toBe('usr_4');
      expect(adminPayload.is_new_device).toBeUndefined();
      expect(adminPayload.is_new_country).toBeUndefined();
      expect(adminPayload.coarse_location).toBeNull();
    });
  });

  describe('2. Pipeline Broadcast Ordering & Payload Structure', () => {
    test('recordSecurityEvent for scored login_success delivers event:recorded then risk:updated in order to user and admin', async () => {
      const userClient = createClient(serverPort, { auth: { token: tokenA1 } });
      const adminClient = createClient(serverPort, { auth: { apiKey: TEST_ADMIN_KEY_VALID } });
      activeClients.push(userClient, adminClient);

      await connectClient(userClient);
      await connectClient(adminClient);

      const userEvents = [];
      const adminEvents = [];

      userClient.on('event:recorded', (data) => userEvents.push({ type: 'event:recorded', data }));
      userClient.on('risk:updated', (data) => userEvents.push({ type: 'risk:updated', data }));

      adminClient.on('event:recorded', (data) => adminEvents.push({ type: 'event:recorded', data }));
      adminClient.on('risk:updated', (data) => adminEvents.push({ type: 'risk:updated', data }));

      const event = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'login_success',
        context: {
          device_fingerprint: 'fp_first_sight',
          geo_country: 'US',
          geo_region: 'CA'
        }
      });

      expect(event).toBeDefined();

      const delivered = await waitForCondition(
        () => userEvents.length >= 2 && adminEvents.length >= 2,
        4000
      );
      expect(delivered).toBe(true);

      // Verify delivery order on both clients: event:recorded FIRST, risk:updated SECOND
      expect(userEvents[0].type).toBe('event:recorded');
      expect(userEvents[1].type).toBe('risk:updated');

      expect(adminEvents[0].type).toBe('event:recorded');
      expect(adminEvents[1].type).toBe('risk:updated');

      // Verify exact keys on user payload
      const userRiskData = userEvents[1].data;
      expect(Object.keys(userRiskData).sort()).toEqual(
        ['evaluated_at', 'event_id', 'explanation', 'risk_tier', 'session_id'].sort()
      );
      expect(userRiskData.user_id).toBeUndefined();
      expect(userRiskData.risk_score).toBeUndefined();
      expect(userRiskData.contributing_signals).toBeUndefined();
      expect(userRiskData.explanation.admin_facing).toBeUndefined();
      expect(typeof userRiskData.explanation.user_facing).toBe('string');

      // Verify exact keys on admin payload
      const adminRiskData = adminEvents[1].data;
      expect(Object.keys(adminRiskData).sort()).toEqual(
        [
          'contributing_signals',
          'evaluated_at',
          'event_id',
          'explanation',
          'risk_score',
          'risk_tier',
          'session_id',
          'user_id'
        ].sort()
      );
      expect(adminRiskData.user_id).toBe(userA.id);
      expect(typeof adminRiskData.risk_score).toBe('number');
      expect(Array.isArray(adminRiskData.contributing_signals)).toBe(true);
      expect(typeof adminRiskData.explanation.admin_facing).toBe('string');
      expect(typeof adminRiskData.explanation.user_facing).toBe('string');
    });
  });

  describe('3. Scenario B Real Scoring Broadcast', () => {
    test('Scenario B delivers risk_score 84 and critical tier to admin, and critical tier with no score to user', async () => {
      const nowMs = Date.now();

      // Seed historical login 1 hour ago
      await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'login_success',
        timestamp: new Date(nowMs - 3600 * 1000),
        context: {
          device_fingerprint: 'fp_historic_device',
          geo_country: 'US'
        }
      });

      const userClient = createClient(serverPort, { auth: { token: tokenA1 } });
      const adminClient = createClient(serverPort, { auth: { apiKey: TEST_ADMIN_KEY_VALID } });
      activeClients.push(userClient, adminClient);

      await connectClient(userClient);
      await connectClient(adminClient);

      const userRisks = [];
      const adminRisks = [];

      userClient.on('risk:updated', (data) => userRisks.push(data));
      adminClient.on('risk:updated', (data) => adminRisks.push(data));

      // 1. Impossible travel login
      await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'login_success',
        timestamp: new Date(nowMs - 300 * 1000),
        context: {
          device_fingerprint: 'fp_attacker_device',
          geo_country: 'RU'
        },
        metadata: {
          travel_anomaly: { impossible_travel: true }
        }
      });

      // 2. Recovery email change
      await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'recovery_email_change',
        timestamp: new Date(nowMs - 180 * 1000),
        context: {
          device_fingerprint: 'fp_attacker_device',
          geo_country: 'RU'
        },
        metadata: {
          action_sensitivity: 'medium'
        }
      });

      // 3. Password change with high behavioral deviation
      const finalEvent = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'password_change',
        timestamp: new Date(nowMs - 60 * 1000),
        context: {
          device_fingerprint: 'fp_attacker_device',
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

      const gotFinalRisk = await waitForCondition(
        () =>
          userRisks.some((r) => r.event_id === finalEvent.event_id) &&
          adminRisks.some((r) => r.event_id === finalEvent.event_id),
        4000
      );
      expect(gotFinalRisk).toBe(true);

      const finalUserRisk = userRisks.find((r) => r.event_id === finalEvent.event_id);
      const finalAdminRisk = adminRisks.find((r) => r.event_id === finalEvent.event_id);

      // Verify admin payload: exact score 84, critical tier, signals sum to 84
      expect(finalAdminRisk.risk_score).toBe(84);
      expect(finalAdminRisk.risk_tier).toBe('critical');
      const sumWeights = finalAdminRisk.contributing_signals.reduce((acc, s) => acc + s.weight, 0);
      expect(sumWeights).toBe(84);

      // Verify user payload: tier critical, no score, no weights
      expect(finalUserRisk.risk_tier).toBe('critical');
      expect(finalUserRisk.risk_score).toBeUndefined();
      expect(finalUserRisk.contributing_signals).toBeUndefined();
    });
  });

  describe('4. Novelty Flags & Location Invariants', () => {
    test('first-sighting device emits is_new_device: true; subsequent recognized device omits key', async () => {
      const nowMs = Date.now();

      // Seed earlier login
      await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'login_success',
        timestamp: new Date(nowMs - 3600 * 1000),
        context: {
          device_fingerprint: 'fp_known',
          geo_country: 'US'
        }
      });

      const userClient = createClient(serverPort, { auth: { token: tokenA1 } });
      activeClients.push(userClient);
      await connectClient(userClient);

      const receivedEvents = [];
      userClient.on('event:recorded', (data) => receivedEvents.push(data));

      // Event 1: new device
      const evt1 = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'login_success',
        timestamp: new Date(nowMs - 120 * 1000),
        context: {
          device_fingerprint: 'fp_new',
          geo_country: 'US'
        }
      });

      // Event 2: known device
      const evt2 = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'login_success',
        timestamp: new Date(nowMs - 60 * 1000),
        context: {
          device_fingerprint: 'fp_known',
          geo_country: 'US'
        }
      });

      const receivedBoth = await waitForCondition(() => receivedEvents.length >= 2, 3000);
      expect(receivedBoth).toBe(true);

      const rec1 = receivedEvents.find((e) => e.event_id === evt1.event_id);
      const rec2 = receivedEvents.find((e) => e.event_id === evt2.event_id);

      expect(rec1.is_new_device).toBe(true);
      expect('is_new_device' in rec2).toBe(false);
      expect(rec2.is_new_device).toBeUndefined();
    });
  });

  describe('5. Unscored and Unavailable Event Behavior', () => {
    test('unscored event (session_created) emits event:recorded but never risk:updated', async () => {
      const userClient = createClient(serverPort, { auth: { token: tokenA1 } });
      const adminClient = createClient(serverPort, { auth: { apiKey: TEST_ADMIN_KEY_VALID } });
      activeClients.push(userClient, adminClient);

      await connectClient(userClient);
      await connectClient(adminClient);

      const userEvents = [];
      const userRisks = [];
      const adminEvents = [];
      const adminRisks = [];

      userClient.on('event:recorded', (d) => userEvents.push(d));
      userClient.on('risk:updated', (d) => userRisks.push(d));
      adminClient.on('event:recorded', (d) => adminEvents.push(d));
      adminClient.on('risk:updated', (d) => adminRisks.push(d));

      const event = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'session_created',
        context: {}
      });

      const gotEvents = await waitForCondition(
        () => userEvents.length >= 1 && adminEvents.length >= 1,
        3000
      );
      expect(gotEvents).toBe(true);
      expect(userEvents[0].event_id).toBe(event.event_id);
      expect(adminEvents[0].event_id).toBe(event.event_id);

      // Verify risk:updated was never emitted
      expect(userRisks.length).toBe(0);
      expect(adminRisks.length).toBe(0);
    });

    test('unavailable scoring (scoring engine returns null) emits event:recorded but never risk:updated', async () => {
      const scoreSpy = jest
        .spyOn(riskEngineService, 'evaluateAndStoreRiskForEvent')
        .mockResolvedValue(null);

      const userClient = createClient(serverPort, { auth: { token: tokenA1 } });
      activeClients.push(userClient);
      await connectClient(userClient);

      const userEvents = [];
      const userRisks = [];

      userClient.on('event:recorded', (d) => userEvents.push(d));
      userClient.on('risk:updated', (d) => userRisks.push(d));

      const event = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'login_success',
        context: {}
      });

      const gotEvent = await waitForCondition(() => userEvents.length >= 1, 3000);
      expect(gotEvent).toBe(true);
      expect(userEvents[0].event_id).toBe(event.event_id);
      expect(userRisks.length).toBe(0);

      scoreSpy.mockRestore();
    });
  });

  describe('6. Isolation & User Boundary Enforcement', () => {
    test('User B receives zero events when User A acts; User A multi-session receives one event per session', async () => {
      // Connect User A on session 1 and session 2
      const userAClient1 = createClient(serverPort, { auth: { token: tokenA1 } });
      const userAClient2 = createClient(serverPort, { auth: { token: tokenA2 } });
      // Connect User B on session B
      const userBClient = createClient(serverPort, { auth: { token: tokenB } });
      // Connect Admin
      const adminClient = createClient(serverPort, { auth: { apiKey: TEST_ADMIN_KEY_VALID } });

      activeClients.push(userAClient1, userAClient2, userBClient, adminClient);

      await connectClient(userAClient1);
      await connectClient(userAClient2);
      await connectClient(userBClient);
      await connectClient(adminClient);

      const client1Events = [];
      const client2Events = [];
      const userBEvents = [];
      const adminEvents = [];

      userAClient1.on('event:recorded', (d) => client1Events.push(d));
      userAClient2.on('event:recorded', (d) => client2Events.push(d));
      userBClient.on('event:recorded', (d) => userBEvents.push(d));
      adminClient.on('event:recorded', (d) => adminEvents.push(d));

      const eventA = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'login_success',
        context: { device_fingerprint: 'fp_a' }
      });

      const delivered = await waitForCondition(
        () => client1Events.length === 1 && client2Events.length === 1 && adminEvents.length === 1,
        3000
      );
      expect(delivered).toBe(true);

      // User A's two sessions received the event exactly once
      expect(client1Events[0].event_id).toBe(eventA.event_id);
      expect(client2Events[0].event_id).toBe(eventA.event_id);

      // User B received ZERO events
      expect(userBEvents.length).toBe(0);

      // Admin received User A's event
      expect(adminEvents[0].event_id).toBe(eventA.event_id);
      expect(adminEvents[0].user_id).toBe(userA.id);

      // User A payload has no user_id, admin payload has user_id
      expect(client1Events[0].user_id).toBeUndefined();
      expect(adminEvents[0].user_id).toBe(userA.id);
    });
  });

  describe('7. Data Privacy & Leakage Safeguards', () => {
    test('JSON-serialized payloads to user socket never leak IP, fingerprint, lat/lon, or password hash', async () => {
      const userClient = createClient(serverPort, { auth: { token: tokenA1 } });
      activeClients.push(userClient);
      await connectClient(userClient);

      let userEventRaw = null;
      let userRiskRaw = null;

      userClient.on('event:recorded', (d) => {
        userEventRaw = JSON.stringify(d);
      });
      userClient.on('risk:updated', (d) => {
        userRiskRaw = JSON.stringify(d);
      });

      await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'login_success',
        context: {
          ip_address: '198.51.100.42',
          device_fingerprint: 'sensitive_fingerprint_hash_98765',
          latitude: 37.7749,
          longitude: -122.4194,
          geo_country: 'US',
          geo_region: 'CA'
        }
      });

      const gotBoth = await waitForCondition(() => userEventRaw && userRiskRaw, 3000);
      expect(gotBoth).toBe(true);

      const forbiddenStrings = [
        '198.51.100.42',
        'sensitive_fingerprint_hash_98765',
        '37.7749',
        '-122.4194',
        'password_hash'
      ];

      for (const forbidden of forbiddenStrings) {
        expect(userEventRaw).not.toContain(forbidden);
        expect(userRiskRaw).not.toContain(forbidden);
      }
    });
  });

  describe('8. Pipeline Decoupling, Error Resilience & Clean Teardown', () => {
    test('throwing bus listener on pipeline:event_processed does not cause recordSecurityEvent to fail or change return value', async () => {
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

      const badListener = () => {
        throw new Error('Explosive bus listener error');
      };
      const unsub = eventBus.on('pipeline:event_processed', badListener);

      try {
        const event = await recordSecurityEvent({
          userId: userA.id,
          sessionId: sessionA1.sessionId,
          eventType: 'login_success',
          context: { device_fingerprint: 'fp_resilience' }
        });

        expect(event).toBeDefined();
        expect(event.event_id).toMatch(/^evt_/);
        expect(event.user_id).toBe(userA.id);

        expect(warnSpy).toHaveBeenCalledWith(
          expect.stringContaining('[EventBus] Synchronous listener error on event "pipeline:event_processed":'),
          expect.stringContaining('Explosive bus listener error')
        );
      } finally {
        unsub();
        warnSpy.mockRestore();
      }
    });

    test('when socketServer is not initialized or closed, recordSecurityEvent succeeds normally', async () => {
      await closeSocketServer();

      const event = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'login_success',
        context: { device_fingerprint: 'fp_no_socket_server' }
      });

      expect(event).toBeDefined();
      expect(event.event_id).toBeDefined();
    });

    test('eventBus.on returns unsubscribe function and off/removeListener work as expected', () => {
      let callCount = 0;
      const listener = () => {
        callCount++;
      };

      const unsub = eventBus.on('test:test_unsub', listener);
      expect(typeof unsub).toBe('function');

      eventBus.safeEmit('test:test_unsub');
      expect(callCount).toBe(1);

      unsub();
      eventBus.safeEmit('test:test_unsub');
      expect(callCount).toBe(1);

      // Test eventBus.off
      let callCount2 = 0;
      const listener2 = () => {
        callCount2++;
      };
      eventBus.on('test:test_off', listener2);
      eventBus.safeEmit('test:test_off');
      expect(callCount2).toBe(1);

      eventBus.off('test:test_off', listener2);
      eventBus.safeEmit('test:test_off');
      expect(callCount2).toBe(1);
    });

    test('socketServer.js source code does not access _emitter or __originalListener', () => {
      const socketServerPath = path.resolve(__dirname, '../src/realtime/socketServer.js');
      const content = fs.readFileSync(socketServerPath, 'utf8');

      expect(content).not.toContain('_emitter');
      expect(content).not.toContain('__originalListener');
    });

    test('after two init/close cycles of socketServer, one event produces exactly one delivery', async () => {
      // Cycle 1: close current and re-create
      await closeSocketServer();
      httpServer = http.createServer(app);
      await new Promise((r) => httpServer.listen(0, r));
      initSocketServer(httpServer, { revalidationIntervalSeconds: 30 });

      // Cycle 2: close and re-create
      await closeSocketServer();
      httpServer = http.createServer(app);
      await new Promise((r) => httpServer.listen(0, r));
      serverPort = httpServer.address().port;
      initSocketServer(httpServer, { revalidationIntervalSeconds: 30 });

      const userClient = createClient(serverPort, { auth: { token: tokenA1 } });
      activeClients.push(userClient);
      await connectClient(userClient);

      const received = [];
      userClient.on('event:recorded', (d) => received.push(d));

      const event = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'login_success',
        context: {}
      });

      const gotEvent = await waitForCondition(() => received.length >= 1, 3000);
      expect(gotEvent).toBe(true);

      // Wait a short moment to ensure no duplicate delivery arrives
      await new Promise((r) => setTimeout(r, 100));
      expect(received.length).toBe(1);
      expect(received[0].event_id).toBe(event.event_id);
    });
  });

  describe('9. Part A — 7.2 Closeout Requirements (A1–A4)', () => {
    test('A1: recordSecurityEvent for an event with no user_id: no pipeline:event_processed, no socket messages', async () => {
      const userClient = createClient(serverPort, { auth: { token: tokenA1 } });
      const adminClient = createClient(serverPort, { auth: { apiKey: TEST_ADMIN_KEY_VALID } });
      activeClients.push(userClient, adminClient);

      await connectClient(userClient);
      await connectClient(adminClient);

      const userMessages = [];
      const adminMessages = [];
      userClient.on('event:recorded', (d) => userMessages.push({ event: 'event:recorded', d }));
      userClient.on('risk:updated', (d) => userMessages.push({ event: 'risk:updated', d }));
      adminClient.on('event:recorded', (d) => adminMessages.push({ event: 'event:recorded', d }));
      adminClient.on('risk:updated', (d) => adminMessages.push({ event: 'risk:updated', d }));

      const busSpy = jest.spyOn(eventBus, 'safeEmit');

      await expect(
        recordSecurityEvent({
          userId: null,
          sessionId: sessionA1.sessionId,
          eventType: 'login_success'
        })
      ).rejects.toThrow('user_id is required to record a security event');

      // Also test with empty string
      await expect(
        recordSecurityEvent({
          userId: '',
          sessionId: sessionA1.sessionId,
          eventType: 'login_failed'
        })
      ).rejects.toThrow('user_id is required to record a security event');

      // Give a moment for any potential async broadcast to arrive
      await new Promise((r) => setTimeout(r, 100));

      expect(busSpy).not.toHaveBeenCalledWith('pipeline:event_processed', expect.anything());
      expect(userMessages.length).toBe(0);
      expect(adminMessages.length).toBe(0);

      busSpy.mockRestore();
    });

    test('A2: exactly one pipeline:event_processed per recordSecurityEvent call for scored, unscored, and scoring-failure cases', async () => {
      const busSpy = jest.spyOn(eventBus, 'safeEmit');

      // 1. Scored event (login_success)
      busSpy.mockClear();
      const scoredEvent = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'login_success',
        context: { device_fingerprint: 'fp_a2_scored' }
      });
      expect(scoredEvent).toBeDefined();
      const scoredCalls = busSpy.mock.calls.filter((c) => c[0] === 'pipeline:event_processed');
      expect(scoredCalls.length).toBe(1);
      expect(scoredCalls[0][1].event.event_id).toBe(scoredEvent.event_id);
      expect(scoredCalls[0][1].assessment).not.toBeNull();

      // 2. Unscored event (session_created)
      busSpy.mockClear();
      const unscoredEvent = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'session_created',
        context: {}
      });
      expect(unscoredEvent).toBeDefined();
      const unscoredCalls = busSpy.mock.calls.filter((c) => c[0] === 'pipeline:event_processed');
      expect(unscoredCalls.length).toBe(1);
      expect(unscoredCalls[0][1].event.event_id).toBe(unscoredEvent.event_id);
      expect(unscoredCalls[0][1].assessment).toBeNull();

      // 3. Scoring-failure case (mock evaluateAndStoreRiskForEvent to throw)
      const scoreSpy = jest
        .spyOn(riskEngineService, 'evaluateAndStoreRiskForEvent')
        .mockRejectedValue(new Error('Simulated scoring pipeline failure'));

      busSpy.mockClear();
      const failureEvent = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'login_success',
        context: { device_fingerprint: 'fp_a2_fail' }
      });
      expect(failureEvent).toBeDefined();
      const failureCalls = busSpy.mock.calls.filter((c) => c[0] === 'pipeline:event_processed');
      expect(failureCalls.length).toBe(1);
      expect(failureCalls[0][1].event.event_id).toBe(failureEvent.event_id);
      expect(failureCalls[0][1].assessment).toBeNull();

      scoreSpy.mockRestore();
      busSpy.mockRestore();
    });

    test('A3: privacy for admin payloads: serialized admin risk:updated and event:recorded contain no IP, fingerprint, lat/long, or password hash, and key sets equal allowlist', async () => {
      const adminClient = createClient(serverPort, { auth: { apiKey: TEST_ADMIN_KEY_VALID } });
      activeClients.push(adminClient);
      await connectClient(adminClient);

      let adminEventRecorded = null;
      let adminRiskUpdated = null;

      adminClient.on('event:recorded', (d) => {
        adminEventRecorded = d;
      });
      adminClient.on('risk:updated', (d) => {
        adminRiskUpdated = d;
      });

      const event = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'login_success',
        context: {
          ip_address: '198.51.100.88',
          device_fingerprint: 'secret_admin_leak_fp_123',
          latitude: 48.8566,
          longitude: 2.3522,
          geo_country: 'FR',
          geo_region: 'IDF'
        }
      });
      expect(event).toBeDefined();

      const delivered = await waitForCondition(
        () => adminEventRecorded !== null && adminRiskUpdated !== null,
        3000
      );
      expect(delivered).toBe(true);

      const serializedEvent = JSON.stringify(adminEventRecorded);
      const serializedRisk = JSON.stringify(adminRiskUpdated);

      const forbiddenValues = [
        '198.51.100.88',
        'secret_admin_leak_fp_123',
        '48.8566',
        '2.3522',
        'latitude',
        'longitude',
        'device_fingerprint',
        'password_hash'
      ];

      for (const forbidden of forbiddenValues) {
        expect(serializedEvent).not.toContain(forbidden);
        expect(serializedRisk).not.toContain(forbidden);
      }

      // Assert key sets equal the exact allowlist
      // event:recorded allowlist for admin (includeUserId: true, novelty flags if present)
      const expectedAdminEventKeys = [
        'coarse_location',
        'event_id',
        'event_type',
        'session_id',
        'timestamp',
        'user_id'
      ];
      if (adminEventRecorded.is_new_device) expectedAdminEventKeys.push('is_new_device');
      if (adminEventRecorded.is_new_country) expectedAdminEventKeys.push('is_new_country');

      expect(Object.keys(adminEventRecorded).sort()).toEqual(expectedAdminEventKeys.sort());

      // risk:updated allowlist for admin
      const expectedAdminRiskKeys = [
        'contributing_signals',
        'evaluated_at',
        'event_id',
        'explanation',
        'risk_score',
        'risk_tier',
        'session_id',
        'user_id'
      ];
      expect(Object.keys(adminRiskUpdated).sort()).toEqual(expectedAdminRiskKeys.sort());
      expect(Object.keys(adminRiskUpdated.explanation).sort()).toEqual(
        ['admin_facing', 'user_facing'].sort()
      );
    });

    test('A4: coarse_location is null when the event context has no geo fields, and filled when it has them (assert both)', async () => {
      const userClient = createClient(serverPort, { auth: { token: tokenA1 } });
      activeClients.push(userClient);
      await connectClient(userClient);

      const received = [];
      userClient.on('event:recorded', (d) => received.push(d));

      // Case 1: No geo fields in event context
      const evtNoGeo = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'login_success',
        context: { device_fingerprint: 'fp_no_geo' }
      });

      // Case 2: Geo fields present in event context
      const evtWithGeo = await recordSecurityEvent({
        userId: userA.id,
        sessionId: sessionA1.sessionId,
        eventType: 'login_success',
        context: {
          device_fingerprint: 'fp_with_geo',
          geo_country: 'JP',
          geo_region: '13'
        }
      });

      const gotBoth = await waitForCondition(() => received.length >= 2, 3000);
      expect(gotBoth).toBe(true);

      const payloadNoGeo = received.find((e) => e.event_id === evtNoGeo.event_id);
      const payloadWithGeo = received.find((e) => e.event_id === evtWithGeo.event_id);

      expect(payloadNoGeo).toBeDefined();
      expect(payloadNoGeo.coarse_location).toBeNull();

      expect(payloadWithGeo).toBeDefined();
      expect(payloadWithGeo.coarse_location).toEqual({
        country: 'JP',
        region: '13'
      });
    });
  });
});
