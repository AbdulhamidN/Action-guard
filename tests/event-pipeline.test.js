const request = require('supertest');
const app = require('../src/app');
const { sequelize, User, Session, SecurityEvent } = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const eventService = require('../src/services/eventService');
const { recordSecurityEvent } = eventService;

describe('Sub-module 2.2 — Event-Write Pipeline', () => {
  let testUser;

  beforeAll(async () => {
    await runMigrations();
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SecurityEvent.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    testUser = await User.create({
      email: 'event-pipeline-user@example.com',
      password_hash: await require('bcrypt').hash('Password123!', 10)
    });
  });

  afterAll(async () => {
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SecurityEvent.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');
  });

  describe('eventService API & contracts', () => {
    test('does not expose update or delete operations (append-only at service level)', () => {
      expect(typeof eventService.recordSecurityEvent).toBe('function');
      expect(eventService.updateSecurityEvent).toBeUndefined();
      expect(eventService.updateEvent).toBeUndefined();
      expect(eventService.deleteSecurityEvent).toBeUndefined();
      expect(eventService.deleteEvent).toBeUndefined();
    });

    test('recordSecurityEvent requires user_id', async () => {
      await expect(
        recordSecurityEvent({
          eventType: 'login_success'
        })
      ).rejects.toThrow(/user_id is required/i);
    });

    test('recordSecurityEvent requires event_type', async () => {
      await expect(
        recordSecurityEvent({
          userId: testUser.id
        })
      ).rejects.toThrow(/event_type is required/i);
    });

    test('recordSecurityEvent persists event in MySQL with context and metadata', async () => {
      const recorded = await recordSecurityEvent({
        userId: testUser.id,
        eventType: 'password_change',
        context: {
          ip_address: '192.168.1.100',
          user_agent: 'TestAgent/1.0'
        },
        metadata: {
          action_sensitivity: 'high'
        }
      });

      expect(recorded.event_id).toBeDefined();
      expect(recorded.event_type).toBe('password_change');
      expect(recorded.user_id).toBe(testUser.id);
      expect(recorded.context.ip_address).toBe('192.168.1.100');
      expect(recorded.context.user_agent).toBe('TestAgent/1.0');
      expect(recorded.metadata.action_sensitivity).toBe('high');

      // Verify directly from MySQL database
      const fromDb = await SecurityEvent.findByPk(recorded.event_id);
      expect(fromDb).not.toBeNull();
      expect(fromDb.event_id).toBe(recorded.event_id);
      expect(fromDb.event_type).toBe('password_change');
    });

    test('recordSecurityEvent accepts explicit event_id', async () => {
      const explicitId = 'evt_custom_explicit_id_001';
      const recorded = await recordSecurityEvent({
        eventId: explicitId,
        userId: testUser.id,
        eventType: 'high_impact_action',
        metadata: {
          action_sensitivity: 'critical'
        }
      });

      expect(recorded.event_id).toBe(explicitId);

      const fromDb = await SecurityEvent.findByPk(explicitId);
      expect(fromDb).not.toBeNull();
      expect(fromDb.event_id).toBe(explicitId);
    });
  });

  describe('Integration with Module 1 flows', () => {
    test('login with invalid password records login_failed event in MySQL', async () => {
      const eventsBefore = await SecurityEvent.count({
        where: { user_id: testUser.id, event_type: 'login_failed' }
      });

      const res = await request(app)
        .post('/api/v1/auth/login')
        .set('User-Agent', 'Supertest-Agent-FailedLogin')
        .send({
          email: testUser.email,
          password: 'WrongPassword999!'
        })
        .expect(401);

      expect(res.body.error.code).toBe('authentication_failed');

      // Verify event was persisted in MySQL
      const eventsAfter = await SecurityEvent.findAll({
        where: { user_id: testUser.id, event_type: 'login_failed' }
      });

      expect(eventsAfter.length).toBe(eventsBefore + 1);
      const latestFailed = eventsAfter[eventsAfter.length - 1];
      expect(latestFailed.event_type).toBe('login_failed');
      expect(latestFailed.user_id).toBe(testUser.id);
      expect(latestFailed.context.user_agent).toBe('Supertest-Agent-FailedLogin');
      expect(latestFailed.session_id).toBeNull();
    });

    test('login with non-existent email returns 401 without recording an event', async () => {
      const totalEventsBefore = await SecurityEvent.count();

      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'non-existent-user-12345@example.com',
          password: 'SomePassword123!'
        })
        .expect(401);

      expect(res.body.error.code).toBe('authentication_failed');

      const totalEventsAfter = await SecurityEvent.count();
      expect(totalEventsAfter).toBe(totalEventsBefore);
    });

    test('successful login records login_success and session_created events in MySQL', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .set('User-Agent', 'Supertest-Agent-SuccessLogin')
        .send({
          email: testUser.email,
          password: 'Password123!'
        })
        .expect(200);

      const { token, session_id } = res.body;
      expect(token).toBeDefined();
      expect(session_id).toBeDefined();

      // Verify login_success event in MySQL
      const loginSuccessEvent = await SecurityEvent.findOne({
        where: {
          user_id: testUser.id,
          session_id: session_id,
          event_type: 'login_success'
        }
      });
      expect(loginSuccessEvent).not.toBeNull();
      expect(loginSuccessEvent.context.user_agent).toBe('Supertest-Agent-SuccessLogin');

      // Verify session_created event in MySQL
      const sessionCreatedEvent = await SecurityEvent.findOne({
        where: {
          user_id: testUser.id,
          session_id: session_id,
          event_type: 'session_created'
        }
      });
      expect(sessionCreatedEvent).not.toBeNull();
      expect(sessionCreatedEvent.context.user_agent).toBe('Supertest-Agent-SuccessLogin');
    });

    test('logout records session_terminated event in MySQL', async () => {
      // First login to get active session
      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .set('User-Agent', 'Supertest-Agent-LogoutFlow')
        .send({
          email: testUser.email,
          password: 'Password123!'
        })
        .expect(200);

      const { token, session_id } = loginRes.body;

      // Now logout
      await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${token}`)
        .set('User-Agent', 'Supertest-Agent-LogoutFlow')
        .expect(200);

      // Verify session_terminated event in MySQL
      const terminatedEvent = await SecurityEvent.findOne({
        where: {
          user_id: testUser.id,
          session_id: session_id,
          event_type: 'session_terminated'
        }
      });

      expect(terminatedEvent).not.toBeNull();
      expect(terminatedEvent.event_type).toBe('session_terminated');
      expect(terminatedEvent.session_id).toBe(session_id);
      expect(terminatedEvent.context.user_agent).toBe('Supertest-Agent-LogoutFlow');
    });
  });
});
