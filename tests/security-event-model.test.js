const { sequelize, User, Session, SecurityEvent } = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const migration002 = require('../src/database/migrations/002_security_events');

describe('Sub-module 2.1 — Security Event Schema', () => {
  let testUser;
  let testSession;

  beforeAll(async () => {
    await runMigrations();
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SecurityEvent.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    testUser = await User.create({
      email: 'sec-event-tester@example.com',
      password_hash: 'hash123'
    });

    testSession = await Session.create({
      user_id: testUser.id,
      expires_at: new Date(Date.now() + 3600000),
      is_active: true
    });
  });

  afterAll(async () => {
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SecurityEvent.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');
  });

  test('security_events table exists in the schema', async () => {
    const queryInterface = sequelize.getQueryInterface();
    const tables = await queryInterface.showAllTables();
    expect(tables).toContain('security_events');
  });

  test('creates a valid Security Event with all schema fields', async () => {
    const eventTime = new Date('2026-09-26T14:32:00.000Z');
    const event = await SecurityEvent.create({
      event_id: 'evt_test_001',
      user_id: testUser.id,
      session_id: testSession.id,
      event_type: 'password_change',
      timestamp: eventTime,
      context: {
        ip_address: '196.189.45.12',
        device_fingerprint: 'fp_a1b2c3',
        geo_country: 'US',
        geo_region: 'CA',
        user_agent: 'Mozilla/5.0 ...'
      },
      metadata: {
        action_sensitivity: 'high'
      }
    });

    expect(event.event_id).toBe('evt_test_001');
    expect(event.user_id).toBe(testUser.id);
    expect(event.session_id).toBe(testSession.id);
    expect(event.event_type).toBe('password_change');
    expect(new Date(event.timestamp).toISOString()).toBe(eventTime.toISOString());
    expect(event.context.ip_address).toBe('196.189.45.12');
    expect(event.context.device_fingerprint).toBe('fp_a1b2c3');
    expect(event.context.geo_country).toBe('US');
    expect(event.metadata.action_sensitivity).toBe('high');
  });

  test('auto-generates event_id with evt_ prefix when omitted', async () => {
    const event = await SecurityEvent.create({
      user_id: testUser.id,
      event_type: 'login_success',
      timestamp: new Date()
    });

    expect(event.event_id).toBeDefined();
    expect(event.event_id.startsWith('evt_')).toBe(true);
  });

  test('session_id can be null when event is not tied to a session', async () => {
    const event = await SecurityEvent.create({
      user_id: testUser.id,
      session_id: null,
      event_type: 'login_failed',
      timestamp: new Date(),
      context: {
        ip_address: '10.0.0.1'
      }
    });

    expect(event.event_id).toBeDefined();
    expect(event.session_id).toBeNull();
  });

  test('enforces required user_id', async () => {
    await expect(
      SecurityEvent.create({
        event_type: 'login_success',
        timestamp: new Date()
      })
    ).rejects.toThrow();
  });

  test('enforces required event_type', async () => {
    await expect(
      SecurityEvent.create({
        user_id: testUser.id,
        timestamp: new Date()
      })
    ).rejects.toThrow();
  });

  test('enforces required timestamp', async () => {
    await expect(
      SecurityEvent.create({
        user_id: testUser.id,
        event_type: 'login_success',
        timestamp: null
      })
    ).rejects.toThrow();
  });

  test('rejects unrecognized event_type', async () => {
    await expect(
      SecurityEvent.create({
        user_id: testUser.id,
        event_type: 'unknown_custom_action',
        timestamp: new Date()
      })
    ).rejects.toThrow();
  });

  test('accepts all 13 recognized event types from API contract', async () => {
    const recognizedTypes = [
      'login_success',
      'login_failed',
      'new_device',
      'password_change',
      'password_reset',
      'recovery_email_change',
      'phone_number_change',
      'mfa_change',
      'session_created',
      'session_terminated',
      'high_impact_action',
      'verification_success',
      'verification_failed'
    ];

    for (const type of recognizedTypes) {
      const event = await SecurityEvent.create({
        user_id: testUser.id,
        event_type: type,
        timestamp: new Date()
      });
      expect(event.event_type).toBe(type);
    }
  });

  test('accepts valid metadata.action_sensitivity values (low, medium, high, critical)', async () => {
    const validLevels = ['low', 'medium', 'high', 'critical'];

    for (const level of validLevels) {
      const event = await SecurityEvent.create({
        user_id: testUser.id,
        event_type: 'high_impact_action',
        timestamp: new Date(),
        metadata: {
          action_sensitivity: level
        }
      });
      expect(event.metadata.action_sensitivity).toBe(level);
    }
  });

  test('rejects invalid metadata.action_sensitivity values', async () => {
    await expect(
      SecurityEvent.create({
        user_id: testUser.id,
        event_type: 'high_impact_action',
        timestamp: new Date(),
        metadata: {
          action_sensitivity: 'extreme' // invalid
        }
      })
    ).rejects.toThrow(/action_sensitivity/i);
  });

  test('associates correctly with User model', async () => {
    const event = await SecurityEvent.create({
      user_id: testUser.id,
      event_type: 'mfa_change',
      timestamp: new Date()
    });

    // Event -> User
    const fetchedEvent = await SecurityEvent.findByPk(event.event_id, {
      include: [{ model: User, as: 'user' }]
    });
    expect(fetchedEvent.user).toBeDefined();
    expect(fetchedEvent.user.id).toBe(testUser.id);
    expect(fetchedEvent.user.email).toBe(testUser.email);

    // User -> SecurityEvents
    const fetchedUser = await User.findByPk(testUser.id, {
      include: [{ model: SecurityEvent, as: 'securityEvents' }]
    });
    expect(fetchedUser.securityEvents.length).toBeGreaterThan(0);
    const found = fetchedUser.securityEvents.some((e) => e.event_id === event.event_id);
    expect(found).toBe(true);
  });

  test('associates correctly with Session model', async () => {
    const event = await SecurityEvent.create({
      user_id: testUser.id,
      session_id: testSession.id,
      event_type: 'session_created',
      timestamp: new Date()
    });

    // Event -> Session
    const fetchedEvent = await SecurityEvent.findByPk(event.event_id, {
      include: [{ model: Session, as: 'session' }]
    });
    expect(fetchedEvent.session).toBeDefined();
    expect(fetchedEvent.session.id).toBe(testSession.id);

    // Session -> SecurityEvents
    const fetchedSession = await Session.findByPk(testSession.id, {
      include: [{ model: SecurityEvent, as: 'securityEvents' }]
    });
    expect(fetchedSession.securityEvents.length).toBeGreaterThan(0);
    const found = fetchedSession.securityEvents.some((e) => e.event_id === event.event_id);
    expect(found).toBe(true);
  });

  test('rejects foreign-key reference to non-existent user', async () => {
    await expect(
      SecurityEvent.create({
        user_id: 'non-existent-user-uuid-99999',
        event_type: 'login_success',
        timestamp: new Date()
      })
    ).rejects.toThrow();
  });

  test('rejects foreign-key reference to non-existent session', async () => {
    await expect(
      SecurityEvent.create({
        user_id: testUser.id,
        session_id: 'non-existent-session-uuid-99999',
        event_type: 'login_success',
        timestamp: new Date()
      })
    ).rejects.toThrow();
  });

  test('migration rollback (down) drops table and up re-creates it', async () => {
    const queryInterface = sequelize.getQueryInterface();

    // Verify down drops the table
    await migration002.down(queryInterface);
    let tables = await queryInterface.showAllTables();
    expect(tables).not.toContain('security_events');

    // Verify up re-creates table and indexes
    await migration002.up(queryInterface);
    tables = await queryInterface.showAllTables();
    expect(tables).toContain('security_events');

    const indexes = await queryInterface.showIndex('security_events');
    const indexNames = indexes.map((i) => i.name);
    expect(indexNames).toContain('idx_security_events_user_id');
    expect(indexNames).toContain('idx_security_events_session_id');
    expect(indexNames).toContain('idx_security_events_event_type');
    expect(indexNames).toContain('idx_security_events_timestamp');
    expect(indexNames).toContain('idx_security_events_user_time');
  });
});
