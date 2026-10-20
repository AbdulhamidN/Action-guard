const { sequelize, User, Session, Device } = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const { runSeeds } = require('../src/database/seed');

describe('Sub-module 1.2 — Data Model (MySQL/Sequelize)', () => {
  beforeAll(async () => {
    await runMigrations();
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await Session.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');
  });

  test('tables users, sessions, devices exist in the schema', async () => {
    const queryInterface = sequelize.getQueryInterface();
    const tables = await queryInterface.showAllTables();
    expect(tables).toContain('users');
    expect(tables).toContain('sessions');
    expect(tables).toContain('devices');
  });

  test('User model requires valid email and required fields', async () => {
    // Missing email
    await expect(
      User.create({
        password_hash: 'hash123'
      })
    ).rejects.toThrow();

    // Invalid email format
    await expect(
      User.create({
        email: 'invalid-email-format',
        password_hash: 'hash123'
      })
    ).rejects.toThrow();

    // Valid user
    const user = await User.create({
      email: 'valid-user@example.com',
      password_hash: 'validhash'
    });
    expect(user.id).toBeDefined();
    expect(user.email).toBe('valid-user@example.com');
  });

  test('Session model associates with User and respects foreign key', async () => {
    const user = await User.create({
      email: 'session-test@example.com',
      password_hash: 'hash123'
    });

    const expiresAt = new Date(Date.now() + 3600000);
    const session = await Session.create({
      user_id: user.id,
      expires_at: expiresAt,
      is_active: true
    });

    expect(session.id).toBeDefined();
    expect(session.user_id).toBe(user.id);
    expect(session.is_active).toBe(true);

    // Association check
    const fetchedUser = await User.findByPk(user.id, {
      include: [{ model: Session, as: 'sessions' }]
    });
    expect(fetchedUser.sessions.length).toBeGreaterThan(0);
    expect(fetchedUser.sessions[0].id).toBe(session.id);
  });

  test('Device model associates with User', async () => {
    const user = await User.create({
      email: 'device-test@example.com',
      password_hash: 'hash123'
    });

    const device = await Device.create({
      user_id: user.id,
      fingerprint: 'fp_test_device_123',
      is_trusted: false
    });

    expect(device.id).toBeDefined();
    expect(device.fingerprint).toBe('fp_test_device_123');
    expect(device.is_trusted).toBe(false);

    const fetchedUser = await User.findByPk(user.id, {
      include: [{ model: Device, as: 'devices' }]
    });
    expect(fetchedUser.devices.length).toBeGreaterThan(0);
    expect(fetchedUser.devices[0].fingerprint).toBe('fp_test_device_123');
  });

  test('Development seed inserts the test user', async () => {
    await runSeeds();

    const devUser = await User.findOne({
      where: { email: 'dev-seed-user@actionguard.test' }
    });

    expect(devUser).not.toBeNull();
    expect(devUser.id).toBe('dev-test-user-00000000-000000000001');
    expect(devUser.email).toBe('dev-seed-user@actionguard.test');
  });
});
