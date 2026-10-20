'use strict';

const { sequelize, User, Device, Session, SecurityEvent } = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const migration012 = require('../src/database/migrations/012_trusted_devices_lifecycle');
const {
  validateDeviceFingerprint,
  validateDeviceLabel,
  isDeviceTrustActive,
  getOrCreateDevice,
  enrollTrustedDevice,
  revokeDeviceTrust,
  updateDeviceLastUsed,
  listUserDevices,
  isUserDeviceTrusted,
  DEFAULT_DEVICE_TRUST_TTL_DAYS
} = require('../src/services/deviceService');

describe('Module 12d-1 — Trusted-Device Foundation', () => {
  let userA;
  let userB;

  beforeAll(async () => {
    await runMigrations();
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    userA = await User.create({
      id: 'usr_12d_test_a',
      email: 'user-a-12d@actionguard.test',
      password_hash: '$2b$10$devdummyhashforseedonlynotforproduction0000000000000000'
    });

    userB = await User.create({
      id: 'usr_12d_test_b',
      email: 'user-b-12d@actionguard.test',
      password_hash: '$2b$10$devdummyhashforseedonlynotforproduction0000000000000000'
    });
  });

  afterAll(async () => {
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');
  });

  beforeEach(async () => {
    await Device.destroy({ where: {}, force: true });
  });

  // Requirement 4.1: New devices default to untrusted
  test('1. New devices default to untrusted', async () => {
    const fingerprint = 'fp_test_device_default_untrusted_001';
    const result = await getOrCreateDevice(userA.id, fingerprint);

    expect(result.isNew).toBe(true);
    expect(result.device).toBeDefined();
    expect(result.device.is_trusted).toBe(false);
    expect(result.device.trusted_at).toBeNull();
    expect(result.device.expires_at).toBeNull();
    expect(result.device.revoked_at).toBeNull();
    expect(result.device.label).toBeNull();
    expect(isDeviceTrustActive(result.device)).toBe(false);
    expect(await isUserDeviceTrusted(userA.id, fingerprint)).toBe(false);
  });

  // Requirement 4.2: A device can be enrolled only for its owner
  test('2. A device can be enrolled only for its owner', async () => {
    const fingerprint = 'fp_test_device_ownership_002';
    const { device: deviceA } = await getOrCreateDevice(userA.id, fingerprint);

    // User B attempts to enroll User A's device
    await expect(
      enrollTrustedDevice({
        userId: userB.id,
        deviceId: deviceA.id,
        label: 'Attacker Enrolled'
      })
    ).rejects.toThrow('Device does not belong to the authenticated user');

    // Confirm device remains untrusted in the database
    const refreshed = await Device.findByPk(deviceA.id);
    expect(refreshed.is_trusted).toBe(false);
    expect(refreshed.trusted_at).toBeNull();
    expect(refreshed.expires_at).toBeNull();
  });

  // Requirement 4.3: Successful enrollment sets trusted_at and a fixed expiry approximately 30 days later
  test('3. Successful enrollment sets trusted_at and a fixed expiry approximately 30 days later', async () => {
    const fingerprint = 'fp_test_device_enrollment_003';
    const { device } = await getOrCreateDevice(userA.id, fingerprint);
    const now = new Date('2026-10-18T12:00:00.000Z');

    const result = await enrollTrustedDevice({
      userId: userA.id,
      deviceId: device.id,
      label: 'Primary Work Laptop',
      now,
      ttlDays: DEFAULT_DEVICE_TRUST_TTL_DAYS
    });

    expect(result.is_trust_active).toBe(true);
    expect(result.device.is_trusted).toBe(true);
    expect(result.device.label).toBe('Primary Work Laptop');
    expect(new Date(result.device.trusted_at).toISOString()).toBe(now.toISOString());

    const expectedExpiryMs = now.getTime() + 30 * 24 * 60 * 60 * 1000;
    expect(new Date(result.device.expires_at).getTime()).toBe(expectedExpiryMs);

    // Verify active trust helper at reference time
    expect(isDeviceTrustActive(result.device, now)).toBe(true);
    expect(await isUserDeviceTrusted(userA.id, fingerprint, now)).toBe(true);
  });

  // Requirement 4.4: Expired trust is inactive
  test('4. Expired trust is inactive', async () => {
    const fingerprint = 'fp_test_device_expired_004';
    const { device } = await getOrCreateDevice(userA.id, fingerprint);
    const now = new Date('2026-10-18T12:00:00.000Z');

    const { device: enrolled } = await enrollTrustedDevice({
      userId: userA.id,
      deviceId: device.id,
      now,
      ttlDays: 30
    });

    // Exactly 30 days later -> expired
    const exactlyExpired = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
    expect(isDeviceTrustActive(enrolled, exactlyExpired)).toBe(false);

    // 1 second after 30 days
    const afterExpiry = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000 + 1000);
    expect(isDeviceTrustActive(enrolled, afterExpiry)).toBe(false);
    expect(await isUserDeviceTrusted(userA.id, fingerprint, afterExpiry)).toBe(false);

    // 1 second before expiry is still active
    const justBeforeExpiry = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000 - 1000);
    expect(isDeviceTrustActive(enrolled, justBeforeExpiry)).toBe(true);
  });

  // Requirement 4.5: Revoked trust is inactive
  test('5. Revoked trust is inactive', async () => {
    const fingerprint = 'fp_test_device_revocation_005';
    const { device } = await getOrCreateDevice(userA.id, fingerprint);
    const now = new Date('2026-10-18T12:00:00.000Z');

    await enrollTrustedDevice({
      userId: userA.id,
      deviceId: device.id,
      now
    });

    const revokeTime = new Date('2026-10-20T15:00:00.000Z');
    const revResult = await revokeDeviceTrust({
      userId: userA.id,
      deviceId: device.id,
      now: revokeTime
    });

    expect(revResult.alreadyRevoked).toBe(false);
    expect(revResult.is_trust_active).toBe(false);
    expect(revResult.device.is_trusted).toBe(false);
    expect(new Date(revResult.device.revoked_at).toISOString()).toBe(revokeTime.toISOString());

    // Verify database state
    const fromDb = await Device.findByPk(device.id);
    expect(fromDb.is_trusted).toBe(false);
    expect(isDeviceTrustActive(fromDb, revokeTime)).toBe(false);
    expect(await isUserDeviceTrusted(userA.id, fingerprint, revokeTime)).toBe(false);
  });

  // Requirement 4.6: Repeated revocation is handled safely and consistently
  test('6. Repeated revocation is handled safely and consistently', async () => {
    const fingerprint = 'fp_test_device_idempotent_revoke_006';
    const { device } = await getOrCreateDevice(userA.id, fingerprint);

    // Initial revocation
    const firstRev = await revokeDeviceTrust({
      userId: userA.id,
      deviceId: device.id,
      now: new Date('2026-10-18T10:00:00.000Z')
    });
    expect(firstRev.alreadyRevoked).toBe(false);
    expect(firstRev.is_trust_active).toBe(false);

    // Second revocation on already-revoked device
    const secondRev = await revokeDeviceTrust({
      userId: userA.id,
      deviceId: device.id,
      now: new Date('2026-10-18T11:00:00.000Z')
    });
    expect(secondRev.alreadyRevoked).toBe(true);
    expect(secondRev.is_trust_active).toBe(false);
    expect(secondRev.device.is_trusted).toBe(false);
    // Preserves original revoked_at timestamp
    expect(new Date(secondRev.device.revoked_at).toISOString()).toBe('2026-10-18T10:00:00.000Z');
  });

  // Requirement 4.7: Invalid labels and invalid lifecycle inputs are rejected
  test('7. Invalid labels and invalid lifecycle inputs are rejected', async () => {
    const fingerprint = 'fp_test_device_validation_007';
    const { device } = await getOrCreateDevice(userA.id, fingerprint);

    // Label length > 100
    await expect(
      enrollTrustedDevice({
        userId: userA.id,
        deviceId: device.id,
        label: 'A'.repeat(101)
      })
    ).rejects.toThrow(/Invalid device label/);

    // Label with null byte or control characters
    await expect(
      enrollTrustedDevice({
        userId: userA.id,
        deviceId: device.id,
        label: 'Bad\x00Label'
      })
    ).rejects.toThrow(/Invalid device label/);

    // Empty label string
    await expect(
      enrollTrustedDevice({
        userId: userA.id,
        deviceId: device.id,
        label: ''
      })
    ).rejects.toThrow(/Invalid device label/);

    // Non-string label
    await expect(
      enrollTrustedDevice({
        userId: userA.id,
        deviceId: device.id,
        label: 12345
      })
    ).rejects.toThrow(/Invalid device label/);

    // Missing deviceId
    await expect(
      enrollTrustedDevice({
        userId: userA.id,
        deviceId: null
      })
    ).rejects.toThrow(/deviceId is required/);

    // Non-existent deviceId
    await expect(
      enrollTrustedDevice({
        userId: userA.id,
        deviceId: 'dev_non_existent_id'
      })
    ).rejects.toThrow(/Device not found/);

    // Negative TTL
    await expect(
      enrollTrustedDevice({
        userId: userA.id,
        deviceId: device.id,
        ttlDays: -5
      })
    ).rejects.toThrow(/ttlDays must be an integer between 1 and 30 days/);

    // Excessive TTL (> 30 days)
    await expect(
      enrollTrustedDevice({
        userId: userA.id,
        deviceId: device.id,
        ttlDays: 31
      })
    ).rejects.toThrow(/ttlDays must be an integer between 1 and 30 days/);

    // Zero TTL
    await expect(
      enrollTrustedDevice({
        userId: userA.id,
        deviceId: device.id,
        ttlDays: 0
      })
    ).rejects.toThrow(/ttlDays must be an integer between 1 and 30 days/);

    // Non-integer float TTL
    await expect(
      enrollTrustedDevice({
        userId: userA.id,
        deviceId: device.id,
        ttlDays: 1.5
      })
    ).rejects.toThrow(/ttlDays must be an integer between 1 and 30 days/);
  });

  // Requirement 4.8: Duplicate device records are prevented or handled safely according to the migration strategy
  test('8. Duplicate device records are prevented or handled safely according to the migration strategy', async () => {
    const fingerprint = 'fp_test_device_duplicate_prevention_008';

    // 1. Direct model create with same user_id and fingerprint throws unique constraint error
    await Device.create({
      user_id: userA.id,
      fingerprint,
      is_trusted: false,
      first_seen_at: new Date()
    });

    await expect(
      Device.create({
        user_id: userA.id,
        fingerprint,
        is_trusted: false,
        first_seen_at: new Date()
      })
    ).rejects.toThrow();

    // 2. getOrCreateDevice handles concurrent calls gracefully without throwing or creating duplicates
    const concurrentFingerprint = 'fp_test_device_concurrent_008b';
    const results = await Promise.all([
      getOrCreateDevice(userA.id, concurrentFingerprint),
      getOrCreateDevice(userA.id, concurrentFingerprint),
      getOrCreateDevice(userA.id, concurrentFingerprint)
    ]);

    const createdCount = results.filter((r) => r.isNew).length;
    expect(createdCount).toBe(1);

    // All return the exact same device ID
    const deviceIds = new Set(results.map((r) => r.device.id));
    expect(deviceIds.size).toBe(1);

    // Confirm only 1 record exists in the database
    const dbRows = await Device.findAll({
      where: { user_id: userA.id, fingerprint: concurrentFingerprint }
    });
    expect(dbRows.length).toBe(1);
  });

  // Requirement 4.9: Existing device records remain untrusted after migration
  test('9. Existing device records remain untrusted after migration', async () => {
    // Seed an untrusted legacy device record
    const legacyDevice = await Device.create({
      user_id: userA.id,
      fingerprint: 'fp_test_legacy_device_009',
      is_trusted: false,
      first_seen_at: new Date('2026-09-01T00:00:00.000Z')
    });

    // Re-run migration 012 up (idempotency check)
    const queryInterface = sequelize.getQueryInterface();
    await migration012.up(queryInterface);

    // Verify existing record remains untrusted and has null lifecycle timestamps
    const reloaded = await Device.findByPk(legacyDevice.id);
    expect(reloaded.is_trusted).toBe(false);
    expect(reloaded.trusted_at).toBeNull();
    expect(reloaded.expires_at).toBeNull();
    expect(reloaded.revoked_at).toBeNull();
    expect(isDeviceTrustActive(reloaded)).toBe(false);
    expect(await isUserDeviceTrusted(userA.id, 'fp_test_legacy_device_009')).toBe(false);
  });

  // Requirement 4.10: Last-used updates do not extend the trust expiry
  test('10. Last-used updates do not extend the trust expiry', async () => {
    const fingerprint = 'fp_test_device_last_used_010';
    const { device } = await getOrCreateDevice(userA.id, fingerprint);
    const enrollmentTime = new Date('2026-10-18T12:00:00.000Z');

    const { device: enrolled } = await enrollTrustedDevice({
      userId: userA.id,
      deviceId: device.id,
      now: enrollmentTime,
      ttlDays: 30
    });

    const originalExpiresAt = new Date(enrolled.expires_at).toISOString();

    // Update last_used_at 10 days later
    const activityTime = new Date('2026-10-28T14:30:00.000Z');
    const updated = await updateDeviceLastUsed(device.id, activityTime);

    expect(updated).not.toBeNull();
    expect(new Date(updated.last_used_at).toISOString()).toBe(activityTime.toISOString());

    // CRITICAL INVARIANT: expires_at and trusted_at must NOT be altered
    expect(new Date(updated.expires_at).toISOString()).toBe(originalExpiresAt);
    expect(new Date(updated.trusted_at).toISOString()).toBe(enrollmentTime.toISOString());

    // Verify from fresh database reload
    const refreshed = await Device.findByPk(device.id);
    expect(new Date(refreshed.last_used_at).toISOString()).toBe(activityTime.toISOString());
    expect(new Date(refreshed.expires_at).toISOString()).toBe(originalExpiresAt);
  });

  describe('isDeviceTrustActive fail-closed evaluation', () => {
    test('returns false when now is invalid, NaN, infinite, or malformed', async () => {
      const now = new Date('2026-10-18T12:00:00.000Z');
      const { device } = await getOrCreateDevice(userA.id, 'fp_eval_failclosed_001');
      await enrollTrustedDevice({ userId: userA.id, deviceId: device.id, now });
      const enrolled = await Device.findByPk(device.id);

      expect(isDeviceTrustActive(enrolled, 'not-a-valid-date')).toBe(false);
      expect(isDeviceTrustActive(enrolled, NaN)).toBe(false);
      expect(isDeviceTrustActive(enrolled, Infinity)).toBe(false);
      expect(isDeviceTrustActive(enrolled, -Infinity)).toBe(false);
      expect(isDeviceTrustActive(enrolled, new Date('invalid'))).toBe(false);
      expect(isDeviceTrustActive(enrolled, {})).toBe(false);
      expect(isDeviceTrustActive(enrolled, [])).toBe(false);
    });

    test('returns false when expires_at is missing, null, or malformed', async () => {
      const now = new Date('2026-10-18T12:00:00.000Z');
      const { device } = await getOrCreateDevice(userA.id, 'fp_eval_missing_exp_002');
      await enrollTrustedDevice({ userId: userA.id, deviceId: device.id, now });

      const devMissing = { is_trusted: true, revoked_at: null, trusted_at: now, expires_at: null };
      expect(isDeviceTrustActive(devMissing, now)).toBe(false);

      const devUndefined = { is_trusted: true, revoked_at: null, trusted_at: now };
      expect(isDeviceTrustActive(devUndefined, now)).toBe(false);

      const devMalformed = { is_trusted: true, revoked_at: null, trusted_at: now, expires_at: 'bad-date' };
      expect(isDeviceTrustActive(devMalformed, now)).toBe(false);
    });

    test('returns false when trusted_at is malformed or in the future relative to now', async () => {
      const now = new Date('2026-10-18T12:00:00.000Z');
      const futureNow = new Date('2026-10-18T11:00:00.000Z');

      const devMalformedTrustedAt = {
        is_trusted: true,
        revoked_at: null,
        trusted_at: 'not-a-date',
        expires_at: new Date('2026-11-18T12:00:00.000Z')
      };
      expect(isDeviceTrustActive(devMalformedTrustedAt, now)).toBe(false);

      const devFuture = {
        is_trusted: true,
        revoked_at: null,
        trusted_at: new Date('2026-10-18T12:00:00.000Z'),
        expires_at: new Date('2026-11-18T12:00:00.000Z')
      };
      // When reference now is 1 hour before trusted_at
      expect(isDeviceTrustActive(devFuture, futureNow)).toBe(false);
    });

    test('returns false at the exact millisecond of expiration boundary', async () => {
      const now = new Date('2026-10-18T12:00:00.000Z');
      const expiresAt = new Date('2026-11-17T12:00:00.000Z');
      const device = {
        is_trusted: true,
        revoked_at: null,
        trusted_at: now,
        expires_at: expiresAt
      };

      // 1 ms before expiration -> active
      expect(isDeviceTrustActive(device, new Date(expiresAt.getTime() - 1))).toBe(true);
      // exact boundary -> inactive
      expect(isDeviceTrustActive(device, expiresAt)).toBe(false);
      // 1 ms after expiration -> inactive
      expect(isDeviceTrustActive(device, new Date(expiresAt.getTime() + 1))).toBe(false);
    });
  });

  describe('revokeDeviceTrust idempotent and safety semantics', () => {
    test('revoking a never-enrolled untrusted device records revoked_at and returns alreadyRevoked: false', async () => {
      const { device } = await getOrCreateDevice(userA.id, 'fp_never_enrolled_001');
      expect(device.is_trusted).toBe(false);
      expect(device.revoked_at).toBeNull();

      const revTime = new Date('2026-10-18T14:00:00.000Z');
      const res = await revokeDeviceTrust({
        userId: userA.id,
        deviceId: device.id,
        now: revTime
      });

      expect(res.alreadyRevoked).toBe(false);
      expect(res.is_trust_active).toBe(false);
      expect(res.device.is_trusted).toBe(false);
      expect(new Date(res.device.revoked_at).toISOString()).toBe(revTime.toISOString());

      // Subsequent revocation returns alreadyRevoked: true and preserves revoked_at
      const later = new Date('2026-10-18T15:00:00.000Z');
      const res2 = await revokeDeviceTrust({
        userId: userA.id,
        deviceId: device.id,
        now: later
      });
      expect(res2.alreadyRevoked).toBe(true);
      expect(new Date(res2.device.revoked_at).toISOString()).toBe(revTime.toISOString());
    });

    test('revoking an expired device with is_trusted: true records revoked_at and sets is_trusted: false', async () => {
      const { device } = await getOrCreateDevice(userA.id, 'fp_expired_revoke_002');
      const enrollmentTime = new Date('2026-09-01T10:00:00.000Z');
      await enrollTrustedDevice({
        userId: userA.id,
        deviceId: device.id,
        now: enrollmentTime,
        ttlDays: 30
      });

      // 40 days later, trust is expired but revoked_at was null
      const revokeTime = new Date('2026-10-11T10:00:00.000Z');
      const res = await revokeDeviceTrust({
        userId: userA.id,
        deviceId: device.id,
        now: revokeTime
      });

      expect(res.alreadyRevoked).toBe(false);
      expect(res.device.is_trusted).toBe(false);
      expect(new Date(res.device.revoked_at).toISOString()).toBe(revokeTime.toISOString());
      expect(res.is_trust_active).toBe(false);
    });

    test('rejects with 404 when device does not exist', async () => {
      await expect(
        revokeDeviceTrust({
          userId: userA.id,
          deviceId: 'dev_nonexistent_xyz'
        })
      ).rejects.toMatchObject({
        message: 'Device not found',
        status: 404
      });
    });

    test('rejects with 403 when user does not own the device', async () => {
      const { device } = await getOrCreateDevice(userA.id, 'fp_cross_user_revoke_003');
      await expect(
        revokeDeviceTrust({
          userId: userB.id,
          deviceId: device.id
        })
      ).rejects.toMatchObject({
        message: 'Device does not belong to the authenticated user',
        status: 403
      });
    });

    test('rejects with 400 when an invalid now timestamp is provided', async () => {
      const { device } = await getOrCreateDevice(userA.id, 'fp_invalid_now_revoke_004');
      await expect(
        revokeDeviceTrust({
          userId: userA.id,
          deviceId: device.id,
          now: 'invalid-date-string'
        })
      ).rejects.toMatchObject({
        message: expect.stringMatching(/Invalid timestamp/),
        status: 400
      });
    });
  });

  describe('enrollTrustedDevice session binding and input validation', () => {
    test('enrollment succeeds when currentDeviceId matches deviceId', async () => {
      const { device } = await getOrCreateDevice(userA.id, 'fp_session_match_001');
      const now = new Date('2026-10-18T12:00:00.000Z');

      const res = await enrollTrustedDevice({
        userId: userA.id,
        deviceId: device.id,
        currentDeviceId: device.id,
        label: 'Current Session Device',
        now
      });

      expect(res.is_trust_active).toBe(true);
      expect(res.device.id).toBe(device.id);
      expect(res.device.label).toBe('Current Session Device');
    });

    test('enrollment fails closed with 403 when currentDeviceId mismatches deviceId', async () => {
      const { device: dev1 } = await getOrCreateDevice(userA.id, 'fp_session_dev1');
      const { device: dev2 } = await getOrCreateDevice(userA.id, 'fp_session_dev2');

      await expect(
        enrollTrustedDevice({
          userId: userA.id,
          deviceId: dev1.id,
          currentDeviceId: dev2.id,
          label: 'Mismatched Session Device'
        })
      ).rejects.toMatchObject({
        message: 'Device does not match the active session device',
        status: 403,
        code: 'DEVICE_SESSION_MISMATCH'
      });
    });

    test('enrollment fails closed with 400 when invalid now timestamp is provided', async () => {
      const { device } = await getOrCreateDevice(userA.id, 'fp_invalid_now_enroll_003');

      await expect(
        enrollTrustedDevice({
          userId: userA.id,
          deviceId: device.id,
          now: 'invalid-date-string'
        })
      ).rejects.toMatchObject({
        message: expect.stringMatching(/Invalid timestamp/),
        status: 400
      });
    });

    test('enrollment succeeds when session.device_id matches deviceId', async () => {
      const { device } = await getOrCreateDevice(userA.id, 'fp_session_obj_match_004');
      const now = new Date('2026-10-18T12:00:00.000Z');

      const res = await enrollTrustedDevice({
        userId: userA.id,
        deviceId: device.id,
        session: { device_id: device.id },
        label: 'Session Object Matching Device',
        now
      });

      expect(res.is_trust_active).toBe(true);
      expect(res.device.id).toBe(device.id);
    });

    test('enrollment fails closed with 403 when session.device_id mismatches deviceId', async () => {
      const { device: dev1 } = await getOrCreateDevice(userA.id, 'fp_session_obj_dev1');
      const { device: dev2 } = await getOrCreateDevice(userA.id, 'fp_session_obj_dev2');

      await expect(
        enrollTrustedDevice({
          userId: userA.id,
          deviceId: dev1.id,
          session: { device_id: dev2.id },
          label: 'Session Object Mismatched Device'
        })
      ).rejects.toMatchObject({
        message: 'Device does not match the active session device',
        status: 403,
        code: 'DEVICE_SESSION_MISMATCH'
      });
    });

    test('enrollment fails closed with 403 when currentDeviceId is a non-string or empty value', async () => {
      const { device } = await getOrCreateDevice(userA.id, 'fp_invalid_current_device_id_005');

      await expect(
        enrollTrustedDevice({
          userId: userA.id,
          deviceId: device.id,
          currentDeviceId: 12345
        })
      ).rejects.toMatchObject({
        message: 'Device does not match the active session device',
        status: 403,
        code: 'DEVICE_SESSION_MISMATCH'
      });
    });
  });

  describe('Additional lifecycle helper checks', () => {
    test('raw device fingerprints are never exposed in toJSON model serialization', async () => {
      const { device } = await getOrCreateDevice(userA.id, 'fp_privacy_test_001');
      const serialized = device.toJSON();
      expect(serialized.fingerprint).toBeUndefined();
      expect(JSON.parse(JSON.stringify(device)).fingerprint).toBeUndefined();
      expect(serialized.id).toBe(device.id);
      expect(serialized.user_id).toBe(userA.id);
    });

    test('listUserDevices returns devices ordered by recency with live trust flag and stripped fingerprints', async () => {
      const { device: d1 } = await getOrCreateDevice(userA.id, 'fp_list_001');
      const { device: d2 } = await getOrCreateDevice(userA.id, 'fp_list_002');

      await enrollTrustedDevice({
        userId: userA.id,
        deviceId: d1.id,
        label: 'Trusted Device 1'
      });

      const list = await listUserDevices(userA.id);
      expect(list.length).toBe(2);

      const item1 = list.find((d) => d.id === d1.id);
      const item2 = list.find((d) => d.id === d2.id);

      expect(item1.is_trust_active).toBe(true);
      expect(item1.label).toBe('Trusted Device 1');
      expect(item1.fingerprint).toBeUndefined();
      expect(item2.is_trust_active).toBe(false);
      expect(item2.fingerprint).toBeUndefined();
    });

    afterEach(async () => {
      const queryInterface = sequelize.getQueryInterface();
      try {
        await migration012.up(queryInterface);
      } catch (_) {}
    });

    test('migration 012 preserves duplicates in durable archive table with canonical reference', async () => {
      const queryInterface = sequelize.getQueryInterface();

      // 1. Roll back migration 012 to pre-012 schema state so duplicates can be inserted
      await migration012.down(queryInterface);

      // Clean out any existing device records
      await Device.destroy({ where: {}, force: true });

      const testFp = 'fp_mig_dup_test_001';

      // Insert User A duplicates:
      // Row 1: Untrusted, earlier first_seen_at
      await queryInterface.sequelize.query(
        `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
         VALUES ('dev_dup_untrusted_earlier', :userId, :fp, 0, '2026-09-01 10:00:00')`,
        { replacements: { userId: userA.id, fp: testFp } }
      );

      // Row 2: Trusted, later first_seen_at (should survive as canonical because is_trusted=1)
      await queryInterface.sequelize.query(
        `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
         VALUES ('dev_dup_trusted_later', :userId, :fp, 1, '2026-09-02 10:00:00')`,
        { replacements: { userId: userA.id, fp: testFp } }
      );

      // Row 3: Untrusted, tie timestamp
      await queryInterface.sequelize.query(
        `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
         VALUES ('dev_dup_tie_2', :userId, :fp, 0, '2026-09-03 10:00:00')`,
        { replacements: { userId: userA.id, fp: testFp } }
      );

      // Row 4: Untrusted, tie timestamp
      await queryInterface.sequelize.query(
        `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
         VALUES ('dev_dup_tie_1', :userId, :fp, 0, '2026-09-03 10:00:00')`,
        { replacements: { userId: userA.id, fp: testFp } }
      );

      // Control Row: User B with the exact same fingerprint (must NOT be touched or consolidated)
      await queryInterface.sequelize.query(
        `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
         VALUES ('dev_user_b_same_fp', :userId, :fp, 0, '2026-09-01 10:00:00')`,
        { replacements: { userId: userB.id, fp: testFp } }
      );

      // 2. Apply migration 012 up
      await migration012.up(queryInterface);

      // 3. Verify devices table state
      const [userADevices] = await queryInterface.sequelize.query(
        'SELECT id, user_id, fingerprint, is_trusted FROM devices WHERE user_id = :userId',
        { replacements: { userId: userA.id } }
      );

      expect(userADevices.length).toBe(1);
      expect(userADevices[0].id).toBe('dev_dup_trusted_later');
      expect(Boolean(userADevices[0].is_trusted)).toBe(true);

      // User B device must remain untouched
      const [userBDevices] = await queryInterface.sequelize.query(
        'SELECT id, user_id, fingerprint FROM devices WHERE user_id = :userId',
        { replacements: { userId: userB.id } }
      );
      expect(userBDevices.length).toBe(1);
      expect(userBDevices[0].id).toBe('dev_user_b_same_fp');

      // 4. Verify durable archive table state
      const [archivedRows] = await queryInterface.sequelize.query(
        'SELECT id, user_id, fingerprint, is_trusted, canonical_device_id, archive_reason FROM devices_duplicate_archive_012 WHERE user_id = :userId ORDER BY id ASC',
        { replacements: { userId: userA.id } }
      );

      expect(archivedRows.length).toBe(3);
      const archivedIds = archivedRows.map((r) => r.id);
      expect(archivedIds).toEqual(['dev_dup_tie_1', 'dev_dup_tie_2', 'dev_dup_untrusted_earlier']);

      for (const row of archivedRows) {
        expect(row.user_id).toBe(userA.id);
        expect(row.fingerprint).toBe(testFp);
        expect(row.canonical_device_id).toBe('dev_dup_trusted_later');
        expect(row.archive_reason).toBe('migration_012_deduplication');
      }

      // 5. Verify unique index prevents subsequent duplicates
      await expect(
        queryInterface.sequelize.query(
          `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
           VALUES ('dev_illegal_dup', :userId, :fp, 0, NOW())`,
          { replacements: { userId: userA.id, fp: testFp } }
        )
      ).rejects.toThrow();
    });

    test('migration 012 canonical selection deterministically breaks ties by id ASC', async () => {
      const queryInterface = sequelize.getQueryInterface();

      // Roll back to pre-012 state
      await migration012.down(queryInterface);
      await Device.destroy({ where: {}, force: true });

      const testFp = 'fp_tie_breaker_002';

      // Insert two untrusted devices with identical first_seen_at
      await queryInterface.sequelize.query(
        `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
         VALUES ('dev_tie_bravo', :userId, :fp, 0, '2026-09-05 12:00:00')`,
        { replacements: { userId: userA.id, fp: testFp } }
      );

      await queryInterface.sequelize.query(
        `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
         VALUES ('dev_tie_alpha', :userId, :fp, 0, '2026-09-05 12:00:00')`,
        { replacements: { userId: userA.id, fp: testFp } }
      );

      // Apply migration 012 up
      await migration012.up(queryInterface);

      // 'dev_tie_alpha' < 'dev_tie_bravo', so dev_tie_alpha MUST be the canonical survivor
      const [survivor] = await queryInterface.sequelize.query(
        'SELECT id FROM devices WHERE user_id = :userId AND fingerprint = :fp',
        { replacements: { userId: userA.id, fp: testFp } }
      );

      expect(survivor.length).toBe(1);
      expect(survivor[0].id).toBe('dev_tie_alpha');

      const [archived] = await queryInterface.sequelize.query(
        'SELECT id, canonical_device_id FROM devices_duplicate_archive_012 WHERE id = :id',
        { replacements: { id: 'dev_tie_bravo' } }
      );
      expect(archived.length).toBe(1);
      expect(archived[0].canonical_device_id).toBe('dev_tie_alpha');
    });

    test('migration 012 down recovers all archived duplicate records into devices without data loss', async () => {
      const queryInterface = sequelize.getQueryInterface();

      // 1. Prepare clean pre-012 state
      await migration012.down(queryInterface);
      await Device.destroy({ where: {}, force: true });

      const testFp = 'fp_recovery_test_003';

      // Insert two duplicate devices for User A
      await queryInterface.sequelize.query(
        `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
         VALUES ('dev_rec_alpha', :userId, :fp, 0, '2026-09-06 10:00:00')`,
        { replacements: { userId: userA.id, fp: testFp } }
      );

      await queryInterface.sequelize.query(
        `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
         VALUES ('dev_rec_bravo', :userId, :fp, 0, '2026-09-06 10:00:00')`,
        { replacements: { userId: userA.id, fp: testFp } }
      );

      // 2. Migrate up to consolidate and archive dev_rec_bravo
      await migration012.up(queryInterface);

      const [canonicalDevices] = await queryInterface.sequelize.query(
        'SELECT id FROM devices WHERE user_id = :userId AND fingerprint = :fp',
        { replacements: { userId: userA.id, fp: testFp } }
      );
      expect(canonicalDevices.length).toBe(1);
      expect(canonicalDevices[0].id).toBe('dev_rec_alpha');

      // 3. Roll back migration 012 down: should restore dev_rec_bravo
      await migration012.down(queryInterface);

      // Verify unique index was dropped and both rows exist in devices table
      const [restoredRows] = await queryInterface.sequelize.query(
        'SELECT id, user_id, fingerprint FROM devices WHERE user_id = :userId AND fingerprint = :fp ORDER BY id ASC',
        { replacements: { userId: userA.id, fp: testFp } }
      );

      expect(restoredRows.length).toBe(2);
      expect(restoredRows.map((r) => r.id)).toEqual(['dev_rec_alpha', 'dev_rec_bravo']);

      // Verify archive table was dropped after successful restoration
      const tables = await queryInterface.showAllTables();
      const tableNames = tables.map((t) => (typeof t === 'string' ? t : t.tableName || Object.values(t)[0]));
      expect(tableNames.includes('devices_duplicate_archive_012')).toBe(false);

      // Re-apply migration 012 to leave database in migrated state
      await migration012.up(queryInterface);
    });

    test('migration 012 down aborts and preserves archive when primary-key restoration conflict occurs', async () => {
      const queryInterface = sequelize.getQueryInterface();

      // 1. Prepare clean pre-012 state
      await migration012.down(queryInterface);
      await Device.destroy({ where: {}, force: true });

      const testFp = 'fp_conflict_test_004';

      // Insert two duplicate devices for User A
      await queryInterface.sequelize.query(
        `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
         VALUES ('dev_conflict_alpha', :userId, :fp, 0, '2026-09-07 10:00:00')`,
        { replacements: { userId: userA.id, fp: testFp } }
      );

      await queryInterface.sequelize.query(
        `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
         VALUES ('dev_conflict_bravo', :userId, :fp, 0, '2026-09-07 11:00:00')`,
        { replacements: { userId: userA.id, fp: testFp } }
      );

      // 2. Migrate up to consolidate and archive dev_conflict_bravo
      await migration012.up(queryInterface);

      // Verify dev_conflict_bravo was archived
      const [archived] = await queryInterface.sequelize.query(
        'SELECT id, canonical_device_id FROM devices_duplicate_archive_012 WHERE id = :id',
        { replacements: { id: 'dev_conflict_bravo' } }
      );
      expect(archived.length).toBe(1);

      // 3. Simulate a primary-key conflict in devices table with DIFFERENT data (e.g. assigned to User B)
      await queryInterface.sequelize.query(
        `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
         VALUES ('dev_conflict_bravo', :userId, 'fp_foreign_device', 0, NOW())`,
        { replacements: { userId: userB.id } }
      );

      // 4. Attempt rollback: MUST fail closed, refuse to overwrite conflicting row, and preserve archive
      await expect(migration012.down(queryInterface)).rejects.toThrow(
        /Restoration conflict: device with id 'dev_conflict_bravo' already exists in devices with conflicting data/
      );

      // 5. Verify archive table was PRESERVED and not dropped
      const tables = await queryInterface.showAllTables();
      const tableNames = tables.map((t) => (typeof t === 'string' ? t : t.tableName || Object.values(t)[0]));
      expect(tableNames.includes('devices_duplicate_archive_012')).toBe(true);

      const [archiveAfterFailure] = await queryInterface.sequelize.query(
        'SELECT id FROM devices_duplicate_archive_012 WHERE id = :id',
        { replacements: { id: 'dev_conflict_bravo' } }
      );
      expect(archiveAfterFailure.length).toBe(1);

      // Clean up conflicting row to safely complete rollback
      await queryInterface.sequelize.query(
        'DELETE FROM devices WHERE id = :id',
        { replacements: { id: 'dev_conflict_bravo' } }
      );
      await migration012.down(queryInterface);
      await migration012.up(queryInterface);
    });

    test('migration 012 retry preserves original archive timestamps and evidence', async () => {
      const queryInterface = sequelize.getQueryInterface();

      // 1. Prepare clean pre-012 state
      await migration012.down(queryInterface);
      await Device.destroy({ where: {}, force: true });

      const testFp = 'fp_retry_preservation_005';

      await queryInterface.sequelize.query(
        `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
         VALUES ('dev_retry_can', :userId, :fp, 1, '2026-09-08 10:00:00')`,
        { replacements: { userId: userA.id, fp: testFp } }
      );

      await queryInterface.sequelize.query(
        `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
         VALUES ('dev_retry_dup', :userId, :fp, 0, '2026-09-08 11:00:00')`,
        { replacements: { userId: userA.id, fp: testFp } }
      );

      // Initial migration
      await migration012.up(queryInterface);

      const [firstArchive] = await queryInterface.sequelize.query(
        'SELECT id, canonical_device_id, archived_at FROM devices_duplicate_archive_012 WHERE id = :id',
        { replacements: { id: 'dev_retry_dup' } }
      );
      expect(firstArchive.length).toBe(1);
      const originalArchivedAt = new Date(firstArchive[0].archived_at).getTime();
      const originalCanonicalId = firstArchive[0].canonical_device_id;

      // 2. Rerun migration 012 up (simulating retry)
      await migration012.up(queryInterface);

      const [secondArchive] = await queryInterface.sequelize.query(
        'SELECT id, canonical_device_id, archived_at FROM devices_duplicate_archive_012 WHERE id = :id',
        { replacements: { id: 'dev_retry_dup' } }
      );
      expect(secondArchive.length).toBe(1);

      // Verify archived_at and canonical_device_id are strictly preserved
      expect(new Date(secondArchive[0].archived_at).getTime()).toBe(originalArchivedAt);
      expect(secondArchive[0].canonical_device_id).toBe(originalCanonicalId);
    });

    test('migration 012 up is idempotent and safe against repeated execution', async () => {
      const queryInterface = sequelize.getQueryInterface();

      // Running migration 012 up multiple times consecutively must not error or corrupt data
      await expect(migration012.up(queryInterface)).resolves.not.toThrow();
      await expect(migration012.up(queryInterface)).resolves.not.toThrow();

      const columns = await queryInterface.describeTable('devices');
      expect(columns.label).toBeDefined();
      expect(columns.trusted_at).toBeDefined();
      expect(columns.expires_at).toBeDefined();
    });

    test('migration 012 down cleanly rolls back columns and indexes without errors', async () => {
      const queryInterface = sequelize.getQueryInterface();

      // Rollback
      await migration012.down(queryInterface);

      // Verify columns removed
      const columnsAfterDown = await queryInterface.describeTable('devices');
      expect(columnsAfterDown.label).toBeUndefined();
      expect(columnsAfterDown.trusted_at).toBeUndefined();
      expect(columnsAfterDown.expires_at).toBeUndefined();
      expect(columnsAfterDown.revoked_at).toBeUndefined();
      expect(columnsAfterDown.last_used_at).toBeUndefined();

      // Re-apply to leave test DB in migrated state
      await migration012.up(queryInterface);
      const columnsAfterUp = await queryInterface.describeTable('devices');
      expect(columnsAfterUp.label).toBeDefined();
      expect(columnsAfterUp.trusted_at).toBeDefined();
      expect(columnsAfterUp.expires_at).toBeDefined();
    });

    test('migration 012 up aborts with Archive integrity violation if existing archive row has conflicting data', async () => {
      const queryInterface = sequelize.getQueryInterface();

      try {
        // 1. Prepare clean pre-012 state
        await migration012.down(queryInterface);
        await Device.destroy({ where: {}, force: true });

        const testFp = 'fp_retry_mismatch_006';

        // Insert canonical device and duplicate device in pre-012 schema
        await queryInterface.sequelize.query(
          `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
           VALUES ('dev_can_mismatch', :userId, :fp, 1, '2026-09-09 10:00:00')`,
          { replacements: { userId: userA.id, fp: testFp } }
        );

        await queryInterface.sequelize.query(
          `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
           VALUES ('dev_dup_mismatch', :userId, :fp, 0, '2026-09-09 11:00:00')`,
          { replacements: { userId: userA.id, fp: testFp } }
        );

        // Pre-create archive table with a conflicting row for dev_dup_mismatch (e.g. mismatched canonical reference)
        // to simulate a retry where the archive table was previously created but has conflicting metadata
        await queryInterface.createTable('devices_duplicate_archive_012', {
          id: { type: sequelize.Sequelize.STRING(64), primaryKey: true },
          user_id: { type: sequelize.Sequelize.STRING(64), allowNull: false },
          fingerprint: { type: sequelize.Sequelize.STRING(255), allowNull: false },
          is_trusted: { type: sequelize.Sequelize.BOOLEAN, allowNull: false, defaultValue: false },
          first_seen_at: { type: sequelize.Sequelize.DATE, allowNull: false },
          canonical_device_id: { type: sequelize.Sequelize.STRING(64), allowNull: false },
          archived_at: { type: sequelize.Sequelize.DATE(3), allowNull: false },
          archive_reason: { type: sequelize.Sequelize.STRING(100), allowNull: false }
        });

        await queryInterface.sequelize.query(
          `INSERT INTO devices_duplicate_archive_012
           (id, user_id, fingerprint, is_trusted, first_seen_at, canonical_device_id, archived_at, archive_reason)
           VALUES ('dev_dup_mismatch', :userId, :fp, 0, '2026-09-09 11:00:00', 'dev_different_canonical', NOW(3), 'migration_012_deduplication')`,
          { replacements: { userId: userA.id, fp: testFp } }
        );

        // Rerunning migration up must detect the mismatch and throw Archive integrity violation
        await expect(migration012.up(queryInterface)).rejects.toThrow(/Archive integrity violation/);
      } finally {
        // Clean up database state and re-migrate cleanly
        await Device.destroy({ where: {}, force: true });
        await queryInterface.dropTable('devices_duplicate_archive_012').catch(() => {});
        await migration012.down(queryInterface).catch(() => {});
        await migration012.up(queryInterface);
      }
    });

    test('migration 012 down aborts and preserves archive if unique constraint on fingerprint is still active', async () => {
      const queryInterface = sequelize.getQueryInterface();

      try {
        // 1. Prepare clean pre-012 state
        await migration012.down(queryInterface);
        await Device.destroy({ where: {}, force: true });

        const testFp = 'fp_uniq_conflict_007';

        // Insert duplicate devices
        await queryInterface.sequelize.query(
          `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
           VALUES ('dev_uniq_alpha', :userId, :fp, 1, '2026-09-10 10:00:00')`,
          { replacements: { userId: userA.id, fp: testFp } }
        );

        await queryInterface.sequelize.query(
          `INSERT INTO devices (id, user_id, fingerprint, is_trusted, first_seen_at)
           VALUES ('dev_uniq_bravo', :userId, :fp, 0, '2026-09-10 11:00:00')`,
          { replacements: { userId: userA.id, fp: testFp } }
        );

        // Run up to archive dev_uniq_bravo
        await migration012.up(queryInterface);

        // Add a secondary unique index covering fingerprint to simulate external/unremoved constraint
        await queryInterface.addIndex('devices', ['fingerprint'], {
          name: 'idx_test_extra_unique_fp',
          unique: true
        });

        // down() should detect that a unique constraint covering fingerprint is active and abort
        await expect(migration012.down(queryInterface)).rejects.toThrow(
          /Restoration conflict: unique constraint 'idx_test_extra_unique_fp' covering fingerprint is still active/
        );

        // Verify archive table was preserved
        const tables = await queryInterface.showAllTables();
        const tableNames = tables.map((t) => (typeof t === 'string' ? t : t.tableName || Object.values(t)[0]));
        expect(tableNames.includes('devices_duplicate_archive_012')).toBe(true);

        // Drop extra index so rollback can be completed cleanly
        await queryInterface.removeIndex('devices', 'idx_test_extra_unique_fp').catch(() => {});
        await migration012.down(queryInterface);
      } finally {
        await queryInterface.removeIndex('devices', 'idx_test_extra_unique_fp').catch(() => {});
        await migration012.down(queryInterface).catch(() => {});
        await Device.destroy({ where: {}, force: true });
        await migration012.up(queryInterface);
      }
    });
  });
});
