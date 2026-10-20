'use strict';

const request = require('supertest');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const app = require('../src/app');
const { JWT_SECRET } = require('../src/middleware/auth');
const { User, Session, Device, SecurityEvent } = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const sessionService = require('../src/services/sessionService');
const { getOrCreateDevice } = require('../src/services/deviceService');

describe('Module 12d-2 — Trusted Device User APIs & Session Binding', () => {
  let userA;
  let userB;
  let deviceA1;
  let deviceA2;
  let deviceB;
  let sessionA1;
  let sessionA_noDevice;
  let sessionB;
  let tokenA1;
  let tokenA_noDevice;
  let tokenB;

  beforeAll(async () => {
    await runMigrations();

    // Clean up test data
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });

    // Seed test users
    userA = await User.create({
      id: `usr_12d2_a_${crypto.randomUUID().slice(0, 8)}`,
      email: 'user-a-12d2@actionguard.test',
      password_hash: '$2b$10$devdummyhashforseedonlynotforproduction0000000000000000'
    });

    userB = await User.create({
      id: `usr_12d2_b_${crypto.randomUUID().slice(0, 8)}`,
      email: 'user-b-12d2@actionguard.test',
      password_hash: '$2b$10$devdummyhashforseedonlynotforproduction0000000000000000'
    });

    // Seed devices
    const resA1 = await getOrCreateDevice(userA.id, 'fp_api_device_a1_primary');
    deviceA1 = resA1.device;

    const resA2 = await getOrCreateDevice(userA.id, 'fp_api_device_a2_secondary');
    deviceA2 = resA2.device;

    const resB = await getOrCreateDevice(userB.id, 'fp_api_device_b1_foreign');
    deviceB = resB.device;

    // Seed session A1 with deviceA1 bound
    const sA1 = await sessionService.createSession(userA.id, userA.email, 3600, {
      device_id: deviceA1.id,
      device_fingerprint: 'fp_api_device_a1_primary'
    });
    sessionA1 = await Session.findByPk(sA1.sessionId);

    // Seed session A without any device attached
    const sA_noDev = await sessionService.createSession(userA.id, userA.email, 3600, null);
    sessionA_noDevice = await Session.findByPk(sA_noDev.sessionId);

    // Seed session B with deviceB bound
    const sB = await sessionService.createSession(userB.id, userB.email, 3600, {
      device_id: deviceB.id,
      device_fingerprint: 'fp_api_device_b1_foreign'
    });
    sessionB = await Session.findByPk(sB.sessionId);

    // Generate valid tokens
    tokenA1 = jwt.sign(
      { id: userA.id, email: userA.email, session_id: sessionA1.id },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    tokenA_noDevice = jwt.sign(
      { id: userA.id, email: userA.email, session_id: sessionA_noDevice.id },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    tokenB = jwt.sign(
      { id: userB.id, email: userB.email, session_id: sessionB.id },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
  });

  afterAll(async () => {
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
  });

  describe('1. Authentication and Authorization Boundaries', () => {
    test('GET /api/v1/me/devices rejects unauthenticated requests with 401', async () => {
      const res = await request(app).get('/api/v1/me/devices');
      expect(res.status).toBe(401);
      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe('unauthorized');
    });

    test('POST /api/v1/me/devices/enroll rejects unauthenticated requests with 401', async () => {
      const res = await request(app)
        .post('/api/v1/me/devices/enroll')
        .send({ label: 'My Device' });
      expect(res.status).toBe(401);
      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe('unauthorized');
    });

    test('POST /api/v1/me/devices/:id/trust rejects unauthenticated requests with 401', async () => {
      const res = await request(app)
        .post(`/api/v1/me/devices/${deviceA1.id}/trust`)
        .send({});
      expect(res.status).toBe(401);
      expect(res.body.error).toBeDefined();
    });

    test('DELETE /api/v1/me/devices/:id rejects unauthenticated requests with 401', async () => {
      const res = await request(app).delete(`/api/v1/me/devices/${deviceA1.id}`);
      expect(res.status).toBe(401);
      expect(res.body.error).toBeDefined();
    });

    test('POST /api/v1/me/devices/:id/revoke rejects unauthenticated requests with 401', async () => {
      const res = await request(app).post(`/api/v1/me/devices/${deviceA1.id}/revoke`);
      expect(res.status).toBe(401);
      expect(res.body.error).toBeDefined();
    });
  });

  describe('2. Device Listing & Privacy Protection', () => {
    test('GET /api/v1/me/devices returns only the authenticated user\'s devices with current device indicator', async () => {
      const res = await request(app)
        .get('/api/v1/me/devices')
        .set('Authorization', `Bearer ${tokenA1}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBe(2);

      const deviceIds = res.body.map((d) => d.id);
      expect(deviceIds).toContain(deviceA1.id);
      expect(deviceIds).toContain(deviceA2.id);
      expect(deviceIds).not.toContain(deviceB.id); // Tenant isolation: User B's device must not be present

      // Current device indicator matches active session's device
      const current = res.body.find((d) => d.id === deviceA1.id);
      const other = res.body.find((d) => d.id === deviceA2.id);

      expect(current.is_current_device).toBe(true);
      expect(other.is_current_device).toBe(false);

      // Privacy verification: raw fingerprint must NEVER be exposed
      for (const d of res.body) {
        expect(d.fingerprint).toBeUndefined();
      }
    });

    test('GET /api/v1/me/devices for User B returns only User B\'s devices', async () => {
      const res = await request(app)
        .get('/api/v1/me/devices')
        .set('Authorization', `Bearer ${tokenB}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBe(1);
      expect(res.body[0].id).toBe(deviceB.id);
      expect(res.body[0].is_current_device).toBe(true);
      expect(res.body[0].fingerprint).toBeUndefined();
    });
  });

  describe('3. Session-to-Device Binding & Current Device Enrollment', () => {
    test('POST /api/v1/me/devices/enroll fails closed with 403 when session has no bound device', async () => {
      const res = await request(app)
        .post('/api/v1/me/devices/enroll')
        .set('Authorization', `Bearer ${tokenA_noDevice}`)
        .send({ label: 'Ghost Device' });

      expect(res.status).toBe(403);
      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe('device_session_mismatch');
      expect(res.body.error.message).toMatch(/No verified device identity is bound/);
    });

    test('POST /api/v1/me/devices/enroll fails closed with 403 when client-supplied deviceId mismatches session device', async () => {
      const res = await request(app)
        .post('/api/v1/me/devices/enroll')
        .set('Authorization', `Bearer ${tokenA1}`)
        .send({
          deviceId: deviceA2.id, // Client attempts to enroll a different device than current session
          label: 'Attempted Hijack'
        });

      expect(res.status).toBe(403);
      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe('device_session_mismatch');
      expect(res.body.error.message).toMatch(/Cannot enroll a device that does not match/);

      // Verify deviceA2 remained untrusted
      const refreshedA2 = await Device.findByPk(deviceA2.id);
      expect(refreshedA2.is_trusted).toBe(false);
    });

    test('POST /api/v1/me/devices/enroll rejects invalid label with 400', async () => {
      const res = await request(app)
        .post('/api/v1/me/devices/enroll')
        .set('Authorization', `Bearer ${tokenA1}`)
        .send({ label: 'A'.repeat(101) });

      expect(res.status).toBe(400);
      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe('invalid_request');
      expect(res.body.error.message).toMatch(/Invalid device label/);
    });

    test('POST /api/v1/me/devices/enroll successfully enrolls the current session device', async () => {
      const res = await request(app)
        .post('/api/v1/me/devices/enroll')
        .set('Authorization', `Bearer ${tokenA1}`)
        .send({ label: 'Primary Work Laptop' });

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch(/successfully/i);
      expect(res.body.is_trust_active).toBe(true);
      expect(res.body.device).toBeDefined();
      expect(res.body.device.id).toBe(deviceA1.id);
      expect(res.body.device.label).toBe('Primary Work Laptop');
      expect(res.body.device.is_trusted).toBe(true);
      expect(res.body.device.trusted_at).toBeDefined();
      expect(res.body.device.expires_at).toBeDefined();
      expect(res.body.device.fingerprint).toBeUndefined(); // Redacted

      // Verify in database
      const inDb = await Device.findByPk(deviceA1.id);
      expect(inDb.is_trusted).toBe(true);
      expect(inDb.label).toBe('Primary Work Laptop');
    });

    test('POST /api/v1/me/devices/:id/trust succeeds when :id matches session device and fails when mismatched', async () => {
      // Mismatched device ID -> 403
      const badRes = await request(app)
        .post(`/api/v1/me/devices/${deviceA2.id}/trust`)
        .set('Authorization', `Bearer ${tokenA1}`)
        .send({ label: 'Wrong Device' });

      expect(badRes.status).toBe(403);
      expect(badRes.body.error.code).toBe('device_session_mismatch');

      // Matching device ID -> 200
      const okRes = await request(app)
        .post(`/api/v1/me/devices/${deviceA1.id}/trust`)
        .set('Authorization', `Bearer ${tokenA1}`)
        .send({ label: 'Updated Laptop Label' });

      expect(okRes.status).toBe(200);
      expect(okRes.body.is_trust_active).toBe(true);
      expect(okRes.body.device.label).toBe('Updated Laptop Label');
    });
  });

  describe('4. Device Revocation & Tenant Isolation', () => {
    test('DELETE /api/v1/me/devices/:id rejects with 403 when attempting to revoke another user\'s device', async () => {
      // User A attempts to revoke User B's device
      const res = await request(app)
        .delete(`/api/v1/me/devices/${deviceB.id}`)
        .set('Authorization', `Bearer ${tokenA1}`);

      expect(res.status).toBe(403);
      expect(res.body.error).toBeDefined();
      expect(res.body.error.message).toMatch(/Device does not belong to the authenticated user/);
    });

    test('DELETE /api/v1/me/devices/:id rejects with 404 when target device does not exist', async () => {
      const res = await request(app)
        .delete('/api/v1/me/devices/dev_nonexistent_99999')
        .set('Authorization', `Bearer ${tokenA1}`);

      expect(res.status).toBe(404);
      expect(res.body.error).toBeDefined();
      expect(res.body.error.message).toMatch(/Device not found/);
    });

    test('DELETE /api/v1/me/devices/:id revokes trusted device owned by caller', async () => {
      const res = await request(app)
        .delete(`/api/v1/me/devices/${deviceA1.id}`)
        .set('Authorization', `Bearer ${tokenA1}`);

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch(/revoked successfully/i);
      expect(res.body.alreadyRevoked).toBe(false);
      expect(res.body.is_trust_active).toBe(false);
      expect(res.body.device.is_trusted).toBe(false);
      expect(res.body.device.revoked_at).toBeDefined();
      expect(res.body.device.fingerprint).toBeUndefined();

      // Database verification
      const fromDb = await Device.findByPk(deviceA1.id);
      expect(fromDb.is_trusted).toBe(false);
      expect(fromDb.revoked_at).not.toBeNull();
    });

    test('DELETE /api/v1/me/devices/:id is idempotent on already-revoked device', async () => {
      const firstCheck = await Device.findByPk(deviceA1.id);
      const originalRevokedAt = firstCheck.revoked_at;

      const res = await request(app)
        .delete(`/api/v1/me/devices/${deviceA1.id}`)
        .set('Authorization', `Bearer ${tokenA1}`);

      expect(res.status).toBe(200);
      expect(res.body.alreadyRevoked).toBe(true);
      expect(res.body.is_trust_active).toBe(false);

      // Timestamp must be preserved
      const secondCheck = await Device.findByPk(deviceA1.id);
      expect(new Date(secondCheck.revoked_at).getTime()).toBe(new Date(originalRevokedAt).getTime());
    });

    test('POST /api/v1/me/devices/:id/revoke endpoint also works and revokes trust safely', async () => {
      // Re-enroll deviceA1 first
      await request(app)
        .post('/api/v1/me/devices/enroll')
        .set('Authorization', `Bearer ${tokenA1}`)
        .send({ label: 'Re-enrolled Device' });

      const enrolled = await Device.findByPk(deviceA1.id);
      expect(enrolled.is_trusted).toBe(true);

      // Now revoke via POST
      const res = await request(app)
        .post(`/api/v1/me/devices/${deviceA1.id}/revoke`)
        .set('Authorization', `Bearer ${tokenA1}`);

      expect(res.status).toBe(200);
      expect(res.body.alreadyRevoked).toBe(false);
      expect(res.body.is_trust_active).toBe(false);
      expect(res.body.device.is_trusted).toBe(false);

      const revoked = await Device.findByPk(deviceA1.id);
      expect(revoked.is_trusted).toBe(false);
      expect(revoked.revoked_at).not.toBeNull();
    });
  });
});
