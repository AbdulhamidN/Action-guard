'use strict';

const request = require('supertest');
const crypto = require('crypto');
const app = require('../src/app');
const { assertRequiredSecrets, JWT_SECRET } = require('../src/middleware/auth');
const { User, Session, SecurityEvent, RiskAssessment, sequelize } = require('../src/database/models');
const sessionService = require('../src/services/sessionService');
const { issueStepUpChallenge, testChallengeOutbox, getDemoChallengeRecord } = require('../src/services/stepUpService');

describe('Module 12c-2 — Backend User Security & Demo OTP Delivery', () => {
  let userA;
  let userB;
  let sessionA1;
  let sessionA2;
  let sessionB;
  let tokenA;
  let tokenB;

  beforeAll(async () => {
    // Clean up
    await SecurityEvent.destroy({ where: {}, force: true });
    await RiskAssessment.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });

    // Seed test user A
    userA = await User.create({
      id: `usr_12c_${crypto.randomUUID()}`,
      email: 'user-a-12c2@actionguard.test',
      password_hash: '$2b$10$devdummyhashforseedonlynotforproduction0000000000000000'
    });

    // Seed test user B
    userB = await User.create({
      id: `usr_12c_${crypto.randomUUID()}`,
      email: 'user-b-12c2@actionguard.test',
      password_hash: '$2b$10$devdummyhashforseedonlynotforproduction0000000000000000'
    });

    // Seed session A1 (current)
    const sA1 = await sessionService.createSession(userA.id, userA.email, 3600);
    sessionA1 = await Session.findByPk(sA1.sessionId);

    // Seed session A2 (other session of user A)
    const sA2 = await sessionService.createSession(userA.id, userA.email, 3600);
    sessionA2 = await Session.findByPk(sA2.sessionId);

    // Seed session B (user B)
    const sB = await sessionService.createSession(userB.id, userB.email, 3600);
    sessionB = await Session.findByPk(sB.sessionId);

    // Seed security event with geo context for session A1
    await SecurityEvent.create({
      event_id: `evt_12c_${crypto.randomUUID()}`,
      user_id: userA.id,
      session_id: sessionA1.id,
      event_type: 'login_success',
      timestamp: new Date(),
      context: {
        geo_country: 'US',
        geo_region: 'VA',
        ip_address: '198.51.100.99',
        device_fingerprint: 'fp_known_device_12c2',
        user_agent: 'SecretBrowser/99.0'
      }
    });

    // Generate JWTs
    const jwt = require('jsonwebtoken');
    tokenA = jwt.sign(
      { id: userA.id, email: userA.email, session_id: sessionA1.id },
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
    await RiskAssessment.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
  });

  describe('1. Active Sessions and Privacy', () => {
    test('GET /api/v1/me/sessions returns coarse_location and omits raw IP/UA/fingerprint', async () => {
      const res = await request(app)
        .get('/api/v1/me/sessions')
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);

      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBe(2);

      const current = res.body.find((s) => s.session_id === sessionA1.id);
      expect(current).toBeDefined();
      expect(current.is_current).toBe(true);
      expect(current.coarse_location).toEqual({ country: 'US', region: 'VA' });
      expect(current.ip_address).toBeUndefined();
      expect(current.user_agent).toBeUndefined();
      expect(current.device_fingerprint).toBeUndefined();
      expect(current.risk_score).toBeUndefined();

      const other = res.body.find((s) => s.session_id === sessionA2.id);
      expect(other).toBeDefined();
      expect(other.is_current).toBe(false);
    });

    test('DELETE /api/v1/me/sessions/:id terminates another session owned by user', async () => {
      const res = await request(app)
        .delete(`/api/v1/me/sessions/${sessionA2.id}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);

      expect(res.body.message).toContain('successfully terminated');
      expect(res.body.session_id).toBe(sessionA2.id);

      // Verify in DB that is_active is now false
      const refreshed = await Session.findByPk(sessionA2.id);
      expect(refreshed.is_active).toBe(false);

      // Verify session_terminated audit event recorded
      const termEvent = await SecurityEvent.findOne({
        where: {
          session_id: sessionA2.id,
          event_type: 'session_terminated'
        }
      });
      expect(termEvent).toBeDefined();
      expect(termEvent.metadata.terminated_by).toBe('user');
    });

    test('DELETE /api/v1/me/sessions/:id rejects terminating active/current session', async () => {
      const res = await request(app)
        .delete(`/api/v1/me/sessions/${sessionA1.id}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(400);

      expect(res.body.error.code).toBe('invalid_request');
      expect(res.body.error.message).toContain('use POST /api/v1/auth/logout');
    });

    test('DELETE /api/v1/me/sessions/:id returns 404 for session owned by another user', async () => {
      const res = await request(app)
        .delete(`/api/v1/me/sessions/${sessionB.id}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(404);

      expect(res.body.error.code).toBe('not_found');
    });

    test('DELETE /api/v1/me/sessions/:id returns 404 for non-existent session', async () => {
      const res = await request(app)
        .delete('/api/v1/me/sessions/sess_non_existent_12345')
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(404);

      expect(res.body.error.code).toBe('not_found');
    });
  });

  describe('2. Demo OTP Delivery & Production Safety Assertions', () => {
    test('assertRequiredSecrets throws if ACTIONGUARD_DEMO_MODE=true in production', () => {
      expect(() => {
        assertRequiredSecrets({
          ACTIONGUARD_DEMO_MODE: 'true',
          NODE_ENV: 'production',
          JWT_SECRET: 'super_secret_production_key_at_least_32_chars_long_12345'
        });
      }).toThrow('ACTIONGUARD_DEMO_MODE must not be enabled in production environments');
    });

    test('issueStepUpChallenge throws if ACTIONGUARD_DEMO_MODE=true and NODE_ENV=production', async () => {
      const prevMode = process.env.ACTIONGUARD_DEMO_MODE;
      const prevEnv = process.env.NODE_ENV;
      try {
        process.env.ACTIONGUARD_DEMO_MODE = 'true';
        process.env.NODE_ENV = 'production';

        await expect(
          issueStepUpChallenge({
            userId: userA.id,
            sessionId: sessionA1.id,
            scope: 'sensitive_action'
          })
        ).rejects.toThrow('ACTIONGUARD_DEMO_MODE cannot be enabled in production environments');
      } finally {
        process.env.ACTIONGUARD_DEMO_MODE = prevMode;
        process.env.NODE_ENV = prevEnv;
      }
    });

    test('GET /api/v1/sessions/:id/step-up/demo-code returns 404 when demo mode is not true', async () => {
      delete process.env.ACTIONGUARD_DEMO_MODE;

      await request(app)
        .get(`/api/v1/sessions/${sessionA1.id}/step-up/demo-code?challenge_id=chl_fake`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(404);
    });

    test('GET /api/v1/sessions/:id/step-up/demo-code returns code when ACTIONGUARD_DEMO_MODE=true', async () => {
      process.env.ACTIONGUARD_DEMO_MODE = 'true';
      try {
        const challengeRes = await issueStepUpChallenge({
          userId: userA.id,
          sessionId: sessionA1.id,
          scope: 'sensitive_action'
        });

        const res = await request(app)
          .get(`/api/v1/sessions/${sessionA1.id}/step-up/demo-code?challenge_id=${challengeRes.challenge_id}`)
          .set('Authorization', `Bearer ${tokenA}`)
          .expect(200);

        expect(res.body.challenge_id).toBe(challengeRes.challenge_id);
        expect(res.body.scope).toBe('sensitive_action');
        expect(res.body.demo_code).toMatch(/^\d{6}$/);

        // Verify in-process outbox has the same code
        const outboxEntry = getDemoChallengeRecord(challengeRes.challenge_id);
        expect(outboxEntry.otp).toBe(res.body.demo_code);
      } finally {
        delete process.env.ACTIONGUARD_DEMO_MODE;
      }
    });

    test('GET /api/v1/sessions/:id/step-up/demo-code returns 404 in NODE_ENV=production even if ACTIONGUARD_DEMO_MODE=true', async () => {
      const prevMode = process.env.ACTIONGUARD_DEMO_MODE;
      const prevEnv = process.env.NODE_ENV;
      const testChallengeId = `chl_prod_test_${Date.now()}`;

      try {
        process.env.ACTIONGUARD_DEMO_MODE = 'true';
        process.env.NODE_ENV = 'production';

        // Pre-populate outbox entry directly without triggering production-rejected issuance or log emission
        testChallengeOutbox.set(testChallengeId, {
          otp: '123456',
          userId: userA.id,
          sessionId: sessionA1.id,
          scope: 'sensitive_action',
          destination: userA.email,
          expiresAt: new Date(Date.now() + 300000).toISOString()
        });

        const res = await request(app)
          .get(`/api/v1/sessions/${sessionA1.id}/step-up/demo-code?challenge_id=${testChallengeId}`)
          .set('Authorization', `Bearer ${tokenA}`)
          .expect(404);

        expect(res.body.error).toBeDefined();
        expect(res.body.error.code).toBe('not_found');
        expect(res.body.demo_code).toBeUndefined();
        expect(res.body.code).toBeUndefined();
        expect(res.body.otp).toBeUndefined();
      } finally {
        testChallengeOutbox.delete(testChallengeId);
        if (prevMode !== undefined) {
          process.env.ACTIONGUARD_DEMO_MODE = prevMode;
        } else {
          delete process.env.ACTIONGUARD_DEMO_MODE;
        }
        if (prevEnv !== undefined) {
          process.env.NODE_ENV = prevEnv;
        } else {
          delete process.env.NODE_ENV;
        }
      }
    });
  });
});
