const request = require('supertest');
const express = require('express');
const jwt = require('jsonwebtoken');
const app = require('../src/app');
const { sequelize, User } = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const { authenticateToken, JWT_SECRET } = require('../src/middleware/auth');

describe('Sub-module 1.3 — Authentication', () => {
  beforeAll(async () => {
    await runMigrations();
  });

  afterAll(async () => {
    await sequelize.close();
  });

  describe('POST /api/v1/auth/signup', () => {
    test('successful signup creates user with hashed password and returns safe info', async () => {
      const res = await request(app)
        .post('/api/v1/auth/signup')
        .send({
          email: 'alice@example.com',
          password: 'Password123!'
        })
        .expect(201);

      expect(res.body.id).toBeDefined();
      expect(res.body.email).toBe('alice@example.com');
      expect(res.body.password).toBeUndefined();
      expect(res.body.password_hash).toBeUndefined();

      // Verify in database
      const dbUser = await User.findByPk(res.body.id);
      expect(dbUser).not.toBeNull();
      expect(dbUser.password_hash).not.toBe('Password123!');
      expect(dbUser.password_hash.startsWith('$2')).toBe(true);
    });

    test('rejects duplicate email registration', async () => {
      // First registration
      await request(app)
        .post('/api/v1/auth/signup')
        .send({
          email: 'duplicate@example.com',
          password: 'Password123!'
        })
        .expect(201);

      // Attempt duplicate
      const res = await request(app)
        .post('/api/v1/auth/signup')
        .send({
          email: 'duplicate@example.com',
          password: 'AnotherPassword!'
        })
        .expect(400);

      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe('duplicate_email');
    });

    test('rejects invalid email and short password', async () => {
      const res1 = await request(app)
        .post('/api/v1/auth/signup')
        .send({
          email: 'not-an-email',
          password: 'Password123!'
        })
        .expect(400);

      expect(res1.body.error.code).toBe('invalid_request');

      const res2 = await request(app)
        .post('/api/v1/auth/signup')
        .send({
          email: 'shortpass@example.com',
          password: '123'
        })
        .expect(400);

      expect(res2.body.error.code).toBe('invalid_request');
    });
  });

  describe('POST /api/v1/auth/login', () => {
    beforeAll(async () => {
      await request(app)
        .post('/api/v1/auth/signup')
        .send({
          email: 'login-test@example.com',
          password: 'SecretPassword123'
        });
    });

    test('successful login returns a valid JWT token', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'login-test@example.com',
          password: 'SecretPassword123'
        })
        .expect(200);

      expect(res.body.token).toBeDefined();
      expect(res.body.user).toBeDefined();
      expect(res.body.user.email).toBe('login-test@example.com');

      // Verify token decoded properly
      const decoded = jwt.verify(res.body.token, JWT_SECRET);
      expect(decoded.email).toBe('login-test@example.com');
      expect(decoded.id).toBe(res.body.user.id);
    });

    test('failed login with incorrect password returns generic 401 error', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'login-test@example.com',
          password: 'WrongPassword'
        })
        .expect(401);

      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe('authentication_failed');
      expect(res.body.error.message).toBe('Invalid email or password');
    });

    test('failed login with non-existent email returns generic 401 error', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'AnyPassword'
        })
        .expect(401);

      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe('authentication_failed');
      expect(res.body.error.message).toBe('Invalid email or password');
    });
  });

  describe('JWT Verification Middleware', () => {
    let testApp;

    beforeAll(() => {
      testApp = express();
      testApp.use(express.json());
      testApp.get('/test-protected', authenticateToken, (req, res) => {
        res.status(200).json({
          status: 'success',
          user: req.user
        });
      });
    });

    test('allows request with valid JWT and exposes user identity', async () => {
      const validToken = jwt.sign(
        { id: 'usr-12345', email: 'verified@example.com' },
        JWT_SECRET,
        { expiresIn: '15m' }
      );

      const res = await request(testApp)
        .get('/test-protected')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      expect(res.body.status).toBe('success');
      expect(res.body.user.id).toBe('usr-12345');
      expect(res.body.user.email).toBe('verified@example.com');
    });

    test('rejects request with missing token', async () => {
      const res = await request(testApp)
        .get('/test-protected')
        .expect(401);

      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe('unauthorized');
    });

    test('rejects request with invalid token', async () => {
      const res = await request(testApp)
        .get('/test-protected')
        .set('Authorization', 'Bearer invalid.jwt.token')
        .expect(401);

      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe('unauthorized');
    });

    test('rejects expired token', async () => {
      const expiredToken = jwt.sign(
        { id: 'usr-expired', email: 'expired@example.com' },
        JWT_SECRET,
        { expiresIn: '-1s' }
      );

      const res = await request(testApp)
        .get('/test-protected')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);

      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBe('token_expired');
    });
  });
});
