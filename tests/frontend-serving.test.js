const request = require('supertest');
const app = require('../src/app');

describe('Module 12b: Production Frontend Static Serving & Security Headers', () => {
  const originalServeFrontend = process.env.SERVE_FRONTEND;

  afterEach(() => {
    if (originalServeFrontend !== undefined) {
      process.env.SERVE_FRONTEND = originalServeFrontend;
    } else {
      delete process.env.SERVE_FRONTEND;
    }
  });

  describe('When SERVE_FRONTEND=true', () => {
    beforeEach(() => {
      process.env.SERVE_FRONTEND = 'true';
    });

    test('GET / returns index.html with security headers intact', async () => {
      const res = await request(app).get('/');

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toMatch(/text\/html/);
      expect(res.text).toContain('<!DOCTYPE html>');
      expect(res.text).toContain('ActionGuard');

      // Assert security headers remain intact
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['x-frame-options']).toBe('DENY');
      expect(res.headers['referrer-policy']).toBe('no-referrer');
      expect(res.headers['strict-transport-security']).toBeDefined();

      // Assert CSP is appropriately adjusted for frontend without weakening boundaries
      const csp = res.headers['content-security-policy'];
      expect(csp).toBeDefined();
      expect(csp).toContain("default-src 'none'");
      expect(csp).toContain("script-src 'self'");
      expect(csp).toContain("style-src 'self'");
      expect(csp).toContain("connect-src 'self'");
      expect(csp).toContain("frame-ancestors 'none'");
      expect(csp).toContain("object-src 'none'");
    });

    test('GET /app/overview routes through SPA fallback returning index.html', async () => {
      const res = await request(app).get('/app/overview');

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toMatch(/text\/html/);
      expect(res.text).toContain('<!DOCTYPE html>');
    });

    test('GET /api/v1/unknown returns JSON 404', async () => {
      const res = await request(app).get('/api/v1/unknown');

      expect(res.status).toBe(404);
      expect(res.headers['content-type']).toMatch(/application\/json/);
      expect(res.body).toEqual({
        error: {
          code: 'not_found',
          message: 'Not found',
          status: 404
        }
      });
    });

    test('POST /api/v1/nonexistent returns JSON 404', async () => {
      const res = await request(app).post('/api/v1/nonexistent').send({ foo: 'bar' });

      expect(res.status).toBe(404);
      expect(res.headers['content-type']).toMatch(/application\/json/);
      expect(res.body.error.code).toBe('not_found');
    });
  });

  describe('When SERVE_FRONTEND is not set or false', () => {
    beforeEach(() => {
      process.env.SERVE_FRONTEND = 'false';
    });

    test('GET / serves nothing and returns 404 with strict API CSP intact', async () => {
      const res = await request(app).get('/');

      expect(res.status).toBe(404);
      expect(res.text).not.toContain('ActionGuard');

      // Verify strict API CSP is maintained
      const csp = res.headers['content-security-policy'];
      expect(csp).toBeDefined();
      expect(csp).toContain("default-src 'none'");
      expect(csp).not.toContain("script-src 'self'");
    });

    test('GET /api/v1/unknown still returns JSON 404', async () => {
      const res = await request(app).get('/api/v1/unknown');

      expect(res.status).toBe(404);
      expect(res.headers['content-type']).toMatch(/application\/json/);
      expect(res.body.error.code).toBe('not_found');
    });
  });
});
