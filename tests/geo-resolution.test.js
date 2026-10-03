const request = require('supertest');
const app = require('../src/app');
const { sequelize, User, Session, Device, SecurityEvent } = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const { normalizeIp, isPrivateOrLoopbackIp } = require('../src/utils/ip');
const {
  resolveGeoLocation,
  setReader,
  closeReader,
  getReader
} = require('../src/services/geoService');
const { collectGeoSignal } = require('../src/collectors/geoCollector');

describe('Sub-module 3.2 — IP / Geo Resolution', () => {
  let testUser;

  beforeAll(async () => {
    await runMigrations();
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    testUser = await User.create({
      email: 'geo-tester@example.com',
      password_hash: await require('bcrypt').hash('Password123!', 10)
    });
  });

  afterAll(async () => {
    closeReader();
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');
  });

  describe('1. IP Normalization & Validation (normalizeIp)', () => {
    test('normalizes standard IPv4 addresses', () => {
      expect(normalizeIp('192.168.1.1')).toBe('192.168.1.1');
      expect(normalizeIp('8.8.8.8')).toBe('8.8.8.8');
      expect(normalizeIp('  207.97.227.239  ')).toBe('207.97.227.239');
    });

    test('normalizes IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)', () => {
      expect(normalizeIp('::ffff:192.0.2.1')).toBe('192.0.2.1');
      expect(normalizeIp('::ffff:8.8.8.8')).toBe('8.8.8.8');
      expect(normalizeIp('::FFFF:127.0.0.1')).toBe('127.0.0.1');
      expect(normalizeIp('  ::ffff:10.0.0.1  ')).toBe('10.0.0.1');
    });

    test('normalizes standard IPv6 addresses', () => {
      expect(normalizeIp('::1')).toBe('::1');
      expect(normalizeIp('2001:db8::1')).toBe('2001:db8::1');
      expect(normalizeIp('2607:f8b0:4005:805::200e')).toBe('2607:f8b0:4005:805::200e');
    });

    test('rejects invalid or non-string inputs safely returning null', () => {
      expect(normalizeIp(null)).toBeNull();
      expect(normalizeIp(undefined)).toBeNull();
      expect(normalizeIp('')).toBeNull();
      expect(normalizeIp('   ')).toBeNull();
      expect(normalizeIp(12345)).toBeNull();
      expect(normalizeIp({})).toBeNull();
      expect(normalizeIp('not-an-ip')).toBeNull();
      expect(normalizeIp('999.999.999.999')).toBeNull();
      expect(normalizeIp('::ffff:not-an-ipv4')).toBeNull();
    });
  });

  describe('2. Private & Loopback Address Detection (isPrivateOrLoopbackIp)', () => {
    test('identifies loopback addresses', () => {
      expect(isPrivateOrLoopbackIp('127.0.0.1')).toBe(true);
      expect(isPrivateOrLoopbackIp('127.0.0.50')).toBe(true);
      expect(isPrivateOrLoopbackIp('::1')).toBe(true);
      expect(isPrivateOrLoopbackIp('::ffff:127.0.0.1')).toBe(true);
    });

    test('identifies RFC 1918 private IPv4 networks', () => {
      expect(isPrivateOrLoopbackIp('10.0.0.1')).toBe(true);
      expect(isPrivateOrLoopbackIp('10.254.254.254')).toBe(true);
      expect(isPrivateOrLoopbackIp('172.16.0.1')).toBe(true);
      expect(isPrivateOrLoopbackIp('172.25.0.1')).toBe(true);
      expect(isPrivateOrLoopbackIp('172.31.255.255')).toBe(true);
      expect(isPrivateOrLoopbackIp('192.168.0.1')).toBe(true);
      expect(isPrivateOrLoopbackIp('192.168.100.254')).toBe(true);
    });

    test('identifies link-local, carrier-grade NAT, and documentation networks', () => {
      expect(isPrivateOrLoopbackIp('169.254.1.1')).toBe(true); // Link-local
      expect(isPrivateOrLoopbackIp('100.64.0.1')).toBe(true); // CGNAT
      expect(isPrivateOrLoopbackIp('192.0.2.1')).toBe(true); // TEST-NET-1
      expect(isPrivateOrLoopbackIp('fe80::1')).toBe(true); // IPv6 Link-local
      expect(isPrivateOrLoopbackIp('fc00::1')).toBe(true); // IPv6 ULA
      expect(isPrivateOrLoopbackIp('fd12:3456:789a::1')).toBe(true); // IPv6 ULA
    });

    test('correctly allows public Internet routable IPs', () => {
      expect(isPrivateOrLoopbackIp('8.8.8.8')).toBe(false);
      expect(isPrivateOrLoopbackIp('1.1.1.1')).toBe(false);
      expect(isPrivateOrLoopbackIp('207.97.227.239')).toBe(false);
      expect(isPrivateOrLoopbackIp('172.15.0.1')).toBe(false); // Below 172.16
      expect(isPrivateOrLoopbackIp('172.32.0.1')).toBe(false); // Above 172.31
      expect(isPrivateOrLoopbackIp('2607:f8b0:4005:805::200e')).toBe(false);
    });
  });

  describe('3. MaxMind GeoLite2 Resolution (geoService & geoCollector)', () => {
    beforeEach(() => {
      closeReader();
    });

    afterEach(() => {
      closeReader();
    });

    test('returns null geo fields for missing/unavailable database without throwing', async () => {
      // Reader points to non-existent path by default when db not present
      const result = await resolveGeoLocation('8.8.8.8');
      expect(result).toBeDefined();
      expect(result.ip).toBe('8.8.8.8');
      expect(result.geo_country).toBeNull();
      expect(result.geo_region).toBeNull();
    });

    test('returns null geo fields for private and loopback addresses without querying reader', async () => {
      const mockReader = {
        get: jest.fn().mockReturnValue({
          country: { iso_code: 'US' },
          subdivisions: [{ iso_code: 'CA' }]
        })
      };
      setReader(mockReader);

      const loopbackResult = await resolveGeoLocation('127.0.0.1');
      expect(loopbackResult.geo_country).toBeNull();
      expect(loopbackResult.geo_region).toBeNull();

      const privateResult = await resolveGeoLocation('192.168.1.1');
      expect(privateResult.geo_country).toBeNull();
      expect(privateResult.geo_region).toBeNull();

      // Reader must never be invoked for private/loopback IPs
      expect(mockReader.get).not.toHaveBeenCalled();
    });

    test('extracts ISO country and region codes from MaxMind record', async () => {
      const mockReader = {
        get: jest.fn().mockImplementation((ip) => {
          if (ip === '8.8.8.8') {
            return {
              country: { iso_code: 'US', names: { en: 'United States' } },
              subdivisions: [{ iso_code: 'CA', names: { en: 'California' } }],
              city: { names: { en: 'Mountain View' } },
              location: { latitude: 37.386, longitude: -122.0838 } // Must be ignored
            };
          }
          if (ip === '212.58.244.20') {
            return {
              country: { iso_code: 'GB' },
              subdivisions: [{ iso_code: 'ENG' }]
            };
          }
          return null;
        })
      };
      setReader(mockReader);

      const resultUS = await resolveGeoLocation('8.8.8.8');
      expect(resultUS.ip).toBe('8.8.8.8');
      expect(resultUS.geo_country).toBe('US');
      expect(resultUS.geo_region).toBe('CA');

      // Crucial: strict verification that coordinates / latitude / longitude are NOT in output
      expect(resultUS.latitude).toBeUndefined();
      expect(resultUS.longitude).toBeUndefined();
      expect(resultUS.location).toBeUndefined();
      expect(resultUS.city).toBeUndefined();

      const resultGB = await resolveGeoLocation('212.58.244.20');
      expect(resultGB.geo_country).toBe('GB');
      expect(resultGB.geo_region).toBe('ENG');
    });

    test('falls back to registered_country if country is absent', async () => {
      const mockReader = {
        get: jest.fn().mockReturnValue({
          registered_country: { iso_code: 'DE' }
        })
      };
      setReader(mockReader);

      const result = await resolveGeoLocation('80.80.80.80');
      expect(result.geo_country).toBe('DE');
      expect(result.geo_region).toBeNull();
    });

    test('handles unknown public IP lookup gracefully returning nulls', async () => {
      const mockReader = {
        get: jest.fn().mockReturnValue(null)
      };
      setReader(mockReader);

      const result = await resolveGeoLocation('198.51.100.99'); // Routed but not in DB
      expect(result.geo_country).toBeNull();
      expect(result.geo_region).toBeNull();
    });

    test('fails safe if reader throws an unexpected error', async () => {
      const mockReader = {
        get: jest.fn().mockImplementation(() => {
          throw new Error('Corrupt MMDB database block');
        })
      };
      setReader(mockReader);

      const result = await resolveGeoLocation('8.8.8.8');
      expect(result.geo_country).toBeNull();
      expect(result.geo_region).toBeNull();
    });

    test('collectGeoSignal wrapper delivers expected country and region shape', async () => {
      const mockReader = {
        get: jest.fn().mockReturnValue({
          country: { iso_code: 'FR' },
          subdivisions: [{ iso_code: 'IDF' }]
        })
      };
      setReader(mockReader);

      const signal = await collectGeoSignal('195.154.120.1');
      expect(signal).toEqual({
        geo_country: 'FR',
        geo_region: 'IDF'
      });
      expect(signal.latitude).toBeUndefined();
      expect(signal.longitude).toBeUndefined();
    });
  });

  describe('4. Auth Integration & Event Context Attachment', () => {
    beforeEach(() => {
      closeReader();
    });

    afterEach(() => {
      closeReader();
    });

    test('login with loopback request IP stores normalized IP and no fabricated geo context', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: 'Password123!'
        })
        .expect(200);

      const { session_id } = res.body;

      const event = await SecurityEvent.findOne({
        where: {
          user_id: testUser.id,
          session_id,
          event_type: 'login_success'
        }
      });

      expect(event).not.toBeNull();
      expect(event.context.ip_address).toBeDefined();
      // Loopback IP must not produce fabricated geo context
      expect(event.context.geo_country).toBeUndefined();
      expect(event.context.geo_region).toBeUndefined();
    });

    test('login_success records geo_country and geo_region when public IP resolves', async () => {
      const mockReader = {
        get: jest.fn().mockImplementation((ip) => {
          if (ip === '127.0.0.1' || ip === '::1') return null;
          return {
            country: { iso_code: 'US' },
            subdivisions: [{ iso_code: 'CA' }]
          };
        })
      };
      setReader(mockReader);

      // Supertest executes locally, so Express canonical req.ip is 127.0.0.1.
      // But we can test login_success context enrichment with mock reader or by testing the pipeline.
      // Let's verify that when resolveGeoLocation resolves for an IP, login_success receives it.
      const geoService = require('../src/services/geoService');
      const spy = jest.spyOn(geoService, 'resolveGeoLocation').mockResolvedValue({
        ip: '198.51.100.1',
        geo_country: 'US',
        geo_region: 'CA'
      });

      try {
        const res = await request(app)
          .post('/api/v1/auth/login')
          .send({
            email: testUser.email,
            password: 'Password123!'
          })
          .expect(200);

        const { session_id } = res.body;

        // Verify login_success has geo_country and geo_region
        const loginEvent = await SecurityEvent.findOne({
          where: {
            user_id: testUser.id,
            session_id,
            event_type: 'login_success'
          },
          order: [['timestamp', 'DESC']]
        });

        expect(loginEvent).not.toBeNull();
        expect(loginEvent.context.geo_country).toBe('US');
        expect(loginEvent.context.geo_region).toBe('CA');

        // Verify session_created does NOT have geo fields (only applicable to login events)
        const sessionCreatedEvent = await SecurityEvent.findOne({
          where: {
            user_id: testUser.id,
            session_id,
            event_type: 'session_created'
          },
          order: [['timestamp', 'DESC']]
        });

        expect(sessionCreatedEvent).not.toBeNull();
        expect(sessionCreatedEvent.context.geo_country).toBeUndefined();
        expect(sessionCreatedEvent.context.geo_region).toBeUndefined();
      } finally {
        spy.mockRestore();
      }
    });

    test('login_failed records geo_country and geo_region when public IP resolves', async () => {
      const geoService = require('../src/services/geoService');
      const spy = jest.spyOn(geoService, 'resolveGeoLocation').mockResolvedValue({
        ip: '198.51.100.1',
        geo_country: 'DE',
        geo_region: 'BE'
      });

      try {
        await request(app)
          .post('/api/v1/auth/login')
          .send({
            email: testUser.email,
            password: 'WrongPassword999!'
          })
          .expect(401);

        const failedEvent = await SecurityEvent.findOne({
          where: {
            user_id: testUser.id,
            event_type: 'login_failed'
          },
          order: [['timestamp', 'DESC']]
        });

        expect(failedEvent).not.toBeNull();
        expect(failedEvent.context.geo_country).toBe('DE');
        expect(failedEvent.context.geo_region).toBe('BE');
      } finally {
        spy.mockRestore();
      }
    });

    test('SecurityEvent schema remains unmodified and valid with geo fields in context', async () => {
      const eventWithGeo = await SecurityEvent.create({
        user_id: testUser.id,
        event_type: 'login_success',
        context: {
          ip_address: '207.97.227.239',
          geo_country: 'US',
          geo_region: 'CA',
          device_fingerprint: 'fp_geo_test_123'
        },
        metadata: {
          action_sensitivity: 'low'
        }
      });

      expect(eventWithGeo).toBeDefined();
      expect(eventWithGeo.event_id).toBeDefined();
      expect(eventWithGeo.context.geo_country).toBe('US');
      expect(eventWithGeo.context.geo_region).toBe('CA');
    });
  });
});
