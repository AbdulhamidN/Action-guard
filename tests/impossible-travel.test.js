const request = require('supertest');
const app = require('../src/app');
const { sequelize, User, Session, Device, SecurityEvent } = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const {
  calculateHaversineDistance,
  calculateElapsedMinutes,
  calculateTravelSpeedKmh,
  roundToTwoDecimals
} = require('../src/utils/geo');
const {
  resolveCoordinates,
  resolveGeoLocation,
  setReader,
  closeReader
} = require('../src/services/geoService');
const {
  DEFAULT_SPEED_THRESHOLD_KMH,
  getSpeedThreshold,
  getPreviousSuccessfulLogin,
  detectImpossibleTravelForUser
} = require('../src/services/travelService');
const { collectTravelAnomalySignal } = require('../src/collectors/travelCollector');

describe('Sub-module 3.3 — Impossible-Travel Detection', () => {
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

    const bcrypt = require('bcrypt');
    userA = await User.create({
      email: 'traveler-a@example.com',
      password_hash: await bcrypt.hash('Password123!', 10)
    });

    userB = await User.create({
      email: 'traveler-b@example.com',
      password_hash: await bcrypt.hash('Password123!', 10)
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

  describe('1. Geographic & Mathematical Utilities (src/utils/geo.js)', () => {
    test('calculateHaversineDistance returns 0 for identical coordinates', () => {
      expect(calculateHaversineDistance(40.7128, -74.006, 40.7128, -74.006)).toBe(0);
      expect(calculateHaversineDistance(0, 0, 0, 0)).toBe(0);
    });

    test('calculateHaversineDistance calculates accurate great-circle distances', () => {
      // New York (40.7128, -74.0060) to London (51.5074, -0.1278) ~ 5,570 km
      const nyToLondon = calculateHaversineDistance(40.7128, -74.006, 51.5074, -0.1278);
      expect(nyToLondon).toBeGreaterThan(5560);
      expect(nyToLondon).toBeLessThan(5585);

      // London to Paris (48.8566, 2.3522) ~ 343 km
      const londonToParis = calculateHaversineDistance(51.5074, -0.1278, 48.8566, 2.3522);
      expect(londonToParis).toBeGreaterThan(340);
      expect(londonToParis).toBeLessThan(346);

      // Tokyo (35.6762, 139.6503) to Sydney (-33.8688, 151.2093) ~ 7,825 km
      const tokyoToSydney = calculateHaversineDistance(35.6762, 139.6503, -33.8688, 151.2093);
      expect(tokyoToSydney).toBeGreaterThan(7800);
      expect(tokyoToSydney).toBeLessThan(7850);
    });

    test('calculateHaversineDistance validates coordinates bounds and types', () => {
      expect(() => calculateHaversineDistance(95, 0, 0, 0)).toThrow('Latitude must be between -90 and 90');
      expect(() => calculateHaversineDistance(0, 0, -95, 0)).toThrow('Latitude must be between -90 and 90');
      expect(() => calculateHaversineDistance(0, 190, 0, 0)).toThrow('Longitude must be between -180 and 180');
      expect(() => calculateHaversineDistance(0, 0, 0, -185)).toThrow('Longitude must be between -180 and 180');
      expect(() => calculateHaversineDistance('invalid', 0, 0, 0)).toThrow('finite numbers');
      expect(() => calculateHaversineDistance(0, null, 0, 0)).toThrow('finite numbers');
    });

    test('calculateElapsedMinutes calculates minutes between timestamps', () => {
      const t1 = new Date('2026-10-04T10:00:00.000Z');
      const t2 = new Date('2026-10-04T10:30:00.000Z');
      expect(calculateElapsedMinutes(t1, t2)).toBe(30);

      const t3 = new Date('2026-10-04T12:00:00.000Z');
      expect(calculateElapsedMinutes(t1, t3)).toBe(120);

      // Non-positive or zero
      expect(calculateElapsedMinutes(t2, t2)).toBe(0);
      expect(calculateElapsedMinutes(t2, t1)).toBe(-30);

      // Invalid inputs
      expect(calculateElapsedMinutes('not-a-date', t2)).toBeNull();
    });

    test('calculateTravelSpeedKmh calculates speed in km/h accurately', () => {
      // 500 km in 30 minutes = 1000 km/h
      expect(calculateTravelSpeedKmh(500, 30)).toBe(1000);

      // Distance 0 km returns 0 km/h
      expect(calculateTravelSpeedKmh(0, 60)).toBe(0);

      // Non-positive elapsed time returns null
      expect(calculateTravelSpeedKmh(500, 0)).toBeNull();
      expect(calculateTravelSpeedKmh(500, -10)).toBeNull();

      // Negative distance returns null
      expect(calculateTravelSpeedKmh(-10, 60)).toBeNull();
    });

    test('roundToTwoDecimals formats deterministic 2-decimal numbers', () => {
      expect(roundToTwoDecimals(123.4567)).toBe(123.46);
      expect(roundToTwoDecimals(100)).toBe(100);
      expect(roundToTwoDecimals(0)).toBe(0);
      expect(roundToTwoDecimals(NaN)).toBe(0);
    });
  });

  describe('2. Coordinate Resolution & Privacy Boundary (src/services/geoService.js)', () => {
    beforeEach(() => {
      closeReader();
    });

    afterEach(() => {
      closeReader();
    });

    test('resolveCoordinates returns null for private, loopback, or invalid IPs', async () => {
      expect(await resolveCoordinates('127.0.0.1')).toBeNull();
      expect(await resolveCoordinates('10.0.0.1')).toBeNull();
      expect(await resolveCoordinates('192.168.1.100')).toBeNull();
      expect(await resolveCoordinates('::1')).toBeNull();
      expect(await resolveCoordinates('invalid-ip')).toBeNull();
      expect(await resolveCoordinates(null)).toBeNull();
    });

    test('resolveCoordinates returns { latitude, longitude } from MaxMind reader', async () => {
      const mockReader = {
        get: jest.fn().mockImplementation((ip) => {
          if (ip === '207.97.227.239') {
            return {
              location: { latitude: 40.7128, longitude: -74.006 }
            };
          }
          return null;
        })
      };
      setReader(mockReader);

      const coords = await resolveCoordinates('207.97.227.239');
      expect(coords).toEqual({ latitude: 40.7128, longitude: -74.006 });
    });

    test('resolveCoordinates returns null if location record is missing or corrupt', async () => {
      const mockReader = {
        get: jest.fn().mockReturnValue({})
      };
      setReader(mockReader);

      expect(await resolveCoordinates('207.97.227.239')).toBeNull();
    });

    test('resolveGeoLocation preserves privacy and does not expose coordinates', async () => {
      const mockReader = {
        get: jest.fn().mockReturnValue({
          country: { iso_code: 'US' },
          subdivisions: [{ iso_code: 'NY' }],
          location: { latitude: 40.7128, longitude: -74.006 }
        })
      };
      setReader(mockReader);

      const geo = await resolveGeoLocation('207.97.227.239');
      expect(geo.geo_country).toBe('US');
      expect(geo.geo_region).toBe('NY');
      expect(geo.latitude).toBeUndefined();
      expect(geo.longitude).toBeUndefined();
      expect(geo.location).toBeUndefined();
    });
  });

  describe('3. Impossible-Travel Service & Thresholds (src/services/travelService.js)', () => {
    beforeEach(async () => {
      closeReader();
      delete process.env.IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD_KMH;
      await SecurityEvent.destroy({ where: {}, force: true });
    });

    afterEach(() => {
      closeReader();
      delete process.env.IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD_KMH;
    });

    test('threshold defaults to 900 km/h and respects environment variable and options', () => {
      expect(DEFAULT_SPEED_THRESHOLD_KMH).toBe(900);
      expect(getSpeedThreshold()).toBe(900);

      process.env.IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD_KMH = '1000';
      expect(getSpeedThreshold()).toBe(1000);

      // Options override environment variable
      expect(getSpeedThreshold({ speedThresholdKmh: 750 })).toBe(750);

      // Invalid env values fall back to default 900
      process.env.IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD_KMH = 'invalid';
      expect(getSpeedThreshold()).toBe(900);

      process.env.IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD_KMH = '-100';
      expect(getSpeedThreshold()).toBe(900);
    });

    test('returns has_previous_login: false for first login ever', async () => {
      const result = await detectImpossibleTravelForUser(
        userA.id,
        '207.97.227.239',
        new Date('2026-10-04T10:00:00Z')
      );

      expect(result).toEqual({
        has_previous_login: false,
        has_sufficient_geo_data: false,
        distance_km: null,
        elapsed_minutes: null,
        required_speed_kmh: null,
        impossible_travel: false
      });
    });

    test('does not leak raw coordinates in any travel result structure', async () => {
      const mockReader = {
        get: jest.fn().mockImplementation((ip) => {
          if (ip === '207.97.227.239') return { location: { latitude: 40.7128, longitude: -74.006 } };
          if (ip === '212.58.244.20') return { location: { latitude: 51.5074, longitude: -0.1278 } };
          return null;
        })
      };
      setReader(mockReader);

      // Seed previous login
      await SecurityEvent.create({
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date('2026-10-04T10:00:00Z'),
        context: { ip_address: '207.97.227.239' }
      });

      const result = await detectImpossibleTravelForUser(
        userA.id,
        '212.58.244.20',
        new Date('2026-10-04T10:30:00Z')
      );

      expect(result.latitude).toBeUndefined();
      expect(result.longitude).toBeUndefined();
      expect(result.coords).toBeUndefined();
      expect(result.current_location).toBeUndefined();
      expect(result.previous_location).toBeUndefined();
    });

    test('handles missing or unresolvable coordinates with has_sufficient_geo_data: false', async () => {
      const mockReader = {
        get: jest.fn().mockReturnValue(null) // Unresolvable public IP
      };
      setReader(mockReader);

      await SecurityEvent.create({
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date('2026-10-04T10:00:00Z'),
        context: { ip_address: '207.97.227.239' }
      });

      const result = await detectImpossibleTravelForUser(
        userA.id,
        '212.58.244.20',
        new Date('2026-10-04T10:30:00Z')
      );

      expect(result).toEqual({
        has_previous_login: true,
        has_sufficient_geo_data: false,
        distance_km: null,
        elapsed_minutes: null,
        required_speed_kmh: null,
        impossible_travel: false
      });
    });

    test('handles non-positive/invalid elapsed time without flagging impossible travel', async () => {
      const mockReader = {
        get: jest.fn().mockImplementation((ip) => {
          if (ip === '207.97.227.239') return { location: { latitude: 40.7128, longitude: -74.006 } };
          if (ip === '212.58.244.20') return { location: { latitude: 51.5074, longitude: -0.1278 } };
          return null;
        })
      };
      setReader(mockReader);

      const travelService = require('../src/services/travelService');
      const prevLoginSpy = jest.spyOn(travelService, 'getPreviousSuccessfulLogin').mockResolvedValue({
        timestamp: new Date('2026-10-04T12:00:00Z'),
        context: { ip_address: '207.97.227.239' }
      });

      try {
        // Elapsed time is 0 (identical time)
        const zeroElapsedResult = await detectImpossibleTravelForUser(
          userA.id,
          '212.58.244.20',
          new Date('2026-10-04T12:00:00Z')
        );

        // Per requirement: has_sufficient_geo_data: true, distance_km populated, elapsed_minutes: null, required_speed_kmh: null, impossible_travel: false
        expect(zeroElapsedResult.has_previous_login).toBe(true);
        expect(zeroElapsedResult.has_sufficient_geo_data).toBe(true);
        expect(zeroElapsedResult.distance_km).toBeGreaterThan(5000);
        expect(zeroElapsedResult.elapsed_minutes).toBeNull();
        expect(zeroElapsedResult.required_speed_kmh).toBeNull();
        expect(zeroElapsedResult.impossible_travel).toBe(false);

        // Elapsed time is negative (clock skew / previous is later)
        const negativeElapsedResult = await detectImpossibleTravelForUser(
          userA.id,
          '212.58.244.20',
          new Date('2026-10-04T11:00:00Z')
        );

        expect(negativeElapsedResult.has_previous_login).toBe(true);
        expect(negativeElapsedResult.has_sufficient_geo_data).toBe(true);
        expect(negativeElapsedResult.distance_km).toBeGreaterThan(5000);
        expect(negativeElapsedResult.elapsed_minutes).toBeNull();
        expect(negativeElapsedResult.required_speed_kmh).toBeNull();
        expect(negativeElapsedResult.impossible_travel).toBe(false);
      } finally {
        prevLoginSpy.mockRestore();
      }
    });

    test('detects plausible travel below 900 km/h (impossible_travel: false)', async () => {
      // London to Paris (~343 km) in 3 hours (180 mins) => speed ~ 114 km/h
      const mockReader = {
        get: jest.fn().mockImplementation((ip) => {
          if (ip === '212.58.244.20') return { location: { latitude: 51.5074, longitude: -0.1278 } }; // London
          if (ip === '93.184.216.34') return { location: { latitude: 48.8566, longitude: 2.3522 } }; // Paris
          return null;
        })
      };
      setReader(mockReader);

      await SecurityEvent.create({
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date('2026-10-04T08:00:00Z'),
        context: { ip_address: '212.58.244.20' }
      });

      const result = await detectImpossibleTravelForUser(
        userA.id,
        '93.184.216.34',
        new Date('2026-10-04T11:00:00Z') // 3 hours later
      );

      expect(result.has_previous_login).toBe(true);
      expect(result.has_sufficient_geo_data).toBe(true);
      expect(result.distance_km).toBeGreaterThan(340);
      expect(result.distance_km).toBeLessThan(346);
      expect(result.elapsed_minutes).toBe(180);
      expect(result.required_speed_kmh).toBeGreaterThan(110);
      expect(result.required_speed_kmh).toBeLessThan(120);
      expect(result.impossible_travel).toBe(false);
    });

    test('detects impossible travel above 900 km/h (impossible_travel: true)', async () => {
      // New York to London (~5,570 km) in 30 minutes => speed ~ 11,140 km/h
      const mockReader = {
        get: jest.fn().mockImplementation((ip) => {
          if (ip === '207.97.227.239') return { location: { latitude: 40.7128, longitude: -74.006 } }; // New York
          if (ip === '212.58.244.20') return { location: { latitude: 51.5074, longitude: -0.1278 } }; // London
          return null;
        })
      };
      setReader(mockReader);

      await SecurityEvent.create({
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date('2026-10-04T14:00:00Z'),
        context: { ip_address: '207.97.227.239' }
      });

      const result = await detectImpossibleTravelForUser(
        userA.id,
        '212.58.244.20',
        new Date('2026-10-04T14:30:00Z') // 30 minutes later
      );

      expect(result.has_previous_login).toBe(true);
      expect(result.has_sufficient_geo_data).toBe(true);
      expect(result.distance_km).toBeGreaterThan(5560);
      expect(result.elapsed_minutes).toBe(30);
      expect(result.required_speed_kmh).toBeGreaterThan(11100);
      expect(result.impossible_travel).toBe(true);
    });

    test('returns speed 0 and impossible_travel: false when distance is 0 km', async () => {
      const mockReader = {
        get: jest.fn().mockReturnValue({ location: { latitude: 40.7128, longitude: -74.006 } })
      };
      setReader(mockReader);

      await SecurityEvent.create({
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: new Date('2026-10-04T15:00:00Z'),
        context: { ip_address: '207.97.227.239' }
      });

      const result = await detectImpossibleTravelForUser(
        userA.id,
        '207.97.227.239',
        new Date('2026-10-04T15:05:00Z')
      );

      expect(result.has_previous_login).toBe(true);
      expect(result.has_sufficient_geo_data).toBe(true);
      expect(result.distance_km).toBe(0);
      expect(result.elapsed_minutes).toBe(5);
      expect(result.required_speed_kmh).toBe(0);
      expect(result.impossible_travel).toBe(false);
    });

    test('strictly selects immediately preceding login_success for the same user and ignores login_failed', async () => {
      const t1 = new Date('2026-10-04T01:00:00Z');
      const t2 = new Date('2026-10-04T02:00:00Z');
      const t3 = new Date('2026-10-04T03:00:00Z');
      const t4 = new Date('2026-10-04T04:00:00Z');

      // User B login
      await SecurityEvent.create({
        user_id: userB.id,
        event_type: 'login_success',
        timestamp: t1,
        context: { ip_address: '212.58.244.20' }
      });

      // User A old login
      await SecurityEvent.create({
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: t1,
        context: { ip_address: '207.97.227.239' }
      });

      // User A failed login at t2 (must be ignored)
      await SecurityEvent.create({
        user_id: userA.id,
        event_type: 'login_failed',
        timestamp: t2,
        context: { ip_address: '8.8.8.8' }
      });

      // User A most recent success at t3
      const recentLogin = await SecurityEvent.create({
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: t3,
        context: { ip_address: '93.184.216.34' }
      });

      const selected = await getPreviousSuccessfulLogin(userA.id, t4);
      expect(selected).not.toBeNull();
      expect(selected.event_id).toBe(recentLogin.event_id);
      expect(selected.event_type).toBe('login_success');
      expect(selected.user_id).toBe(userA.id);
    });
  });

  describe('4. Auth Integration & Event Context Attachment (POST /api/v1/auth/login)', () => {
    beforeEach(async () => {
      closeReader();
      await SecurityEvent.destroy({ where: {}, force: true });
    });

    afterEach(() => {
      closeReader();
    });

    test('initial login for a user records travel_anomaly with has_previous_login: false', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: userB.email,
          password: 'Password123!'
        })
        .expect(200);

      const { session_id } = res.body;

      const event = await SecurityEvent.findOne({
        where: {
          user_id: userB.id,
          session_id,
          event_type: 'login_success'
        },
        order: [['timestamp', 'DESC']]
      });

      expect(event).not.toBeNull();
      expect(event.metadata).toBeDefined();
      expect(event.metadata.travel_anomaly).toBeDefined();
      expect(event.metadata.travel_anomaly.has_previous_login).toBe(false);
      expect(event.metadata.travel_anomaly.impossible_travel).toBe(false);

      // Verify NO coordinates in metadata, context, or response
      expect(event.metadata.travel_anomaly.latitude).toBeUndefined();
      expect(event.metadata.travel_anomaly.longitude).toBeUndefined();
      expect(event.context.latitude).toBeUndefined();
      expect(event.context.longitude).toBeUndefined();
      expect(res.body.latitude).toBeUndefined();
      expect(res.body.longitude).toBeUndefined();
    });

    test('consecutive login requiring speed > 900 km/h flags impossible_travel: true', async () => {
      const prevLoginTime = new Date(Date.now() - 20 * 60 * 1000); // 20 minutes ago

      // Seed previous login from NY
      const prevEvent = await SecurityEvent.create({
        user_id: userA.id,
        event_type: 'login_success',
        timestamp: prevLoginTime,
        context: { ip_address: '207.97.227.239' },
        metadata: { travel_anomaly: { has_previous_login: false } }
      });

      const geoService = require('../src/services/geoService');
      // Spy resolveGeoLocation and resolveCoordinates for login request
      const geoSpy = jest.spyOn(geoService, 'resolveGeoLocation').mockResolvedValue({
        ip: '212.58.244.20',
        geo_country: 'GB',
        geo_region: 'ENG'
      });
      const coordsSpy = jest.spyOn(geoService, 'resolveCoordinates').mockImplementation(async (ip) => {
        if (ip === '207.97.227.239') return { latitude: 40.7128, longitude: -74.006 };
        if (ip === '212.58.244.20' || ip === '127.0.0.1' || ip === '::ffff:127.0.0.1') {
          return { latitude: 51.5074, longitude: -0.1278 };
        }
        return null;
      });

      try {
        const res = await request(app)
          .post('/api/v1/auth/login')
          .send({
            email: userA.email,
            password: 'Password123!'
          })
          .expect(200);

        const { session_id } = res.body;

        const newLoginEvent = await SecurityEvent.findOne({
          where: {
            user_id: userA.id,
            session_id,
            event_type: 'login_success'
          },
          order: [['timestamp', 'DESC']]
        });

        expect(newLoginEvent).not.toBeNull();
        const anomaly = newLoginEvent.metadata?.travel_anomaly;
        expect(anomaly).toBeDefined();
        expect(anomaly.has_previous_login).toBe(true);
        expect(anomaly.has_sufficient_geo_data).toBe(true);
        expect(anomaly.distance_km).toBeGreaterThan(5500);
        expect(anomaly.elapsed_minutes).toBeGreaterThan(0);
        expect(anomaly.required_speed_kmh).toBeGreaterThan(900);
        expect(anomaly.impossible_travel).toBe(true);

        // Previous login event MUST NOT be modified
        const refetchedPrevEvent = await SecurityEvent.findByPk(prevEvent.event_id);
        expect(refetchedPrevEvent.metadata).toEqual(prevEvent.metadata);

        // Verification of coordinate privacy across event and response
        expect(newLoginEvent.context.latitude).toBeUndefined();
        expect(newLoginEvent.context.longitude).toBeUndefined();
        expect(anomaly.latitude).toBeUndefined();
        expect(anomaly.longitude).toBeUndefined();
        expect(res.body.travel_anomaly).toBeUndefined();
      } finally {
        geoSpy.mockRestore();
        coordsSpy.mockRestore();
      }
    });

    test('preserves existing metadata fields when attaching travel_anomaly', async () => {
      const geoService = require('../src/services/geoService');
      const coordsSpy = jest.spyOn(geoService, 'resolveCoordinates').mockResolvedValue(null);

      try {
        const res = await request(app)
          .post('/api/v1/auth/login')
          .send({
            email: userA.email,
            password: 'Password123!'
          })
          .expect(200);

        const { session_id } = res.body;

        const loginEvent = await SecurityEvent.findOne({
          where: {
            user_id: userA.id,
            session_id,
            event_type: 'login_success'
          },
          order: [['timestamp', 'DESC']]
        });

        expect(loginEvent).not.toBeNull();
        expect(loginEvent.metadata).toBeDefined();
        expect(loginEvent.metadata.travel_anomaly).toBeDefined();
      } finally {
        coordsSpy.mockRestore();
      }
    });
  });

  describe('5. Health Endpoint Compatibility', () => {
    test('GET /health continues to return healthy status', async () => {
      const res = await request(app)
        .get('/health')
        .expect(200);

      expect(res.body.status).toBe('ok');
    });
  });
});
