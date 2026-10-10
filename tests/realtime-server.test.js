const http = require('http');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const request = require('supertest');
const { io: ioClient } = require('socket.io-client');

const app = require('../src/app');
const {
  sequelize,
  User,
  Session,
  Device,
  SecurityEvent
} = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const {
  createSession,
  invalidateSession,
  DEFAULT_SESSION_TTL_SECONDS
} = require('../src/services/sessionService');
const { deleteSession } = require('../src/storage/redis');
const eventBus = require('../src/events/eventBus');
const {
  initSocketServer,
  getSocketServer,
  closeSocketServer
} = require('../src/realtime/socketServer');
const {
  verifyUserAndSessionToken,
  JWT_SECRET
} = require('../src/middleware/auth');
const sessionService = require('../src/services/sessionService');

// Valid 32-character test admin API key
const TEST_ADMIN_KEY_VALID = 'admin_secret_key_with_at_least_32_characters_12345';
const TEST_ADMIN_KEY_31_CHARS = '1234567890123456789012345678901'; // 31 chars

async function waitForCondition(predicate, timeoutMs = 3000, intervalMs = 25) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await predicate()) return true;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return false;
}

function createClient(port, options = {}) {
  return ioClient(`http://localhost:${port}`, {
    transports: ['websocket'],
    autoConnect: false,
    reconnection: false,
    ...options
  });
}

function connectClient(client) {
  return new Promise((resolve, reject) => {
    client.on('connect', () => resolve(client));
    client.on('connect_error', (err) => reject(err));
    client.connect();
  });
}

describe('Module 7.1 — Server Foundation, Handshake Auth & Session Revocation', () => {
  let httpServer;
  let serverPort;
  let userA;
  let userB;
  let sessionA1;
  let sessionA2;
  let sessionB;
  let tokenA1;
  let tokenA2;
  let tokenB;
  const activeClients = [];

  const originalAdminKey = process.env.ACTIONGUARD_ADMIN_API_KEY;
  const originalRevalInterval = process.env.SOCKET_SESSION_REVALIDATION_INTERVAL_SECONDS;

  beforeAll(async () => {
    await runMigrations();

    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    const passwordHash = await bcrypt.hash('Secret123!', 10);

    userA = await User.create({
      email: 'user-a-71@example.com',
      password_hash: passwordHash
    });

    userB = await User.create({
      email: 'user-b-71@example.com',
      password_hash: passwordHash
    });

    sessionA1 = await createSession(userA.id, userA.email);
    sessionA2 = await createSession(userA.id, userA.email);
    sessionB = await createSession(userB.id, userB.email);

    tokenA1 = jwt.sign(
      { id: userA.id, email: userA.email, session_id: sessionA1.sessionId },
      JWT_SECRET,
      { expiresIn: '900s' }
    );

    tokenA2 = jwt.sign(
      { id: userA.id, email: userA.email, session_id: sessionA2.sessionId },
      JWT_SECRET,
      { expiresIn: '900s' }
    );

    tokenB = jwt.sign(
      { id: userB.id, email: userB.email, session_id: sessionB.sessionId },
      JWT_SECRET,
      { expiresIn: '900s' }
    );
  });

  afterAll(async () => {
    process.env.ACTIONGUARD_ADMIN_API_KEY = originalAdminKey;
    process.env.SOCKET_SESSION_REVALIDATION_INTERVAL_SECONDS = originalRevalInterval;
  });

  beforeEach(async () => {
    process.env.ACTIONGUARD_ADMIN_API_KEY = TEST_ADMIN_KEY_VALID;

    httpServer = http.createServer(app);
    await new Promise((resolve) => {
      httpServer.listen(0, () => {
        serverPort = httpServer.address().port;
        resolve();
      });
    });

    initSocketServer(httpServer, {
      revalidationIntervalSeconds: 30
    });
  });

  afterEach(async () => {
    while (activeClients.length > 0) {
      const c = activeClients.pop();
      if (c && c.connected) {
        c.disconnect();
      }
    }

    await closeSocketServer();

    if (httpServer && httpServer.listening) {
      await new Promise((resolve) => httpServer.close(resolve));
    }

    eventBus.removeAllListeners();
    jest.restoreAllMocks();
  });

  describe('Handshake Authentication (User Path)', () => {
    test('valid user connects successfully and receives identity in socket.data', async () => {
      const client = createClient(serverPort, {
        auth: { token: tokenA1 }
      });
      activeClients.push(client);

      await connectClient(client);
      expect(client.connected).toBe(true);

      const io = getSocketServer();
      const serverSocket = io.sockets.sockets.get(client.id);
      expect(serverSocket).toBeDefined();
      expect(serverSocket.data.isAdmin).toBe(false);
      expect(serverSocket.data.user.id).toBe(userA.id);
      expect(serverSocket.data.session.session_id).toBe(sessionA1.sessionId);
    });

    test('missing token is rejected with unauthorized', async () => {
      const client = createClient(serverPort, {
        auth: {}
      });
      activeClients.push(client);

      await expect(connectClient(client)).rejects.toMatchObject({
        message: 'unauthorized'
      });
      expect(client.connected).toBe(false);
    });

    test('malformed token is rejected with unauthorized', async () => {
      const client = createClient(serverPort, {
        auth: { token: 'malformed.token.payload' }
      });
      activeClients.push(client);

      await expect(connectClient(client)).rejects.toMatchObject({
        message: 'unauthorized'
      });
      expect(client.connected).toBe(false);
    });

    test('expired JWT is rejected with token_expired', async () => {
      const expiredToken = jwt.sign(
        { id: userA.id, email: userA.email, session_id: sessionA1.sessionId },
        JWT_SECRET,
        { expiresIn: '-10s' }
      );

      const client = createClient(serverPort, {
        auth: { token: expiredToken }
      });
      activeClients.push(client);

      await expect(connectClient(client)).rejects.toMatchObject({
        message: 'token_expired'
      });
      expect(client.connected).toBe(false);
    });

    test('wrong-signature JWT is rejected with unauthorized', async () => {
      const badSigToken = jwt.sign(
        { id: userA.id, email: userA.email, session_id: sessionA1.sessionId },
        'completely_wrong_signature_secret_12345'
      );

      const client = createClient(serverPort, {
        auth: { token: badSigToken }
      });
      activeClients.push(client);

      await expect(connectClient(client)).rejects.toMatchObject({
        message: 'unauthorized'
      });
      expect(client.connected).toBe(false);
    });

    test('revoked or expired Redis session is rejected with invalid_session', async () => {
      const orphanSessionId = 'sess_nonexistent_or_expired_12345';
      const tokenWithOrphanSession = jwt.sign(
        { id: userA.id, email: userA.email, session_id: orphanSessionId },
        JWT_SECRET,
        { expiresIn: '900s' }
      );

      const client = createClient(serverPort, {
        auth: { token: tokenWithOrphanSession }
      });
      activeClients.push(client);

      await expect(connectClient(client)).rejects.toMatchObject({
        message: 'invalid_session'
      });
      expect(client.connected).toBe(false);
    });

    test('token without session_id is rejected with invalid_session', async () => {
      const tokenWithoutSession = jwt.sign(
        { id: userA.id, email: userA.email },
        JWT_SECRET,
        { expiresIn: '900s' }
      );

      const client = createClient(serverPort, {
        auth: { token: tokenWithoutSession }
      });
      activeClients.push(client);

      await expect(connectClient(client)).rejects.toMatchObject({
        message: 'invalid_session'
      });
      expect(client.connected).toBe(false);
    });

    test('JWT that expires mid-connection disconnects the socket', async () => {
      // 1-second short-lived token
      const shortToken = jwt.sign(
        { id: userA.id, email: userA.email, session_id: sessionA1.sessionId },
        JWT_SECRET,
        { expiresIn: '1s' }
      );

      const client = createClient(serverPort, {
        auth: { token: shortToken }
      });
      activeClients.push(client);

      await connectClient(client);
      expect(client.connected).toBe(true);

      let disconnected = false;
      client.on('disconnect', () => {
        disconnected = true;
      });

      const didDisconnect = await waitForCondition(() => disconnected, 3000);
      expect(didDisconnect).toBe(true);
      expect(client.connected).toBe(false);
    });
  });

  describe('Admin Handshake Authentication', () => {
    test('valid admin key connects and is in admin:stream only', async () => {
      const client = createClient(serverPort, {
        auth: { apiKey: TEST_ADMIN_KEY_VALID }
      });
      activeClients.push(client);

      await connectClient(client);
      expect(client.connected).toBe(true);

      const io = getSocketServer();
      const serverSocket = io.sockets.sockets.get(client.id);
      expect(serverSocket.data.isAdmin).toBe(true);
      expect(serverSocket.rooms.has('admin:stream')).toBe(true);

      // Verify no user or session rooms
      const otherRooms = Array.from(serverSocket.rooms).filter(
        (r) => r.startsWith('user:') || r.startsWith('session:')
      );
      expect(otherRooms).toHaveLength(0);
    });

    test('unset admin key disables admin connections and rejects with unauthorized', async () => {
      delete process.env.ACTIONGUARD_ADMIN_API_KEY;

      const client = createClient(serverPort, {
        auth: { apiKey: TEST_ADMIN_KEY_VALID }
      });
      activeClients.push(client);

      await expect(connectClient(client)).rejects.toMatchObject({
        message: 'unauthorized'
      });
    });

    test('empty admin key rejects with unauthorized', async () => {
      const client = createClient(serverPort, {
        auth: { apiKey: '' }
      });
      activeClients.push(client);

      await expect(connectClient(client)).rejects.toMatchObject({
        message: 'unauthorized'
      });
    });

    test('a 31-character admin key is rejected (< 32 characters requirement)', async () => {
      process.env.ACTIONGUARD_ADMIN_API_KEY = TEST_ADMIN_KEY_31_CHARS;

      const client = createClient(serverPort, {
        auth: { apiKey: TEST_ADMIN_KEY_31_CHARS }
      });
      activeClients.push(client);

      await expect(connectClient(client)).rejects.toMatchObject({
        message: 'unauthorized'
      });
    });

    test('wrong admin key is rejected with unauthorized with no token fallback', async () => {
      const client = createClient(serverPort, {
        auth: { apiKey: 'wrong_key_that_is_at_least_32_characters_long_000000' }
      });
      activeClients.push(client);

      await expect(connectClient(client)).rejects.toMatchObject({
        message: 'unauthorized'
      });
    });

    test('key passed in handshake query string is rejected with unauthorized', async () => {
      const client = createClient(serverPort, {
        query: { apiKey: TEST_ADMIN_KEY_VALID }
      });
      activeClients.push(client);

      await expect(connectClient(client)).rejects.toMatchObject({
        message: 'unauthorized'
      });
    });

    test('token passed in handshake query string is rejected with unauthorized', async () => {
      const client = createClient(serverPort, {
        query: { token: tokenA1 }
      });
      activeClients.push(client);

      await expect(connectClient(client)).rejects.toMatchObject({
        message: 'unauthorized'
      });
    });

    test('both apiKey and token supplied is rejected with unauthorized', async () => {
      const client = createClient(serverPort, {
        auth: {
          apiKey: TEST_ADMIN_KEY_VALID,
          token: tokenA1
        }
      });
      activeClients.push(client);

      await expect(connectClient(client)).rejects.toMatchObject({
        message: 'unauthorized'
      });
    });
  });

  describe('Room Isolation & Server-Managed Boundaries', () => {
    test("user B's socket never receives a message sent to user A's user or session room", async () => {
      const clientA = createClient(serverPort, { auth: { token: tokenA1 } });
      const clientB = createClient(serverPort, { auth: { token: tokenB } });
      activeClients.push(clientA, clientB);

      await connectClient(clientA);
      await connectClient(clientB);

      let clientAReceived = false;
      let clientBReceived = false;

      clientA.on('test:alert', () => { clientAReceived = true; });
      clientB.on('test:alert', () => { clientBReceived = true; });

      const io = getSocketServer();
      io.to(`user:${userA.id}`).emit('test:alert', { target: 'userA' });
      io.to(`session:${sessionA1.sessionId}`).emit('test:alert', { target: 'sessionA1' });

      await waitForCondition(() => clientAReceived, 1000);

      expect(clientAReceived).toBe(true);
      expect(clientBReceived).toBe(false);
    });

    test('a client emitting join or subscribe events gains no rooms', async () => {
      const client = createClient(serverPort, { auth: { token: tokenA1 } });
      activeClients.push(client);
      await connectClient(client);

      const io = getSocketServer();
      const serverSocket = io.sockets.sockets.get(client.id);

      client.emit('join', 'admin:stream');
      client.emit('subscribe', `user:${userB.id}`);

      // Allow event loop to process any unhandled packets
      await new Promise((r) => setTimeout(r, 100));

      expect(serverSocket.rooms.has('admin:stream')).toBe(false);
      expect(serverSocket.rooms.has(`user:${userB.id}`)).toBe(false);
    });

    test('two sessions of one user are in distinct session rooms and shared user room', async () => {
      const clientA1 = createClient(serverPort, { auth: { token: tokenA1 } });
      const clientA2 = createClient(serverPort, { auth: { token: tokenA2 } });
      activeClients.push(clientA1, clientA2);

      await connectClient(clientA1);
      await connectClient(clientA2);

      const io = getSocketServer();
      const sock1 = io.sockets.sockets.get(clientA1.id);
      const sock2 = io.sockets.sockets.get(clientA2.id);

      // Shared user room
      expect(sock1.rooms.has(`user:${userA.id}`)).toBe(true);
      expect(sock2.rooms.has(`user:${userA.id}`)).toBe(true);

      // Distinct session rooms
      expect(sock1.rooms.has(`session:${sessionA1.sessionId}`)).toBe(true);
      expect(sock1.rooms.has(`session:${sessionA2.sessionId}`)).toBe(false);

      expect(sock2.rooms.has(`session:${sessionA2.sessionId}`)).toBe(true);
      expect(sock2.rooms.has(`session:${sessionA1.sessionId}`)).toBe(false);
    });
  });

  describe('Session Revocation & Revalidation', () => {
    test("invalidateSession on session A disconnects A's socket, not the same user's session B socket", async () => {
      const clientA1 = createClient(serverPort, { auth: { token: tokenA1 } });
      const clientA2 = createClient(serverPort, { auth: { token: tokenA2 } });
      activeClients.push(clientA1, clientA2);

      await connectClient(clientA1);
      await connectClient(clientA2);

      let a1TerminatedPayload = null;
      let a1Disconnected = false;
      let a2Disconnected = false;

      clientA1.on('session:terminated', (data) => {
        a1TerminatedPayload = data;
      });
      clientA1.on('disconnect', () => {
        a1Disconnected = true;
      });
      clientA2.on('disconnect', () => {
        a2Disconnected = true;
      });

      // Revoke session A1
      await invalidateSession(sessionA1.sessionId);

      const didDisconnectA1 = await waitForCondition(() => a1Disconnected, 2000);

      expect(didDisconnectA1).toBe(true);
      expect(clientA1.connected).toBe(false);
      expect(a1TerminatedPayload).toBeDefined();
      expect(a1TerminatedPayload.session_id).toBe(sessionA1.sessionId);
      expect(a1TerminatedPayload.reason).toBe('session_invalidated');
      expect(a1TerminatedPayload.user_id).toBeUndefined(); // Must not leak user_id

      // Session A2 remains connected
      expect(a2Disconnected).toBe(false);
      expect(clientA2.connected).toBe(true);
    });

    test('the logout route calls invalidateSession and disconnects the client', async () => {
      // Create new session specifically for logout route test
      const tempSession = await createSession(userA.id, userA.email);
      const tempToken = jwt.sign(
        { id: userA.id, email: userA.email, session_id: tempSession.sessionId },
        JWT_SECRET,
        { expiresIn: '900s' }
      );

      const client = createClient(serverPort, { auth: { token: tempToken } });
      activeClients.push(client);
      await connectClient(client);

      let disconnected = false;
      client.on('disconnect', () => {
        disconnected = true;
      });

      // Call POST /api/v1/auth/logout with token
      const res = await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${tempToken}`)
        .send();

      expect(res.status).toBe(200);

      const didDisconnect = await waitForCondition(() => disconnected, 2000);
      expect(didDisconnect).toBe(true);
      expect(client.connected).toBe(false);
    });

    test('the client receives session:terminated before the disconnect event', async () => {
      const tempSession = await createSession(userA.id, userA.email);
      const tempToken = jwt.sign(
        { id: userA.id, email: userA.email, session_id: tempSession.sessionId },
        JWT_SECRET,
        { expiresIn: '900s' }
      );

      const client = createClient(serverPort, { auth: { token: tempToken } });
      activeClients.push(client);
      await connectClient(client);

      const eventOrder = [];
      client.on('session:terminated', () => {
        eventOrder.push('session:terminated');
      });
      client.on('disconnect', () => {
        eventOrder.push('disconnect');
      });

      await invalidateSession(tempSession.sessionId);

      await waitForCondition(() => eventOrder.includes('disconnect'), 2000);

      expect(eventOrder).toEqual(['session:terminated', 'disconnect']);
    });

    test('deleting Redis session key causes disconnection on the next revalidation tick', async () => {
      // Re-init socket server with 1-second revalidation interval on a fresh HTTP server
      await closeSocketServer();
      httpServer = http.createServer(app);
      await new Promise((resolve) => {
        httpServer.listen(0, () => {
          serverPort = httpServer.address().port;
          resolve();
        });
      });

      initSocketServer(httpServer, {
        revalidationIntervalSeconds: 1
      });

      const tempSession = await createSession(userA.id, userA.email);
      const tempToken = jwt.sign(
        { id: userA.id, email: userA.email, session_id: tempSession.sessionId },
        JWT_SECRET,
        { expiresIn: '900s' }
      );

      const client = createClient(serverPort, { auth: { token: tempToken } });
      activeClients.push(client);
      await connectClient(client);
      expect(client.connected).toBe(true);

      let disconnected = false;
      client.on('disconnect', () => {
        disconnected = true;
      });

      // Delete Redis session directly (simulating TTL expiry or Redis flush)
      await deleteSession(tempSession.sessionId);

      // Wait for tick (runs every 1 second)
      const didDisconnect = await waitForCondition(() => disconnected, 3000);
      expect(didDisconnect).toBe(true);
      expect(client.connected).toBe(false);
    });

    test('a Redis error on a revalidation tick leaves sockets connected and logs warning', async () => {
      await closeSocketServer();
      httpServer = http.createServer(app);
      await new Promise((resolve) => {
        httpServer.listen(0, () => {
          serverPort = httpServer.address().port;
          resolve();
        });
      });

      initSocketServer(httpServer, {
        revalidationIntervalSeconds: 1
      });

      const tempSession = await createSession(userA.id, userA.email);
      const tempToken = jwt.sign(
        { id: userA.id, email: userA.email, session_id: tempSession.sessionId },
        JWT_SECRET,
        { expiresIn: '900s' }
      );

      const client = createClient(serverPort, { auth: { token: tempToken } });
      activeClients.push(client);
      await connectClient(client);

      // Mock validateActiveSession to reject simulating Redis failure
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      jest.spyOn(sessionService, 'validateActiveSession').mockRejectedValue(new Error('Redis connection refused'));

      let disconnected = false;
      client.on('disconnect', () => {
        disconnected = true;
      });

      // Wait 1.5 seconds for at least one tick to execute
      await new Promise((r) => setTimeout(r, 1500));

      expect(disconnected).toBe(false);
      expect(client.connected).toBe(true);
      expect(warnSpy).toHaveBeenCalled();
    });
  });

  describe('EventBus Isolation & Non-Throwing Invariants', () => {
    test('a throwing listener never propagates through safeEmit', () => {
      eventBus.on('test:throwing:event', () => {
        throw new Error('Explosive listener failure');
      });

      const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

      expect(() => {
        eventBus.safeEmit('test:throwing:event', { data: 123 });
      }).not.toThrow();

      expect(warnSpy).toHaveBeenCalled();
    });

    test('invalidateSession behaves identically with a throwing listener attached', async () => {
      const tempSession = await createSession(userA.id, userA.email);

      eventBus.on('session:terminated', () => {
        throw new Error('Malicious listener failure in session:terminated');
      });

      const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

      const result = await invalidateSession(tempSession.sessionId);
      expect(result).toBe(true);
      expect(warnSpy).toHaveBeenCalled();
    });
  });

  describe('Shared Verification Parity with Express Middleware', () => {
    test('parity: missing token produces identical rejection code', async () => {
      // Helper directly
      await expect(verifyUserAndSessionToken(undefined)).rejects.toMatchObject({
        code: 'unauthorized'
      });

      // Express middleware via HTTP
      const res = await request(app).get('/api/v1/me');
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('unauthorized');
    });

    test('parity: malformed token produces identical rejection code', async () => {
      await expect(verifyUserAndSessionToken('bad-token-xyz')).rejects.toMatchObject({
        code: 'unauthorized'
      });

      const res = await request(app)
        .get('/api/v1/me')
        .set('Authorization', 'Bearer bad-token-xyz');
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('unauthorized');
    });

    test('parity: expired token produces identical rejection code', async () => {
      const expiredToken = jwt.sign(
        { id: userA.id, email: userA.email, session_id: sessionA1.sessionId },
        JWT_SECRET,
        { expiresIn: '-10s' }
      );

      await expect(verifyUserAndSessionToken(expiredToken)).rejects.toMatchObject({
        code: 'token_expired'
      });

      const res = await request(app)
        .get('/api/v1/me')
        .set('Authorization', `Bearer ${expiredToken}`);
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('token_expired');
    });

    test('parity: wrong signature produces identical rejection code', async () => {
      const wrongSigToken = jwt.sign(
        { id: userA.id, email: userA.email, session_id: sessionA1.sessionId },
        'other_secret_key'
      );

      await expect(verifyUserAndSessionToken(wrongSigToken)).rejects.toMatchObject({
        code: 'unauthorized'
      });

      const res = await request(app)
        .get('/api/v1/me')
        .set('Authorization', `Bearer ${wrongSigToken}`);
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('unauthorized');
    });

    test('parity: invalid/missing Redis session produces identical rejection code', async () => {
      const orphanToken = jwt.sign(
        { id: userA.id, email: userA.email, session_id: 'sess_missing_12345' },
        JWT_SECRET,
        { expiresIn: '900s' }
      );

      await expect(verifyUserAndSessionToken(orphanToken)).rejects.toMatchObject({
        code: 'invalid_session'
      });

      const res = await request(app)
        .get('/api/v1/me')
        .set('Authorization', `Bearer ${orphanToken}`);
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('invalid_session');
    });
  });

  describe('Configuration & Lifecycle Invariants', () => {
    test('a wildcard CORS value throws at init', () => {
      const dummyServer = http.createServer();
      expect(() => {
        initSocketServer(dummyServer, { corsOrigins: '*' });
      }).toThrow('Wildcard CORS origin is not permitted');

      expect(() => {
        initSocketServer(dummyServer, { corsOrigins: 'http://localhost:3000,*' });
      }).toThrow('Wildcard CORS origin is not permitted');
    });

    test('closeSocketServer is idempotent and clears the interval cleanly', async () => {
      expect(getSocketServer()).toBeDefined();

      await closeSocketServer();
      expect(getSocketServer()).toBeNull();

      // Calling again should resolve with no error
      await expect(closeSocketServer()).resolves.toBeUndefined();
    });

    test('after two init/close cycles, one invalidateSession produces exactly one session:terminated delivery', async () => {
      // Cycle 1
      await closeSocketServer();
      httpServer = http.createServer(app);
      await new Promise((r) => httpServer.listen(0, r));
      initSocketServer(httpServer, { revalidationIntervalSeconds: 30 });

      // Cycle 2
      await closeSocketServer();
      httpServer = http.createServer(app);
      await new Promise((r) => httpServer.listen(0, r));
      serverPort = httpServer.address().port;
      initSocketServer(httpServer, { revalidationIntervalSeconds: 30 });

      const tempSession = await createSession(userA.id, userA.email);
      const tempToken = jwt.sign(
        { id: userA.id, email: userA.email, session_id: tempSession.sessionId },
        JWT_SECRET,
        { expiresIn: '900s' }
      );

      const client = createClient(serverPort, { auth: { token: tempToken } });
      activeClients.push(client);
      await connectClient(client);

      let terminationCount = 0;
      client.on('session:terminated', () => {
        terminationCount++;
      });

      await invalidateSession(tempSession.sessionId);

      await waitForCondition(() => !client.connected, 2000);

      expect(terminationCount).toBe(1);
    });
  });
});
