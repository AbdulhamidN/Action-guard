const crypto = require('crypto');
const { Server } = require('socket.io');
const eventBus = require('../events/eventBus');
const { verifyUserAndSessionToken } = require('../middleware/auth');
const sessionService = require('../services/sessionService');
const {
  buildUserRiskPayload,
  buildAdminRiskPayload,
  buildEventRecordedPayload
} = require('./payloads');

let ioInstance = null;
let revalidationInterval = null;
let unsubSessionTerminated = null;
let unsubPipelineProcessed = null;

/**
 * Initializes the Socket.IO server mounted on an HTTP server.
 *
 * @param {import('http').Server} httpServer
 * @param {object} [options={}]
 * @returns {Server}
 */
function initSocketServer(httpServer, options = {}) {
  const rawOrigins =
    options.corsOrigins ||
    process.env.CORS_ALLOWED_ORIGINS ||
    'http://localhost:3000,http://localhost:5173';

  if (typeof rawOrigins === 'string' && rawOrigins.includes('*')) {
    throw new Error('Wildcard CORS origin is not permitted');
  }

  const allowedOrigins = (typeof rawOrigins === 'string' ? rawOrigins.split(',') : rawOrigins)
    .map((o) => (typeof o === 'string' ? o.trim() : o))
    .filter(Boolean);

  if (allowedOrigins.some((o) => o === '*')) {
    throw new Error('Wildcard CORS origin is not permitted');
  }

  const io = new Server(httpServer, {
    cors: {
      origin: allowedOrigins,
      methods: ['GET', 'POST'],
      credentials: true
    },
    ...options.socketIoOptions
  });

  // Handshake authentication middleware
  io.use(async (socket, next) => {
    // 1. Reject credentials passed in query string
    if (socket.handshake.query && (socket.handshake.query.token !== undefined || socket.handshake.query.apiKey !== undefined)) {
      return next(new Error('unauthorized'));
    }

    const auth = socket.handshake.auth || {};

    // 2. Reject if both apiKey and token are supplied
    if (auth.apiKey !== undefined && auth.token !== undefined) {
      return next(new Error('unauthorized'));
    }

    // 3. Admin authentication path (auth.apiKey)
    if (auth.apiKey !== undefined) {
      const configuredAdminKey = process.env.ACTIONGUARD_ADMIN_API_KEY;

      if (!configuredAdminKey || typeof configuredAdminKey !== 'string' || configuredAdminKey.length < 32) {
        return next(new Error('unauthorized'));
      }

      if (typeof auth.apiKey !== 'string' || auth.apiKey.length === 0) {
        return next(new Error('unauthorized'));
      }

      const providedHash = crypto.createHash('sha256').update(String(auth.apiKey)).digest();
      const configuredHash = crypto.createHash('sha256').update(String(configuredAdminKey)).digest();

      if (!crypto.timingSafeEqual(providedHash, configuredHash)) {
        return next(new Error('unauthorized'));
      }

      // Valid admin key
      socket.data.isAdmin = true;
      socket.data.authType = 'apiKey';
      return next();
    }

    // 4. User authentication path (auth.token)
    if (!auth.token || typeof auth.token !== 'string') {
      return next(new Error('unauthorized'));
    }

    try {
      const result = await verifyUserAndSessionToken(auth.token);
      if (!result.user || !result.user.session_id || !result.session) {
        return next(new Error('invalid_session'));
      }
      socket.data.user = result.user;
      socket.data.session = result.session;
      socket.data.isAdmin = false;
      socket.data.authType = 'token';
      return next();
    } catch (err) {
      const code = (err && err.code) || 'unauthorized';
      const safeCode = ['unauthorized', 'token_expired', 'invalid_session'].includes(code)
        ? code
        : 'unauthorized';
      return next(new Error(safeCode));
    }
  });

  // Connection handler
  io.on('connection', (socket) => {
    if (socket.data.isAdmin) {
      socket.join('admin:stream');
    } else {
      if (socket.data.user && socket.data.user.id) {
        socket.join(`user:${socket.data.user.id}`);
      }
      if (socket.data.user && socket.data.user.session_id) {
        socket.join(`session:${socket.data.user.session_id}`);
      }

      // One-shot JWT expiry disconnect timer (unref'd)
      if (socket.data.user && socket.data.user.exp) {
        const remainingMs = socket.data.user.exp * 1000 - Date.now();
        const delay = Math.max(0, Math.min(remainingMs, 2147483647));
        const timer = setTimeout(() => {
          socket.disconnect(true);
        }, delay);
        if (typeof timer.unref === 'function') {
          timer.unref();
        }
        socket.data._jwtExpiryTimer = timer;

        socket.on('disconnect', () => {
          if (socket.data._jwtExpiryTimer) {
            clearTimeout(socket.data._jwtExpiryTimer);
            socket.data._jwtExpiryTimer = null;
          }
        });
      }
    }
  });

  // Global session revalidation interval
  const intervalSeconds = parseInt(
    options.revalidationIntervalSeconds ||
      process.env.SOCKET_SESSION_REVALIDATION_INTERVAL_SECONDS ||
      '30',
    10
  );
  const intervalMs = Math.max(1, intervalSeconds) * 1000;

  revalidationInterval = setInterval(async () => {
    if (!ioInstance) return;
    try {
      const sockets = await ioInstance.fetchSockets();
      let redisErrorLoggedThisTick = false;
      for (const s of sockets) {
        if (s.data && !s.data.isAdmin && s.data.user && s.data.user.session_id) {
          try {
            const activeSession = await sessionService.validateActiveSession(s.data.user.session_id, { touch: false });
            if (!activeSession) {
              s.disconnect(true);
            }
          } catch (err) {
            if (!redisErrorLoggedThisTick) {
              console.warn('[SocketServer] Session revalidation error during tick:', err.message);
              redisErrorLoggedThisTick = true;
            }
          }
        }
      }
    } catch (err) {
      console.warn('[SocketServer] Tick execution error:', err.message);
    }
  }, intervalMs);

  if (typeof revalidationInterval.unref === 'function') {
    revalidationInterval.unref();
  }

  // Clean up any previously attached listeners on eventBus
  if (typeof unsubSessionTerminated === 'function') {
    unsubSessionTerminated();
    unsubSessionTerminated = null;
  }
  if (typeof unsubPipelineProcessed === 'function') {
    unsubPipelineProcessed();
    unsubPipelineProcessed = null;
  }

  // 1. Subscribe to session:terminated event for immediate room disconnection
  const onSessionTerminated = (payload) => {
    try {
      if (!ioInstance || !payload || !payload.session_id) return;
      const room = `session:${payload.session_id}`;
      ioInstance.to(room).emit('session:terminated', {
        session_id: payload.session_id,
        reason: payload.reason || 'session_invalidated',
        terminated_at: payload.terminated_at || new Date().toISOString()
      });
      ioInstance.in(room).disconnectSockets(true);
    } catch (err) {
      console.warn('[SocketServer] Error handling session:terminated:', err.message);
    }
  };
  unsubSessionTerminated = eventBus.on('session:terminated', onSessionTerminated);

  // 2. Subscribe to pipeline:event_processed for live sanitized broadcasts
  const onPipelineEventProcessed = (data) => {
    try {
      if (!ioInstance || !data || !data.event) return;
      const { event, assessment } = data;
      const userId = event.user_id || event.userId;
      if (!userId) return;

      const userRoom = `user:${userId}`;
      const adminRoom = 'admin:stream';

      // (a) Emit event:recorded first
      try {
        const userEventPayload = buildEventRecordedPayload(event, assessment, { includeUserId: false });
        ioInstance.to(userRoom).emit('event:recorded', userEventPayload);
      } catch (err) {
        console.warn('[SocketServer] Error broadcasting user event:recorded:', err.message);
      }

      try {
        const adminEventPayload = buildEventRecordedPayload(event, assessment, { includeUserId: true });
        ioInstance.to(adminRoom).emit('event:recorded', adminEventPayload);
      } catch (err) {
        console.warn('[SocketServer] Error broadcasting admin event:recorded:', err.message);
      }

      // (b) Emit risk:updated second (only when assessment is non-null)
      if (assessment) {
        try {
          const userRiskPayload = buildUserRiskPayload(event, assessment);
          ioInstance.to(userRoom).emit('risk:updated', userRiskPayload);
        } catch (err) {
          console.warn('[SocketServer] Error broadcasting user risk:updated:', err.message);
        }

        try {
          const adminRiskPayload = buildAdminRiskPayload(event, assessment);
          ioInstance.to(adminRoom).emit('risk:updated', adminRiskPayload);
        } catch (err) {
          console.warn('[SocketServer] Error broadcasting admin risk:updated:', err.message);
        }
      }
    } catch (err) {
      console.warn('[SocketServer] Error handling pipeline:event_processed:', err.message);
    }
  };
  unsubPipelineProcessed = eventBus.on('pipeline:event_processed', onPipelineEventProcessed);

  ioInstance = io;
  return io;
}

/**
 * Returns the current active Socket.IO instance or null.
 *
 * @returns {Server|null}
 */
function getSocketServer() {
  return ioInstance;
}

/**
 * Gracefully and idempotently closes the Socket.IO server, disconnecting all sockets
 * and stopping all revalidation and token timers.
 *
 * @returns {Promise<void>}
 */
async function closeSocketServer() {
  if (revalidationInterval) {
    clearInterval(revalidationInterval);
    revalidationInterval = null;
  }

  if (typeof unsubSessionTerminated === 'function') {
    unsubSessionTerminated();
    unsubSessionTerminated = null;
  }

  if (typeof unsubPipelineProcessed === 'function') {
    unsubPipelineProcessed();
    unsubPipelineProcessed = null;
  }

  if (!ioInstance) {
    return;
  }

  const ioToClose = ioInstance;
  ioInstance = null;

  ioToClose.disconnectSockets(true);

  await new Promise((resolve) => {
    ioToClose.close(() => {
      resolve();
    });
  });
}

module.exports = {
  initSocketServer,
  getSocketServer,
  closeSocketServer
};
