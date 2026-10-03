const Redis = require('ioredis');

/**
 * Built-in in-memory client used exclusively for test isolation
 * without introducing unapproved third-party packages.
 */
class InMemoryRedisClient {
  constructor() {
    this.store = new Map();
  }

  async set(key, value, mode, duration) {
    let expiresAt = null;
    if (mode === 'EX' && duration) {
      expiresAt = Date.now() + duration * 1000;
    } else if (mode === 'PX' && duration) {
      expiresAt = Date.now() + duration;
    }
    this.store.set(key, { value, expiresAt });
    return 'OK';
  }

  async get(key) {
    const item = this.store.get(key);
    if (!item) return null;
    if (item.expiresAt && Date.now() > item.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return item.value;
  }

  async del(key) {
    const exists = this.store.has(key);
    this.store.delete(key);
    return exists ? 1 : 0;
  }

  async ttl(key) {
    const item = this.store.get(key);
    if (!item) return -2;
    if (!item.expiresAt) return -1;
    const remainingMs = item.expiresAt - Date.now();
    if (remainingMs <= 0) {
      this.store.delete(key);
      return -2;
    }
    return Math.ceil(remainingMs / 1000);
  }

  on() {
    return this;
  }

  async quit() {
    this.store.clear();
    return 'OK';
  }

  disconnect() {
    this.store.clear();
  }
}

let redisClient;

function getRedisClient() {
  if (redisClient) {
    return redisClient;
  }

  const isTest = process.env.NODE_ENV === 'test';
  const useMock = process.env.USE_REDIS_MOCK === 'true' || (isTest && process.env.USE_REAL_REDIS !== 'true');

  if (useMock) {
    redisClient = new InMemoryRedisClient();
  } else {
    const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
    redisClient = new Redis(redisUrl, {
      maxRetriesPerRequest: 3,
      enableReadyCheck: true,
      lazyConnect: true,
      retryStrategy: (times) => Math.min(times * 200, 3000)
    });

    redisClient.on('error', (err) => {
      console.error('Redis connection error:', err);
    });
  }

  return redisClient;
}

const SESSION_PREFIX = 'session:';

async function storeSession(sessionId, data, ttlSeconds) {
  const client = getRedisClient();
  const key = `${SESSION_PREFIX}${sessionId}`;
  const payload = JSON.stringify(data);
  if (ttlSeconds && ttlSeconds > 0) {
    await client.set(key, payload, 'EX', ttlSeconds);
  } else {
    await client.set(key, payload);
  }
}

async function getSession(sessionId) {
  const client = getRedisClient();
  const key = `${SESSION_PREFIX}${sessionId}`;
  const raw = await client.get(key);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function deleteSession(sessionId) {
  const client = getRedisClient();
  const key = `${SESSION_PREFIX}${sessionId}`;
  await client.del(key);
}

async function getSessionTTL(sessionId) {
  const client = getRedisClient();
  const key = `${SESSION_PREFIX}${sessionId}`;
  return client.ttl(key);
}

module.exports = {
  getRedisClient,
  storeSession,
  getSession,
  deleteSession,
  getSessionTTL,
  SESSION_PREFIX
};
