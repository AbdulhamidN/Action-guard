const Redis = require('ioredis');
const RedisMock = require('ioredis-mock');

let redisClient;

function getRedisClient() {
  if (redisClient) {
    return redisClient;
  }

  const isTest = process.env.NODE_ENV === 'test';
  const useMock = process.env.USE_REDIS_MOCK === 'true' || isTest;

  if (useMock) {
    redisClient = new RedisMock();
  } else {
    const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
    redisClient = new Redis(redisUrl, {
      maxRetriesPerRequest: 3,
      enableReadyCheck: true,
      lazyConnect: true
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
