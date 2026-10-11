const Redis = require('ioredis');

/**
 * Built-in in-memory client used exclusively for test isolation
 * without introducing unapproved third-party packages.
 */
class InMemoryRedisClient {
  constructor() {
    this.store = new Map();
  }

  _setSync(key, value, mode, duration, flag) {
    if (flag === 'NX' && this.store.has(key)) {
      const item = this.store.get(key);
      if (!item.expiresAt || Date.now() <= item.expiresAt) {
        return null;
      }
      this.store.delete(key);
    }

    let expiresAt = null;
    if (mode === 'EX' && duration) {
      expiresAt = Date.now() + duration * 1000;
    } else if (mode === 'PX' && duration) {
      expiresAt = Date.now() + duration;
    }
    this.store.set(key, { value, expiresAt });
    return 'OK';
  }

  _getSync(key) {
    const item = this.store.get(key);
    if (!item) return null;
    if (item.expiresAt && Date.now() > item.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return item.value;
  }

  _delSync(key) {
    const exists = this.store.has(key);
    this.store.delete(key);
    return exists ? 1 : 0;
  }

  _ttlSync(key) {
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

  _expireSync(key, seconds) {
    const item = this.store.get(key);
    if (!item) return 0;
    if (item.expiresAt && Date.now() > item.expiresAt) {
      this.store.delete(key);
      return 0;
    }
    item.expiresAt = Date.now() + seconds * 1000;
    return 1;
  }

  _saddSync(key, ...members) {
    const item = this.store.get(key);
    let setInstance;
    let existingExpiresAt = null;
    if (!item || !(item.value instanceof Set)) {
      setInstance = new Set();
      this.store.set(key, { value: setInstance, expiresAt: null });
    } else {
      if (item.expiresAt && Date.now() > item.expiresAt) {
        setInstance = new Set();
        this.store.set(key, { value: setInstance, expiresAt: null });
      } else {
        setInstance = item.value;
        existingExpiresAt = item.expiresAt;
      }
    }

    let addedCount = 0;
    for (const m of members) {
      if (!setInstance.has(m)) {
        setInstance.add(m);
        addedCount++;
      }
    }
    if (existingExpiresAt) {
      this.store.get(key).expiresAt = existingExpiresAt;
    }
    return addedCount;
  }

  _sremSync(key, ...members) {
    const item = this.store.get(key);
    if (!item || !(item.value instanceof Set)) return 0;
    if (item.expiresAt && Date.now() > item.expiresAt) {
      this.store.delete(key);
      return 0;
    }
    let removedCount = 0;
    for (const m of members) {
      if (item.value.delete(m)) {
        removedCount++;
      }
    }
    return removedCount;
  }

  _smembersSync(key) {
    const item = this.store.get(key);
    if (!item || !(item.value instanceof Set)) return [];
    if (item.expiresAt && Date.now() > item.expiresAt) {
      this.store.delete(key);
      return [];
    }
    return Array.from(item.value);
  }

  async set(key, value, mode, duration, flag) {
    return this._setSync(key, value, mode, duration, flag);
  }

  async get(key) {
    return this._getSync(key);
  }

  async del(key) {
    return this._delSync(key);
  }

  async ttl(key) {
    return this._ttlSync(key);
  }

  async expire(key, seconds) {
    return this._expireSync(key, seconds);
  }

  async sadd(key, ...members) {
    return this._saddSync(key, ...members);
  }

  async srem(key, ...members) {
    return this._sremSync(key, ...members);
  }

  async smembers(key) {
    return this._smembersSync(key);
  }

  async sismember(key, member) {
    const item = this.store.get(key);
    if (!item || !(item.value instanceof Set)) return 0;
    if (item.expiresAt && Date.now() > item.expiresAt) {
      this.store.delete(key);
      return 0;
    }
    return item.value.has(member) ? 1 : 0;
  }

  async eval(script, numkeys, ...args) {
    const keys = args.slice(0, numkeys);
    const argv = args.slice(numkeys);

    if (script.includes('-- ATOMIC_VALIDATE_AND_TOUCH')) {
      const sessionKey = keys[0];
      const nowMs = Number(argv[0]);
      const defaultIdleWindowSec = Number(argv[1]);
      const throttleSec = Number(argv[2]);

      const raw = this._getSync(sessionKey);
      if (!raw) {
        return [-1, 'EXPIRED_OR_NOT_FOUND', 0, ''];
      }

      let session;
      try {
        session = JSON.parse(raw);
      } catch {
        this._delSync(sessionKey);
        return [-1, 'EXPIRED_OR_NOT_FOUND', 0, ''];
      }

      if (!session.is_active) {
        this._delSync(sessionKey);
        return [-1, 'EXPIRED_OR_NOT_FOUND', 0, ''];
      }

      const maxExpiresAt = Number(session.max_expires_at);
      if (nowMs >= maxExpiresAt) {
        this._delSync(sessionKey);
        return [-2, 'MAX_LIFETIME_EXCEEDED', 0, ''];
      }

      const remainingMaxSec = Math.floor((maxExpiresAt - nowMs) / 1000);
      if (remainingMaxSec <= 0) {
        this._delSync(sessionKey);
        return [-2, 'MAX_LIFETIME_EXCEEDED', 0, ''];
      }

      const sessionIdleWindowSec = Number(session.idle_timeout_seconds) > 0
        ? Number(session.idle_timeout_seconds)
        : defaultIdleWindowSec;

      const lastRenewed = Number(session.last_renewed_at || 0);
      const timeSinceRenew = Math.floor((nowMs - lastRenewed) / 1000);

      if (timeSinceRenew >= throttleSec) {
        const newTtl = Math.min(sessionIdleWindowSec, remainingMaxSec);
        session.last_renewed_at = nowMs;
        session.expires_at = new Date(nowMs + newTtl * 1000).toISOString();
        const updatedJson = JSON.stringify(session);
        this._setSync(sessionKey, updatedJson, 'EX', newTtl);
        return [1, 'RENEWED', newTtl, updatedJson];
      } else {
        return [0, 'VALID', 0, raw];
      }
    }

    if (script.includes('-- ATOMIC_GRANT_ELEVATION')) {
      const sessionKey = keys[0];
      const claimKey = keys[1];
      const indexKey = keys[2];
      const elevationKey = keys[3];

      const nowMs = Number(argv[0]);
      const expectedUserId = String(argv[1]);
      const claimTtlSec = Number(argv[2]);
      const scope = argv[3];
      const payloadJson = argv[4];
      const elevationTtlSec = Number(argv[5]);
      const indexTtlSec = Number(argv[6]);

      // 1. Verify parent session exists and is within absolute lifetime BEFORE claiming ticket
      const rawSession = this._getSync(sessionKey);
      if (!rawSession) {
        return [-1, 'SESSION_EXPIRED'];
      }

      let parentSession;
      try {
        parentSession = JSON.parse(rawSession);
      } catch {
        return [-1, 'SESSION_EXPIRED'];
      }

      if (!parentSession || !parentSession.is_active) {
        return [-1, 'SESSION_EXPIRED'];
      }

      if (String(parentSession.user_id) !== expectedUserId) {
        return [-3, 'SESSION_USER_MISMATCH'];
      }

      const maxExpiresAt = Number(parentSession.max_expires_at);
      if (Number.isFinite(maxExpiresAt) && maxExpiresAt > 0) {
        if (nowMs >= maxExpiresAt || Math.floor((maxExpiresAt - nowMs) / 1000) <= 0) {
          return [-2, 'SESSION_MAX_LIFETIME_EXCEEDED'];
        }
      }

      // 2. Claim single-use ticket atomically
      const claimRes = this._setSync(claimKey, '1', 'EX', claimTtlSec, 'NX');
      if (!claimRes) {
        return [0, 'TICKET_ALREADY_USED'];
      }

      // 3. Update session elevation Set index and write elevation key
      this._saddSync(indexKey, scope);
      const currentIdxTtl = this._ttlSync(indexKey);
      const nextIdxTtl = Math.max(currentIdxTtl > 0 ? currentIdxTtl : 0, indexTtlSec);
      this._expireSync(indexKey, nextIdxTtl);
      this._setSync(elevationKey, payloadJson, 'EX', elevationTtlSec);

      return [1, 'GRANTED'];
    }

    if (script.includes('-- ATOMIC_REVOKE_SESSION_ELEVATIONS')) {
      const setKey = keys[0];
      const elevationPrefix = argv[0];
      const sessionId = argv[1];

      const members = this._smembersSync(setKey);
      let deletedCount = 0;
      for (const scope of members) {
        const elevKey = `${elevationPrefix}${sessionId}:${scope}`;
        const delRes = this._delSync(elevKey);
        if (delRes) deletedCount++;
      }
      this._delSync(setKey);
      return deletedCount;
    }

    throw new Error('Unsupported Lua script in InMemoryRedisClient mock');
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

// Lua Script Definitions
const VALIDATE_AND_TOUCH_LUA = `
-- ATOMIC_VALIDATE_AND_TOUCH
-- KEYS[1]: session:<sessionId>
-- ARGV[1]: now_ms
-- ARGV[2]: default_idle_window_sec
-- ARGV[3]: throttle_sec
-- Returns table: { code, status_str, new_ttl, session_json }

local function msToIso8601(ms)
    local totalSec = math.floor(ms / 1000)
    local millis = ms % 1000
    local days = math.floor(totalSec / 86400)
    local remSec = totalSec % 86400
    local hour = math.floor(remSec / 3600)
    remSec = remSec % 3600
    local min = math.floor(remSec / 60)
    local sec = remSec % 60

    local z = days + 719468
    local era = math.floor((z >= 0 and z or z - 146096) / 146097)
    local doe = z - era * 146097
    local yoe = math.floor((doe - math.floor(doe / 1460) + math.floor(doe / 36524) - math.floor(doe / 146096)) / 365)
    local y = yoe + era * 400
    local doy = doe - (365 * yoe + math.floor(yoe / 4) - math.floor(yoe / 100))
    local mp = math.floor((5 * doy + 2) / 153)
    local d = doy - math.floor((153 * mp + 2) / 5) + 1
    local m = mp < 10 and (mp + 3) or (mp - 9)
    if m <= 2 then
        y = y + 1
    end
    return string.format("%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", y, m, d, hour, min, sec, millis)
end

local raw = redis.call('GET', KEYS[1])
if not raw then
    return { -1, "EXPIRED_OR_NOT_FOUND", 0, "" }
end

local session = cjson.decode(raw)
if not session.is_active then
    redis.call('DEL', KEYS[1])
    return { -1, "EXPIRED_OR_NOT_FOUND", 0, "" }
end

local now = tonumber(ARGV[1])
local maxExpiresAt = tonumber(session.max_expires_at)

if now >= maxExpiresAt then
    redis.call('DEL', KEYS[1])
    return { -2, "MAX_LIFETIME_EXCEEDED", 0, "" }
end

local remainingMaxSec = math.floor((maxExpiresAt - now) / 1000)
if remainingMaxSec <= 0 then
    redis.call('DEL', KEYS[1])
    return { -2, "MAX_LIFETIME_EXCEEDED", 0, "" }
end

local idleWindowSec = tonumber(session.idle_timeout_seconds)
if not idleWindowSec or idleWindowSec <= 0 then
    idleWindowSec = tonumber(ARGV[2])
end

local lastRenewed = tonumber(session.last_renewed_at or 0)
local throttleSec = tonumber(ARGV[3])
local timeSinceRenew = math.floor((now - lastRenewed) / 1000)

if timeSinceRenew >= throttleSec then
    local newTtl = math.min(idleWindowSec, remainingMaxSec)
    session.last_renewed_at = now
    session.expires_at = msToIso8601(now + newTtl * 1000)
    local updatedJson = cjson.encode(session)
    redis.call('SET', KEYS[1], updatedJson, 'EX', newTtl)
    return { 1, "RENEWED", newTtl, updatedJson }
else
    return { 0, "VALID", 0, raw }
end
`;

const GRANT_ELEVATION_LUA = `
-- ATOMIC_GRANT_ELEVATION
-- KEYS[1]: session:<sessionId>
-- KEYS[2]: ticket_used:<jti>
-- KEYS[3]: session_elevations:<sessionId>
-- KEYS[4]: elevation:session:<sessionId>:<scope>
-- ARGV[1]: now_ms
-- ARGV[2]: expected_user_id
-- ARGV[3]: claim_ttl_sec
-- ARGV[4]: scope
-- ARGV[5]: payload_json
-- ARGV[6]: elevation_ttl_sec
-- ARGV[7]: index_ttl_sec

local rawSession = redis.call('GET', KEYS[1])
if not rawSession then
    return { -1, "SESSION_EXPIRED" }
end

local session = cjson.decode(rawSession)
if not session or not session.is_active then
    return { -1, "SESSION_EXPIRED" }
end

if tostring(session.user_id) ~= tostring(ARGV[2]) then
    return { -3, "SESSION_USER_MISMATCH" }
end

local nowMs = tonumber(ARGV[1])
local maxExpiresAt = tonumber(session.max_expires_at)
if maxExpiresAt and maxExpiresAt > 0 then
    if nowMs >= maxExpiresAt or math.floor((maxExpiresAt - nowMs) / 1000) <= 0 then
        return { -2, "SESSION_MAX_LIFETIME_EXCEEDED" }
    end
end

local claimed = redis.call('SET', KEYS[2], '1', 'EX', tonumber(ARGV[3]), 'NX')
if not claimed then
    return { 0, "TICKET_ALREADY_USED" }
end

redis.call('SADD', KEYS[3], ARGV[4])
local curTtl = redis.call('TTL', KEYS[3])
local nextIdxTtl = tonumber(ARGV[7])
if curTtl > nextIdxTtl then
    nextIdxTtl = curTtl
end
redis.call('EXPIRE', KEYS[3], nextIdxTtl)
redis.call('SET', KEYS[4], ARGV[5], 'EX', tonumber(ARGV[6]))

return { 1, "GRANTED" }
`;

const REVOKE_SESSION_ELEVATIONS_LUA = `
-- ATOMIC_REVOKE_SESSION_ELEVATIONS
-- KEYS[1]: session_elevations:<sessionId>
-- ARGV[1]: elevation_prefix (e.g. "elevation:session:")
-- ARGV[2]: session_id
-- Returns: count of deleted elevation keys

local members = redis.call('SMEMBERS', KEYS[1])
local count = 0
for i, scope in ipairs(members) do
    local elevKey = ARGV[1] .. ARGV[2] .. ":" .. scope
    local delRes = redis.call('DEL', elevKey)
    if delRes == 1 then
        count = count + 1
    end
end
redis.call('DEL', KEYS[1])
return count
`;

async function executeValidateAndTouch(sessionId, nowMs, idleWindowSec, throttleSec) {
  const client = getRedisClient();
  const key = `${SESSION_PREFIX}${sessionId}`;
  return client.eval(VALIDATE_AND_TOUCH_LUA, 1, key, String(nowMs), String(idleWindowSec), String(throttleSec));
}

async function executeGrantElevation({
  sessionKey,
  claimKey,
  indexKey,
  elevationKey,
  nowMs,
  userId,
  claimTtlSec,
  scope,
  payloadJson,
  elevationTtlSec,
  indexTtlSec
}) {
  const client = getRedisClient();
  return client.eval(
    GRANT_ELEVATION_LUA,
    4,
    sessionKey,
    claimKey,
    indexKey,
    elevationKey,
    String(nowMs),
    String(userId),
    String(claimTtlSec),
    String(scope),
    String(payloadJson),
    String(elevationTtlSec),
    String(indexTtlSec)
  );
}

async function executeRevokeSessionElevations(sessionId, elevationPrefix, sessionElevationsIndexPrefix) {
  const client = getRedisClient();
  const setKey = `${sessionElevationsIndexPrefix}${sessionId}`;
  return client.eval(REVOKE_SESSION_ELEVATIONS_LUA, 1, setKey, elevationPrefix, sessionId);
}

module.exports = {
  getRedisClient,
  storeSession,
  getSession,
  deleteSession,
  getSessionTTL,
  executeValidateAndTouch,
  executeGrantElevation,
  executeRevokeSessionElevations,
  SESSION_PREFIX
};
