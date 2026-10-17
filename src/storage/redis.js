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

    if (script.includes('-- ATOMIC_VERIFY_STEP_UP_CHALLENGE')) {
      const crypto = require('crypto');
      const challengeKey = keys[0];
      const nowMs = Number(argv[0]);
      const expectedUserId = String(argv[1]);
      const expectedSessionId = String(argv[2]);
      const candidateHashesJson = argv[3];

      const raw = this._getSync(challengeKey);
      if (!raw) {
        return [-1, 'CHALLENGE_EXPIRED_OR_NOT_FOUND', 0, 0, '', ''];
      }

      let challenge;
      try {
        challenge = JSON.parse(raw);
      } catch {
        this._delSync(challengeKey);
        return [-1, 'CHALLENGE_EXPIRED_OR_NOT_FOUND', 0, 0, '', ''];
      }

      const expiresAtMs = Number(
        challenge.expires_at_ms !== undefined
          ? challenge.expires_at_ms
          : new Date(challenge.expires_at).getTime()
      );
      if (!Number.isFinite(expiresAtMs) || nowMs >= expiresAtMs) {
        this._delSync(challengeKey);
        return [-1, 'CHALLENGE_EXPIRED_OR_NOT_FOUND', 0, 0, '', ''];
      }

      if (
        String(challenge.user_id) !== expectedUserId ||
        String(challenge.session_id) !== expectedSessionId
      ) {
        return [-2, 'CHALLENGE_BINDING_MISMATCH', 0, 0, String(challenge.scope || ''), ''];
      }

      const maxAttempts = Number(challenge.max_attempts) || 3;
      const currentAttempts = Number(challenge.attempts) || 0;
      if (currentAttempts >= maxAttempts) {
        this._delSync(challengeKey);
        return [
          -3,
          'CHALLENGE_MAX_ATTEMPTS_EXCEEDED',
          currentAttempts,
          maxAttempts,
          String(challenge.scope || ''),
          ''
        ];
      }

      let candidateHashes;
      try {
        candidateHashes = JSON.parse(candidateHashesJson);
      } catch {
        return [-1, 'CHALLENGE_EXPIRED_OR_NOT_FOUND', 0, 0, '', ''];
      }

      const scope = String(challenge.scope || '');
      const expectedHash = String(challenge.code_hash || '');
      const candidateHash = String((candidateHashes && candidateHashes[scope]) || '');

      let isMatch = false;
      if (expectedHash.length > 0 && expectedHash.length === candidateHash.length) {
        const expectedBuf = Buffer.from(expectedHash, 'hex');
        const candidateBuf = Buffer.from(candidateHash, 'hex');
        isMatch =
          expectedBuf.length > 0 &&
          expectedBuf.length === candidateBuf.length &&
          crypto.timingSafeEqual(expectedBuf, candidateBuf);
      }

      if (isMatch) {
        this._delSync(challengeKey);
        return [1, 'VERIFIED', currentAttempts + 1, maxAttempts, scope, expectedHash];
      }

      const nextAttempts = currentAttempts + 1;
      if (nextAttempts >= maxAttempts) {
        this._delSync(challengeKey);
      } else {
        challenge.attempts = nextAttempts;
        const remainingTtlSec = Math.max(1, Math.ceil((expiresAtMs - nowMs) / 1000));
        this._setSync(challengeKey, JSON.stringify(challenge), 'EX', remainingTtlSec);
      }

      return [0, 'INVALID_CODE', nextAttempts, maxAttempts, scope, expectedHash];
    }

    if (script.includes('-- ATOMIC_REVOKE_ELEVATIONS_ON_RISK_INCREASE')) {
      const indexKey = keys[0];
      const elevationPrefix = argv[0];
      const sessionId = argv[1];
      const newRank = Number(argv[2]) || 0;
      const tierRanks = { low: 0, medium: 1, high: 2, critical: 3 };

      const scopes = this._smembersSync(indexKey);
      const revokedList = [];

      for (const scope of scopes) {
        const elevationKey = `${elevationPrefix}${sessionId}:${scope}`;
        const raw = this._getSync(elevationKey);
        if (!raw) {
          this._sremSync(indexKey, scope);
          continue;
        }

        let data;
        try {
          data = JSON.parse(raw);
        } catch {
          continue;
        }

        const grantedTier = String((data && data.granted_at_risk_tier) || 'low');
        const grantedRank = tierRanks[grantedTier] !== undefined ? tierRanks[grantedTier] : 0;

        if (newRank > grantedRank) {
          this._delSync(elevationKey);
          this._sremSync(indexKey, scope);
          revokedList.push(raw);
        }
      }

      return revokedList;
    }

    if (script.includes('-- ATOMIC_RELEASE_LOCK')) {
      const lockKey = keys[0];
      const expectedValue = String(argv[0]);
      const currentVal = this._getSync(lockKey);
      if (currentVal !== null && String(currentVal) === expectedValue) {
        return this._delSync(lockKey);
      }
      return 0;
    }

    if (script.includes('-- ATOMIC_COMPLETE_IDEMPOTENCY_LEASE')) {
      const idemKey = keys[0];
      const expectedValue = String(argv[0]);
      const completedJson = String(argv[1]);
      const ttlSeconds = Number(argv[2]);
      const currentVal = this._getSync(idemKey);
      if (currentVal !== null && String(currentVal) === expectedValue) {
        if (Number.isFinite(ttlSeconds) && ttlSeconds > 0) {
          this._setSync(idemKey, completedJson, 'EX', ttlSeconds);
        } else {
          this._setSync(idemKey, completedJson);
        }
        return 1;
      }
      return 0;
    }

    if (script.includes('-- ATOMIC_RATE_LIMIT')) {
      const rateKey = keys[0];
      const nowMs = Number(argv[0]);
      const windowMs = Number(argv[1]);
      const maxReq = Number(argv[2]);

      const raw = this._getSync(rateKey);
      let state = null;
      if (raw) {
        try {
          const decoded = JSON.parse(raw);
          if (decoded && typeof decoded === 'object') {
            state = decoded;
          }
        } catch {
          state = null;
        }
      }

      if (!state || !Number.isFinite(Number(state.resetAtMs)) || nowMs >= Number(state.resetAtMs)) {
        const resetAtMs = nowMs + windowMs;
        state = { count: 1, resetAtMs };
        this._setSync(rateKey, JSON.stringify(state), 'PX', windowMs);
        const allowed = 1 <= maxReq ? 1 : 0;
        const remaining = Math.max(0, maxReq - 1);
        return [allowed, 1, remaining, resetAtMs];
      }

      const nextCount = (Number(state.count) || 0) + 1;
      const resetAtMs = Number(state.resetAtMs);
      state.count = nextCount;
      const remMs = Math.max(1, resetAtMs - nowMs);
      this._setSync(rateKey, JSON.stringify(state), 'PX', remMs);

      if (nextCount > maxReq) {
        return [0, nextCount, 0, resetAtMs];
      }
      return [1, nextCount, Math.max(0, maxReq - nextCount), resetAtMs];
    }

    if (script.includes('-- ATOMIC_CHECK_STEP_UP_CHALLENGE_LIMITS')) {
      const cooldownKey = keys[0];
      const sessionScopeKey = keys[1];
      const userKey = keys[2];

      const cooldownSec = Number(argv[0]);
      const windowSec = Number(argv[1]);
      const sessionScopeMax = Number(argv[2]);
      const userMax = Number(argv[3]);

      // 1. Check cooldown
      const cooldownVal = this._getSync(cooldownKey);
      if (cooldownVal !== null) {
        let ttl = this._ttlSync(cooldownKey);
        if (ttl < 1) ttl = 1;
        return [0, 'cooldown', ttl];
      }

      // 2. Check session+scope limit
      const sessionScopeRaw = this._getSync(sessionScopeKey);
      const sessionScopeCount = sessionScopeRaw ? Number(sessionScopeRaw) : 0;
      if (sessionScopeCount >= sessionScopeMax) {
        let ttl = this._ttlSync(sessionScopeKey);
        if (ttl < 1) ttl = 1;
        return [0, 'session_scope_limit', ttl];
      }

      // 3. Check user limit
      const userRaw = this._getSync(userKey);
      const userCount = userRaw ? Number(userRaw) : 0;
      if (userCount >= userMax) {
        let ttl = this._ttlSync(userKey);
        if (ttl < 1) ttl = 1;
        return [0, 'user_limit', ttl];
      }

      // 4. Apply changes atomically
      this._setSync(cooldownKey, '1', 'EX', cooldownSec);

      const nextSessionScope = sessionScopeCount + 1;
      if (sessionScopeCount === 0) {
        this._setSync(sessionScopeKey, String(nextSessionScope), 'EX', windowSec);
      } else {
        const remainingTtl = this._ttlSync(sessionScopeKey);
        this._setSync(
          sessionScopeKey,
          String(nextSessionScope),
          'EX',
          remainingTtl > 0 ? remainingTtl : windowSec
        );
      }

      const nextUser = userCount + 1;
      if (userCount === 0) {
        this._setSync(userKey, String(nextUser), 'EX', windowSec);
      } else {
        const remainingTtl = this._ttlSync(userKey);
        this._setSync(
          userKey,
          String(nextUser),
          'EX',
          remainingTtl > 0 ? remainingTtl : windowSec
        );
      }

      return [1, 'ok', 0];
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

const RELEASE_LOCK_LUA = `
-- ATOMIC_RELEASE_LOCK
-- KEYS[1]: lock_key
-- ARGV[1]: expected_owner_token
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
else
    return 0
end
`;

const CONSUME_RATE_LIMIT_LUA = `
-- ATOMIC_RATE_LIMIT
-- KEYS[1]: rate_limit_key
-- ARGV[1]: now_ms
-- ARGV[2]: window_ms
-- ARGV[3]: max_requests
local raw = redis.call('GET', KEYS[1])
local nowMs = tonumber(ARGV[1])
local windowMs = tonumber(ARGV[2])
local maxReq = tonumber(ARGV[3])
local state = nil
if raw then
    local ok, decoded = pcall(cjson.decode, raw)
    if ok and type(decoded) == 'table' then
        state = decoded
    end
end
if not state or not state.resetAtMs or nowMs >= tonumber(state.resetAtMs) then
    local resetAtMs = nowMs + windowMs
    state = { count = 1, resetAtMs = resetAtMs }
    redis.call('SET', KEYS[1], cjson.encode(state), 'PX', windowMs)
    local allowed = (1 <= maxReq) and 1 or 0
    local remaining = math.max(0, maxReq - 1)
    return { allowed, 1, remaining, resetAtMs }
end
local nextCount = (tonumber(state.count) or 0) + 1
local resetAtMs = tonumber(state.resetAtMs)
state.count = nextCount
local remMs = math.max(1, resetAtMs - nowMs)
redis.call('SET', KEYS[1], cjson.encode(state), 'PX', remMs)
if nextCount > maxReq then
    return { 0, nextCount, 0, resetAtMs }
end
return { 1, nextCount, math.max(0, maxReq - nextCount), resetAtMs }
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

async function executeReleaseLock(lockKey, expectedValue) {
  const client = getRedisClient();
  return client.eval(RELEASE_LOCK_LUA, 1, lockKey, String(expectedValue));
}

async function executeConsumeRateLimit(rateKey, nowMs, windowMs, maxRequests) {
  const client = getRedisClient();
  return client.eval(
    CONSUME_RATE_LIMIT_LUA,
    1,
    rateKey,
    String(nowMs),
    String(windowMs),
    String(maxRequests)
  );
}

const CHECK_STEP_UP_CHALLENGE_LIMITS_LUA = `
-- ATOMIC_CHECK_STEP_UP_CHALLENGE_LIMITS
local cooldownKey = KEYS[1]
local sessionScopeKey = KEYS[2]
local userKey = KEYS[3]

local cooldownSec = tonumber(ARGV[1])
local windowSec = tonumber(ARGV[2])
local sessionScopeMax = tonumber(ARGV[3])
local userMax = tonumber(ARGV[4])

-- 1. Check cooldown
if redis.call('EXISTS', cooldownKey) == 1 then
    local ttl = redis.call('TTL', cooldownKey)
    if ttl < 1 then ttl = 1 end
    return { 0, 'cooldown', ttl }
end

-- 2. Check session+scope limit
local sessionScopeCount = tonumber(redis.call('GET', sessionScopeKey) or '0')
if sessionScopeCount >= sessionScopeMax then
    local ttl = redis.call('TTL', sessionScopeKey)
    if ttl < 1 then ttl = 1 end
    return { 0, 'session_scope_limit', ttl }
end

-- 3. Check user limit
local userCount = tonumber(redis.call('GET', userKey) or '0')
if userCount >= userMax then
    local ttl = redis.call('TTL', userKey)
    if ttl < 1 then ttl = 1 end
    return { 0, 'user_limit', ttl }
end

-- 4. Apply changes atomically
redis.call('SET', cooldownKey, '1', 'EX', cooldownSec)

local newSessionScope = redis.call('INCR', sessionScopeKey)
if newSessionScope == 1 then
    redis.call('EXPIRE', sessionScopeKey, windowSec)
end

local newUser = redis.call('INCR', userKey)
if newUser == 1 then
    redis.call('EXPIRE', userKey, windowSec)
end

return { 1, 'ok', 0 }
`;

async function executeCheckStepUpChallengeLimits({
  cooldownKey,
  sessionScopeKey,
  userKey,
  cooldownSec,
  windowSec,
  sessionScopeMax,
  userMax
}) {
  const client = getRedisClient();
  return client.eval(
    CHECK_STEP_UP_CHALLENGE_LIMITS_LUA,
    3,
    cooldownKey,
    sessionScopeKey,
    userKey,
    String(cooldownSec),
    String(windowSec),
    String(sessionScopeMax),
    String(userMax)
  );
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
  executeReleaseLock,
  executeConsumeRateLimit,
  executeCheckStepUpChallengeLimits,
  CHECK_STEP_UP_CHALLENGE_LIMITS_LUA,
  SESSION_PREFIX
};
