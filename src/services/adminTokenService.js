'use strict';

const crypto = require('crypto');
const { getRedisClient } = require('../storage/redis');
const { REDIS_PREFIXES } = require('../config/sessionConfig');

const TOKEN_PREFIX = 'agadm_';
const DEFAULT_IDLE_TTL_SECONDS = 1800; // 30 minutes
const DEFAULT_MAX_LIFETIME_SECONDS = 14400; // 4 hours

function parsePositiveInt(val, fallback) {
  if (val === undefined || val === null || val === '') return fallback;
  const parsed = parseInt(String(val).trim(), 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function getIdleTtlSeconds(override) {
  return parsePositiveInt(override || process.env.ADMIN_TOKEN_IDLE_TTL_SECONDS, DEFAULT_IDLE_TTL_SECONDS);
}

function getMaxLifetimeSeconds(override) {
  return parsePositiveInt(override || process.env.ADMIN_TOKEN_MAX_LIFETIME_SECONDS, DEFAULT_MAX_LIFETIME_SECONDS);
}

function hashAdminToken(token) {
  if (typeof token !== 'string' || token.length === 0) return null;
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

/**
 * Creates a new opaque admin session token.
 * Token is 32 random bytes, base64url, prefixed agadm_.
 * Stored in Redis ONLY as its SHA-256 hash.
 *
 * @param {object} [options={}]
 * @returns {Promise<{ admin_token: string, expires_at: string }>}
 */
async function createAdminToken(options = {}) {
  const randomBytes = crypto.randomBytes(32);
  const token = `${TOKEN_PREFIX}${randomBytes.toString('base64url')}`;
  const tokenHash = hashAdminToken(token);

  const idleTtl = getIdleTtlSeconds(options.idleTtlSeconds);
  const maxLifetime = getMaxLifetimeSeconds(options.maxLifetimeSeconds);

  const nowMs = options.now instanceof Date ? options.now.getTime() : typeof options.now === 'number' ? options.now : Date.now();
  const maxExpiresAtMs = nowMs + maxLifetime * 1000;
  const initialTtl = Math.min(idleTtl, maxLifetime);
  const expiresAtIso = new Date(nowMs + initialTtl * 1000).toISOString();

  const payload = JSON.stringify({
    token_hash: tokenHash,
    created_at: nowMs,
    max_expires_at: maxExpiresAtMs,
    expires_at: expiresAtIso,
    last_seen_at: nowMs
  });

  const client = getRedisClient();
  const key = `${REDIS_PREFIXES.ADMIN_TOKEN}${tokenHash}`;
  await client.set(key, payload, 'EX', initialTtl);

  return {
    admin_token: token,
    expires_at: expiresAtIso
  };
}

/**
 * Validates and optionally slides an admin token's idle TTL.
 *
 * @param {string} token - Raw admin token
 * @param {object} [options={}]
 * @param {boolean} [options.touch=true] - Whether to slide idle TTL
 * @param {number|Date} [options.now=Date.now()]
 * @returns {Promise<object|null>} The token record if valid, null otherwise
 */
async function validateAdminToken(token, options = {}) {
  if (typeof token !== 'string' || !token.startsWith(TOKEN_PREFIX)) {
    return null;
  }

  const tokenHash = hashAdminToken(token);
  if (!tokenHash) return null;

  const client = getRedisClient();
  const key = `${REDIS_PREFIXES.ADMIN_TOKEN}${tokenHash}`;
  const raw = await client.get(key);
  if (!raw) return null;

  let record;
  try {
    record = JSON.parse(raw);
  } catch {
    await client.del(key);
    return null;
  }

  if (!record || typeof record !== 'object') {
    await client.del(key);
    return null;
  }

  const nowMs = options.now instanceof Date ? options.now.getTime() : typeof options.now === 'number' ? options.now : Date.now();
  const maxExpiresAtMs = Number(record.max_expires_at);

  // Check absolute cap
  if (!Number.isFinite(maxExpiresAtMs) || nowMs >= maxExpiresAtMs) {
    await client.del(key);
    return null;
  }

  const remainingMaxSec = Math.floor((maxExpiresAtMs - nowMs) / 1000);
  if (remainingMaxSec <= 0) {
    await client.del(key);
    return null;
  }

  const shouldTouch = options.touch !== false;
  if (shouldTouch) {
    const idleTtl = getIdleTtlSeconds(options.idleTtlSeconds);
    const newTtl = Math.min(idleTtl, remainingMaxSec);
    record.expires_at = new Date(nowMs + newTtl * 1000).toISOString();
    record.last_seen_at = nowMs;

    await client.set(key, JSON.stringify(record), 'EX', newTtl);
  }

  return record;
}

/**
 * Revokes an admin token by deleting its hash from Redis.
 *
 * @param {string} token
 * @returns {Promise<boolean>}
 */
async function revokeAdminToken(token) {
  if (typeof token !== 'string' || !token.startsWith(TOKEN_PREFIX)) {
    return false;
  }

  const tokenHash = hashAdminToken(token);
  if (!tokenHash) return false;

  const client = getRedisClient();
  const key = `${REDIS_PREFIXES.ADMIN_TOKEN}${tokenHash}`;
  const deleted = await client.del(key);
  return deleted > 0;
}

module.exports = {
  createAdminToken,
  validateAdminToken,
  revokeAdminToken,
  hashAdminToken,
  TOKEN_PREFIX,
  DEFAULT_IDLE_TTL_SECONDS,
  DEFAULT_MAX_LIFETIME_SECONDS
};
