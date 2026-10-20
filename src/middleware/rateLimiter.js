'use strict';

const { executeConsumeRateLimit } = require('../storage/redis');
const { REDIS_PREFIXES } = require('../config/sessionConfig');
const { sendError } = require('../utils/errors');

/**
 * Production default rate-limit tiers (fixed window).
 */
const DEFAULT_RATE_LIMIT_TIERS = Object.freeze({
  auth: Object.freeze({
    tier: 'auth',
    windowMs: 60 * 1000,
    max: 10,
    windowEnvVar: 'RATE_LIMIT_AUTH_WINDOW_MS',
    maxEnvVar: 'RATE_LIMIT_AUTH_MAX'
  }),
  step_up: Object.freeze({
    tier: 'step_up',
    windowMs: 60 * 1000,
    max: 5,
    windowEnvVar: 'RATE_LIMIT_STEP_UP_WINDOW_MS',
    maxEnvVar: 'RATE_LIMIT_STEP_UP_MAX'
  }),
  sensitive_action: Object.freeze({
    tier: 'sensitive_action',
    windowMs: 60 * 1000,
    max: 15,
    windowEnvVar: 'RATE_LIMIT_SENSITIVE_WINDOW_MS',
    maxEnvVar: 'RATE_LIMIT_SENSITIVE_MAX'
  }),
  api: Object.freeze({
    tier: 'api',
    windowMs: 60 * 1000,
    max: 60,
    windowEnvVar: 'RATE_LIMIT_API_WINDOW_MS',
    maxEnvVar: 'RATE_LIMIT_API_MAX'
  })
});

const TEST_DEFAULT_MAX_REQUESTS = 10000;

/**
 * Normalizes an IP address string consistently and safely.
 * Does not trust unverified X-Forwarded-For headers directly; relies on
 * Express `req.ip` (which only uses proxy headers if `trust proxy` is explicitly configured)
 * or the underlying socket remoteAddress.
 *
 * @param {import('express').Request} req
 * @returns {string}
 */
function resolveClientIp(req) {
  const raw =
    (req && typeof req.ip === 'string' && req.ip.trim().length > 0
      ? req.ip
      : req?.socket?.remoteAddress || req?.connection?.remoteAddress) || '127.0.0.1';

  const trimmed = String(raw).trim();
  if (trimmed === '::1') {
    return '127.0.0.1';
  }
  if (trimmed.startsWith('::ffff:')) {
    return trimmed.slice(7);
  }
  return trimmed;
}

function parsePositiveIntOption(rawVal, fallbackVal) {
  if (rawVal === undefined || rawVal === null || rawVal === '') {
    return fallbackVal;
  }
  const num = Number.parseInt(String(rawVal).trim(), 10);
  if (!Number.isSafeInteger(num) || num <= 0) {
    return fallbackVal;
  }
  return num;
}

/**
 * Resolves effective windowMs and max requests for a tier at request time,
 * allowing environment overrides in tests while keeping existing integration suites
 * isolated unless rate-limit env vars or explicit options are provided.
 *
 * @param {object} config
 * @param {NodeJS.ProcessEnv} [env=process.env]
 * @returns {{ windowMs: number, max: number }}
 */
function resolveEffectiveLimits(config, env = process.env) {
  const isTestEnv =
    (env.NODE_ENV === 'test' || env.JEST_WORKER_ID !== undefined) &&
    env.RATE_LIMIT_ENFORCE_IN_TESTS !== 'true';

  const envWindow = config.windowEnvVar ? env[config.windowEnvVar] : undefined;
  const envMax = config.maxEnvVar ? env[config.maxEnvVar] : undefined;

  const windowMs =
    config.explicitWindowMs !== undefined
      ? parsePositiveIntOption(config.explicitWindowMs, config.defaultWindowMs)
      : parsePositiveIntOption(envWindow, config.defaultWindowMs);

  let max;
  if (config.explicitMax !== undefined) {
    max = parsePositiveIntOption(config.explicitMax, config.defaultMax);
  } else if (envMax !== undefined && envMax !== '') {
    max = parsePositiveIntOption(envMax, config.defaultMax);
  } else if (isTestEnv) {
    max = TEST_DEFAULT_MAX_REQUESTS;
  } else {
    max = config.defaultMax;
  }

  return { windowMs, max };
}

/**
 * Creates a Redis-backed fixed-window rate-limiting middleware.
 *
 * Security & operational properties:
 * - Atomic increment + window expiration in Redis via CONSUME_RATE_LIMIT_LUA (`-- ATOMIC_RATE_LIMIT`).
 * - Always sets `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers.
 * - On HTTP 429, sets `Retry-After` (in seconds) and returns ActionGuard standard error envelope.
 * - Fails closed (`503 rate_limit_unavailable`) if Redis throws an error, unless `failOpen: true`.
 *
 * @param {object} [options={}]
 * @param {string} [options.tier='api'] - Logical tier namespace
 * @param {number} [options.windowMs] - Explicit fixed window duration in milliseconds
 * @param {number} [options.max] - Explicit maximum requests per window
 * @param {string} [options.windowEnvVar] - Env var name for windowMs
 * @param {string} [options.maxEnvVar] - Env var name for max requests
 * @param {function} [options.keyGenerator] - Custom function `(req) => string`
 * @param {boolean} [options.failOpen=false] - Whether to allow requests if Redis fails (defaults to false / fail-closed)
 * @param {function} [options.nowFn=Date.now] - Clock function for deterministic testing
 */
function createRateLimiter(options = {}) {
  const tierPreset = DEFAULT_RATE_LIMIT_TIERS[options.tier] || DEFAULT_RATE_LIMIT_TIERS.api;
  const tierName = String(options.tier || tierPreset.tier || 'api');
  const defaultWindowMs = tierPreset.windowMs;
  const defaultMax = tierPreset.max;
  const windowEnvVar = options.windowEnvVar || tierPreset.windowEnvVar;
  const maxEnvVar = options.maxEnvVar || tierPreset.maxEnvVar;
  const failOpen = Boolean(options.failOpen);
  const nowFn = typeof options.nowFn === 'function' ? options.nowFn : Date.now;
  const keyGenerator =
    typeof options.keyGenerator === 'function'
      ? options.keyGenerator
      : (req) => resolveClientIp(req);

  return async function rateLimiterMiddleware(req, res, next) {
    const { windowMs, max } = resolveEffectiveLimits({
      defaultWindowMs,
      defaultMax,
      explicitWindowMs: options.windowMs,
      explicitMax: options.max,
      windowEnvVar,
      maxEnvVar
    });

    const identifier = String(keyGenerator(req) || 'unknown');
    const rateKey = `${REDIS_PREFIXES.RATE_LIMIT}${tierName}:${identifier}`;
    const nowMs = nowFn();

    try {
      const result = await executeConsumeRateLimit(rateKey, nowMs, windowMs, max);
      const allowed = Number(result[0]) === 1;
      const remaining = Math.max(0, Number(result[2]) || 0);
      const resetAtMs = Number(result[3]) || nowMs + windowMs;
      const retryAfterSeconds = Math.max(1, Math.ceil((resetAtMs - nowMs) / 1000));
      const resetEpochSeconds = Math.ceil(resetAtMs / 1000);

      res.setHeader('X-RateLimit-Limit', String(max));
      res.setHeader('X-RateLimit-Remaining', String(remaining));
      res.setHeader('X-RateLimit-Reset', String(resetEpochSeconds));

      if (!allowed) {
        res.setHeader('Retry-After', String(retryAfterSeconds));
        return res.status(429).json({
          error: {
            code: 'rate_limited',
            message: 'Too many requests. Please wait before retrying.',
            status: 429,
            tier: tierName,
            retry_after_seconds: retryAfterSeconds
          }
        });
      }

      return next();
    } catch (_err) {
      if (failOpen) {
        return next();
      }
      return sendError(
        res,
        503,
        'rate_limit_unavailable',
        'Rate limiting service is temporarily unavailable'
      );
    }
  };
}

const authRateLimiter = createRateLimiter({ tier: 'auth' });
const stepUpRateLimiter = createRateLimiter({ tier: 'step_up' });
const sensitiveActionRateLimiter = createRateLimiter({ tier: 'sensitive_action' });
const apiRateLimiter = createRateLimiter({ tier: 'api' });

module.exports = {
  DEFAULT_RATE_LIMIT_TIERS,
  createRateLimiter,
  authRateLimiter,
  stepUpRateLimiter,
  sensitiveActionRateLimiter,
  apiRateLimiter,
  resolveClientIp,
  resolveEffectiveLimits
};
