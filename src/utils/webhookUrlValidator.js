'use strict';

const net = require('net');
const { normalizeIp, isPrivateOrLoopbackIp } = require('./ip');
const { ApiError } = require('./errors');

const MAX_WEBHOOK_URL_LENGTH = 512;
const CONTROL_OR_WHITESPACE_REGEX = /[\x00-\x20\x7f]/;

/**
 * Checks whether a normalized hostname or IP literal is a forbidden local,
 * private, loopback, link-local, transition, special-purpose, or cloud-metadata target.
 *
 * @param {string} rawHostname
 * @returns {boolean}
 */
function isForbiddenWebhookHostname(rawHostname) {
  if (typeof rawHostname !== 'string' || rawHostname.trim().length === 0) {
    return true;
  }

  let host = rawHostname.trim().toLowerCase();

  // Strip surrounding IPv6 brackets `[...]` from URL.hostname
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1);
  }

  // Strip trailing dot in FQDN
  while (host.endsWith('.')) {
    host = host.slice(0, -1);
  }

  if (!host) {
    return true;
  }

  // Block localhost and internal/local reserved TLDs
  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host.endsWith('.localdomain') ||
    host.endsWith('.home.arpa') ||
    host.endsWith('.test') ||
    host.endsWith('.invalid') ||
    host.endsWith('.lan') ||
    host.endsWith('.corp')
  ) {
    return true;
  }

  const normalizedIp = normalizeIp(host);
  if (normalizedIp !== null || net.isIP(host) !== 0) {
    return isPrivateOrLoopbackIp(normalizedIp || host);
  }

  // Reject single-label internal hostnames without a dot (e.g. `redis`, `mysql`, `metadata`)
  if (!host.includes('.')) {
    return true;
  }

  return false;
}

/**
 * Validates and normalizes a webhook destination URL.
 *
 * Security rules:
 * - Must be a non-empty string <= 512 chars with no whitespace or control characters.
 * - Must parse as a valid WHATWG URL.
 * - Requires `https:` in production unconditionally (`NODE_ENV === 'production'`).
 * - Allows `http:` ONLY in non-production environments when `ALLOW_INSECURE_HTTP_WEBHOOKS === 'true'`.
 * - Rejects embedded credentials (`username` / `password`) and URL fragments (`#...`).
 * - Rejects private, loopback, link-local, cloud-metadata, and single-label internal targets
 *   unless in non-production with `ALLOW_LOCAL_WEBHOOK_TARGETS === 'true'`.
 *
 * @param {unknown} rawUrl
 * @param {NodeJS.ProcessEnv} [env=process.env]
 * @returns {string} Validated URL string
 * @throws {ApiError} 400 `invalid_webhook_url` when validation fails
 */
function validateWebhookDestinationUrl(rawUrl, env = process.env) {
  if (typeof rawUrl !== 'string') {
    throw new ApiError(400, 'invalid_webhook_url', 'Webhook url must be a non-empty string');
  }

  const trimmed = rawUrl.trim();
  if (trimmed.length === 0) {
    throw new ApiError(400, 'invalid_webhook_url', 'Webhook url cannot be empty');
  }

  if (trimmed.length > MAX_WEBHOOK_URL_LENGTH) {
    throw new ApiError(
      400,
      'invalid_webhook_url',
      `Webhook url must not exceed ${MAX_WEBHOOK_URL_LENGTH} characters`
    );
  }

  if (CONTROL_OR_WHITESPACE_REGEX.test(trimmed)) {
    throw new ApiError(
      400,
      'invalid_webhook_url',
      'Webhook url must not contain whitespace or control characters'
    );
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new ApiError(400, 'invalid_webhook_url', 'Webhook url must be a valid URL');
  }

  const isProduction = env.NODE_ENV === 'production';
  const allowInsecureHttp = !isProduction && env.ALLOW_INSECURE_HTTP_WEBHOOKS === 'true';

  if (parsed.protocol !== 'https:' && !(allowInsecureHttp && parsed.protocol === 'http:')) {
    throw new ApiError(
      400,
      'invalid_webhook_url',
      'Webhook url must use https:// protocol'
    );
  }

  if (parsed.username || parsed.password) {
    throw new ApiError(
      400,
      'invalid_webhook_url',
      'Webhook url must not contain embedded credentials'
    );
  }

  if (parsed.hash) {
    throw new ApiError(
      400,
      'invalid_webhook_url',
      'Webhook url must not contain a URL fragment'
    );
  }

  const allowLocalTargets = !isProduction && env.ALLOW_LOCAL_WEBHOOK_TARGETS === 'true';
  if (!allowLocalTargets && isForbiddenWebhookHostname(parsed.hostname)) {
    throw new ApiError(
      400,
      'invalid_webhook_url',
      'Webhook url hostname is not permitted (loopback, private, link-local, or internal hosts are blocked)'
    );
  }

  return trimmed;
}

module.exports = {
  MAX_WEBHOOK_URL_LENGTH,
  isForbiddenWebhookHostname,
  validateWebhookDestinationUrl
};
