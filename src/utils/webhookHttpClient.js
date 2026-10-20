'use strict';

const dns = require('dns');
const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const { validateWebhookDestinationUrl } = require('./webhookUrlValidator');
const { normalizeIp, isPrivateOrLoopbackIp } = require('./ip');

const DEFAULT_REQUEST_TIMEOUT_MS = 5000;
const MIN_REQUEST_TIMEOUT_MS = 1000;
const MAX_REQUEST_TIMEOUT_MS = 15000;
const DEFAULT_MAX_RESPONSE_BYTES = 4096;
const DEFAULT_DNS_TIMEOUT_MS = 3000;

/**
 * Sanitized, typed error representing an outbound webhook delivery failure.
 * Never exposes DNS internals, sensitive URL credentials, signing secrets,
 * or receiver response bodies in public error messages.
 */
class WebhookDeliveryError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {object} [options={}]
   * @param {boolean} [options.retryable=false]
   * @param {number|null} [options.httpStatus=null]
   */
  constructor(code, message, options = {}) {
    super(message);
    this.name = 'WebhookDeliveryError';
    this.code = code;
    this.retryable = Boolean(options.retryable);
    this.httpStatus =
      typeof options.httpStatus === 'number' ? options.httpStatus : null;
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Clamps a requested timeout in milliseconds to `[MIN_REQUEST_TIMEOUT_MS, MAX_REQUEST_TIMEOUT_MS]`.
 *
 * @param {unknown} rawTimeoutMs
 * @returns {number}
 */
function clampRequestTimeoutMs(rawTimeoutMs) {
  if (rawTimeoutMs === undefined || rawTimeoutMs === null || rawTimeoutMs === '') {
    return DEFAULT_REQUEST_TIMEOUT_MS;
  }
  const parsed = Number(rawTimeoutMs);
  if (!Number.isFinite(parsed)) {
    return DEFAULT_REQUEST_TIMEOUT_MS;
  }
  return Math.min(
    MAX_REQUEST_TIMEOUT_MS,
    Math.max(MIN_REQUEST_TIMEOUT_MS, Math.round(parsed))
  );
}

/**
 * Strips IPv6 brackets `[...]` and trailing FQDN dots from a parsed URL hostname.
 *
 * @param {string} hostname
 * @returns {string}
 */
function normalizeParsedHostname(hostname) {
  let clean = String(hostname || '').trim().toLowerCase();
  if (clean.startsWith('[') && clean.endsWith(']')) {
    clean = clean.slice(1, -1);
  }
  while (clean.endsWith('.')) {
    clean = clean.slice(0, -1);
  }
  return clean;
}

/**
 * Classifies whether a low-level Node socket/TLS error is a permanent TLS
 * certificate or hostname verification failure.
 *
 * @param {Error} err
 * @returns {boolean}
 */
function isTlsVerificationError(err) {
  if (!err || typeof err !== 'object') {
    return false;
  }
  const code = String(err.code || '');
  if (
    code === 'ERR_TLS_CERT_ALTNAME_INVALID' ||
    code === 'ERR_TLS_CERT_ALTNAME_FORMAT' ||
    code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
    code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
    code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
    code === 'UNABLE_TO_GET_ISSUER_CERT' ||
    code === 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY' ||
    code === 'CERT_HAS_EXPIRED' ||
    code === 'CERT_NOT_YET_VALID' ||
    code === 'CERT_REVOKED' ||
    code === 'CERT_UNTRUSTED' ||
    code === 'CERT_REJECTED' ||
    code === 'INVALID_PURPOSE' ||
    code === 'HOSTNAME_MISMATCH'
  ) {
    return true;
  }
  if (code.startsWith('ERR_TLS_') && code !== 'ERR_TLS_HANDSHAKE_TIMEOUT') {
    return true;
  }
  const msg = String(err.message || '');
  if (
    /certificate|altnames|self[- ]signed|unable to verify|tls alert/i.test(msg)
  ) {
    return true;
  }
  return false;
}

/**
 * Executes a DNS lookup with a strict timeout guard.
 *
 * @param {Function} lookupFn
 * @param {string} hostname
 * @param {number} timeoutMs
 * @returns {Promise<Array<{ address: string, family: number }>>}
 */
async function lookupAllWithTimeout(lookupFn, hostname, timeoutMs) {
  let timer = null;
  try {
    const lookupPromise = Promise.resolve(
      lookupFn(hostname, { all: true, verbatim: true })
    );
    const timeoutPromise = new Promise((_, reject) => {
      timer = setTimeout(() => {
        const timeoutErr = new Error('DNS lookup timed out');
        timeoutErr.code = 'ETIMEOUT';
        reject(timeoutErr);
      }, timeoutMs);
      if (timer && typeof timer.unref === 'function') {
        timer.unref();
      }
    });
    return await Promise.race([lookupPromise, timeoutPromise]);
  } finally {
    if (timer) {
      clearTimeout(timer);
    }
  }
}

/**
 * Revalidates a webhook destination URL, resolves all DNS records, validates every
 * resolved IP against ActionGuard's SSRF blocklist (`isPrivateOrLoopbackIp`), and
 * selects a validated IP address to pin for the outbound socket connection.
 *
 * Security invariants:
 * - Production (`env.NODE_ENV === 'production'`) NEVER permits private, loopback,
 *   link-local, or insecure HTTP destinations, regardless of options or env flags.
 * - Rejects empty or malformed DNS responses (`DNS_RESOLUTION_FAILED`).
 * - Rejects the entire DNS result if ANY resolved IPv4 or IPv6 address is prohibited
 *   (`SSRF_BLOCKED_IP`), preventing mixed public/private DNS rebinding attacks.
 *
 * @param {string} urlStr
 * @param {object} [options={}]
 * @param {NodeJS.ProcessEnv} [options.env=process.env]
 * @param {Function} [options.lookupFn=dns.promises.lookup]
 * @param {number} [options.dnsTimeoutMs=DEFAULT_DNS_TIMEOUT_MS]
 * @param {boolean} [options.allowLocalTargets=false] - Test-only override; ignored in production
 * @param {boolean} [options.allowInsecureHttp=false] - Test-only override; ignored in production
 * @returns {Promise<{
 *   parsedUrl: URL,
 *   hostname: string,
 *   isIpLiteral: boolean,
 *   pinnedAddress: string,
 *   pinnedFamily: 4 | 6,
 *   resolvedAddresses: Array<{ address: string, family: 4 | 6 }>
 * }>}
 */
async function resolveAndValidateWebhookTarget(urlStr, options = {}) {
  const env = options.env || process.env;
  const isProduction = env.NODE_ENV === 'production';

  // Production lockout: never permit local targets or HTTP in production regardless of options or env
  const allowLocalTargets =
    !isProduction &&
    (options.allowLocalTargets === true ||
      env.ALLOW_LOCAL_WEBHOOK_TARGETS === 'true');
  const allowInsecureHttp =
    !isProduction &&
    (options.allowInsecureHttp === true ||
      env.ALLOW_INSECURE_HTTP_WEBHOOKS === 'true');

  const effectiveValidationEnv = {
    ...env,
    NODE_ENV: isProduction ? 'production' : env.NODE_ENV || 'development',
    ALLOW_LOCAL_WEBHOOK_TARGETS: allowLocalTargets ? 'true' : 'false',
    ALLOW_INSECURE_HTTP_WEBHOOKS: allowInsecureHttp ? 'true' : 'false'
  };

  let validatedUrl;
  try {
    validatedUrl = validateWebhookDestinationUrl(urlStr, effectiveValidationEnv);
  } catch {
    throw new WebhookDeliveryError(
      'INVALID_DESTINATION_URL',
      'Webhook destination URL failed security validation',
      { retryable: false }
    );
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(validatedUrl);
  } catch {
    throw new WebhookDeliveryError(
      'INVALID_DESTINATION_URL',
      'Webhook destination URL could not be parsed',
      { retryable: false }
    );
  }

  const hostname = normalizeParsedHostname(parsedUrl.hostname);
  if (!hostname) {
    throw new WebhookDeliveryError(
      'INVALID_DESTINATION_URL',
      'Webhook destination hostname is empty',
      { retryable: false }
    );
  }

  // Case 1: Hostname is already an IP literal
  const rawFamily = net.isIP(hostname);
  if (rawFamily !== 0 || normalizeIp(hostname) !== null) {
    if (!allowLocalTargets && isPrivateOrLoopbackIp(hostname)) {
      throw new WebhookDeliveryError(
        'SSRF_BLOCKED_IP',
        'Webhook destination IP address is prohibited',
        { retryable: false }
      );
    }

    const pinnedAddress = rawFamily === 6 ? hostname : normalizeIp(hostname);
    const pinnedFamily = net.isIP(pinnedAddress);
    if (pinnedFamily !== 4 && pinnedFamily !== 6) {
      throw new WebhookDeliveryError(
        'INVALID_DESTINATION_URL',
        'Webhook destination IP literal is invalid',
        { retryable: false }
      );
    }

    return {
      parsedUrl,
      hostname,
      isIpLiteral: true,
      pinnedAddress,
      pinnedFamily,
      resolvedAddresses: [{ address: pinnedAddress, family: pinnedFamily }]
    };
  }

  // Case 2: Hostname is a DNS name -> resolve all A/AAAA records
  const lookupFn =
    typeof options.lookupFn === 'function'
      ? options.lookupFn
      : dns.promises.lookup;
  const dnsTimeoutMs =
    typeof options.dnsTimeoutMs === 'number' && options.dnsTimeoutMs > 0
      ? options.dnsTimeoutMs
      : DEFAULT_DNS_TIMEOUT_MS;

  let rawAnswers;
  try {
    rawAnswers = await lookupAllWithTimeout(lookupFn, hostname, dnsTimeoutMs);
  } catch {
    throw new WebhookDeliveryError(
      'DNS_RESOLUTION_FAILED',
      'Failed to resolve webhook destination hostname',
      { retryable: true }
    );
  }

  if (!Array.isArray(rawAnswers) || rawAnswers.length === 0) {
    throw new WebhookDeliveryError(
      'DNS_RESOLUTION_FAILED',
      'DNS resolution returned no addresses for webhook destination',
      { retryable: true }
    );
  }

  const resolvedAddresses = [];
  for (const entry of rawAnswers) {
    if (
      !entry ||
      typeof entry !== 'object' ||
      typeof entry.address !== 'string' ||
      entry.address.trim().length === 0
    ) {
      throw new WebhookDeliveryError(
        'DNS_RESOLUTION_FAILED',
        'DNS resolver returned a malformed address record',
        { retryable: true }
      );
    }

    const trimmedAddr = entry.address.trim();
    const detectedFamily = net.isIP(trimmedAddr);
    if (detectedFamily !== 4 && detectedFamily !== 6) {
      throw new WebhookDeliveryError(
        'DNS_RESOLUTION_FAILED',
        'DNS resolver returned an invalid IP address',
        { retryable: true }
      );
    }

    if (
      entry.family !== undefined &&
      entry.family !== 4 &&
      entry.family !== 6 &&
      entry.family !== `IPv${detectedFamily}`
    ) {
      throw new WebhookDeliveryError(
        'DNS_RESOLUTION_FAILED',
        'DNS resolver returned an invalid address family',
        { retryable: true }
      );
    }

    // Validate EVERY resolved IP against SSRF classification; reject entire set if any is prohibited
    if (!allowLocalTargets && isPrivateOrLoopbackIp(trimmedAddr)) {
      throw new WebhookDeliveryError(
        'SSRF_BLOCKED_IP',
        'Webhook destination resolved to a prohibited private, loopback, or reserved IP address',
        { retryable: false }
      );
    }

    resolvedAddresses.push({
      address: trimmedAddr,
      family: detectedFamily
    });
  }

  const selected = resolvedAddresses[0];

  return {
    parsedUrl,
    hostname,
    isIpLiteral: false,
    pinnedAddress: selected.address,
    pinnedFamily: selected.family,
    resolvedAddresses
  };
}

/**
 * Sends an outbound HTTP/HTTPS webhook request pinned to a pre-validated IP address.
 *
 * Security invariants:
 * - Resolves and validates all DNS answers before opening a socket.
 * - Supplies a custom `lookup` callback to `https.request` / `http.request` that
 *   returns the pinned IP directly without performing a second DNS lookup.
 * - Uses `agent: false` so pooled sockets can never bypass per-attempt validation.
 * - Preserves `Host` header, TLS SNI (`servername`), certificate chain verification
 *   (`rejectUnauthorized: true` unconditionally), and hostname identity checks.
 * - Rejects all `3xx` redirects (`HTTP_REDIRECT_REJECTED`) without following `Location`.
 * - Enforces bounded total request timeout (`1000..15000` ms, default `5000` ms).
 * - Enforces response body limit (`4096` bytes) and never stores or logs response bodies.
 *
 * @param {string} urlStr
 * @param {object} [options={}]
 * @param {object} [options.headers={}]
 * @param {Buffer|string} [options.bodyBuffer]
 * @param {number} [options.timeoutMs=DEFAULT_REQUEST_TIMEOUT_MS]
 * @param {number} [options.maxResponseBytes=DEFAULT_MAX_RESPONSE_BYTES]
 * @param {Function} [options.lookupFn]
 * @param {NodeJS.ProcessEnv} [options.env=process.env]
 * @param {boolean} [options.allowLocalTargets=false]
 * @param {boolean} [options.allowInsecureHttp=false]
 * @param {object} [options.tlsOptions={}] - Optional trusted `ca` for testing; `rejectUnauthorized: false` is forbidden
 * @returns {Promise<{
 *   httpStatus: number,
 *   retryAfterHeader: string|null,
 *   pinnedAddress: string,
 *   pinnedFamily: 4 | 6
 * }>}
 */
async function sendPinnedWebhookRequest(urlStr, options = {}) {
  const env = options.env || process.env;
  const isProduction = env.NODE_ENV === 'production';

  // Forbid disabling TLS certificate verification in any environment
  if (
    options.tlsOptions &&
    typeof options.tlsOptions === 'object' &&
    options.tlsOptions.rejectUnauthorized === false
  ) {
    throw new WebhookDeliveryError(
      'TLS_VERIFICATION_FAILED',
      'Disabling TLS certificate verification (rejectUnauthorized: false) is strictly prohibited',
      { retryable: false }
    );
  }

  const allowLocalTargets =
    !isProduction &&
    (options.allowLocalTargets === true ||
      env.ALLOW_LOCAL_WEBHOOK_TARGETS === 'true');
  const allowInsecureHttp =
    !isProduction &&
    (options.allowInsecureHttp === true ||
      env.ALLOW_INSECURE_HTTP_WEBHOOKS === 'true');

  const timeoutMs = clampRequestTimeoutMs(options.timeoutMs);
  const maxResponseBytes =
    typeof options.maxResponseBytes === 'number' &&
    Number.isFinite(options.maxResponseBytes) &&
    options.maxResponseBytes > 0
      ? Math.min(Math.floor(options.maxResponseBytes), DEFAULT_MAX_RESPONSE_BYTES)
      : DEFAULT_MAX_RESPONSE_BYTES;

  const payloadBuffer = Buffer.isBuffer(options.bodyBuffer)
    ? options.bodyBuffer
    : typeof options.bodyBuffer === 'string'
    ? Buffer.from(options.bodyBuffer, 'utf8')
    : Buffer.alloc(0);

  // 1. Validate URL, resolve all DNS answers, and select a validated IP to pin
  const target = await resolveAndValidateWebhookTarget(urlStr, {
    env,
    lookupFn: options.lookupFn,
    dnsTimeoutMs: Math.min(timeoutMs, DEFAULT_DNS_TIMEOUT_MS),
    allowLocalTargets,
    allowInsecureHttp
  });

  const { parsedUrl, hostname, isIpLiteral, pinnedAddress, pinnedFamily } = target;
  const isHttps = parsedUrl.protocol === 'https:';
  const transport = isHttps ? https : http;
  const defaultPort = isHttps ? 443 : 80;
  const port = parsedUrl.port ? Number.parseInt(parsedUrl.port, 10) : defaultPort;
  const requestPath = `${parsedUrl.pathname || '/'}${parsedUrl.search || ''}`;

  // Custom lookup callback that immediately supplies the validated pinned IP
  // without performing a second DNS lookup. Supports both single-address and `{ all: true }` modes.
  const pinnedLookup = (_reqHost, lookupOpts, callback) => {
    const cb = typeof lookupOpts === 'function' ? lookupOpts : callback;
    const opts =
      typeof lookupOpts === 'object' && lookupOpts !== null ? lookupOpts : {};

    if (opts.all) {
      return process.nextTick(() =>
        cb(null, [{ address: pinnedAddress, family: pinnedFamily }])
      );
    }
    return process.nextTick(() => cb(null, pinnedAddress, pinnedFamily));
  };

  const requestHeaders = {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': String(payloadBuffer.length),
    'User-Agent': 'ActionGuard-Webhook/1.0',
    Host: parsedUrl.host,
    ...(options.headers || {})
  };

  const requestOptions = {
    protocol: parsedUrl.protocol,
    hostname,
    port,
    path: requestPath,
    method: 'POST',
    headers: requestHeaders,
    agent: false,
    lookup: pinnedLookup,
    family: pinnedFamily
  };

  if (isHttps) {
    requestOptions.rejectUnauthorized = true;
    if (!isIpLiteral) {
      requestOptions.servername = hostname;
      requestOptions.checkServerIdentity = (servername, cert) =>
        tls.checkServerIdentity(hostname, cert);
    }
    if (options.tlsOptions && options.tlsOptions.ca) {
      requestOptions.ca = options.tlsOptions.ca;
    }
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    let totalTimeoutTimer = null;
    let req = null;

    const finishWithError = (err) => {
      if (settled) {
        return;
      }
      settled = true;
      if (totalTimeoutTimer) {
        clearTimeout(totalTimeoutTimer);
        totalTimeoutTimer = null;
      }
      if (req) {
        try {
          req.destroy();
        } catch {}
      }
      reject(err);
    };

    const finishWithSuccess = (result) => {
      if (settled) {
        return;
      }
      settled = true;
      if (totalTimeoutTimer) {
        clearTimeout(totalTimeoutTimer);
        totalTimeoutTimer = null;
      }
      resolve(result);
    };

    totalTimeoutTimer = setTimeout(() => {
      finishWithError(
        new WebhookDeliveryError(
          'REQUEST_TIMEOUT',
          'Webhook delivery request timed out',
          { retryable: true }
        )
      );
    }, timeoutMs);

    if (totalTimeoutTimer && typeof totalTimeoutTimer.unref === 'function') {
      totalTimeoutTimer.unref();
    }

    try {
      req = transport.request(requestOptions, (res) => {
        const statusCode = Number(res.statusCode) || 0;

        // Reject all 3xx redirects immediately without following Location
        if (statusCode >= 300 && statusCode < 400) {
          finishWithError(
            new WebhookDeliveryError(
              'HTTP_REDIRECT_REJECTED',
              'Webhook destination returned an HTTP redirect which is not permitted',
              { retryable: false, httpStatus: statusCode }
            )
          );
          try {
            res.destroy();
          } catch {}
          return;
        }

        let receivedBytes = 0;

        res.on('data', (chunk) => {
          if (settled) {
            return;
          }
          const chunkLen = Buffer.isBuffer(chunk)
            ? chunk.length
            : Buffer.byteLength(String(chunk));
          receivedBytes += chunkLen;

          if (receivedBytes > maxResponseBytes) {
            finishWithError(
              new WebhookDeliveryError(
                'RESPONSE_TOO_LARGE',
                'Webhook receiver response exceeded maximum allowed size',
                { retryable: false, httpStatus: statusCode }
              )
            );
            try {
              res.destroy();
            } catch {}
            return;
          }
          // Discard chunk bytes immediately — never buffer, store, or log receiver body
        });

        res.on('error', (resErr) => {
          if (settled) {
            return;
          }
          if (resErr instanceof WebhookDeliveryError) {
            return finishWithError(resErr);
          }
          return finishWithError(
            new WebhookDeliveryError(
              'NETWORK_ERROR',
              'Network error while reading webhook response',
              { retryable: true, httpStatus: statusCode || null }
            )
          );
        });

        res.on('end', () => {
          if (settled) {
            return;
          }
          const rawRetryAfter =
            res.headers && typeof res.headers['retry-after'] === 'string'
              ? res.headers['retry-after'].trim()
              : null;

          finishWithSuccess({
            httpStatus: statusCode,
            retryAfterHeader: rawRetryAfter || null,
            pinnedAddress,
            pinnedFamily
          });
        });

        res.on('aborted', () => {
          if (!settled) {
            finishWithError(
              new WebhookDeliveryError(
                'NETWORK_ERROR',
                'Webhook response was prematurely aborted',
                { retryable: true, httpStatus: statusCode || null }
              )
            );
          }
        });
      });
    } catch (syncReqErr) {
      if (syncReqErr instanceof WebhookDeliveryError) {
        return finishWithError(syncReqErr);
      }
      return finishWithError(
        new WebhookDeliveryError(
          'NETWORK_ERROR',
          'Failed to initialize outbound webhook request',
          { retryable: true }
        )
      );
    }

    req.on('socket', (socket) => {
      socket.on('connect', () => {
        if (settled) {
          return;
        }
        // Defense-in-depth post-connect check: verify the connected remote IP is permitted
        if (
          socket.remoteAddress &&
          !allowLocalTargets &&
          isPrivateOrLoopbackIp(socket.remoteAddress)
        ) {
          finishWithError(
            new WebhookDeliveryError(
              'SSRF_BLOCKED_IP',
              'Connected socket remote address is prohibited',
              { retryable: false }
            )
          );
          try {
            socket.destroy();
          } catch {}
        }
      });
    });

    req.on('timeout', () => {
      finishWithError(
        new WebhookDeliveryError(
          'REQUEST_TIMEOUT',
          'Webhook socket timed out',
          { retryable: true }
        )
      );
    });

    req.on('error', (reqErr) => {
      if (settled) {
        return;
      }
      if (reqErr instanceof WebhookDeliveryError) {
        return finishWithError(reqErr);
      }
      if (isTlsVerificationError(reqErr)) {
        return finishWithError(
          new WebhookDeliveryError(
            'TLS_VERIFICATION_FAILED',
            'TLS certificate or hostname verification failed for webhook destination',
            { retryable: false }
          )
        );
      }
      if (reqErr && (reqErr.code === 'ETIMEDOUT' || reqErr.code === 'ESOCKETTIMEDOUT')) {
        return finishWithError(
          new WebhookDeliveryError(
            'REQUEST_TIMEOUT',
            'Webhook connection timed out',
            { retryable: true }
          )
        );
      }
      return finishWithError(
        new WebhookDeliveryError(
          'NETWORK_ERROR',
          'Outbound webhook network request failed',
          { retryable: true }
        )
      );
    });

    req.end(payloadBuffer);
  });
}

module.exports = {
  WebhookDeliveryError,
  DEFAULT_REQUEST_TIMEOUT_MS,
  MIN_REQUEST_TIMEOUT_MS,
  MAX_REQUEST_TIMEOUT_MS,
  DEFAULT_MAX_RESPONSE_BYTES,
  DEFAULT_DNS_TIMEOUT_MS,
  clampRequestTimeoutMs,
  resolveAndValidateWebhookTarget,
  sendPinnedWebhookRequest
};
