'use strict';

const crypto = require('crypto');
const { ApiError } = require('./errors');

const AES_ALGORITHM = 'aes-256-gcm';
const IV_BYTE_LENGTH = 12; // 96-bit NIST recommended GCM IV
const AUTH_TAG_BYTE_LENGTH = 16; // 128-bit GCM authentication tag
const KEY_BYTE_LENGTH = 32; // 256-bit key
const MIN_RAW_KEY_LENGTH = 32;
const SECRET_RANDOM_BYTES = 32; // 256 bits -> 64 hex chars
const SECRET_PREFIX_HEX_CHARS = 8; // whsec_<8 hex chars> = 14 chars total

// Process-ephemeral key used ONLY in automated test runs (`NODE_ENV === 'test'`)
// when WEBHOOK_SECRET_ENCRYPTION_KEY is not explicitly configured.
// Never used in development or production, and never hardcoded.
let ephemeralTestEncryptionKey = null;

/**
 * Resets the in-memory test-only ephemeral key cache (used by tests to verify
 * key resolution and restart persistence semantics).
 */
function resetEphemeralTestEncryptionKey() {
  ephemeralTestEncryptionKey = null;
}

/**
 * Resolves and validates the 32-byte AES-256 encryption key used to protect
 * webhook signing secrets at rest.
 *
 * Security rules:
 * - Never falls back to JWT_SECRET or a hardcoded string.
 * - In development and production (`NODE_ENV !== 'test'`) or when
 *   `REQUIRE_WEBHOOK_ENCRYPTION_KEY === 'true'`, requires `WEBHOOK_SECRET_ENCRYPTION_KEY`
 *   (or `WEBHOOK_ENCRYPTION_KEY`) to be explicitly configured so persisted secrets
 *   remain decryptable across process restarts and future delivery-worker processes.
 * - Whenever a key is provided in any environment, validates minimum length/entropy:
 *   - 64-character hex string -> decoded directly to 32 bytes.
 *   - Base64 string that decodes to 32 bytes -> decoded directly to 32 bytes.
 *   - High-entropy string >= 32 characters -> derived via HKDF-SHA256 into a 32-byte key.
 *   - Any shorter or blank value fails closed with 503 `webhook_encryption_unavailable`.
 *
 * @param {NodeJS.ProcessEnv} [env=process.env]
 * @returns {Buffer} 32-byte encryption key buffer
 * @throws {ApiError} 503 `webhook_encryption_unavailable` when unconfigured or invalid
 */
function resolveWebhookEncryptionKey(env = process.env) {
  const rawKey =
    env.WEBHOOK_SECRET_ENCRYPTION_KEY !== undefined
      ? env.WEBHOOK_SECRET_ENCRYPTION_KEY
      : env.WEBHOOK_ENCRYPTION_KEY;

  const isConfigured =
    rawKey !== undefined && rawKey !== null && String(rawKey).trim() !== '';
  const isTestEnv = env.NODE_ENV === 'test';
  const mustRequireExplicitKey =
    !isTestEnv || env.REQUIRE_WEBHOOK_ENCRYPTION_KEY === 'true';

  if (mustRequireExplicitKey && !isConfigured) {
    throw new ApiError(
      503,
      'webhook_encryption_unavailable',
      'Webhook secret encryption key is not configured'
    );
  }

  if (isConfigured) {
    if (typeof rawKey !== 'string') {
      throw new ApiError(
        503,
        'webhook_encryption_unavailable',
        'Webhook secret encryption key configuration is invalid'
      );
    }

    const trimmed = rawKey.trim();
    if (trimmed.length < MIN_RAW_KEY_LENGTH) {
      throw new ApiError(
        503,
        'webhook_encryption_unavailable',
        'Webhook secret encryption key does not meet minimum length requirements'
      );
    }

    // 1. Exact 64-char hex string (32 bytes)
    if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
      return Buffer.from(trimmed, 'hex');
    }

    // 2. Base64-encoded 32-byte key (43 or 44 chars)
    if (/^[A-Za-z0-9+/]{43}=?$/.test(trimmed)) {
      const decoded = Buffer.from(trimmed, 'base64');
      if (decoded.length === KEY_BYTE_LENGTH) {
        return decoded;
      }
    }

    // 3. Passphrase / key material >= 32 chars derived via HKDF-SHA256
    return Buffer.from(
      crypto.hkdfSync(
        'sha256',
        Buffer.from(trimmed, 'utf8'),
        Buffer.from('actionguard:webhook_secret:salt:v1', 'utf8'),
        Buffer.from('actionguard:webhook_secret:aes256gcm:v1', 'utf8'),
        KEY_BYTE_LENGTH
      )
    );
  }

  // Automated test-only (`NODE_ENV === 'test'`) fallback: in-memory CSPRNG ephemeral key
  if (!ephemeralTestEncryptionKey) {
    ephemeralTestEncryptionKey = crypto.randomBytes(KEY_BYTE_LENGTH);
  }
  return ephemeralTestEncryptionKey;
}

/**
 * Generates a cryptographically strong server-side webhook signing secret
 * and its non-sensitive display prefix.
 *
 * @returns {{ secret: string, secret_prefix: string }}
 */
function generateWebhookSecret() {
  const randomHex = crypto.randomBytes(SECRET_RANDOM_BYTES).toString('hex');
  const secret = `whsec_${randomHex}`;
  const secret_prefix = `whsec_${randomHex.slice(0, SECRET_PREFIX_HEX_CHARS)}`;
  return {
    secret,
    secret_prefix
  };
}

/**
 * Encrypts a plaintext webhook signing secret using AES-256-GCM.
 *
 * @param {string} plaintextSecret
 * @param {NodeJS.ProcessEnv} [env=process.env]
 * @returns {{ encrypted_secret: string, secret_iv: string, secret_auth_tag: string }}
 * @throws {ApiError} 503 `webhook_encryption_unavailable` on key or encryption failure
 */
function encryptWebhookSecret(plaintextSecret, env = process.env) {
  if (typeof plaintextSecret !== 'string' || plaintextSecret.length === 0) {
    throw new ApiError(
      503,
      'webhook_encryption_unavailable',
      'Unable to encrypt webhook signing secret'
    );
  }

  const key = resolveWebhookEncryptionKey(env);

  try {
    const iv = crypto.randomBytes(IV_BYTE_LENGTH);
    const cipher = crypto.createCipheriv(AES_ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_BYTE_LENGTH
    });

    const encryptedBuffer = Buffer.concat([
      cipher.update(plaintextSecret, 'utf8'),
      cipher.final()
    ]);
    const authTag = cipher.getAuthTag();

    return {
      encrypted_secret: encryptedBuffer.toString('hex'),
      secret_iv: iv.toString('hex'),
      secret_auth_tag: authTag.toString('hex')
    };
  } catch (err) {
    if (err instanceof ApiError) {
      throw err;
    }
    throw new ApiError(
      503,
      'webhook_encryption_unavailable',
      'Unable to encrypt webhook signing secret'
    );
  }
}

/**
 * Decrypts a stored webhook signing secret using AES-256-GCM and verifies its
 * authentication tag.
 *
 * @param {object} record
 * @param {string} record.encrypted_secret
 * @param {string} record.secret_iv
 * @param {string} record.secret_auth_tag
 * @param {NodeJS.ProcessEnv} [env=process.env]
 * @returns {string} Decrypted plaintext signing secret
 * @throws {ApiError} 503 `webhook_encryption_unavailable` on key or authentication failure
 */
function decryptWebhookSecret(record, env = process.env) {
  if (
    !record ||
    typeof record.encrypted_secret !== 'string' ||
    typeof record.secret_iv !== 'string' ||
    typeof record.secret_auth_tag !== 'string' ||
    !/^[0-9a-fA-F]+$/.test(record.encrypted_secret) ||
    !/^[0-9a-fA-F]+$/.test(record.secret_iv) ||
    !/^[0-9a-fA-F]+$/.test(record.secret_auth_tag)
  ) {
    throw new ApiError(
      503,
      'webhook_encryption_unavailable',
      'Stored webhook secret metadata is invalid or corrupted'
    );
  }

  const key = resolveWebhookEncryptionKey(env);

  try {
    const iv = Buffer.from(record.secret_iv, 'hex');
    const authTag = Buffer.from(record.secret_auth_tag, 'hex');
    const ciphertext = Buffer.from(record.encrypted_secret, 'hex');

    if (
      iv.length !== IV_BYTE_LENGTH ||
      authTag.length !== AUTH_TAG_BYTE_LENGTH ||
      ciphertext.length === 0
    ) {
      throw new Error('Invalid IV, auth tag, or ciphertext length');
    }

    const decipher = crypto.createDecipheriv(AES_ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_BYTE_LENGTH
    });
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf8');
  } catch (err) {
    if (err instanceof ApiError) {
      throw err;
    }
    throw new ApiError(
      503,
      'webhook_encryption_unavailable',
      'Unable to decrypt webhook signing secret'
    );
  }
}

module.exports = {
  AES_ALGORITHM,
  IV_BYTE_LENGTH,
  AUTH_TAG_BYTE_LENGTH,
  KEY_BYTE_LENGTH,
  MIN_RAW_KEY_LENGTH,
  resetEphemeralTestEncryptionKey,
  resolveWebhookEncryptionKey,
  generateWebhookSecret,
  encryptWebhookSecret,
  decryptWebhookSecret
};
