'use strict';

const { Device } = require('../database/models');

const FINGERPRINT_REGEX = /^[a-zA-Z0-9_\-\.:]{4,255}$/;
const MAX_DEVICE_LABEL_LENGTH = 100;
const DEFAULT_DEVICE_TRUST_TTL_DAYS = 30;
const DEFAULT_DEVICE_TRUST_TTL_SECONDS = DEFAULT_DEVICE_TRUST_TTL_DAYS * 24 * 60 * 60;

/**
 * Validates whether a device fingerprint is safe, non-empty, and bounded.
 *
 * @param {any} fingerprint - Untrusted input
 * @returns {boolean} True if fingerprint satisfies length and character constraints
 */
function validateDeviceFingerprint(fingerprint) {
  if (typeof fingerprint !== 'string') {
    return false;
  }

  const trimmed = fingerprint.trim();
  if (trimmed.length < 4 || trimmed.length > 255) {
    return false;
  }

  return FINGERPRINT_REGEX.test(trimmed);
}

/**
 * Validates an optional human-readable device label.
 * Allows null/undefined (unlabeled). Rejects non-string, empty, oversized,
 * or control-character containing strings.
 *
 * @param {any} label - Untrusted label
 * @returns {boolean}
 */
function validateDeviceLabel(label) {
  if (label === null || label === undefined) {
    return true;
  }
  if (typeof label !== 'string') {
    return false;
  }
  const trimmed = label.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_DEVICE_LABEL_LENGTH) {
    return false;
  }
  // Reject control characters (0x00-0x1F, 0x7F)
  if (/[\x00-\x1F\x7F]/.test(trimmed)) {
    return false;
  }
  return true;
}

/**
 * Safely parses Date, finite numeric timestamp, or non-empty date string.
 * Returns timestamp in milliseconds, null if input was null/undefined, or NaN if malformed.
 *
 * @param {any} val - Untrusted date/timestamp input
 * @returns {number|null} Timestamp ms, null if absent, or NaN if invalid
 */
function parseTimestamp(val) {
  if (val === null || val === undefined) {
    return null;
  }
  if (val instanceof Date) {
    const t = val.getTime();
    return Number.isNaN(t) ? NaN : t;
  }
  if (typeof val === 'number') {
    return Number.isFinite(val) ? val : NaN;
  }
  if (typeof val === 'string' && val.trim().length > 0) {
    const t = new Date(val).getTime();
    return Number.isNaN(t) ? NaN : t;
  }
  return NaN;
}

/**
 * Determines whether device trust is currently active.
 *
 * Strict criteria:
 * 1. device must be a valid object.
 * 2. device.is_trusted must be explicitly true.
 * 3. device.revoked_at must be null/undefined.
 * 4. now must parse to a valid timestamp.
 * 5. device.expires_at must exist and parse to a valid timestamp strictly later than now.
 * 6. If device.trusted_at is present, it must parse to a valid timestamp not in the future.
 *
 * @param {object|Device} device - Device record or instance
 * @param {Date|number|string} [now=new Date()] - Reference time for validation
 * @returns {boolean}
 */
function isDeviceTrustActive(device, now = new Date()) {
  if (!device || typeof device !== 'object') {
    return false;
  }

  if (device.is_trusted !== true) {
    return false;
  }

  if (device.revoked_at !== null && device.revoked_at !== undefined) {
    return false;
  }

  const nowMs = parseTimestamp(now);
  if (nowMs === null || Number.isNaN(nowMs)) {
    return false;
  }

  if (device.expires_at === null || device.expires_at === undefined) {
    return false;
  }

  const expiresMs = parseTimestamp(device.expires_at);
  if (expiresMs === null || Number.isNaN(expiresMs) || nowMs >= expiresMs) {
    return false;
  }

  if (device.trusted_at !== null && device.trusted_at !== undefined) {
    const trustedMs = parseTimestamp(device.trusted_at);
    if (trustedMs === null || Number.isNaN(trustedMs) || trustedMs > nowMs) {
      return false;
    }
  }

  return true;
}

/**
 * Retrieves an existing device for a user or creates a new untrusted device record.
 * Preserves existing is_trusted value. Newly created devices are always is_trusted = false.
 * Handles concurrent insert attempts safely via unique constraint handling.
 *
 * @param {string} userId - Authenticated user's ID
 * @param {string} fingerprint - Validated device fingerprint
 * @param {object} [options={}]
 * @returns {Promise<{ device: object, isNew: boolean }>}
 */
async function getOrCreateDevice(userId, fingerprint, options = {}) {
  if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
    const err = new Error('userId is required for device association');
    err.code = 'INVALID_INPUT';
    throw err;
  }

  if (!validateDeviceFingerprint(fingerprint)) {
    const err = new Error('Invalid device fingerprint');
    err.code = 'INVALID_FINGERPRINT';
    throw err;
  }

  const normalizedFingerprint = fingerprint.trim();

  // 1. Check if device is already known for this user
  const existingDevice = await Device.findOne({
    where: {
      user_id: userId,
      fingerprint: normalizedFingerprint
    }
  });

  if (existingDevice) {
    return {
      device: existingDevice,
      isNew: false
    };
  }

  // 2. Attempt to create new untrusted device record
  const now = options.now instanceof Date ? options.now : new Date();
  try {
    const newDevice = await Device.create({
      user_id: userId,
      fingerprint: normalizedFingerprint,
      is_trusted: false,
      first_seen_at: now
    });

    return {
      device: newDevice,
      isNew: true
    };
  } catch (createErr) {
    // Concurrency guard: if another request created the record concurrently, return it
    if (
      createErr.name === 'SequelizeUniqueConstraintError' ||
      createErr.code === 'ER_DUP_ENTRY'
    ) {
      const concurrentDevice = await Device.findOne({
        where: {
          user_id: userId,
          fingerprint: normalizedFingerprint
        }
      });
      if (concurrentDevice) {
        return {
          device: concurrentDevice,
          isNew: false
        };
      }
    }
    throw createErr;
  }
}

/**
 * Enrolls an existing device belonging to a user as trusted.
 * Sets trusted_at to now, clears revoked_at, and sets a fixed expiration (30 days default).
 * Ordinary user activity must not silently extend this expiry.
 *
 * @param {object} params
 * @param {string} params.userId - Authenticated user's ID
 * @param {string} params.deviceId - Target Device ID
 * @param {string|null} [params.label=null] - Optional device label (e.g. "Work Laptop")
 * @param {Date|number} [params.now=new Date()] - Reference timestamp
 * @param {number} [params.ttlDays=DEFAULT_DEVICE_TRUST_TTL_DAYS] - Trust duration in days
 * @param {string|null} [params.currentDeviceId=null] - Device ID from authenticated session context
 * @param {object|null} [params.session=null] - Authenticated session object containing device_id
 * @returns {Promise<{ device: object, is_trust_active: boolean }>}
 */
async function enrollTrustedDevice({
  userId,
  deviceId,
  label = null,
  now = new Date(),
  ttlDays = DEFAULT_DEVICE_TRUST_TTL_DAYS,
  currentDeviceId = null,
  session = null
}) {
  if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
    const err = new Error('userId is required for trusted device enrollment');
    err.code = 'INVALID_INPUT';
    err.status = 400;
    throw err;
  }

  if (!deviceId || typeof deviceId !== 'string' || deviceId.trim().length === 0) {
    const err = new Error('deviceId is required for trusted device enrollment');
    err.code = 'INVALID_INPUT';
    err.status = 400;
    throw err;
  }

  // Session-to-device binding verification:
  // currentDeviceId / session.device_id must originate strictly from trusted server-side
  // authenticated session context (e.g. req.session.device_id), NEVER from client request payload.
  const sessionDeviceId = session && typeof session === 'object' ? session.device_id : null;
  const effectiveCurrentDeviceId = sessionDeviceId || currentDeviceId;
  if (effectiveCurrentDeviceId !== null && effectiveCurrentDeviceId !== undefined) {
    if (typeof effectiveCurrentDeviceId !== 'string' || effectiveCurrentDeviceId.trim() !== deviceId) {
      const err = new Error('Device does not match the active session device');
      err.code = 'DEVICE_SESSION_MISMATCH';
      err.status = 403;
      throw err;
    }
  }

  if (!validateDeviceLabel(label)) {
    const err = new Error('Invalid device label: must be between 1 and 100 characters without control characters');
    err.code = 'INVALID_LABEL';
    err.status = 400;
    throw err;
  }

  if (
    typeof ttlDays !== 'number' ||
    !Number.isInteger(ttlDays) ||
    ttlDays <= 0 ||
    ttlDays > DEFAULT_DEVICE_TRUST_TTL_DAYS
  ) {
    const err = new Error(`ttlDays must be an integer between 1 and ${DEFAULT_DEVICE_TRUST_TTL_DAYS} days`);
    err.code = 'INVALID_INPUT';
    err.status = 400;
    throw err;
  }

  const targetDevice = await Device.findByPk(deviceId);
  if (!targetDevice) {
    const err = new Error('Device not found');
    err.code = 'DEVICE_NOT_FOUND';
    err.status = 404;
    throw err;
  }

  if (targetDevice.user_id !== userId) {
    const err = new Error('Device does not belong to the authenticated user');
    err.code = 'DEVICE_OWNERSHIP_MISMATCH';
    err.status = 403;
    throw err;
  }

  const nowMs = parseTimestamp(now);
  if (nowMs === null || Number.isNaN(nowMs)) {
    const err = new Error('Invalid timestamp provided for enrollment');
    err.code = 'INVALID_INPUT';
    err.status = 400;
    throw err;
  }
  const nowDate = new Date(nowMs);

  const expiresAt = new Date(nowDate.getTime() + ttlDays * 24 * 60 * 60 * 1000);

  targetDevice.is_trusted = true;
  targetDevice.trusted_at = nowDate;
  targetDevice.expires_at = expiresAt;
  targetDevice.revoked_at = null; // Re-enrolling clears prior revocation
  if (label !== undefined && label !== null) {
    targetDevice.label = label.trim();
  }

  await targetDevice.save();

  return {
    device: targetDevice,
    is_trust_active: true
  };
}

/**
 * Revokes trust for a user's device.
 * Sets is_trusted to false and records revoked_at.
 * Repeated revocations are handled safely and idempotently.
 *
 * @param {object} params
 * @param {string} params.userId - Authenticated user's ID
 * @param {string} params.deviceId - Target Device ID
 * @param {Date|number|string} [params.now=new Date()] - Reference timestamp
 * @returns {Promise<{ device: object, alreadyRevoked: boolean, is_trust_active: boolean }>}
 */
async function revokeDeviceTrust({ userId, deviceId, now = new Date() }) {
  if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
    const err = new Error('userId is required for device trust revocation');
    err.code = 'INVALID_INPUT';
    err.status = 400;
    throw err;
  }

  if (!deviceId || typeof deviceId !== 'string' || deviceId.trim().length === 0) {
    const err = new Error('deviceId is required for device trust revocation');
    err.code = 'INVALID_INPUT';
    err.status = 400;
    throw err;
  }

  const nowMs = parseTimestamp(now);
  if (nowMs === null || Number.isNaN(nowMs)) {
    const err = new Error('Invalid timestamp provided for revocation');
    err.code = 'INVALID_INPUT';
    err.status = 400;
    throw err;
  }
  const nowDate = new Date(nowMs);

  const targetDevice = await Device.findByPk(deviceId);
  if (!targetDevice) {
    const err = new Error('Device not found');
    err.code = 'DEVICE_NOT_FOUND';
    err.status = 404;
    throw err;
  }

  if (targetDevice.user_id !== userId) {
    const err = new Error('Device does not belong to the authenticated user');
    err.code = 'DEVICE_OWNERSHIP_MISMATCH';
    err.status = 403;
    throw err;
  }

  // Idempotency: if already revoked
  if (targetDevice.revoked_at !== null && targetDevice.revoked_at !== undefined) {
    return {
      device: targetDevice,
      alreadyRevoked: true,
      is_trust_active: false
    };
  }

  targetDevice.is_trusted = false;
  targetDevice.revoked_at = nowDate;

  await targetDevice.save();

  return {
    device: targetDevice,
    alreadyRevoked: false,
    is_trust_active: false
  };
}

/**
 * Updates last_used_at for a device.
 * CRITICAL INVARIANT: Updating last_used_at must NEVER extend the trust expires_at.
 *
 * @param {string} deviceId - Target Device ID
 * @param {Date|number} [now=new Date()] - Current timestamp
 * @returns {Promise<object|null>} Updated device or null if not found
 */
async function updateDeviceLastUsed(deviceId, now = new Date()) {
  if (!deviceId || typeof deviceId !== 'string') {
    return null;
  }

  const targetDevice = await Device.findByPk(deviceId);
  if (!targetDevice) {
    return null;
  }

  const nowDate = now instanceof Date ? now : new Date(now);
  if (Number.isNaN(nowDate.getTime())) {
    return null;
  }

  // Preserve existing expires_at untouched
  targetDevice.last_used_at = nowDate;
  await targetDevice.save();

  return targetDevice;
}

/**
 * Lists all devices associated with a user, enriched with their live trust state.
 *
 * @param {string} userId - Target User ID
 * @param {object} [options={}]
 * @param {Date|number} [options.now=new Date()] - Reference timestamp
 * @returns {Promise<Array<object>>}
 */
async function listUserDevices(userId, options = {}) {
  if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
    const err = new Error('userId is required to list devices');
    err.code = 'INVALID_INPUT';
    throw err;
  }

  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());

  const devices = await Device.findAll({
    where: { user_id: userId },
    order: [
      ['last_used_at', 'DESC'],
      ['first_seen_at', 'DESC']
    ]
  });

  return devices.map((d) => {
    const plain = d.toJSON ? d.toJSON() : { ...d };
    delete plain.fingerprint;
    plain.is_trust_active = isDeviceTrustActive(d, now);
    return plain;
  });
}

/**
 * Checks whether a specific fingerprint is currently trusted for a user.
 *
 * @param {string} userId - Authenticated user's ID
 * @param {string} fingerprint - Device fingerprint
 * @param {Date|number} [now=new Date()] - Reference timestamp
 * @returns {Promise<boolean>}
 */
async function isUserDeviceTrusted(userId, fingerprint, now = new Date()) {
  if (!userId || !fingerprint || !validateDeviceFingerprint(fingerprint)) {
    return false;
  }

  const device = await Device.findOne({
    where: {
      user_id: userId,
      fingerprint: fingerprint.trim()
    }
  });

  if (!device) {
    return false;
  }

  return isDeviceTrustActive(device, now);
}

module.exports = {
  validateDeviceFingerprint,
  validateDeviceLabel,
  isDeviceTrustActive,
  getOrCreateDevice,
  enrollTrustedDevice,
  revokeDeviceTrust,
  updateDeviceLastUsed,
  listUserDevices,
  isUserDeviceTrusted,
  DEFAULT_DEVICE_TRUST_TTL_DAYS,
  DEFAULT_DEVICE_TRUST_TTL_SECONDS,
  MAX_DEVICE_LABEL_LENGTH
};
