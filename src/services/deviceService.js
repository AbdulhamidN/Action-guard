const { Device } = require('../database/models');

const FINGERPRINT_REGEX = /^[a-zA-Z0-9_\-\.:]{4,255}$/;

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
 * Retrieves an existing device for a user or creates a new untrusted device record.
 * Preserves existing is_trusted value. Newly created devices are always is_trusted = false.
 *
 * @param {string} userId - Authenticated user's ID
 * @param {string} fingerprint - Validated device fingerprint
 * @returns {Promise<{ device: object, isNew: boolean }>}
 */
async function getOrCreateDevice(userId, fingerprint) {
  if (!userId || typeof userId !== 'string') {
    throw new Error('userId is required for device association');
  }

  if (!validateDeviceFingerprint(fingerprint)) {
    throw new Error('Invalid device fingerprint');
  }

  const normalizedFingerprint = fingerprint.trim();

  // Check if device is already known for this user
  const existingDevice = await Device.findOne({
    where: {
      user_id: userId,
      fingerprint: normalizedFingerprint
    }
  });

  if (existingDevice) {
    // Preserves existing is_trusted value; no schema activity field exists to update
    return {
      device: existingDevice,
      isNew: false
    };
  }

  // Create new untrusted device record
  const newDevice = await Device.create({
    user_id: userId,
    fingerprint: normalizedFingerprint,
    is_trusted: false,
    first_seen_at: new Date()
  });

  return {
    device: newDevice,
    isNew: true
  };
}

module.exports = {
  validateDeviceFingerprint,
  getOrCreateDevice
};
