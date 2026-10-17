/**
 * @fileoverview Device fingerprint generation service.
 * Uses FingerprintJS to derive an identifier for Zero Trust device recognition.
 * In DEV mode only, permits a localStorage override key (ag_fp_override) for testing.
 * The override is strictly eliminated from production builds.
 */

import FingerprintJS from '@fingerprintjs/fingerprintjs';

/**
 * Resolves the device fingerprint for the current client.
 *
 * @returns {Promise<string>} Validated visitor fingerprint string
 */
export async function getDeviceFingerprint() {
  if (import.meta.env.DEV) {
    try {
      const override = localStorage.getItem('ag_fp_override');
      if (override && typeof override === 'string' && override.trim().length >= 4) {
        return override.trim();
      }
    } catch {
      // Ignore storage errors in dev
    }
  }

  const fp = await FingerprintJS.load();
  const result = await fp.get();
  return result.visitorId;
}
