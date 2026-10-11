'use strict';

/**
 * Centralized Session & Temporary Elevation Configuration.
 * Governs session dual-window lifetimes, throttling intervals,
 * and scoped elevation privilege boundaries.
 */

function parsePositiveInt(rawVal, defaultVal, settingName) {
  const str = rawVal !== undefined && rawVal !== '' ? String(rawVal) : String(defaultVal);
  if (!/^\d+$/.test(str.trim())) {
    throw new Error(`[SessionConfig] Invalid configuration for ${settingName}: expected positive integer, got '${rawVal}'`);
  }
  const num = Number.parseInt(str.trim(), 10);
  if (!Number.isSafeInteger(num) || num <= 0) {
    throw new Error(`[SessionConfig] Invalid configuration for ${settingName}: must be a positive integer > 0, got ${num}`);
  }
  return num;
}

function loadAndValidateSessionConfig(env = process.env) {
  const idleTimeoutSeconds = parsePositiveInt(
    env.SESSION_IDLE_TIMEOUT_SECONDS || env.SESSION_TTL_SECONDS,
    900,
    'SESSION_IDLE_TIMEOUT_SECONDS'
  );
  const maxSessionLifetimeSeconds = parsePositiveInt(
    env.MAX_SESSION_LIFETIME_SECONDS,
    28800,
    'MAX_SESSION_LIFETIME_SECONDS'
  );
  const renewalThrottleSeconds = parsePositiveInt(
    env.SESSION_RENEWAL_THROTTLE_SECONDS,
    30,
    'SESSION_RENEWAL_THROTTLE_SECONDS'
  );

  const defaultElevationDurationSeconds = parsePositiveInt(
    env.DEFAULT_ELEVATION_DURATION_SECONDS,
    300,
    'DEFAULT_ELEVATION_DURATION_SECONDS'
  );
  const maxElevationDurationSeconds = parsePositiveInt(
    env.MAX_ELEVATION_DURATION_SECONDS,
    900,
    'MAX_ELEVATION_DURATION_SECONDS'
  );
  const verificationTicketTtlSeconds = parsePositiveInt(
    env.VERIFICATION_TICKET_TTL_SECONDS,
    60,
    'VERIFICATION_TICKET_TTL_SECONDS'
  );
  const stepUpChallengeTtlSeconds = parsePositiveInt(
    env.STEP_UP_CHALLENGE_TTL_SECONDS,
    300,
    'STEP_UP_CHALLENGE_TTL_SECONDS'
  );
  const stepUpMaxAttempts = parsePositiveInt(
    env.STEP_UP_MAX_ATTEMPTS,
    3,
    'STEP_UP_MAX_ATTEMPTS'
  );
  const accountLockDurationSeconds = parsePositiveInt(
    env.ACCOUNT_LOCK_DURATION_SECONDS,
    900,
    'ACCOUNT_LOCK_DURATION_SECONDS'
  );

  if (idleTimeoutSeconds > maxSessionLifetimeSeconds) {
    throw new Error(
      `[SessionConfig] Configuration invariant violation: IDLE_TIMEOUT_SECONDS (${idleTimeoutSeconds}) cannot exceed MAX_SESSION_LIFETIME_SECONDS (${maxSessionLifetimeSeconds})`
    );
  }

  if (defaultElevationDurationSeconds > maxElevationDurationSeconds) {
    throw new Error(
      `[SessionConfig] Configuration invariant violation: DEFAULT_ELEVATION_DURATION_SECONDS (${defaultElevationDurationSeconds}) cannot exceed MAX_ELEVATION_DURATION_SECONDS (${maxElevationDurationSeconds})`
    );
  }

  return Object.freeze({
    IDLE_TIMEOUT_SECONDS: idleTimeoutSeconds,
    MAX_SESSION_LIFETIME_SECONDS: maxSessionLifetimeSeconds,
    RENEWAL_THROTTLE_SECONDS: renewalThrottleSeconds,
    DEFAULT_ELEVATION_DURATION_SECONDS: defaultElevationDurationSeconds,
    MAX_ELEVATION_DURATION_SECONDS: maxElevationDurationSeconds,
    VERIFICATION_TICKET_TTL_SECONDS: verificationTicketTtlSeconds,
    STEP_UP_CHALLENGE_TTL_SECONDS: stepUpChallengeTtlSeconds,
    STEP_UP_MAX_ATTEMPTS: stepUpMaxAttempts,
    ACCOUNT_LOCK_DURATION_SECONDS: accountLockDurationSeconds
  });
}

const validated = loadAndValidateSessionConfig(process.env);

// Allowlisted Elevation Scopes
const ALLOWLISTED_ELEVATION_SCOPES = Object.freeze([
  'sensitive_action',
  'credential_change',
  'account_recovery',
  'export_data',
  'admin_action'
]);

// Canonical mapping of protected action types to required elevation scopes
const ACTION_ELEVATION_SCOPE_MAP = Object.freeze({
  password_change: 'credential_change',
  mfa_change: 'credential_change',
  recovery_email_change: 'account_recovery',
  phone_number_change: 'account_recovery',
  high_impact_action: 'sensitive_action'
});

// Redis Key Namespaces
const REDIS_PREFIXES = Object.freeze({
  SESSION: 'session:',
  ELEVATION: 'elevation:session:',
  SESSION_ELEVATIONS_INDEX: 'session_elevations:',
  TICKET_CLAIM: 'ticket_used:',
  STEP_UP_CHALLENGE: 'step_up_challenge:',
  ACCOUNT_LOCK: 'account_lock:',
  COOLING_OFF_ACTION: 'cooling_off:action:',
  COOLING_OFF_USER_INDEX: 'cooling_off:user:',
  COOLING_OFF_TOKEN_MAP: 'cooling_off:token:',
  COOLING_OFF_LOCK: 'cooling_off:lock:'
});

module.exports = {
  IDLE_TIMEOUT_SECONDS: validated.IDLE_TIMEOUT_SECONDS,
  MAX_SESSION_LIFETIME_SECONDS: validated.MAX_SESSION_LIFETIME_SECONDS,
  RENEWAL_THROTTLE_SECONDS: validated.RENEWAL_THROTTLE_SECONDS,
  DEFAULT_ELEVATION_DURATION_SECONDS: validated.DEFAULT_ELEVATION_DURATION_SECONDS,
  MAX_ELEVATION_DURATION_SECONDS: validated.MAX_ELEVATION_DURATION_SECONDS,
  VERIFICATION_TICKET_TTL_SECONDS: validated.VERIFICATION_TICKET_TTL_SECONDS,
  STEP_UP_CHALLENGE_TTL_SECONDS: validated.STEP_UP_CHALLENGE_TTL_SECONDS,
  STEP_UP_MAX_ATTEMPTS: validated.STEP_UP_MAX_ATTEMPTS,
  ACCOUNT_LOCK_DURATION_SECONDS: validated.ACCOUNT_LOCK_DURATION_SECONDS,
  ALLOWLISTED_ELEVATION_SCOPES,
  ACTION_ELEVATION_SCOPE_MAP,
  REDIS_PREFIXES,
  loadAndValidateSessionConfig
};
