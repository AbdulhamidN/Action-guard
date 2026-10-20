/**
 * Risk Configuration Module (PDP Core — Module 6.1)
 *
 * Authoritative, deeply frozen configuration holding all weights, caps,
 * tier thresholds, and rule parameters defined in the approved Module 6 design note.
 *
 * Pure configuration object — contains no logic, database queries, or environment lookups.
 */

function deepFreeze(obj) {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }
  Object.keys(obj).forEach((prop) => {
    if (typeof obj[prop] === 'object' && obj[prop] !== null && !Object.isFrozen(obj[prop])) {
      deepFreeze(obj[prop]);
    }
  });
  return Object.freeze(obj);
}

const rawConfig = {
  // Base risk values for all 13 supported event types
  BASE_RISK_MAP: {
    session_created: 0,
    session_terminated: 0,
    login_success: 5,
    verification_success: 0,
    login_failed: 10,
    verification_failed: 15,
    new_device: 10,
    phone_number_change: 15,
    recovery_email_change: 18,
    mfa_change: 20,
    password_change: 20,
    password_reset: 20,
    high_impact_action: 22
  },

  // Action sensitivity modifiers
  SENSITIVITY_MODIFIERS: {
    low: 0,
    medium: 0,
    high: 3,
    critical: 5
  },

  // Context signal weights
  CONTEXT_WEIGHTS: {
    unrecognized_device: 10,
    unrecognized_country: 10,
    impossible_travel: 20
  },

  // Category ceilings ensuring maximum potential sum equals exactly 100
  CATEGORY_CAPS: {
    base_action: 25,
    context: 25,
    sequence: 25,
    timing: 10,
    baseline: 15
  },

  // Timing automation risk weight
  TIMING_WEIGHT: 10,

  // Baseline deviation scaling factor (multiplier for deviation_score [0, 1])
  BASELINE_SCALE: 15,

  // Step-up verification confidence parameters
  VERIFICATION: {
    max: 30,
    window_seconds: 900
  },

  // Risk tier thresholds
  TIER_THRESHOLDS: {
    medium: 30,
    high: 60,
    critical: 80
  },

  // Sensitive and account modification action sets (used by Sequence Rules)
  SENSITIVE_ACTION_TYPES: [
    'password_change',
    'password_reset',
    'recovery_email_change',
    'phone_number_change',
    'mfa_change',
    'high_impact_action'
  ],

  ACCOUNT_MODIFICATION_TYPES: [
    'recovery_email_change',
    'phone_number_change',
    'mfa_change',
    'password_change',
    'password_reset'
  ],

  // Deterministic sequence rule parameters (data-only for 6.2 matcher)
  SEQUENCE_RULES: {
    seq_rapid_credential_cascade: {
      rule_id: 'seq_rapid_credential_cascade',
      points: 20,
      window_seconds: 600
    },
    seq_takeover_progression: {
      rule_id: 'seq_takeover_progression',
      points: 25,
      window_seconds: 900
    },
    seq_auth_failure_burst: {
      rule_id: 'seq_auth_failure_burst',
      points: 15,
      failure_count: 3,
      window_seconds: 900
    },
    seq_multi_factor_tampering: {
      rule_id: 'seq_multi_factor_tampering',
      points: 15,
      window_seconds: 900
    },
    seq_high_velocity_actions: {
      rule_id: 'seq_high_velocity_actions',
      points: 10,
      action_count: 4,
      window_seconds: 180
    }
  },

  // Housekeeping event types excluded from scoring / risk assessment creation
  UNSCORED_EVENT_TYPES: [
    'session_created',
    'session_terminated'
  ]
};

const riskConfig = deepFreeze(rawConfig);

module.exports = riskConfig;
