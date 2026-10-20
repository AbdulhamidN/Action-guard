/**
 * Sequence Pattern & Risk Analyzer (Sub-module 6.2)
 *
 * Pure analyzer that evaluates an active sequence of security events
 * against deterministic pattern rules defined in SEQUENCE_RULES.
 * Pure functions only — no persistence, no cache, no clock, no external dependencies.
 */

const riskConfig = require('../config/riskConfig');
const { RiskInputError } = require('../utils/riskScoring');

/**
 * Validates and stably sorts events by timestamp without mutating the input array.
 * Deliberately sorts a copy of the input stably by parsed timestamp (ties keep input order):
 * one out-of-order event must not make scoring unavailable for the rest of the sequence.
 *
 * @param {Array<object>} events - Array of plain event objects
 * @returns {Array<{ event: object, timestampMs: number, originalIndex: number }>}
 */
function parseAndSortEvents(events) {
  if (!Array.isArray(events)) {
    throw new RiskInputError('events must be an array');
  }

  const parsed = events.map((ev, index) => {
    if (!ev || typeof ev !== 'object') {
      throw new RiskInputError(`Event at index ${index} must be a non-null object`);
    }

    if (typeof ev.event_type !== 'string' || ev.event_type.trim() === '') {
      throw new RiskInputError(`Event at index ${index} must have a non-empty string event_type`);
    }

    if (ev.timestamp === undefined || ev.timestamp === null) {
      throw new RiskInputError(`Event at index ${index} must have a timestamp`);
    }

    const dateObj = new Date(ev.timestamp);
    const timeMs = dateObj.getTime();

    if (!Number.isFinite(timeMs) || Number.isNaN(timeMs)) {
      throw new RiskInputError(`Event at index ${index} has an unparseable timestamp: ${ev.timestamp}`);
    }

    return {
      event: ev,
      timestampMs: timeMs,
      originalIndex: index
    };
  });

  // Deliberate stable sort: ties maintain original input order
  parsed.sort((a, b) => {
    if (a.timestampMs !== b.timestampMs) {
      return a.timestampMs - b.timestampMs;
    }
    return a.originalIndex - b.originalIndex;
  });

  return parsed;
}

/**
 * Checks if an event qualifies as an untrusted login or device event.
 * Strict equality rules:
 * - event_type === 'new_device'
 * - event_type === 'login_success' AND (is_trusted_device === false OR is_new_device === true OR device_recognized === false)
 * Missing or undefined fields do NOT count as untrusted.
 *
 * @param {object} ev
 * @returns {boolean}
 */
function isUntrustedLoginOrDevice(ev) {
  if (ev.event_type === 'new_device') {
    return true;
  }
  if (ev.event_type === 'login_success') {
    return (
      ev.is_trusted_device === false ||
      ev.is_new_device === true ||
      ev.device_recognized === false
    );
  }
  return false;
}

/**
 * Evaluates an active sequence of security events against deterministic pattern rules.
 *
 * @param {Array<object>} events - Active event sequence
 * @param {object} [config=riskConfig] - Risk configuration object
 * @returns {{ matched_rules: Array<{ rule_id: string, points: number }> }}
 */
function analyzeSequence(events, config = riskConfig) {
  const sorted = parseAndSortEvents(events);
  const matched_rules = [];

  if (sorted.length === 0) {
    return { matched_rules };
  }

  const sequenceRules = config.SEQUENCE_RULES || {};

  // Rule 1: seq_rapid_credential_cascade
  // An event in {recovery_email_change, phone_number_change} at position i,
  // followed by an event in {password_change, password_reset} at position j (i < j),
  // with 0 <= t_j - t_i <= window_seconds (converted to milliseconds: e.g. 600s = 600,000ms = 10 minutes inclusive).
  if (sequenceRules.seq_rapid_credential_cascade) {
    const ruleConfig = sequenceRules.seq_rapid_credential_cascade;
    // Explicit unit conversion: window_seconds to milliseconds (default 600 s = 600,000 ms = 10 minutes)
    const windowMs = (ruleConfig.window_seconds ?? 600) * 1000;
    const initialTypes = ['recovery_email_change', 'phone_number_change'];
    const followUpTypes = ['password_change', 'password_reset'];

    let matched = false;
    for (let i = 0; i < sorted.length; i++) {
      if (initialTypes.includes(sorted[i].event.event_type)) {
        for (let j = i + 1; j < sorted.length; j++) {
          if (followUpTypes.includes(sorted[j].event.event_type)) {
            const timeDiff = sorted[j].timestampMs - sorted[i].timestampMs;
            if (timeDiff >= 0 && timeDiff <= windowMs) {
              matched = true;
              break;
            }
          }
        }
      }
      if (matched) break;
    }

    if (matched) {
      matched_rules.push({
        rule_id: 'seq_rapid_credential_cascade',
        points: ruleConfig.points
      });
    }
  }

  // Rule 2: seq_takeover_progression
  // Untrusted login/device at position i, then account modification at position j,
  // then high_impact_action at position k (i < j < k),
  // with t_k - t_i <= window_seconds (converted to milliseconds: e.g. 900s = 900,000ms = 15 minutes inclusive).
  if (sequenceRules.seq_takeover_progression) {
    const ruleConfig = sequenceRules.seq_takeover_progression;
    // Explicit unit conversion: window_seconds to milliseconds (default 900 s = 900,000 ms = 15 minutes)
    const windowMs = (ruleConfig.window_seconds ?? 900) * 1000;
    const accountModTypes = config.ACCOUNT_MODIFICATION_TYPES || [
      'recovery_email_change',
      'phone_number_change',
      'mfa_change',
      'password_change',
      'password_reset'
    ];

    let matched = false;
    for (let i = 0; i < sorted.length; i++) {
      if (isUntrustedLoginOrDevice(sorted[i].event)) {
        for (let j = i + 1; j < sorted.length; j++) {
          if (accountModTypes.includes(sorted[j].event.event_type)) {
            for (let k = j + 1; k < sorted.length; k++) {
              if (sorted[k].event.event_type === 'high_impact_action') {
                const totalSpan = sorted[k].timestampMs - sorted[i].timestampMs;
                if (totalSpan >= 0 && totalSpan <= windowMs) {
                  matched = true;
                  break;
                }
              }
            }
            if (matched) break;
          }
        }
        if (matched) break;
      }
    }

    if (matched) {
      matched_rules.push({
        rule_id: 'seq_takeover_progression',
        points: ruleConfig.points
      });
    }
  }

  // Rule 3: seq_auth_failure_burst
  // A login_success at position k preceded immediately by a run of at least failure_count (default 3)
  // consecutive events whose types are login_failed or verification_failed (any mix).
  // "Immediately" means adjacent in the ordered array; an unrelated event between the run and the success breaks it.
  if (sequenceRules.seq_auth_failure_burst) {
    const ruleConfig = sequenceRules.seq_auth_failure_burst;
    const minFailures = ruleConfig.failure_count ?? 3;
    // Unit conversion: window_seconds to milliseconds (default 900 s = 900,000 ms)
    const windowMs = (ruleConfig.window_seconds ?? 900) * 1000;

    let matched = false;
    for (let k = 0; k < sorted.length; k++) {
      if (sorted[k].event.event_type === 'login_success') {
        let failureCount = 0;
        for (let p = k - 1; p >= 0; p--) {
          const type = sorted[p].event.event_type;
          if (type === 'login_failed' || type === 'verification_failed') {
            failureCount++;
          } else {
            // Adjacent only — any unrelated event breaks the run
            break;
          }
        }

        if (failureCount >= minFailures) {
          // Check that the required failure run occurred within the configured window
          const runSpan = sorted[k].timestampMs - sorted[k - minFailures].timestampMs;
          if (runSpan >= 0 && runSpan <= windowMs) {
            matched = true;
            break;
          }
        }
      }
    }

    if (matched) {
      matched_rules.push({
        rule_id: 'seq_auth_failure_burst',
        points: ruleConfig.points
      });
    }
  }

  // Rule 4: seq_multi_factor_tampering
  // Both mfa_change and recovery_email_change appear anywhere in the sequence, in either order.
  if (sequenceRules.seq_multi_factor_tampering) {
    const ruleConfig = sequenceRules.seq_multi_factor_tampering;
    const hasMfa = sorted.some((item) => item.event.event_type === 'mfa_change');
    const hasRecovery = sorted.some((item) => item.event.event_type === 'recovery_email_change');

    if (hasMfa && hasRecovery) {
      matched_rules.push({
        rule_id: 'seq_multi_factor_tampering',
        points: ruleConfig.points
      });
    }
  }

  // Rule 5: seq_high_velocity_actions
  // At least action_count (default 4) events from SENSITIVE_ACTION_TYPES whose first-to-last span
  // is strictly less than window_seconds (converted to milliseconds: e.g. 180s = 180,000ms = 3 minutes).
  if (sequenceRules.seq_high_velocity_actions) {
    const ruleConfig = sequenceRules.seq_high_velocity_actions;
    const requiredCount = ruleConfig.action_count ?? 4;
    // Explicit unit conversion: window_seconds to milliseconds (default 180 s = 180,000 ms = 3 minutes)
    const windowMs = (ruleConfig.window_seconds ?? 180) * 1000;
    const sensitiveTypes = new Set(config.SENSITIVE_ACTION_TYPES || []);

    const sensitiveTimestamps = [];
    for (let i = 0; i < sorted.length; i++) {
      if (sensitiveTypes.has(sorted[i].event.event_type)) {
        sensitiveTimestamps.push(sorted[i].timestampMs);
      }
    }

    let matched = false;
    if (sensitiveTimestamps.length >= requiredCount) {
      for (let s = 0; s <= sensitiveTimestamps.length - requiredCount; s++) {
        const span = sensitiveTimestamps[s + requiredCount - 1] - sensitiveTimestamps[s];
        // Strictly less than windowMs (< 3 minutes)
        if (span >= 0 && span < windowMs) {
          matched = true;
          break;
        }
      }
    }

    if (matched) {
      matched_rules.push({
        rule_id: 'seq_high_velocity_actions',
        points: ruleConfig.points
      });
    }
  }

  return { matched_rules };
}

/**
 * Appends a proposed event to an existing sequence without mutating inputs.
 * Requires proposedEvent.timestamp (no clock reads).
 *
 * @param {Array<object>} events - Current sequence
 * @param {object} proposedEvent - Event to append
 * @returns {Array<object>} New array with copied events plus proposedEvent
 */
function appendProposedEvent(events, proposedEvent) {
  if (!Array.isArray(events)) {
    throw new RiskInputError('events must be an array');
  }

  if (!proposedEvent || typeof proposedEvent !== 'object') {
    throw new RiskInputError('proposedEvent must be a non-null object');
  }

  if (typeof proposedEvent.event_type !== 'string' || proposedEvent.event_type.trim() === '') {
    throw new RiskInputError('proposedEvent must have a non-empty string event_type');
  }

  if (proposedEvent.timestamp === undefined || proposedEvent.timestamp === null) {
    throw new RiskInputError('proposedEvent must have a timestamp');
  }

  const parsedTime = new Date(proposedEvent.timestamp).getTime();
  if (!Number.isFinite(parsedTime) || Number.isNaN(parsedTime)) {
    throw new RiskInputError(`proposedEvent has an unparseable timestamp: ${proposedEvent.timestamp}`);
  }

  return [
    ...events.map((e) => ({ ...e })),
    { ...proposedEvent }
  ];
}

module.exports = {
  analyzeSequence,
  appendProposedEvent
};
