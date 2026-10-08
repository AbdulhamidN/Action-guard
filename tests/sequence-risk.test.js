/**
 * Unit & Integration Tests for Sequence Pattern & Risk Analyzer (Sub-module 6.2)
 *
 * Verifies deterministic sequence rule pattern matching, boundary conditions,
 * untrusted login/device criteria, sorting stability, immutability, validation,
 * purity, and end-to-end integration with the Sub-module 6.1 scoring engine.
 */

const fs = require('fs');
const path = require('path');
const riskConfig = require('../src/config/riskConfig');
const { scoreRisk, RiskInputError } = require('../src/utils/riskScoring');
const {
  analyzeSequence,
  appendProposedEvent
} = require('../src/services/sequenceRiskService');

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

describe('Sub-module 6.2 — Sequence Pattern & Risk Analyzer', () => {
  const baseTime = new Date('2026-10-08T10:00:00.000Z').getTime();

  describe('1. Rule 1: seq_rapid_credential_cascade', () => {
    test('positive case: recovery_email_change followed by password_change within window', () => {
      const events = [
        { event_type: 'recovery_email_change', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'password_change', timestamp: new Date(baseTime + 5 * 60 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules).toEqual([
        { rule_id: 'seq_rapid_credential_cascade', points: 20 }
      ]);
    });

    test('positive case: phone_number_change followed by password_reset within window', () => {
      const events = [
        { event_type: 'phone_number_change', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'password_reset', timestamp: new Date(baseTime + 2 * 60 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules).toEqual([
        { rule_id: 'seq_rapid_credential_cascade', points: 20 }
      ]);
    });

    test('boundary: exactly 10:00 (600 s) matches', () => {
      const events = [
        { event_type: 'recovery_email_change', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'password_change', timestamp: new Date(baseTime + 600 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules).toEqual([
        { rule_id: 'seq_rapid_credential_cascade', points: 20 }
      ]);
    });

    test('boundary: 10:01 (601 s) does not match', () => {
      const events = [
        { event_type: 'recovery_email_change', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'password_change', timestamp: new Date(baseTime + 601 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules).toEqual([]);
    });

    test('wrong order: password_change followed by recovery_email_change does not match', () => {
      const events = [
        { event_type: 'password_change', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'recovery_email_change', timestamp: new Date(baseTime + 2 * 60 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules).toEqual([]);
    });
  });

  describe('2. Rule 2: seq_takeover_progression & Untrusted Login Criteria', () => {
    test('positive case: untrusted login, then account mod, then high_impact_action within 900 s', () => {
      const events = [
        { event_type: 'login_success', is_new_device: true, timestamp: new Date(baseTime).toISOString() },
        { event_type: 'recovery_email_change', timestamp: new Date(baseTime + 3 * 60 * 1000).toISOString() },
        { event_type: 'high_impact_action', timestamp: new Date(baseTime + 10 * 60 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      const rule = result.matched_rules.find((r) => r.rule_id === 'seq_takeover_progression');
      expect(rule).toEqual({ rule_id: 'seq_takeover_progression', points: 25 });
    });

    test('untrusted criterion 1: new_device alone triggers untrusted', () => {
      const events = [
        { event_type: 'new_device', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'mfa_change', timestamp: new Date(baseTime + 2 * 60 * 1000).toISOString() },
        { event_type: 'high_impact_action', timestamp: new Date(baseTime + 5 * 60 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules).toContainEqual({ rule_id: 'seq_takeover_progression', points: 25 });
    });

    test('untrusted criterion 2: login_success with is_trusted_device === false', () => {
      const events = [
        { event_type: 'login_success', is_trusted_device: false, timestamp: new Date(baseTime).toISOString() },
        { event_type: 'password_change', timestamp: new Date(baseTime + 2 * 60 * 1000).toISOString() },
        { event_type: 'high_impact_action', timestamp: new Date(baseTime + 5 * 60 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules).toContainEqual({ rule_id: 'seq_takeover_progression', points: 25 });
    });

    test('untrusted criterion 3: login_success with is_new_device === true', () => {
      const events = [
        { event_type: 'login_success', is_new_device: true, timestamp: new Date(baseTime).toISOString() },
        { event_type: 'phone_number_change', timestamp: new Date(baseTime + 2 * 60 * 1000).toISOString() },
        { event_type: 'high_impact_action', timestamp: new Date(baseTime + 5 * 60 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules).toContainEqual({ rule_id: 'seq_takeover_progression', points: 25 });
    });

    test('untrusted criterion 4: login_success with device_recognized === false', () => {
      const events = [
        { event_type: 'login_success', device_recognized: false, timestamp: new Date(baseTime).toISOString() },
        { event_type: 'password_reset', timestamp: new Date(baseTime + 2 * 60 * 1000).toISOString() },
        { event_type: 'high_impact_action', timestamp: new Date(baseTime + 5 * 60 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules).toContainEqual({ rule_id: 'seq_takeover_progression', points: 25 });
    });

    test('missing/undefined fields do NOT count as untrusted', () => {
      const events = [
        { event_type: 'login_success', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'recovery_email_change', timestamp: new Date(baseTime + 2 * 60 * 1000).toISOString() },
        { event_type: 'high_impact_action', timestamp: new Date(baseTime + 5 * 60 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules.some((r) => r.rule_id === 'seq_takeover_progression')).toBe(false);
    });

    test('boundary: span exactly 900 s matches, 901 s does not', () => {
      const eventsAt900 = [
        { event_type: 'new_device', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'mfa_change', timestamp: new Date(baseTime + 400 * 1000).toISOString() },
        { event_type: 'high_impact_action', timestamp: new Date(baseTime + 900 * 1000).toISOString() }
      ];
      expect(analyzeSequence(eventsAt900).matched_rules).toContainEqual({
        rule_id: 'seq_takeover_progression',
        points: 25
      });

      const eventsAt901 = [
        { event_type: 'new_device', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'mfa_change', timestamp: new Date(baseTime + 400 * 1000).toISOString() },
        { event_type: 'high_impact_action', timestamp: new Date(baseTime + 901 * 1000).toISOString() }
      ];
      expect(analyzeSequence(eventsAt901).matched_rules.some((r) => r.rule_id === 'seq_takeover_progression')).toBe(false);
    });

    test('wrong order: high_impact_action before account modification does not match', () => {
      const events = [
        { event_type: 'new_device', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'high_impact_action', timestamp: new Date(baseTime + 2 * 60 * 1000).toISOString() },
        { event_type: 'password_change', timestamp: new Date(baseTime + 5 * 60 * 1000).toISOString() }
      ];
      expect(analyzeSequence(events).matched_rules.some((r) => r.rule_id === 'seq_takeover_progression')).toBe(false);
    });
  });

  describe('3. Rule 3: seq_auth_failure_burst', () => {
    test('positive case: exactly 3 consecutive login_failed immediately preceding login_success', () => {
      const events = [
        { event_type: 'login_failed', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'login_failed', timestamp: new Date(baseTime + 10 * 1000).toISOString() },
        { event_type: 'login_failed', timestamp: new Date(baseTime + 20 * 1000).toISOString() },
        { event_type: 'login_success', timestamp: new Date(baseTime + 30 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules).toEqual([
        { rule_id: 'seq_auth_failure_burst', points: 15 }
      ]);
    });

    test('boundary: exactly 2 failures does not match', () => {
      const events = [
        { event_type: 'login_failed', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'login_failed', timestamp: new Date(baseTime + 10 * 1000).toISOString() },
        { event_type: 'login_success', timestamp: new Date(baseTime + 20 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules).toEqual([]);
    });

    test('mix of login_failed and verification_failed counts toward failure run', () => {
      const events = [
        { event_type: 'login_failed', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'verification_failed', timestamp: new Date(baseTime + 10 * 1000).toISOString() },
        { event_type: 'login_failed', timestamp: new Date(baseTime + 20 * 1000).toISOString() },
        { event_type: 'login_success', timestamp: new Date(baseTime + 30 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules).toEqual([
        { rule_id: 'seq_auth_failure_burst', points: 15 }
      ]);
    });

    test('an unrelated event between the failures and the success breaks adjacency', () => {
      const events = [
        { event_type: 'login_failed', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'login_failed', timestamp: new Date(baseTime + 10 * 1000).toISOString() },
        { event_type: 'login_failed', timestamp: new Date(baseTime + 20 * 1000).toISOString() },
        { event_type: 'session_created', timestamp: new Date(baseTime + 25 * 1000).toISOString() },
        { event_type: 'login_success', timestamp: new Date(baseTime + 30 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules).toEqual([]);
    });

    test('failures occurring after the login_success do not match', () => {
      const events = [
        { event_type: 'login_success', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'login_failed', timestamp: new Date(baseTime + 10 * 1000).toISOString() },
        { event_type: 'login_failed', timestamp: new Date(baseTime + 20 * 1000).toISOString() },
        { event_type: 'login_failed', timestamp: new Date(baseTime + 30 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules).toEqual([]);
    });
  });

  describe('4. Rule 4: seq_multi_factor_tampering', () => {
    test('positive case: mfa_change followed by recovery_email_change', () => {
      const events = [
        { event_type: 'mfa_change', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'recovery_email_change', timestamp: new Date(baseTime + 2 * 60 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules).toEqual([
        { rule_id: 'seq_multi_factor_tampering', points: 15 }
      ]);
    });

    test('positive case: recovery_email_change followed by mfa_change (reverse order)', () => {
      const events = [
        { event_type: 'recovery_email_change', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'mfa_change', timestamp: new Date(baseTime + 2 * 60 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules).toEqual([
        { rule_id: 'seq_multi_factor_tampering', points: 15 }
      ]);
    });

    test('only mfa_change alone does not match', () => {
      const events = [
        { event_type: 'mfa_change', timestamp: new Date(baseTime).toISOString() }
      ];
      expect(analyzeSequence(events).matched_rules).toEqual([]);
    });

    test('only recovery_email_change alone does not match', () => {
      const events = [
        { event_type: 'recovery_email_change', timestamp: new Date(baseTime).toISOString() }
      ];
      expect(analyzeSequence(events).matched_rules).toEqual([]);
    });
  });

  describe('5. Rule 5: seq_high_velocity_actions', () => {
    test('positive case: 4 sensitive actions spanning 120 s (< 180 s)', () => {
      const events = [
        { event_type: 'password_change', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'recovery_email_change', timestamp: new Date(baseTime + 30 * 1000).toISOString() },
        { event_type: 'mfa_change', timestamp: new Date(baseTime + 60 * 1000).toISOString() },
        { event_type: 'high_impact_action', timestamp: new Date(baseTime + 120 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules).toContainEqual({
        rule_id: 'seq_high_velocity_actions',
        points: 10
      });
    });

    test('boundary: 4 events spanning exactly 179 s matches (< 180 s)', () => {
      const events = [
        { event_type: 'phone_number_change', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'password_reset', timestamp: new Date(baseTime + 50 * 1000).toISOString() },
        { event_type: 'mfa_change', timestamp: new Date(baseTime + 100 * 1000).toISOString() },
        { event_type: 'high_impact_action', timestamp: new Date(baseTime + 179 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules).toContainEqual({
        rule_id: 'seq_high_velocity_actions',
        points: 10
      });
    });

    test('boundary: 4 events spanning exactly 180 s does not match', () => {
      const events = [
        { event_type: 'phone_number_change', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'password_reset', timestamp: new Date(baseTime + 50 * 1000).toISOString() },
        { event_type: 'mfa_change', timestamp: new Date(baseTime + 100 * 1000).toISOString() },
        { event_type: 'high_impact_action', timestamp: new Date(baseTime + 180 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules.some((r) => r.rule_id === 'seq_high_velocity_actions')).toBe(false);
    });

    test('fewer than 4 sensitive events does not match even if fast', () => {
      const events = [
        { event_type: 'phone_number_change', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'password_reset', timestamp: new Date(baseTime + 10 * 1000).toISOString() },
        { event_type: 'mfa_change', timestamp: new Date(baseTime + 20 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);
      expect(result.matched_rules.some((r) => r.rule_id === 'seq_high_velocity_actions')).toBe(false);
    });
  });

  describe('6. Ordering, Immutability & Multi-Rule Match Order', () => {
    test('several matching rules come back in SEQUENCE_RULES order, each once', () => {
      // Constructs a sequence matching cascade (rule 1), takeover (rule 2), and velocity (rule 5)
      const events = [
        { event_type: 'login_success', is_new_device: true, timestamp: new Date(baseTime).toISOString() },
        { event_type: 'recovery_email_change', timestamp: new Date(baseTime + 10 * 1000).toISOString() },
        { event_type: 'password_change', timestamp: new Date(baseTime + 20 * 1000).toISOString() },
        { event_type: 'mfa_change', timestamp: new Date(baseTime + 30 * 1000).toISOString() },
        { event_type: 'high_impact_action', timestamp: new Date(baseTime + 40 * 1000).toISOString() }
      ];
      const result = analyzeSequence(events);

      const matchedRuleIds = result.matched_rules.map((r) => r.rule_id);
      expect(matchedRuleIds).toEqual([
        'seq_rapid_credential_cascade',
        'seq_takeover_progression',
        'seq_multi_factor_tampering',
        'seq_high_velocity_actions'
      ]);

      // Verify each appears at most once
      const uniqueIds = new Set(matchedRuleIds);
      expect(uniqueIds.size).toBe(matchedRuleIds.length);
    });

    test('empty array returns no matches', () => {
      expect(analyzeSequence([])).toEqual({ matched_rules: [] });
    });

    test('single-event arrays return no matches', () => {
      const events = [
        { event_type: 'login_success', timestamp: new Date(baseTime).toISOString() }
      ];
      expect(analyzeSequence(events)).toEqual({ matched_rules: [] });
    });

    test('unsorted input is analyzed in timestamp order and input array is left unmodified', () => {
      // Provide events intentionally reversed in input order
      const rawEvents = [
        { event_type: 'password_change', timestamp: new Date(baseTime + 5 * 60 * 1000).toISOString() },
        { event_type: 'recovery_email_change', timestamp: new Date(baseTime).toISOString() }
      ];
      const frozenEvents = deepFreeze(rawEvents);

      const result = analyzeSequence(frozenEvents);
      expect(result.matched_rules).toEqual([
        { rule_id: 'seq_rapid_credential_cascade', points: 20 }
      ]);
      // Verify frozen array was not reordered
      expect(frozenEvents[0].event_type).toBe('password_change');
      expect(frozenEvents[1].event_type).toBe('recovery_email_change');
    });
  });

  describe('7. Validation (RiskInputError)', () => {
    test('throws for non-array input', () => {
      expect(() => analyzeSequence(null)).toThrow(RiskInputError);
      expect(() => analyzeSequence('string')).toThrow(RiskInputError);
      expect(() => analyzeSequence({})).toThrow(RiskInputError);
    });

    test('throws for non-object element', () => {
      expect(() => analyzeSequence([null])).toThrow(RiskInputError);
      expect(() => analyzeSequence(['event'])).toThrow(RiskInputError);
      expect(() => analyzeSequence([123])).toThrow(RiskInputError);
    });

    test('throws for missing or non-string event_type', () => {
      expect(() => analyzeSequence([{ timestamp: new Date().toISOString() }])).toThrow(RiskInputError);
      expect(() => analyzeSequence([{ event_type: '', timestamp: new Date().toISOString() }])).toThrow(RiskInputError);
      expect(() => analyzeSequence([{ event_type: 123, timestamp: new Date().toISOString() }])).toThrow(RiskInputError);
    });

    test('throws for unparseable timestamp', () => {
      expect(() => analyzeSequence([{ event_type: 'login_success' }])).toThrow(RiskInputError);
      expect(() => analyzeSequence([{ event_type: 'login_success', timestamp: 'not-a-timestamp' }])).toThrow(RiskInputError);
      expect(() => analyzeSequence([{ event_type: 'login_success', timestamp: null }])).toThrow(RiskInputError);
    });

    test('unknown event types are allowed and match nothing', () => {
      const events = [
        { event_type: 'custom_telemetry_event', timestamp: new Date(baseTime).toISOString() },
        { event_type: 'another_unknown_event', timestamp: new Date(baseTime + 10 * 1000).toISOString() }
      ];
      expect(analyzeSequence(events)).toEqual({ matched_rules: [] });
    });
  });

  describe('8. appendProposedEvent Helper', () => {
    test('returns a new array with proposed event copied, inputs untouched', () => {
      const existing = deepFreeze([
        { event_type: 'login_success', timestamp: new Date(baseTime).toISOString() }
      ]);
      const proposed = deepFreeze({
        event_type: 'password_change',
        timestamp: new Date(baseTime + 60 * 1000).toISOString()
      });

      const appended = appendProposedEvent(existing, proposed);
      expect(appended.length).toBe(2);
      expect(appended[0].event_type).toBe('login_success');
      expect(appended[1].event_type).toBe('password_change');
      expect(appended).not.toBe(existing);
      expect(Object.isFrozen(appended)).toBe(false);
    });

    test('throws RiskInputError if proposedEvent has missing or invalid timestamp', () => {
      const existing = [{ event_type: 'login_success', timestamp: new Date(baseTime).toISOString() }];
      expect(() => appendProposedEvent(existing, { event_type: 'password_change' })).toThrow(RiskInputError);
      expect(() => appendProposedEvent(existing, { event_type: 'password_change', timestamp: 'invalid' })).toThrow(RiskInputError);
    });

    test('throws RiskInputError if proposedEvent is missing or invalid event_type', () => {
      const existing = [{ event_type: 'login_success', timestamp: new Date(baseTime).toISOString() }];
      expect(() => appendProposedEvent(existing, { timestamp: new Date(baseTime).toISOString() })).toThrow(RiskInputError);
      expect(() => appendProposedEvent(existing, { event_type: '', timestamp: new Date(baseTime).toISOString() })).toThrow(RiskInputError);
    });
  });

  describe('9. Integration with Sub-module 6.1 (scoreRisk)', () => {
    test('(a) Live Scenario B sequence matches cascade (20), scores 84 critical with invariant holding', () => {
      // Sequence: login_success with is_new_device: true, recovery_email_change, password_change
      const sequenceEvents = [
        {
          event_type: 'login_success',
          is_new_device: true,
          timestamp: new Date(baseTime).toISOString()
        },
        {
          event_type: 'recovery_email_change',
          timestamp: new Date(baseTime + 2 * 60 * 1000).toISOString()
        },
        {
          event_type: 'password_change',
          timestamp: new Date(baseTime + 4 * 60 * 1000).toISOString()
        }
      ];

      const seqAnalysis = analyzeSequence(sequenceEvents);
      expect(seqAnalysis.matched_rules).toEqual([
        { rule_id: 'seq_rapid_credential_cascade', points: 20 }
      ]);

      const scoringInput = {
        event_type: 'password_change',
        action_sensitivity: 'critical',
        context: {
          unrecognized_device: true,
          unrecognized_country: true,
          impossible_travel: true
        },
        sequence: { matched_rules: seqAnalysis.matched_rules },
        timing: { automation_suspected: false },
        baseline: {
          evaluated: true,
          has_sufficient_history: true,
          deviation_score: 0.90
        },
        verification: null
      };

      const result = scoreRisk(scoringInput);
      expect(result.status).toBe('ok');
      expect(result.risk_score).toBe(84);
      expect(result.risk_tier).toBe('critical');

      // Arithmetic invariant: weights sum equals score
      const weightSum = result.contributing_signals.reduce((acc, s) => acc + s.weight, 0);
      expect(weightSum).toBe(84);
    });

    test('(b) Sequence ending in high_impact_action matches cascade and takeover (45 raw), capped with -20 adjustment', () => {
      const sequenceEvents = [
        {
          event_type: 'login_success',
          is_new_device: true,
          timestamp: new Date(baseTime).toISOString()
        },
        {
          event_type: 'recovery_email_change',
          timestamp: new Date(baseTime + 2 * 60 * 1000).toISOString()
        },
        {
          event_type: 'password_change',
          timestamp: new Date(baseTime + 4 * 60 * 1000).toISOString()
        },
        {
          event_type: 'high_impact_action',
          timestamp: new Date(baseTime + 6 * 60 * 1000).toISOString()
        }
      ];

      const seqAnalysis = analyzeSequence(sequenceEvents);
      expect(seqAnalysis.matched_rules).toEqual([
        { rule_id: 'seq_rapid_credential_cascade', points: 20 },
        { rule_id: 'seq_takeover_progression', points: 25 }
      ]);

      const scoringInput = {
        event_type: 'high_impact_action',
        action_sensitivity: 'high',
        context: {
          unrecognized_device: true,
          unrecognized_country: false,
          impossible_travel: false
        },
        sequence: { matched_rules: seqAnalysis.matched_rules },
        timing: { automation_suspected: false },
        baseline: {
          evaluated: false,
          has_sufficient_history: false,
          deviation_score: 0.0
        },
        verification: null
      };

      const result = scoreRisk(scoringInput);
      expect(result.status).toBe('ok');

      // Check cap adjustment signal
      const capSignal = result.contributing_signals.find((s) => s.signal === 'sequence_risk_cap_adjustment');
      expect(capSignal).toBeDefined();
      expect(capSignal.weight).toBe(-20);

      // Invariant holds
      const weightSum = result.contributing_signals.reduce((acc, s) => acc + s.weight, 0);
      expect(weightSum).toBe(result.risk_score);
    });
  });

  describe('10. Architectural Purity Guard', () => {
    test('sequenceRiskService.js is strictly pure (no DB, redis, clock, random, env, or service imports)', () => {
      const filePath = path.join(__dirname, '../src/services/sequenceRiskService.js');
      const fileContent = fs.readFileSync(filePath, 'utf8');

      const prohibitedPatterns = [
        /\bsequelize\b/i,
        /\bredis\b/i,
        /\bioredis\b/i,
        /\bmodels\b/i,
        /\bexpress\b/i,
        /\bservices\/(?!sequenceRiskService)/,
        /\bDate\.now\s*\(/,
        /new\s+Date\s*\(\s*\)/,
        /\bMath\.random\b/,
        /process\.env/i
      ];

      for (const pattern of prohibitedPatterns) {
        expect(fileContent).not.toMatch(pattern);
      }
    });
  });
});
