const fs = require('fs');
const path = require('path');
const policyConfig = require('../src/config/policyConfig');
const { decide, SENSITIVITY_RANKS } = require('../src/utils/policyDecision');

function deepFreeze(obj) {
  Object.keys(obj).forEach((prop) => {
    if (typeof obj[prop] === 'object' && obj[prop] !== null && !Object.isFrozen(obj[prop])) {
      deepFreeze(obj[prop]);
    }
  });
  return Object.freeze(obj);
}

function getDecisionRank(decision) {
  return policyConfig.DECISION_ORDER.indexOf(decision);
}

function getAllSubsets(arr) {
  const result = [[]];
  for (const el of arr) {
    const len = result.length;
    for (let i = 0; i < len; i++) {
      result.push([...result[i], el]);
    }
  }
  return result;
}

describe('Module 8 — Pure Policy Decision Unit Tests', () => {
  const TIERS = ['low', 'medium', 'high', 'critical'];
  const SENSITIVITIES = ['low', 'medium', 'high', 'critical'];
  const SIX_SIGNALS = [
    'impossible_travel',
    'unrecognized_device',
    'unrecognized_country',
    'seq_rapid_credential_cascade',
    'seq_takeover_progression',
    'automation_timing_burst'
  ];

  describe('T1. Exhaustive Sweep', () => {
    const allSignalSubsets = getAllSubsets(SIX_SIGNALS); // 64 subsets

    test('T1. Exhaustive sweep over 2,048 combinations: valid decision, >= BASE_MATRIX cell, monotonic in tier, sensitivity, and signals, decision === max(reason.decision), reasons non-empty', () => {
      const eventTypes = [
        { type: 'login_success', isAccountMod: false },
        { type: 'recovery_email_change', isAccountMod: true }
      ];

      for (const evt of eventTypes) {
        for (const tier of TIERS) {
          for (const sens of SENSITIVITIES) {
            for (const subset of allSignalSubsets) {
              const input = {
                risk: {
                  status: 'ok',
                  risk_tier: tier,
                  signal_names: subset
                },
                action: {
                  event_type: evt.type,
                  provided_sensitivity: sens
                }
              };

              const res = decide(input, policyConfig);

              // 1. Valid decision always returns
              expect(policyConfig.DECISION_ORDER).toContain(res.decision);

              // 2. Effective sensitivity calculation
              const defaultSens = policyConfig.DEFAULT_ACTION_SENSITIVITY[evt.type] || 'low';
              const effSens =
                SENSITIVITY_RANKS[sens] > SENSITIVITY_RANKS[defaultSens] ? sens : defaultSens;

              // 3. decision >= its BASE_MATRIX cell
              const baseCell = policyConfig.BASE_MATRIX[tier][effSens];
              expect(getDecisionRank(res.decision)).toBeGreaterThanOrEqual(getDecisionRank(baseCell));

              // 4. decision === max(reason.decision) with reasons non-empty
              expect(res.reasons.length).toBeGreaterThan(0);
              let maxReasonRank = -1;
              for (const r of res.reasons) {
                expect(policyConfig.DECISION_ORDER).toContain(r.decision);
                const rRank = getDecisionRank(r.decision);
                if (rRank > maxReasonRank) {
                  maxReasonRank = rRank;
                }
              }
              expect(getDecisionRank(res.decision)).toBe(maxReasonRank);
            }
          }
        }
      }

      // Monotonicity checks across tier, sensitivity, and signals for low-default action
      const testEvent = 'login_success';
      for (const subset of allSignalSubsets) {
        // Monotonic in tier (with sensitivity and signals fixed)
        for (const sens of SENSITIVITIES) {
          let prevRank = -1;
          for (const tier of TIERS) {
            const res = decide(
              {
                risk: { status: 'ok', risk_tier: tier, signal_names: subset },
                action: { event_type: testEvent, provided_sensitivity: sens }
              },
              policyConfig
            );
            const currentRank = getDecisionRank(res.decision);
            expect(currentRank).toBeGreaterThanOrEqual(prevRank);
            prevRank = currentRank;
          }
        }

        // Monotonic in sensitivity (with tier and signals fixed)
        for (const tier of TIERS) {
          let prevRank = -1;
          for (const sens of SENSITIVITIES) {
            const res = decide(
              {
                risk: { status: 'ok', risk_tier: tier, signal_names: subset },
                action: { event_type: testEvent, provided_sensitivity: sens }
              },
              policyConfig
            );
            const currentRank = getDecisionRank(res.decision);
            expect(currentRank).toBeGreaterThanOrEqual(prevRank);
            prevRank = currentRank;
          }
        }
      }

      // Adding a signal never lowers the decision
      for (const tier of TIERS) {
        for (const sens of SENSITIVITIES) {
          for (const subset of allSignalSubsets) {
            const baseRes = decide(
              {
                risk: { status: 'ok', risk_tier: tier, signal_names: subset },
                action: { event_type: testEvent, provided_sensitivity: sens }
              },
              policyConfig
            );
            const baseRank = getDecisionRank(baseRes.decision);

            for (const sig of SIX_SIGNALS) {
              if (!subset.includes(sig)) {
                const augmentedRes = decide(
                  {
                    risk: { status: 'ok', risk_tier: tier, signal_names: [...subset, sig] },
                    action: { event_type: testEvent, provided_sensitivity: sens }
                  },
                  policyConfig
                );
                const augmentedRank = getDecisionRank(augmentedRes.decision);
                expect(augmentedRank).toBeGreaterThanOrEqual(baseRank);
              }
            }
          }
        }
      }
    });
  });

  describe('T2. Escalation Rules Firing & Boundary Conditions', () => {
    test('esc_impossible_travel: fires when present, raises allow to monitor, does not lower stricter base', () => {
      // Fires inside condition: tier low, sensitivity low -> base is allow, raised to monitor
      const inside = decide(
        {
          risk: { status: 'ok', risk_tier: 'low', signal_names: ['impossible_travel'] },
          action: { event_type: 'login_success', provided_sensitivity: 'low' }
        },
        policyConfig
      );
      expect(inside.decision).toBe('monitor');
      expect(inside.reasons.some((r) => r.rule_id === 'esc_impossible_travel')).toBe(true);

      // Outside condition: missing signal
      const outside = decide(
        {
          risk: { status: 'ok', risk_tier: 'low', signal_names: [] },
          action: { event_type: 'login_success', provided_sensitivity: 'low' }
        },
        policyConfig
      );
      expect(outside.decision).toBe('allow');
      expect(outside.reasons.some((r) => r.rule_id === 'esc_impossible_travel')).toBe(false);

      // Cannot lower stricter base decision (tier critical, sensitivity low -> base is reverify)
      const stricter = decide(
        {
          risk: { status: 'ok', risk_tier: 'critical', signal_names: ['impossible_travel'] },
          action: { event_type: 'login_success', provided_sensitivity: 'low' }
        },
        policyConfig
      );
      expect(stricter.decision).toBe('reverify');
    });

    test('esc_impossible_travel_sensitive: fires when impossible_travel and sensitivity >= medium, boundary at low, cannot lower stricter base', () => {
      // Fires inside: sensitivity medium, tier low -> base allow, raised to reverify
      const inside = decide(
        {
          risk: { status: 'ok', risk_tier: 'low', signal_names: ['impossible_travel'] },
          action: { event_type: 'login_success', provided_sensitivity: 'medium' }
        },
        policyConfig
      );
      expect(inside.decision).toBe('reverify');
      expect(inside.reasons.some((r) => r.rule_id === 'esc_impossible_travel_sensitive')).toBe(true);

      // Boundary: sensitivity low -> rule does not fire
      const boundaryLow = decide(
        {
          risk: { status: 'ok', risk_tier: 'low', signal_names: ['impossible_travel'] },
          action: { event_type: 'login_success', provided_sensitivity: 'low' }
        },
        policyConfig
      );
      expect(boundaryLow.reasons.some((r) => r.rule_id === 'esc_impossible_travel_sensitive')).toBe(false);

      // Missing co-signal: sensitivity medium without impossible_travel
      const noSignal = decide(
        {
          risk: { status: 'ok', risk_tier: 'low', signal_names: ['unrecognized_device'] },
          action: { event_type: 'login_success', provided_sensitivity: 'medium' }
        },
        policyConfig
      );
      expect(noSignal.reasons.some((r) => r.rule_id === 'esc_impossible_travel_sensitive')).toBe(false);

      // Cannot lower stricter base (tier critical, sensitivity medium -> base delay)
      const stricter = decide(
        {
          risk: { status: 'ok', risk_tier: 'critical', signal_names: ['impossible_travel'] },
          action: { event_type: 'login_success', provided_sensitivity: 'medium' }
        },
        policyConfig
      );
      expect(stricter.decision).toBe('delay');
    });

    test('esc_travel_and_novelty: fires with impossible_travel, novelty, and sensitivity >= high, min delay, checks boundaries', () => {
      // Fires with unrecognized_device
      const withDevice = decide(
        {
          risk: {
            status: 'ok',
            risk_tier: 'low',
            signal_names: ['impossible_travel', 'unrecognized_device']
          },
          action: { event_type: 'login_success', provided_sensitivity: 'high' }
        },
        policyConfig
      );
      expect(withDevice.decision).toBe('delay');
      expect(withDevice.reasons.some((r) => r.rule_id === 'esc_travel_and_novelty')).toBe(true);

      // Fires with unrecognized_country
      const withCountry = decide(
        {
          risk: {
            status: 'ok',
            risk_tier: 'low',
            signal_names: ['impossible_travel', 'unrecognized_country']
          },
          action: { event_type: 'login_success', provided_sensitivity: 'high' }
        },
        policyConfig
      );
      expect(withCountry.decision).toBe('delay');
      expect(withCountry.reasons.some((r) => r.rule_id === 'esc_travel_and_novelty')).toBe(true);

      // Boundary: sensitivity medium (< high) -> does not fire
      const boundaryMedium = decide(
        {
          risk: {
            status: 'ok',
            risk_tier: 'low',
            signal_names: ['impossible_travel', 'unrecognized_device']
          },
          action: { event_type: 'login_success', provided_sensitivity: 'medium' }
        },
        policyConfig
      );
      expect(boundaryMedium.reasons.some((r) => r.rule_id === 'esc_travel_and_novelty')).toBe(false);

      // Missing novelty co-signal: impossible_travel alone at high sensitivity
      const noNovelty = decide(
        {
          risk: { status: 'ok', risk_tier: 'low', signal_names: ['impossible_travel'] },
          action: { event_type: 'login_success', provided_sensitivity: 'high' }
        },
        policyConfig
      );
      expect(noNovelty.reasons.some((r) => r.rule_id === 'esc_travel_and_novelty')).toBe(false);

      // Missing travel co-signal: unrecognized_device alone at high sensitivity
      const noTravel = decide(
        {
          risk: { status: 'ok', risk_tier: 'low', signal_names: ['unrecognized_device'] },
          action: { event_type: 'login_success', provided_sensitivity: 'high' }
        },
        policyConfig
      );
      expect(noTravel.reasons.some((r) => r.rule_id === 'esc_travel_and_novelty')).toBe(false);

      // Cannot lower stricter base (tier critical, sensitivity high -> base block)
      const stricter = decide(
        {
          risk: {
            status: 'ok',
            risk_tier: 'critical',
            signal_names: ['impossible_travel', 'unrecognized_device']
          },
          action: { event_type: 'login_success', provided_sensitivity: 'high' }
        },
        policyConfig
      );
      expect(stricter.decision).toBe('block');
    });

    test('esc_credential_cascade: fires when seq_rapid_credential_cascade matched and action in account-modification types, min reverify', () => {
      // Fires inside: action is password_change (in ACCOUNT_MODIFICATION_TYPES)
      const inside = decide(
        {
          risk: {
            status: 'ok',
            risk_tier: 'low',
            signal_names: ['seq_rapid_credential_cascade']
          },
          action: { event_type: 'password_change' }
        },
        policyConfig
      );
      expect(getDecisionRank(inside.decision)).toBeGreaterThanOrEqual(getDecisionRank('reverify'));
      expect(inside.reasons.some((r) => r.rule_id === 'esc_credential_cascade')).toBe(true);

      // Outside: action is login_success (not in ACCOUNT_MODIFICATION_TYPES)
      const nonMod = decide(
        {
          risk: {
            status: 'ok',
            risk_tier: 'low',
            signal_names: ['seq_rapid_credential_cascade']
          },
          action: { event_type: 'login_success', provided_sensitivity: 'low' }
        },
        policyConfig
      );
      expect(nonMod.reasons.some((r) => r.rule_id === 'esc_credential_cascade')).toBe(false);

      // Missing signal: password_change without seq_rapid_credential_cascade
      const noSignal = decide(
        {
          risk: { status: 'ok', risk_tier: 'low', signal_names: [] },
          action: { event_type: 'password_change' }
        },
        policyConfig
      );
      expect(noSignal.reasons.some((r) => r.rule_id === 'esc_credential_cascade')).toBe(false);

      // Cannot lower stricter base (tier high, sensitivity critical -> base block)
      const stricter = decide(
        {
          risk: {
            status: 'ok',
            risk_tier: 'high',
            signal_names: ['seq_rapid_credential_cascade']
          },
          action: { event_type: 'password_change', provided_sensitivity: 'critical' }
        },
        policyConfig
      );
      expect(stricter.decision).toBe('block');
    });

    test('esc_takeover_progression: fires when seq_takeover_progression matched and sensitivity >= high, min block', () => {
      // Fires inside: sensitivity high
      const inside = decide(
        {
          risk: {
            status: 'ok',
            risk_tier: 'low',
            signal_names: ['seq_takeover_progression']
          },
          action: { event_type: 'login_success', provided_sensitivity: 'high' }
        },
        policyConfig
      );
      expect(inside.decision).toBe('block');
      expect(inside.reasons.some((r) => r.rule_id === 'esc_takeover_progression')).toBe(true);

      // Boundary: sensitivity medium -> does not fire
      const boundaryMedium = decide(
        {
          risk: {
            status: 'ok',
            risk_tier: 'low',
            signal_names: ['seq_takeover_progression']
          },
          action: { event_type: 'login_success', provided_sensitivity: 'medium' }
        },
        policyConfig
      );
      expect(boundaryMedium.reasons.some((r) => r.rule_id === 'esc_takeover_progression')).toBe(false);

      // Missing signal: sensitivity high without seq_takeover_progression
      const noSignal = decide(
        {
          risk: { status: 'ok', risk_tier: 'low', signal_names: [] },
          action: { event_type: 'login_success', provided_sensitivity: 'high' }
        },
        policyConfig
      );
      expect(noSignal.reasons.some((r) => r.rule_id === 'esc_takeover_progression')).toBe(false);
    });

    test('esc_automation: fires when automation_timing_burst present and sensitivity >= medium, min reverify', () => {
      // Fires inside: sensitivity medium
      const inside = decide(
        {
          risk: {
            status: 'ok',
            risk_tier: 'low',
            signal_names: ['automation_timing_burst']
          },
          action: { event_type: 'login_success', provided_sensitivity: 'medium' }
        },
        policyConfig
      );
      expect(inside.decision).toBe('reverify');
      expect(inside.reasons.some((r) => r.rule_id === 'esc_automation')).toBe(true);

      // Boundary: sensitivity low -> does not fire
      const boundaryLow = decide(
        {
          risk: {
            status: 'ok',
            risk_tier: 'low',
            signal_names: ['automation_timing_burst']
          },
          action: { event_type: 'login_success', provided_sensitivity: 'low' }
        },
        policyConfig
      );
      expect(boundaryLow.reasons.some((r) => r.rule_id === 'esc_automation')).toBe(false);

      // Missing signal: sensitivity medium without automation_timing_burst
      const noSignal = decide(
        {
          risk: { status: 'ok', risk_tier: 'low', signal_names: [] },
          action: { event_type: 'login_success', provided_sensitivity: 'medium' }
        },
        policyConfig
      );
      expect(noSignal.reasons.some((r) => r.rule_id === 'esc_automation')).toBe(false);

      // Cannot lower stricter base (tier critical, sensitivity medium -> base delay)
      const stricter = decide(
        {
          risk: {
            status: 'ok',
            risk_tier: 'critical',
            signal_names: ['automation_timing_burst']
          },
          action: { event_type: 'login_success', provided_sensitivity: 'medium' }
        },
        policyConfig
      );
      expect(stricter.decision).toBe('delay');
    });

    test('esc_double_novelty: fires when unrecognized_device and unrecognized_country present and sensitivity >= medium, min reverify', () => {
      // Fires inside: both novelty signals + sensitivity medium
      const inside = decide(
        {
          risk: {
            status: 'ok',
            risk_tier: 'low',
            signal_names: ['unrecognized_device', 'unrecognized_country']
          },
          action: { event_type: 'login_success', provided_sensitivity: 'medium' }
        },
        policyConfig
      );
      expect(inside.decision).toBe('reverify');
      expect(inside.reasons.some((r) => r.rule_id === 'esc_double_novelty')).toBe(true);

      // Missing co-signal: unrecognized_device alone
      const onlyDevice = decide(
        {
          risk: {
            status: 'ok',
            risk_tier: 'low',
            signal_names: ['unrecognized_device']
          },
          action: { event_type: 'login_success', provided_sensitivity: 'medium' }
        },
        policyConfig
      );
      expect(onlyDevice.reasons.some((r) => r.rule_id === 'esc_double_novelty')).toBe(false);

      // Missing co-signal: unrecognized_country alone
      const onlyCountry = decide(
        {
          risk: {
            status: 'ok',
            risk_tier: 'low',
            signal_names: ['unrecognized_country']
          },
          action: { event_type: 'login_success', provided_sensitivity: 'medium' }
        },
        policyConfig
      );
      expect(onlyCountry.reasons.some((r) => r.rule_id === 'esc_double_novelty')).toBe(false);

      // Boundary: sensitivity low with both novelty signals -> does not fire
      const boundaryLow = decide(
        {
          risk: {
            status: 'ok',
            risk_tier: 'low',
            signal_names: ['unrecognized_device', 'unrecognized_country']
          },
          action: { event_type: 'login_success', provided_sensitivity: 'low' }
        },
        policyConfig
      );
      expect(boundaryLow.reasons.some((r) => r.rule_id === 'esc_double_novelty')).toBe(false);

      // Cannot lower stricter base (tier critical, sensitivity high -> base block)
      const stricter = decide(
        {
          risk: {
            status: 'ok',
            risk_tier: 'critical',
            signal_names: ['unrecognized_device', 'unrecognized_country']
          },
          action: { event_type: 'login_success', provided_sensitivity: 'high' }
        },
        policyConfig
      );
      expect(stricter.decision).toBe('block');
    });
  });

  describe('T3. Action Sensitivity Rule (R4)', () => {
    test('a lower caller-provided sensitivity never lowers the server default', () => {
      // password_change has default high
      const lowerLow = decide(
        {
          risk: { status: 'ok', risk_tier: 'medium', signal_names: [] },
          action: { event_type: 'password_change', provided_sensitivity: 'low' }
        },
        policyConfig
      );
      // At medium tier and high sensitivity, base matrix gives reverify
      expect(lowerLow.decision).toBe('reverify');

      const lowerMedium = decide(
        {
          risk: { status: 'ok', risk_tier: 'medium', signal_names: [] },
          action: { event_type: 'password_change', provided_sensitivity: 'medium' }
        },
        policyConfig
      );
      expect(lowerMedium.decision).toBe('reverify');
    });

    test('a higher caller-provided sensitivity raises the effective sensitivity', () => {
      // login_success has default low
      const raisedHigh = decide(
        {
          risk: { status: 'ok', risk_tier: 'medium', signal_names: [] },
          action: { event_type: 'login_success', provided_sensitivity: 'high' }
        },
        policyConfig
      );
      // At medium tier, low sensitivity yields allow, but high sensitivity yields reverify
      expect(raisedHigh.decision).toBe('reverify');

      const raisedCritical = decide(
        {
          risk: { status: 'ok', risk_tier: 'high', signal_names: [] },
          action: { event_type: 'login_success', provided_sensitivity: 'critical' }
        },
        policyConfig
      );
      // At high tier, critical sensitivity yields block
      expect(raisedCritical.decision).toBe('block');
    });
  });

  describe('T4. Fail-Safe for Unavailable Risk (R6)', () => {
    test('evaluates fail-safe decisions for all four sensitivity levels correctly', () => {
      // Low sensitivity -> monitor
      const lowRes = decide(
        {
          risk: { status: 'unavailable', risk_tier: null, signal_names: [] },
          action: { event_type: 'login_success', provided_sensitivity: 'low' }
        },
        policyConfig
      );
      expect(lowRes.decision).toBe('monitor');
      expect(lowRes.reasons).toEqual([
        { rule_id: 'fail_safe_low', kind: 'fail_safe', decision: 'monitor' }
      ]);
      expect(lowRes.requires_review).toBe(true);

      // Medium sensitivity -> monitor
      const medRes = decide(
        {
          risk: { status: 'unavailable', risk_tier: null, signal_names: [] },
          action: { event_type: 'phone_number_change', provided_sensitivity: 'medium' }
        },
        policyConfig
      );
      expect(medRes.decision).toBe('monitor');
      expect(medRes.reasons).toEqual([
        { rule_id: 'fail_safe_medium', kind: 'fail_safe', decision: 'monitor' }
      ]);
      expect(medRes.requires_review).toBe(true);

      // High sensitivity -> block
      const highRes = decide(
        {
          risk: { status: 'unavailable', risk_tier: null, signal_names: [] },
          action: { event_type: 'password_change', provided_sensitivity: 'high' }
        },
        policyConfig
      );
      expect(highRes.decision).toBe('block');
      expect(highRes.reasons).toEqual([
        { rule_id: 'fail_safe_high', kind: 'fail_safe', decision: 'block' }
      ]);
      expect(highRes.requires_review).toBe(true);

      // Critical sensitivity -> block
      const critRes = decide(
        {
          risk: { status: 'unavailable', risk_tier: null, signal_names: [] },
          action: { event_type: 'high_impact_action', provided_sensitivity: 'critical' }
        },
        policyConfig
      );
      expect(critRes.decision).toBe('block');
      expect(critRes.reasons).toEqual([
        { rule_id: 'fail_safe_critical', kind: 'fail_safe', decision: 'block' }
      ]);
      expect(critRes.requires_review).toBe(true);
    });

    test('unavailable risk never yields allow for high or critical sensitivity', () => {
      const highMissingTier = decide(
        {
          risk: { status: 'ok', risk_tier: null, signal_names: [] },
          action: { event_type: 'password_change' }
        },
        policyConfig
      );
      expect(highMissingTier.decision).not.toBe('allow');
      expect(highMissingTier.decision).toBe('block');

      const critNullRisk = decide(
        {
          risk: null,
          action: { event_type: 'high_impact_action' }
        },
        policyConfig
      );
      expect(critNullRisk.decision).not.toBe('allow');
      expect(critNullRisk.decision).toBe('block');
    });
  });

  describe('T5. Recommended Actions, Review Flag, Explanations, and Enforcement Mode (R7 & R8)', () => {
    test('recommended_actions is deterministic and derives from decision and reasons', () => {
      const allowRes = decide(
        {
          risk: { status: 'ok', risk_tier: 'low', signal_names: [] },
          action: { event_type: 'login_success', provided_sensitivity: 'low' }
        },
        policyConfig
      );
      expect(allowRes.recommended_actions).toEqual(['proceed']);

      const monitorRes = decide(
        {
          risk: { status: 'ok', risk_tier: 'low', signal_names: ['impossible_travel'] },
          action: { event_type: 'login_success', provided_sensitivity: 'low' }
        },
        policyConfig
      );
      expect(monitorRes.recommended_actions).toEqual(['log_telemetry']);

      const reverifyRes = decide(
        {
          risk: { status: 'ok', risk_tier: 'medium', signal_names: [] },
          action: { event_type: 'password_change', provided_sensitivity: 'high' }
        },
        policyConfig
      );
      expect(reverifyRes.recommended_actions).toEqual(['require_step_up']);

      const delayRes = decide(
        {
          risk: { status: 'ok', risk_tier: 'high', signal_names: [] },
          action: { event_type: 'password_change', provided_sensitivity: 'high' }
        },
        policyConfig
      );
      expect(delayRes.recommended_actions).toEqual([
        'delay_with_cancel',
        'notify_user',
        'admin_review'
      ]);

      const blockRes = decide(
        {
          risk: { status: 'ok', risk_tier: 'critical', signal_names: [] },
          action: { event_type: 'password_change', provided_sensitivity: 'high' }
        },
        policyConfig
      );
      expect(blockRes.recommended_actions).toEqual(['block_action', 'notify_user', 'admin_review']);
    });

    test('requires_review rules: true for delay, block, and any fail_safe decision, false for normal allow, monitor, reverify', () => {
      const allow = decide(
        {
          risk: { status: 'ok', risk_tier: 'low', signal_names: [] },
          action: { event_type: 'login_success', provided_sensitivity: 'low' }
        },
        policyConfig
      );
      expect(allow.requires_review).toBe(false);

      const monitor = decide(
        {
          risk: { status: 'ok', risk_tier: 'low', signal_names: ['impossible_travel'] },
          action: { event_type: 'login_success', provided_sensitivity: 'low' }
        },
        policyConfig
      );
      expect(monitor.requires_review).toBe(false);

      const reverify = decide(
        {
          risk: { status: 'ok', risk_tier: 'medium', signal_names: [] },
          action: { event_type: 'password_change', provided_sensitivity: 'high' }
        },
        policyConfig
      );
      expect(reverify.requires_review).toBe(false);

      const delay = decide(
        {
          risk: { status: 'ok', risk_tier: 'high', signal_names: [] },
          action: { event_type: 'password_change', provided_sensitivity: 'high' }
        },
        policyConfig
      );
      expect(delay.requires_review).toBe(true);

      const block = decide(
        {
          risk: { status: 'ok', risk_tier: 'critical', signal_names: [] },
          action: { event_type: 'password_change', provided_sensitivity: 'high' }
        },
        policyConfig
      );
      expect(block.requires_review).toBe(true);

      const failSafeMonitor = decide(
        {
          risk: { status: 'unavailable', risk_tier: null, signal_names: [] },
          action: { event_type: 'login_success', provided_sensitivity: 'low' }
        },
        policyConfig
      );
      expect(failSafeMonitor.decision).toBe('monitor');
      expect(failSafeMonitor.requires_review).toBe(true);
    });

    test('user_facing explanation contains no digits, no signal names, and no forbidden claim words across all decisions', () => {
      const forbiddenWords = [/prevent/i, /guarantee/i, /breach/i, /hacked/i];
      const allKnownSignalNames = [
        'impossible_travel',
        'unrecognized_device',
        'unrecognized_country',
        'seq_rapid_credential_cascade',
        'seq_takeover_progression',
        'automation_timing_burst'
      ];

      for (const dec of policyConfig.DECISION_ORDER) {
        // Construct an input that produces decision dec
        let input;
        if (dec === 'allow') {
          input = {
            risk: { status: 'ok', risk_tier: 'low', signal_names: [] },
            action: { event_type: 'login_success', provided_sensitivity: 'low' }
          };
        } else if (dec === 'monitor') {
          input = {
            risk: { status: 'ok', risk_tier: 'low', signal_names: ['impossible_travel'] },
            action: { event_type: 'login_success', provided_sensitivity: 'low' }
          };
        } else if (dec === 'reverify') {
          input = {
            risk: { status: 'ok', risk_tier: 'medium', signal_names: [] },
            action: { event_type: 'password_change', provided_sensitivity: 'high' }
          };
        } else if (dec === 'delay') {
          input = {
            risk: { status: 'ok', risk_tier: 'high', signal_names: [] },
            action: { event_type: 'password_change', provided_sensitivity: 'high' }
          };
        } else if (dec === 'block') {
          input = {
            risk: { status: 'ok', risk_tier: 'critical', signal_names: [] },
            action: { event_type: 'password_change', provided_sensitivity: 'high' }
          };
        }

        const res = decide(input, policyConfig);
        expect(res.decision).toBe(dec);

        const uf = res.explanation.user_facing;
        expect(typeof uf).toBe('string');
        expect(uf.length).toBeGreaterThan(10);

        // No digits
        expect(uf).not.toMatch(/\d/);

        // No forbidden words
        for (const re of forbiddenWords) {
          expect(uf).not.toMatch(re);
        }

        // No signal names
        for (const sig of allKnownSignalNames) {
          expect(uf.toLowerCase()).not.toContain(sig.toLowerCase());
        }

        // Admin facing lists the reasons
        expect(typeof res.explanation.admin_facing).toBe('string');
        expect(res.explanation.admin_facing).toContain('Policy decision');
        for (const r of res.reasons) {
          expect(res.explanation.admin_facing).toContain(r.rule_id);
        }
      }
    });

    test('enforcement_mode strictly follows config', () => {
      const res = decide(
        {
          risk: { status: 'ok', risk_tier: 'low', signal_names: [] },
          action: { event_type: 'login_success', provided_sensitivity: 'low' }
        },
        policyConfig
      );
      expect(res.enforcement_mode).toBe('automatic');
    });
  });

  describe('T6. Strict Purity and Source-Text Guard', () => {
    test('deep-frozen inputs and config are never mutated; same input produces deep-equal output', () => {
      const rawInput = {
        risk: {
          status: 'ok',
          risk_tier: 'high',
          signal_names: ['impossible_travel', 'unrecognized_device']
        },
        action: {
          event_type: 'recovery_email_change',
          provided_sensitivity: 'high'
        }
      };

      const frozenInput = deepFreeze(JSON.parse(JSON.stringify(rawInput)));
      const frozenConfig = deepFreeze(JSON.parse(JSON.stringify(policyConfig)));

      const out1 = decide(frozenInput, frozenConfig);
      const out2 = decide(frozenInput, frozenConfig);

      expect(out1).toEqual(out2);

      // Verify inputs were not modified
      expect(frozenInput.risk.risk_tier).toBe('high');
      expect(frozenInput.risk.signal_names).toEqual(['impossible_travel', 'unrecognized_device']);
    });

    test('source-text guard: policyDecision.js contains zero occurrences of sequelize, redis, models, services, process.env, Date, Math.random', () => {
      const filePath = path.join(__dirname, '../src/utils/policyDecision.js');
      const source = fs.readFileSync(filePath, 'utf8');

      const forbiddenTokens = [
        'sequelize',
        'redis',
        'models',
        'services',
        'process.env',
        'Date',
        'Math.random'
      ];

      for (const token of forbiddenTokens) {
        const regex = new RegExp(`\\b${token.replace('.', '\\.')}\\b`, 'i');
        expect(source).not.toMatch(regex);
      }
    });
  });
});
