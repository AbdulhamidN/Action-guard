/**
 * Unit & Invariant Tests for Risk Scoring Engine (Sub-module 6.1)
 *
 * Verifies mathematical correctness, boundary caps, floor/ceiling adjustments,
 * exact arithmetic invariants, purity, and input validation.
 */

const fs = require('fs');
const path = require('path');
const riskConfig = require('../src/config/riskConfig');
const {
  scoreRisk,
  tierForScore,
  buildExplanation,
  RiskInputError
} = require('../src/utils/riskScoring');

/**
 * Shared helper asserting the exact arithmetic invariant and consistency rules.
 */
function assertRiskInvariant(result, expectedScore = null, expectedTier = null) {
  expect(result).toBeDefined();
  expect(result.status).toBe('ok');
  expect(Number.isInteger(result.risk_score)).toBe(true);
  expect(result.risk_score).toBeGreaterThanOrEqual(0);
  expect(result.risk_score).toBeLessThanOrEqual(100);

  // Exact arithmetic invariant: sum of weights === risk_score
  const computedSum = result.contributing_signals.reduce((acc, s) => acc + s.weight, 0);
  expect(computedSum).toBe(result.risk_score);

  // Tier consistency
  expect(tierForScore(result.risk_score)).toBe(result.risk_tier);

  if (expectedScore !== null) {
    expect(result.risk_score).toBe(expectedScore);
  }
  if (expectedTier !== null) {
    expect(result.risk_tier).toBe(expectedTier);
  }
}

/**
 * Default clean input generator helper.
 */
function createBaseInput(overrides = {}) {
  return {
    event_type: 'login_success',
    action_sensitivity: 'medium',
    context: {
      unrecognized_device: false,
      unrecognized_country: false,
      impossible_travel: false
    },
    sequence: {
      matched_rules: []
    },
    timing: {
      automation_suspected: false
    },
    baseline: {
      evaluated: true,
      has_sufficient_history: true,
      deviation_score: 0.0
    },
    verification: null,
    ...overrides
  };
}

describe('Sub-module 6.1 — Risk Config & Pure Scoring Engine', () => {
  describe('1. Config Sanity', () => {
    test('riskConfig is deeply frozen', () => {
      expect(Object.isFrozen(riskConfig)).toBe(true);
      expect(Object.isFrozen(riskConfig.BASE_RISK_MAP)).toBe(true);
      expect(Object.isFrozen(riskConfig.CATEGORY_CAPS)).toBe(true);
      expect(Object.isFrozen(riskConfig.TIER_THRESHOLDS)).toBe(true);
    });

    test('CATEGORY_CAPS sum to exactly 100', () => {
      const caps = riskConfig.CATEGORY_CAPS;
      const totalCaps = caps.base_action + caps.context + caps.sequence + caps.timing + caps.baseline;
      expect(totalCaps).toBe(100);
    });
  });

  describe('2. Tier Threshold Boundaries', () => {
    test.each([
      [0, 'low'],
      [15, 'low'],
      [29, 'low'],
      [30, 'medium'],
      [45, 'medium'],
      [59, 'medium'],
      [60, 'high'],
      [70, 'high'],
      [79, 'high'],
      [80, 'critical'],
      [90, 'critical'],
      [100, 'critical']
    ])('score %i maps to tier %s', (score, expectedTier) => {
      expect(tierForScore(score)).toBe(expectedTier);
    });
  });

  describe('3. Base Action Term & Sensitivity', () => {
    test.each(Object.keys(riskConfig.BASE_RISK_MAP))(
      'evaluates base risk for event_type %s',
      (eventType) => {
        const input = createBaseInput({
          event_type: eventType,
          action_sensitivity: 'low'
        });
        const res = scoreRisk(input);
        const expectedBase = riskConfig.BASE_RISK_MAP[eventType];
        assertRiskInvariant(res, expectedBase);

        const baseSignal = res.contributing_signals.find((s) => s.signal === `base_action_${eventType}`);
        expect(baseSignal).toBeDefined();
        expect(baseSignal.weight).toBe(expectedBase);
      }
    );

    test.each([
      ['low', 0],
      ['medium', 0],
      ['high', 3],
      ['critical', 5]
    ])('evaluates sensitivity %s with modifier %i', (sensitivity, expectedModifier) => {
      const input = createBaseInput({
        event_type: 'login_success',
        action_sensitivity: sensitivity
      });
      const res = scoreRisk(input);
      const expectedScore = 5 + expectedModifier;
      assertRiskInvariant(res, expectedScore);

      if (expectedModifier > 0) {
        const sensSignal = res.contributing_signals.find((s) => s.signal === `action_sensitivity_${sensitivity}`);
        expect(sensSignal).toBeDefined();
        expect(sensSignal.weight).toBe(expectedModifier);
      }
    });

    test('enforces base action cap: high_impact_action (22) + critical (5) = 27 capped to 25 with -2 adjustment', () => {
      const input = createBaseInput({
        event_type: 'high_impact_action',
        action_sensitivity: 'critical'
      });
      const res = scoreRisk(input);
      assertRiskInvariant(res, 25);

      const capAdj = res.contributing_signals.find((s) => s.signal === 'base_action_cap_adjustment');
      expect(capAdj).toBeDefined();
      expect(capAdj.weight).toBe(-2);
    });
  });

  describe('4. Context Term & Cap Adjustment', () => {
    test('unrecognized_device alone adds 10', () => {
      const input = createBaseInput({
        context: { unrecognized_device: true, unrecognized_country: false, impossible_travel: false }
      });
      const res = scoreRisk(input);
      assertRiskInvariant(res, 15); // base 5 + 10
      expect(res.contributing_signals).toContainEqual({
        signal: 'unrecognized_device',
        category: 'context',
        weight: 10
      });
    });

    test('unrecognized_country alone adds 10', () => {
      const input = createBaseInput({
        context: { unrecognized_device: false, unrecognized_country: true, impossible_travel: false }
      });
      const res = scoreRisk(input);
      assertRiskInvariant(res, 15); // base 5 + 10
      expect(res.contributing_signals).toContainEqual({
        signal: 'unrecognized_country',
        category: 'context',
        weight: 10
      });
    });

    test('impossible_travel alone adds 20', () => {
      const input = createBaseInput({
        context: { unrecognized_device: false, unrecognized_country: false, impossible_travel: true }
      });
      const res = scoreRisk(input);
      assertRiskInvariant(res, 25); // base 5 + 20
      expect(res.contributing_signals).toContainEqual({
        signal: 'impossible_travel',
        category: 'context',
        weight: 20
      });
    });

    test('all three context flags active: 10 + 10 + 20 = 40, capped to 25 with -15 adjustment', () => {
      const input = createBaseInput({
        context: { unrecognized_device: true, unrecognized_country: true, impossible_travel: true }
      });
      const res = scoreRisk(input);
      // base 5 + context cap 25 = 30
      assertRiskInvariant(res, 30);

      const capAdj = res.contributing_signals.find((s) => s.signal === 'context_risk_cap_adjustment');
      expect(capAdj).toBeDefined();
      expect(capAdj.weight).toBe(-15);
    });
  });

  describe('5. Sequence Term & Cap Adjustment', () => {
    test('matched rules under cap contribute exact points', () => {
      const input = createBaseInput({
        sequence: {
          matched_rules: [
            { rule_id: 'seq_rapid_credential_cascade', points: 20 }
          ]
        }
      });
      const res = scoreRisk(input);
      assertRiskInvariant(res, 25); // base 5 + sequence 20

      expect(res.contributing_signals).toContainEqual({
        signal: 'seq_rapid_credential_cascade',
        category: 'sequence',
        weight: 20
      });
    });

    test('matched rules over cap: 20 + 10 = 30, capped to 25 with -5 adjustment', () => {
      const input = createBaseInput({
        sequence: {
          matched_rules: [
            { rule_id: 'seq_rapid_credential_cascade', points: 20 },
            { rule_id: 'seq_high_velocity_actions', points: 10 }
          ]
        }
      });
      const res = scoreRisk(input);
      assertRiskInvariant(res, 30); // base 5 + sequence 25

      const capAdj = res.contributing_signals.find((s) => s.signal === 'sequence_risk_cap_adjustment');
      expect(capAdj).toBeDefined();
      expect(capAdj.weight).toBe(-5);
    });
  });

  describe('6. Timing & Baseline Terms', () => {
    test('timing automation_suspected true contributes 10', () => {
      const input = createBaseInput({
        timing: { automation_suspected: true }
      });
      const res = scoreRisk(input);
      assertRiskInvariant(res, 15); // base 5 + timing 10
      expect(res.contributing_signals).toContainEqual({
        signal: 'automation_timing_burst',
        category: 'timing',
        weight: 10
      });
    });

    test('timing automation_suspected false contributes 0 and emits no timing signal', () => {
      const input = createBaseInput({
        timing: { automation_suspected: false }
      });
      const res = scoreRisk(input);
      assertRiskInvariant(res, 5);
      const timingSignal = res.contributing_signals.find((s) => s.category === 'timing');
      expect(timingSignal).toBeUndefined();
    });

    test('baseline deviation rounding: 0.90 yields 14 points', () => {
      const input = createBaseInput({
        baseline: { evaluated: true, has_sufficient_history: true, deviation_score: 0.90 }
      });
      const res = scoreRisk(input);
      assertRiskInvariant(res, 19); // base 5 + 14
      expect(res.contributing_signals).toContainEqual({
        signal: 'behavioral_baseline_deviation',
        category: 'baseline',
        weight: 14
      });
    });

    test('baseline deviation rounding: 0.50 yields 8 points', () => {
      const input = createBaseInput({
        baseline: { evaluated: true, has_sufficient_history: true, deviation_score: 0.50 }
      });
      const res = scoreRisk(input);
      assertRiskInvariant(res, 13); // base 5 + 8
      expect(res.contributing_signals).toContainEqual({
        signal: 'behavioral_baseline_deviation',
        category: 'baseline',
        weight: 8
      });
    });

    test('baseline deviation 0 yields no behavioral deviation signal', () => {
      const input = createBaseInput({
        baseline: { evaluated: true, has_sufficient_history: true, deviation_score: 0.0 }
      });
      const res = scoreRisk(input);
      assertRiskInvariant(res, 5);
      const devSignal = res.contributing_signals.find((s) => s.signal === 'behavioral_baseline_deviation');
      expect(devSignal).toBeUndefined();
    });

    test('baseline unevaluated or insufficient history yields weight-0 informational signal', () => {
      const input1 = createBaseInput({
        baseline: { evaluated: false, has_sufficient_history: true, deviation_score: null }
      });
      const res1 = scoreRisk(input1);
      assertRiskInvariant(res1, 5);
      expect(res1.contributing_signals).toContainEqual({
        signal: 'baseline_insufficient_history',
        category: 'baseline',
        weight: 0
      });

      const input2 = createBaseInput({
        baseline: { evaluated: true, has_sufficient_history: false, deviation_score: null }
      });
      const res2 = scoreRisk(input2);
      assertRiskInvariant(res2, 5);
      expect(res2.contributing_signals).toContainEqual({
        signal: 'baseline_insufficient_history',
        category: 'baseline',
        weight: 0
      });
    });
  });

  describe('7. Verification Confidence Deduction', () => {
    test('elapsed 0 gives maximum -30 deduction', () => {
      const input = createBaseInput({
        event_type: 'password_change', // 20
        verification: { elapsed_seconds: 0 }
      });
      // base 20 - 30 = -10, but floor adjustment brings it to 0
      const res = scoreRisk(input);
      assertRiskInvariant(res, 0);

      const verifSignal = res.contributing_signals.find((s) => s.signal === 'recent_step_up_verification');
      expect(verifSignal).toBeDefined();
      expect(verifSignal.weight).toBe(-30);
    });

    test('elapsed 450 gives half -15 deduction', () => {
      const input = createBaseInput({
        event_type: 'password_change', // 20
        verification: { elapsed_seconds: 450 }
      });
      const res = scoreRisk(input);
      assertRiskInvariant(res, 5); // 20 - 15 = 5

      const verifSignal = res.contributing_signals.find((s) => s.signal === 'recent_step_up_verification');
      expect(verifSignal).toBeDefined();
      expect(verifSignal.weight).toBe(-15);
    });

    test('elapsed 900 or greater gives 0 deduction and emits no verification signal', () => {
      const input = createBaseInput({
        event_type: 'password_change',
        verification: { elapsed_seconds: 900 }
      });
      const res = scoreRisk(input);
      assertRiskInvariant(res, 20);

      const verifSignal = res.contributing_signals.find((s) => s.signal === 'recent_step_up_verification');
      expect(verifSignal).toBeUndefined();
    });

    test('verification null emits no verification signal', () => {
      const input = createBaseInput({
        verification: null
      });
      const res = scoreRisk(input);
      const verifSignal = res.contributing_signals.find((s) => s.category === 'verification');
      expect(verifSignal).toBeUndefined();
    });
  });

  describe('8. Global Ceiling and Floor Bounds', () => {
    test('exercises floor branch when verification deduction exceeds raw risk', () => {
      const input = createBaseInput({
        event_type: 'session_created', // base 0
        verification: { elapsed_seconds: 0 } // deduction 30
      });
      const res = scoreRisk(input);
      assertRiskInvariant(res, 0, 'low');

      const floorAdj = res.contributing_signals.find((s) => s.signal === 'score_floor_adjustment');
      expect(floorAdj).toBeDefined();
      expect(floorAdj.weight).toBe(30); // 0 - 30 + 30 = 0
    });

    test('exercises ceiling branch with custom config where caps sum exceeds 100', () => {
      const customConfig = {
        ...riskConfig,
        CATEGORY_CAPS: {
          base_action: 50,
          context: 50,
          sequence: 50,
          timing: 20,
          baseline: 30
        }
      };

      const input = createBaseInput({
        event_type: 'high_impact_action',
        action_sensitivity: 'critical',
        context: { unrecognized_device: true, unrecognized_country: true, impossible_travel: true },
        sequence: { matched_rules: [{ rule_id: 'rule1', points: 30 }] },
        timing: { automation_suspected: true },
        baseline: { evaluated: true, has_sufficient_history: true, deviation_score: 1.0 }
      });

      const res = scoreRisk(input, customConfig);
      assertRiskInvariant(res, 100, 'critical');

      const ceilingAdj = res.contributing_signals.find((s) => s.signal === 'score_ceiling_adjustment');
      expect(ceilingAdj).toBeDefined();
      expect(ceilingAdj.weight).toBeLessThan(0);
    });
  });

  describe('9. Worked Scenarios from Approved Design Note', () => {
    test('Scenario A (Legitimate User Routine Login): score 5, tier low, single signal', () => {
      const input = createBaseInput({
        event_type: 'login_success',
        action_sensitivity: 'medium',
        context: {
          unrecognized_device: false,
          unrecognized_country: false,
          impossible_travel: false
        },
        sequence: { matched_rules: [] },
        timing: { automation_suspected: false },
        baseline: { evaluated: true, has_sufficient_history: true, deviation_score: 0.0 },
        verification: null
      });

      const res = scoreRisk(input);
      assertRiskInvariant(res, 5, 'low');
      expect(res.contributing_signals).toEqual([
        { signal: 'base_action_login_success', category: 'base_action', weight: 5 }
      ]);
    });

    test('Scenario B (Simulated Takeover Sequence): score 89, tier critical, exact signal list', () => {
      const input = {
        event_type: 'password_change',
        action_sensitivity: 'critical',
        context: {
          unrecognized_device: true,
          unrecognized_country: true,
          impossible_travel: true
        },
        sequence: {
          matched_rules: [
            { rule_id: 'seq_rapid_credential_cascade', points: 20 },
            { rule_id: 'seq_high_velocity_actions', points: 10 }
          ]
        },
        timing: { automation_suspected: false }, // Non-login: login-only bot timing
        baseline: {
          evaluated: true,
          has_sufficient_history: true,
          deviation_score: 0.90
        },
        verification: null
      };

      const res = scoreRisk(input);
      assertRiskInvariant(res, 89, 'critical');

      // Exact 10 signals from design note Section 4
      expect(res.contributing_signals).toEqual([
        { signal: 'base_action_password_change', category: 'base_action', weight: 20 },
        { signal: 'action_sensitivity_critical', category: 'base_action', weight: 5 },
        { signal: 'unrecognized_device', category: 'context', weight: 10 },
        { signal: 'unrecognized_country', category: 'context', weight: 10 },
        { signal: 'impossible_travel', category: 'context', weight: 20 },
        { signal: 'context_risk_cap_adjustment', category: 'adjustment', weight: -15 },
        { signal: 'seq_rapid_credential_cascade', category: 'sequence', weight: 20 },
        { signal: 'seq_high_velocity_actions', category: 'sequence', weight: 10 },
        { signal: 'sequence_risk_cap_adjustment', category: 'adjustment', weight: -5 },
        { signal: 'behavioral_baseline_deviation', category: 'baseline', weight: 14 }
      ]);
    });
  });

  describe('10. Exhaustive Deterministic Sweep', () => {
    test('asserts exact invariant across combinatorial permutations', () => {
      const eventTypes = ['login_success', 'password_change', 'high_impact_action', 'login_failed'];
      const sensitivities = ['low', 'medium', 'high', 'critical'];
      const contextCombos = [
        { unrecognized_device: false, unrecognized_country: false, impossible_travel: false },
        { unrecognized_device: true, unrecognized_country: false, impossible_travel: false },
        { unrecognized_device: true, unrecognized_country: true, impossible_travel: false },
        { unrecognized_device: true, unrecognized_country: true, impossible_travel: true }
      ];
      const deviations = [0.0, 0.25, 0.65, 0.95];
      const verifications = [null, { elapsed_seconds: 0 }, { elapsed_seconds: 300 }, { elapsed_seconds: 900 }];

      for (const event_type of eventTypes) {
        for (const action_sensitivity of sensitivities) {
          for (const context of contextCombos) {
            for (const deviation_score of deviations) {
              for (const verification of verifications) {
                const input = {
                  event_type,
                  action_sensitivity,
                  context,
                  sequence: {
                    matched_rules: [{ rule_id: 'seq_rapid_credential_cascade', points: 20 }]
                  },
                  timing: { automation_suspected: true },
                  baseline: {
                    evaluated: true,
                    has_sufficient_history: true,
                    deviation_score
                  },
                  verification
                };

                const res = scoreRisk(input);
                assertRiskInvariant(res);
              }
            }
          }
        }
      }
    });
  });

  describe('11. Input Validation (RiskInputError)', () => {
    test('throws for null or non-object input', () => {
      expect(() => scoreRisk(null)).toThrow(RiskInputError);
      expect(() => scoreRisk('string')).toThrow(RiskInputError);
    });

    test('throws for unknown event_type', () => {
      const input = createBaseInput({ event_type: 'invalid_event_type' });
      expect(() => scoreRisk(input)).toThrow(RiskInputError);
    });

    test('throws for unknown action_sensitivity', () => {
      const input = createBaseInput({ action_sensitivity: 'extreme' });
      expect(() => scoreRisk(input)).toThrow(RiskInputError);
    });

    test('throws for non-boolean context flags', () => {
      const input = createBaseInput({
        context: { unrecognized_device: 'yes', unrecognized_country: false, impossible_travel: false }
      });
      expect(() => scoreRisk(input)).toThrow(RiskInputError);
    });

    test('throws for invalid baseline deviation_score (out of bounds or NaN)', () => {
      const input1 = createBaseInput({
        baseline: { evaluated: true, has_sufficient_history: true, deviation_score: 1.5 }
      });
      expect(() => scoreRisk(input1)).toThrow(RiskInputError);

      const input2 = createBaseInput({
        baseline: { evaluated: true, has_sufficient_history: true, deviation_score: -0.1 }
      });
      expect(() => scoreRisk(input2)).toThrow(RiskInputError);

      const input3 = createBaseInput({
        baseline: { evaluated: true, has_sufficient_history: true, deviation_score: NaN }
      });
      expect(() => scoreRisk(input3)).toThrow(RiskInputError);
    });

    test('throws for negative or non-finite verification elapsed_seconds', () => {
      const input1 = createBaseInput({
        verification: { elapsed_seconds: -10 }
      });
      expect(() => scoreRisk(input1)).toThrow(RiskInputError);

      const input2 = createBaseInput({
        verification: { elapsed_seconds: Infinity }
      });
      expect(() => scoreRisk(input2)).toThrow(RiskInputError);
    });

    test('throws for malformed sequence matched_rules', () => {
      const input1 = createBaseInput({
        sequence: { matched_rules: 'not-an-array' }
      });
      expect(() => scoreRisk(input1)).toThrow(RiskInputError);

      const input2 = createBaseInput({
        sequence: { matched_rules: [{ rule_id: '', points: 10 }] }
      });
      expect(() => scoreRisk(input2)).toThrow(RiskInputError);

      const input3 = createBaseInput({
        sequence: { matched_rules: [{ rule_id: 'r1', points: -5 }] }
      });
      expect(() => scoreRisk(input3)).toThrow(RiskInputError);
    });
  });

  describe('12. Architectural Purity Guard', () => {
    test('inputs and config are deep-frozen and never mutated across repeated calls', () => {
      const frozenInput = Object.freeze({
        event_type: 'login_success',
        action_sensitivity: 'high',
        context: Object.freeze({
          unrecognized_device: true,
          unrecognized_country: false,
          impossible_travel: false
        }),
        sequence: Object.freeze({
          matched_rules: Object.freeze([{ rule_id: 'r1', points: 10 }])
        }),
        timing: Object.freeze({ automation_suspected: false }),
        baseline: Object.freeze({
          evaluated: true,
          has_sufficient_history: true,
          deviation_score: 0.5
        }),
        verification: null
      });

      const res1 = scoreRisk(frozenInput);
      const res2 = scoreRisk(frozenInput);
      expect(res1).toEqual(res2);
    });

    test('riskScoring.js is strictly pure (no DB, redis, clock, random, env, or service imports)', () => {
      const filePath = path.join(__dirname, '../src/utils/riskScoring.js');
      const fileContent = fs.readFileSync(filePath, 'utf8');

      const prohibitedPatterns = [
        /\bsequelize\b/i,
        /\bredis\b/i,
        /\bmodels\b/i,
        /\bservices\b/i,
        /process\.env/i,
        /\bDate\b/,
        /Math\.random/
      ];

      for (const pattern of prohibitedPatterns) {
        expect(fileContent).not.toMatch(pattern);
      }
    });
  });

  describe('13. Explanations (Detect-and-Contain Compliance)', () => {
    test.each(['low', 'medium', 'high', 'critical'])('generates explanations for tier %s', (tier) => {
      const mockResult = {
        risk_score: tier === 'low' ? 10 : tier === 'medium' ? 45 : tier === 'high' ? 70 : 90,
        risk_tier: tier,
        contributing_signals: [
          { signal: 'base_action_login_success', category: 'base_action', weight: 5 },
          { signal: 'unrecognized_device', category: 'context', weight: 10 }
        ]
      };

      const explanation = buildExplanation(mockResult);
      expect(explanation).toBeDefined();
      expect(typeof explanation.user_facing).toBe('string');
      expect(typeof explanation.admin_facing).toBe('string');

      // user_facing constraints:
      // No digits
      expect(explanation.user_facing).not.toMatch(/\d/);
      // No signal names
      expect(explanation.user_facing).not.toMatch(/base_action|unrecognized_device|impossible_travel/i);
      // None of the prohibited words
      expect(explanation.user_facing).not.toMatch(/\b(prevent|guarantee|breach|hacked)\b/i);

      // admin_facing constraints:
      expect(explanation.admin_facing).toContain(String(mockResult.risk_score));
      expect(explanation.admin_facing).toContain(mockResult.risk_tier);
      expect(explanation.admin_facing).toContain('base_action_login_success');
      expect(explanation.admin_facing).toContain('unrecognized_device');
    });
  });
});
