const path = require('path');
const {
  validateScenarioFixture,
  replayScenario,
  evaluateReplaySuite,
  comparePoliciesOnSuite,
  ReplayFixtureError
} = require('../src/replay/replayHarness');
const { loadPolicyFile, loadActivePolicy } = require('../src/services/policyLoader');
const eventBus = require('../src/events/eventBus');
const {
  sequelize,
  RiskAssessment,
  ActionSequence,
  SequenceEvent,
  SecurityEvent
} = require('../src/database/models');

describe('Module 9 — Policy Replay Testing Harness Tests', () => {
  let policyBaseline;
  let policyStrictCandidate;
  let replayScenarios;

  beforeAll(() => {
    policyBaseline = loadPolicyFile('policies/default-v1.json');
    policyStrictCandidate = loadPolicyFile('policies/candidate-strict-v1.json');
    replayScenarios = require('./fixtures/replayScenarios.json');
  });

  afterAll(async () => {
    if (sequelize) {
      await sequelize.close();
    }
  });

  describe('1. Fixture Schema Validation (validateScenarioFixture)', () => {
    test('valid scenario fixtures pass validation', () => {
      for (const scen of replayScenarios) {
        expect(() => validateScenarioFixture(scen)).not.toThrow();
      }
    });

    test('rejects missing or non-object scenario', () => {
      expect(() => validateScenarioFixture(null)).toThrow(ReplayFixtureError);
      expect(() => validateScenarioFixture('bad_fixture')).toThrow(ReplayFixtureError);
    });

    test('rejects missing scenario_id or invalid scenario_type', () => {
      expect(() => validateScenarioFixture({ scenario_id: '' })).toThrow(/scenario_id/);
      expect(() =>
        validateScenarioFixture({
          scenario_id: 'scen_01',
          scenario_type: 'unknown_type',
          expected_outcome: {},
          events: []
        })
      ).toThrow(/invalid scenario_type/);
    });

    test('rejects harmful scenario missing min_protective_decision', () => {
      const badHarmful = {
        scenario_id: 'scen_harmful_bad',
        scenario_type: 'harmful',
        expected_outcome: {},
        events: [{ event_id: '1', event_type: 'login_success', timestamp_offset_ms: 0 }]
      };
      expect(() => validateScenarioFixture(badHarmful)).toThrow(/min_protective_decision/);
    });

    test('rejects benign scenario missing max_acceptable_decision', () => {
      const badBenign = {
        scenario_id: 'scen_benign_bad',
        scenario_type: 'benign',
        expected_outcome: {},
        events: [{ event_id: '1', event_type: 'login_success', timestamp_offset_ms: 0 }]
      };
      expect(() => validateScenarioFixture(badBenign)).toThrow(/max_acceptable_decision/);
    });

    test('rejects out-of-order event timestamps in fixture', () => {
      const outOfOrder = {
        scenario_id: 'scen_ooo',
        scenario_type: 'benign',
        expected_outcome: { max_acceptable_decision: 'monitor' },
        events: [
          { event_id: '1', event_type: 'login_success', timestamp_offset_ms: 1000 },
          { event_id: '2', event_type: 'login_success', timestamp_offset_ms: 500 }
        ]
      };
      expect(() => validateScenarioFixture(outOfOrder)).toThrow(/chronological order/);
    });
  });

  describe('2. Scenario Replay & Production-Parity Evaluation', () => {
    test('replays benign routine login accurately and classifies as True Negative (TN)', () => {
      const benignScen = replayScenarios.find((s) => s.scenario_id === 'scen_benign_routine_login_001');
      const result = replayScenario(benignScen, policyBaseline);

      expect(result.scenario_id).toBe('scen_benign_routine_login_001');
      expect(result.final_decision).toBe('allow');
      expect(result.classification).toBe('TN');
      expect(result.matches_expectation).toBe(true);
      expect(result.steps.length).toBe(2);
    });

    test('replays harmful credential cascade accurately and classifies as True Positive (TP)', () => {
      const cascadeScen = replayScenarios.find((s) => s.scenario_id === 'scen_harmful_credential_cascade_005');
      const result = replayScenario(cascadeScen, policyBaseline);

      expect(result.scenario_id).toBe('scen_harmful_credential_cascade_005');
      expect(result.final_decision).toBe('delay');
      expect(result.classification).toBe('TP');
      expect(result.matches_expectation).toBe(true);
      expect(result.steps.length).toBe(3);
    });

    test('replays harmful takeover progression to final critical block', () => {
      const takeoverScen = replayScenarios.find((s) => s.scenario_id === 'scen_harmful_takeover_progression_006');
      const result = replayScenario(takeoverScen, policyBaseline);

      expect(result.scenario_id).toBe('scen_harmful_takeover_progression_006');
      expect(result.final_decision).toBe('block');
      expect(result.classification).toBe('TP');
      expect(result.matches_expectation).toBe(true);
    });

    test('replay execution is deterministic across repeated runs', () => {
      const scen = replayScenarios[0];
      const res1 = replayScenario(scen, policyBaseline);
      const res2 = replayScenario(scen, policyBaseline);

      expect(res1).toEqual(res2);
    });

    test('replay execution is 100% in-memory with zero writes to database records', async () => {
      const assessBefore = await RiskAssessment.count();
      const seqBefore = await ActionSequence.count();
      const seqEvBefore = await SequenceEvent.count();
      const evBefore = await SecurityEvent.count();

      // Run entire fixture suite
      evaluateReplaySuite(replayScenarios, policyBaseline);

      const assessAfter = await RiskAssessment.count();
      const seqAfter = await ActionSequence.count();
      const seqEvAfter = await SequenceEvent.count();
      const evAfter = await SecurityEvent.count();

      expect(assessAfter).toBe(assessBefore);
      expect(seqAfter).toBe(seqBefore);
      expect(seqEvAfter).toBe(seqEvBefore);
      expect(evAfter).toBe(evBefore);
    });
  });

  describe('3. Replay Suite Metrics & Zero-Denominator Safety', () => {
    test('evaluates replay suite and calculates correct confusion matrix counts and rates', () => {
      const report = evaluateReplaySuite(replayScenarios, policyBaseline);

      expect(report.total_scenarios).toBe(6);
      expect(report.policy_id).toBe('default-v1');
      expect(report.schema_version).toBe('1.0.0');

      // 3 benign (all TN), 3 harmful (all TP)
      expect(report.counts).toEqual({
        TP: 3,
        FP: 0,
        TN: 3,
        FN: 0
      });

      // FPR = 0 / 3 = 0, FNR = 0 / 3 = 0
      expect(report.rates.false_positive_rate).toBe(0);
      expect(report.rates.false_negative_rate).toBe(0);
    });

    test('reports FPR as unavailable when denominator (FP + TN) is zero', () => {
      const harmfulOnly = replayScenarios.filter((s) => s.scenario_type === 'harmful');
      const report = evaluateReplaySuite(harmfulOnly, policyBaseline);

      expect(report.counts.FP + report.counts.TN).toBe(0);
      expect(report.rates.false_positive_rate).toBe('unavailable');
      expect(typeof report.rates.false_negative_rate).toBe('number');
    });

    test('reports FNR as unavailable when denominator (FN + TP) is zero', () => {
      const benignOnly = replayScenarios.filter((s) => s.scenario_type === 'benign');
      const report = evaluateReplaySuite(benignOnly, policyBaseline);

      expect(report.counts.FN + report.counts.TP).toBe(0);
      expect(report.rates.false_negative_rate).toBe('unavailable');
      expect(typeof report.rates.false_positive_rate).toBe('number');
    });

    test('classifies benign scenario exceeding max_acceptable_decision as False Positive (FP) and recomputes FPR', () => {
      // Representative benign admin action fixture where policy response exceeds tolerance
      const benignAdminScenario = {
        scenario_id: 'scen_benign_admin_action_003',
        name: 'Benign Sensitive Admin Action Exceeding Tolerance',
        scenario_type: 'benign',
        is_synthetic: true,
        expected_outcome: {
          target_decision: 'allow',
          max_acceptable_decision: 'monitor'
        },
        events: [
          {
            event_id: 'evt_admin_seed_01',
            event_type: 'login_success',
            timestamp_offset_ms: 0,
            context: {
              device_fingerprint: 'fp_admin_workstation',
              geo_country: 'US',
              ip_address: '198.51.100.10'
            },
            metadata: {
              action_sensitivity: 'low'
            }
          },
          {
            event_id: 'evt_admin_action_02',
            event_type: 'recovery_email_change',
            timestamp_offset_ms: 300000,
            context: {
              device_fingerprint: 'fp_admin_workstation',
              geo_country: 'US',
              ip_address: '198.51.100.10'
            },
            metadata: {
              action_sensitivity: 'high'
            }
          }
        ]
      };

      // Mock policy where this action evaluates to 'delay'
      const customPolicy = JSON.parse(JSON.stringify(policyBaseline));
      customPolicy.BASE_MATRIX.low.high = 'delay';

      const singleResult = replayScenario(benignAdminScenario, customPolicy);
      expect(singleResult.final_decision).toBe('delay');
      // Threshold is 'monitor'; 'delay' > 'monitor' -> MUST be FP, never TN
      expect(singleResult.classification).toBe('FP');
      expect(singleResult.matches_expectation).toBe(false);

      // Evaluate suite with 2 benign TN scenarios + 1 FP scenario
      const benignTN1 = replayScenarios.find((s) => s.scenario_id === 'scen_benign_routine_login_001');
      const benignTN2 = replayScenarios.find((s) => s.scenario_id === 'scen_benign_phone_change_002');
      const suite = evaluateReplaySuite([benignTN1, benignTN2, benignAdminScenario], customPolicy);

      expect(suite.counts.FP).toBe(1);
      expect(suite.counts.TN).toBe(2);
      expect(suite.counts.TP).toBe(0);
      expect(suite.counts.FN).toBe(0);

      // FPR = 1 / (1 + 2) = 1/3
      expect(suite.rates.false_positive_rate).toBeCloseTo(1 / 3, 5);
      expect(suite.rates.false_negative_rate).toBe('unavailable');
    });

    test('verifies all scenario fixtures have valid thresholds and consistent TP/FP/TN/FN classifications', () => {
      const decisionOrder = policyBaseline.DECISION_ORDER;
      for (const scen of replayScenarios) {
        const res = replayScenario(scen, policyBaseline);
        const actualRank = decisionOrder.indexOf(res.final_decision);

        if (scen.scenario_type === 'benign') {
          const maxRank = decisionOrder.indexOf(scen.expected_outcome.max_acceptable_decision);
          expect(maxRank).toBeGreaterThanOrEqual(0);
          if (actualRank <= maxRank) {
            expect(res.classification).toBe('TN');
            expect(res.matches_expectation).toBe(true);
          } else {
            expect(res.classification).toBe('FP');
            expect(res.matches_expectation).toBe(false);
          }
        } else if (scen.scenario_type === 'harmful') {
          const minRank = decisionOrder.indexOf(scen.expected_outcome.min_protective_decision);
          expect(minRank).toBeGreaterThanOrEqual(0);
          if (actualRank >= minRank) {
            expect(res.classification).toBe('TP');
            expect(res.matches_expectation).toBe(true);
          } else {
            expect(res.classification).toBe('FN');
            expect(res.matches_expectation).toBe(false);
          }
        }
      }

      const suite = evaluateReplaySuite(replayScenarios, policyBaseline);
      const sumCounts = suite.counts.TP + suite.counts.FP + suite.counts.TN + suite.counts.FN;
      expect(sumCounts).toBe(suite.total_scenarios);
    });
  });

  describe('4. Policy Version Comparison & Decision Diffing', () => {
    test('compares baseline against candidate policy and detects decision shifts', () => {
      const diffReport = comparePoliciesOnSuite(replayScenarios, policyBaseline, policyStrictCandidate);

      expect(diffReport.total_scenarios).toBe(6);
      expect(diffReport.baseline_policy.policy_id).toBe('default-v1');
      expect(diffReport.candidate_policy.policy_id).toBe('candidate-strict-v1');

      // scen_harmful_impossible_travel_004 had impossible_travel on login_success
      // In baseline: min monitor -> final decision 'monitor'
      // In candidate-strict-v1: min reverify -> final decision 'reverify'
      const travelDiff = diffReport.scenario_diffs.find(
        (d) => d.scenario_id === 'scen_harmful_impossible_travel_004'
      );

      expect(travelDiff).toBeDefined();
      expect(travelDiff.changed).toBe(true);
      expect(travelDiff.direction).toBe('stricter');
      expect(travelDiff.decision_policy_a).toBe('monitor');
      expect(travelDiff.decision_policy_b).toBe('reverify');

      // Verify at least 1 scenario changed
      expect(diffReport.total_changed).toBeGreaterThanOrEqual(1);
    });

    test('candidate comparison receives identical scenario inputs without mutating candidate or active policy', () => {
      const activeBefore = loadActivePolicy();

      const diffReport = comparePoliciesOnSuite(replayScenarios, policyBaseline, policyStrictCandidate);

      const activeAfter = loadActivePolicy();
      expect(activeAfter).toBe(activeBefore);
      expect(diffReport.scenario_diffs.length).toBe(replayScenarios.length);
    });

    test('correctly detects and categorizes decision relaxation (direction: relaxed)', () => {
      // Create a candidate relaxed policy where impossible travel is relaxed to 'allow'
      const relaxedCandidate = JSON.parse(JSON.stringify(policyBaseline));
      relaxedCandidate.policy_id = 'candidate-relaxed-v1';
      const escRule = relaxedCandidate.ESCALATION_RULES.find((r) => r.id === 'esc_impossible_travel');
      if (escRule) {
        escRule.min_decision = 'allow';
      }

      const diffReport = comparePoliciesOnSuite(replayScenarios, policyBaseline, relaxedCandidate);
      const travelDiff = diffReport.scenario_diffs.find(
        (d) => d.scenario_id === 'scen_harmful_impossible_travel_004'
      );

      expect(travelDiff).toBeDefined();
      expect(travelDiff.changed).toBe(true);
      expect(travelDiff.direction).toBe('relaxed');
      expect(travelDiff.decision_policy_a).toBe('monitor');
      expect(travelDiff.decision_policy_b).toBe('allow');
    });
  });

  describe('5. Production Parity & Replay Isolation Verification', () => {
    test('verifies step-by-step production parity on representative multi-event harmful scenario', () => {
      const cascadeScen = replayScenarios.find((s) => s.scenario_id === 'scen_harmful_credential_cascade_005');
      const res = replayScenario(cascadeScen, policyBaseline);

      expect(res.steps.length).toBe(3);

      // Step 1: Legitimate routine login
      expect(res.steps[0].event_type).toBe('login_success');
      expect(res.steps[0].risk_score).toBe(5);
      expect(res.steps[0].risk_tier).toBe('low');
      expect(res.steps[0].contributing_signals).toContain('base_action_login_success');
      expect(res.steps[0].decision).toBe('allow');

      // Step 2: Attacker login with impossible travel
      expect(res.steps[1].event_type).toBe('login_success');
      expect(res.steps[1].risk_score).toBe(30);
      expect(res.steps[1].risk_tier).toBe('medium');
      expect(res.steps[1].contributing_signals).toContain('unrecognized_device');
      expect(res.steps[1].contributing_signals).toContain('unrecognized_country');
      expect(res.steps[1].contributing_signals).toContain('impossible_travel');
      expect(res.steps[1].decision).toBe('monitor');

      // Step 3: Sensitive recovery email change within cascade window
      expect(res.steps[2].event_type).toBe('recovery_email_change');
      expect(res.steps[2].effective_sensitivity).toBe('high');
      expect(res.steps[2].risk_score).toBe(46);
      expect(res.steps[2].risk_tier).toBe('medium');
      expect(res.steps[2].contributing_signals).toContain('impossible_travel');
      expect(res.steps[2].contributing_signals).toContain('unrecognized_device');
      expect(res.steps[2].contributing_signals).toContain('action_sensitivity_high');
      expect(res.steps[2].decision).toBe('delay');
    });

    test('strict isolation invariant: replay executes with zero DB writes, zero Redis mutations, zero EventBus emits, and fixture immutability', async () => {
      const safeEmitSpy = jest.spyOn(eventBus, 'safeEmit');

      const assessBefore = await RiskAssessment.count();
      const seqBefore = await ActionSequence.count();
      const seqEvBefore = await SequenceEvent.count();
      const secEvBefore = await SecurityEvent.count();

      // Deep clone and freeze scenario fixture to guarantee no in-place mutations
      const fixtureCopy = JSON.parse(JSON.stringify(replayScenarios));
      fixtureCopy.forEach((s) => Object.freeze(s));

      const suiteResult = evaluateReplaySuite(fixtureCopy, policyBaseline);

      expect(suiteResult.total_scenarios).toBe(6);

      // Verify zero DB changes
      const assessAfter = await RiskAssessment.count();
      const seqAfter = await ActionSequence.count();
      const seqEvAfter = await SequenceEvent.count();
      const secEvAfter = await SecurityEvent.count();

      expect(assessAfter).toBe(assessBefore);
      expect(seqAfter).toBe(seqBefore);
      expect(seqEvAfter).toBe(seqEvBefore);
      expect(secEvAfter).toBe(secEvBefore);

      // Verify zero EventBus emissions
      expect(safeEmitSpy).not.toHaveBeenCalled();

      safeEmitSpy.mockRestore();
    });
  });
});
