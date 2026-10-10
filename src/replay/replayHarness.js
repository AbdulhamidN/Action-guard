/**
 * Replay Testing Harness (Module 9 - Policy-as-Code & Replay Testing)
 *
 * Provides pure, offline, in-memory replay evaluation of recorded security event sequences
 * against versioned policy configurations.
 *
 * Guarantees:
 * 1. Production parity: Reuses production risk scoring (riskScoring.js), sequence analysis
 *    (sequenceRisk.js), and policy decision logic (policyDecision.js).
 * 2. Complete isolation: Operates 100% in-memory with zero writes to MySQL, Redis,
 *    eventBus, or live socket server.
 * 3. Determinism: Same fixtures and policy version produce identical results.
 * 4. Multi-tier classification: Implements TP, FP, TN, FN, FPR, and FNR contract,
 *    treating zero denominators as 'unavailable'.
 * 5. Version diffing: Compares decisions across two policy versions to detect behavioral shifts.
 */

const riskConfig = require('../config/riskConfig');
const { analyzeSequence } = require('../services/sequenceRiskService');
const { scoreRisk } = require('../utils/riskScoring');
const { decide, SENSITIVITY_RANKS } = require('../utils/policyDecision');

class ReplayFixtureError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'ReplayFixtureError';
    this.details = details;
  }
}

/**
 * Validates the schema of a scenario fixture.
 *
 * @param {object} scenario
 * @throws {ReplayFixtureError}
 */
function validateScenarioFixture(scenario) {
  if (!scenario || typeof scenario !== 'object') {
    throw new ReplayFixtureError('Scenario fixture must be a non-null object');
  }

  if (typeof scenario.scenario_id !== 'string' || scenario.scenario_id.trim() === '') {
    throw new ReplayFixtureError('Scenario fixture must have a non-empty string scenario_id');
  }

  if (scenario.scenario_type !== 'benign' && scenario.scenario_type !== 'harmful') {
    throw new ReplayFixtureError(
      `Scenario '${scenario.scenario_id}' has invalid scenario_type '${scenario.scenario_type}'. Must be 'benign' or 'harmful'.`
    );
  }

  if (!scenario.expected_outcome || typeof scenario.expected_outcome !== 'object') {
    throw new ReplayFixtureError(`Scenario '${scenario.scenario_id}' must specify an expected_outcome object`);
  }

  if (scenario.scenario_type === 'harmful') {
    const minProt = scenario.expected_outcome.min_protective_decision;
    if (!minProt || typeof minProt !== 'string') {
      throw new ReplayFixtureError(
        `Harmful scenario '${scenario.scenario_id}' must define expected_outcome.min_protective_decision`
      );
    }
  } else if (scenario.scenario_type === 'benign') {
    const maxAcc = scenario.expected_outcome.max_acceptable_decision;
    if (!maxAcc || typeof maxAcc !== 'string') {
      throw new ReplayFixtureError(
        `Benign scenario '${scenario.scenario_id}' must define expected_outcome.max_acceptable_decision`
      );
    }
  }

  if (!Array.isArray(scenario.events) || scenario.events.length === 0) {
    throw new ReplayFixtureError(`Scenario '${scenario.scenario_id}' must contain a non-empty events array`);
  }

  let prevOffset = -Infinity;
  for (let i = 0; i < scenario.events.length; i++) {
    const ev = scenario.events[i];
    if (!ev || typeof ev !== 'object') {
      throw new ReplayFixtureError(`Scenario '${scenario.scenario_id}' events[${i}] must be an object`);
    }
    if (typeof ev.event_id !== 'string' || ev.event_id.trim() === '') {
      throw new ReplayFixtureError(`Scenario '${scenario.scenario_id}' events[${i}] must have a valid event_id`);
    }
    if (typeof ev.event_type !== 'string' || ev.event_type.trim() === '') {
      throw new ReplayFixtureError(`Scenario '${scenario.scenario_id}' events[${i}] must have a valid event_type`);
    }
    if (typeof ev.timestamp_offset_ms !== 'number' || !Number.isFinite(ev.timestamp_offset_ms)) {
      throw new ReplayFixtureError(
        `Scenario '${scenario.scenario_id}' events[${i}] must have a numeric timestamp_offset_ms`
      );
    }
    if (ev.timestamp_offset_ms < prevOffset) {
      throw new ReplayFixtureError(
        `Scenario '${scenario.scenario_id}' events are out of chronological order at index ${i}`
      );
    }
    prevOffset = ev.timestamp_offset_ms;
  }
}

/**
 * Replays a single scenario through pure in-memory risk scoring and policy decisioning.
 *
 * @param {object} scenario - Validated scenario fixture
 * @param {object} policyConfig - Policy configuration object
 * @param {object} [options={}]
 * @param {number} [options.baseTime=1700000000000] - Base timestamp in milliseconds
 * @returns {object} Detailed scenario execution result
 */
function replayScenario(scenario, policyConfig, options = {}) {
  validateScenarioFixture(scenario);

  const baseTime = options.baseTime || 1700000000000;
  const decisionOrder = policyConfig.DECISION_ORDER || ['allow', 'monitor', 'reverify', 'delay', 'block'];

  // History tracking for novelty detection
  const priorLogins = [];
  const sequenceEvents = [];
  const stepResults = [];

  for (let i = 0; i < scenario.events.length; i++) {
    const rawEv = scenario.events[i];
    const eventTime = new Date(baseTime + rawEv.timestamp_offset_ms);
    const context = rawEv.context || {};
    const metadata = rawEv.metadata || {};

    // Novelty calculation:
    // Matches live deriveNoveltyFlags: novelty is only evaluated if user has prior login_success
    let isNewDevice = false;
    let isNewCountry = false;

    if (rawEv.event_type === 'login_success') {
      if (priorLogins.length > 0) {
        const fp = context.device_fingerprint;
        const country = context.geo_country;
        const hasMatchingDevice = priorLogins.some((p) => p.device_fingerprint === fp);
        const hasMatchingCountry = priorLogins.some((p) => p.geo_country === country);

        isNewDevice = Boolean(fp && !hasMatchingDevice);
        isNewCountry = Boolean(country && !hasMatchingCountry);
      }
      priorLogins.push({
        event_id: rawEv.event_id,
        timestamp: eventTime,
        device_fingerprint: context.device_fingerprint,
        geo_country: context.geo_country,
        isNewDevice,
        isNewCountry,
        impossibleTravel: Boolean(metadata.travel_anomaly && metadata.travel_anomaly.impossible_travel)
      });
    } else {
      // Inherit session novelty and impossible travel from session login
      if (priorLogins.length > 0) {
        const lastLogin = priorLogins[priorLogins.length - 1];
        if (lastLogin.isNewDevice) {
          isNewDevice = true;
        }
        if (lastLogin.isNewCountry) {
          isNewCountry = true;
        }
      }
    }

    // Context flags for scoreRisk (event override takes precedence, fallback to inherited session context)
    const unrecognizedDevice = context.unrecognized_device !== undefined ? Boolean(context.unrecognized_device) : isNewDevice;
    const unrecognizedCountry = context.unrecognized_country !== undefined ? Boolean(context.unrecognized_country) : isNewCountry;
    
    let impossibleTravel = false;
    if (metadata.travel_anomaly && typeof metadata.travel_anomaly.impossible_travel === 'boolean') {
      impossibleTravel = metadata.travel_anomaly.impossible_travel;
    } else if (priorLogins.length > 0) {
      const lastLogin = priorLogins[priorLogins.length - 1];
      if (lastLogin.impossibleTravel) {
        impossibleTravel = true;
      }
    }

    // Sequence representation for analyzeSequence
    sequenceEvents.push({
      event_id: rawEv.event_id,
      event_type: rawEv.event_type,
      timestamp: eventTime.toISOString(),
      is_new_device: isNewDevice,
      device_recognized: !isNewDevice
    });

    const sequenceAnalysis = analyzeSequence(sequenceEvents, riskConfig);

    // Action sensitivity resolution
    const defaultSens =
      (policyConfig.DEFAULT_ACTION_SENSITIVITY && policyConfig.DEFAULT_ACTION_SENSITIVITY[rawEv.event_type]) ||
      (rawEv.event_type.startsWith('login_') ? 'low' : null) ||
      'low';
    const providedSens = metadata.action_sensitivity || null;
    let effectiveSens = defaultSens;
    if (providedSens && SENSITIVITY_RANKS[providedSens] > SENSITIVITY_RANKS[defaultSens]) {
      effectiveSens = providedSens;
    }

    // Timing automation
    const automationSuspected = Boolean(metadata.bot_detection && metadata.bot_detection.automation_suspected);

    // Behavioral baseline
    let baselinePayload = {
      evaluated: false,
      has_sufficient_history: false,
      deviation_score: 0.0
    };
    if (metadata.behavioral_deviation && typeof metadata.behavioral_deviation === 'object') {
      baselinePayload = {
        evaluated: Boolean(metadata.behavioral_deviation.is_evaluated),
        has_sufficient_history: Boolean(metadata.behavioral_deviation.has_sufficient_history),
        deviation_score: Number(metadata.behavioral_deviation.deviation_score) || 0.0
      };
    }

    const scoringInput = {
      event_type: rawEv.event_type,
      action_sensitivity: effectiveSens,
      context: {
        unrecognized_device: unrecognizedDevice,
        unrecognized_country: unrecognizedCountry,
        impossible_travel: impossibleTravel
      },
      timing: {
        automation_suspected: automationSuspected
      },
      baseline: baselinePayload,
      sequence: sequenceAnalysis,
      verification: null
    };

    const scoredResult = scoreRisk(scoringInput, riskConfig);
    const signalNames = scoredResult.contributing_signals.map((s) => s.signal);

    const decisionInput = {
      risk: {
        status: 'ok',
        risk_tier: scoredResult.risk_tier,
        signal_names: signalNames
      },
      action: {
        event_type: rawEv.event_type,
        provided_sensitivity: providedSens
      }
    };

    const decisionResult = decide(decisionInput, policyConfig);

    stepResults.push({
      step: i + 1,
      event_id: rawEv.event_id,
      event_type: rawEv.event_type,
      effective_sensitivity: effectiveSens,
      risk_score: scoredResult.risk_score,
      risk_tier: scoredResult.risk_tier,
      contributing_signals: signalNames,
      decision: decisionResult.decision,
      reasons: decisionResult.reasons
    });
  }

  // Final step evaluates the scenario outcome
  const finalStep = stepResults[stepResults.length - 1];
  const actualDecision = finalStep.decision;
  const actualRank = decisionOrder.indexOf(actualDecision);

  let classification;
  let matchesExpectation = false;

  if (scenario.scenario_type === 'harmful') {
    const minProtective = scenario.expected_outcome.min_protective_decision;
    const minRank = decisionOrder.indexOf(minProtective);

    if (actualRank >= minRank) {
      classification = 'TP';
      matchesExpectation = true;
    } else {
      classification = 'FN';
      matchesExpectation = false;
    }
  } else {
    // benign
    const maxAcceptable = scenario.expected_outcome.max_acceptable_decision;
    const maxRank = decisionOrder.indexOf(maxAcceptable);

    if (actualRank <= maxRank) {
      classification = 'TN';
      matchesExpectation = true;
    } else {
      classification = 'FP';
      matchesExpectation = false;
    }
  }

  return {
    scenario_id: scenario.scenario_id,
    name: scenario.name,
    scenario_type: scenario.scenario_type,
    is_synthetic: Boolean(scenario.is_synthetic),
    final_decision: actualDecision,
    expected_outcome: scenario.expected_outcome,
    classification,
    matches_expectation: matchesExpectation,
    steps: stepResults
  };
}

/**
 * Replays a collection of scenarios and computes confusion matrix metrics.
 *
 * @param {Array<object>} scenarios - Array of scenario fixtures
 * @param {object} policyConfig - Policy configuration object
 * @returns {object} Replay suite evaluation report
 */
function evaluateReplaySuite(scenarios, policyConfig) {
  if (!Array.isArray(scenarios)) {
    throw new ReplayFixtureError('scenarios must be an array');
  }

  const results = [];
  const counts = {
    TP: 0,
    FP: 0,
    TN: 0,
    FN: 0
  };

  for (const scen of scenarios) {
    const res = replayScenario(scen, policyConfig);
    results.push(res);
    counts[res.classification]++;
  }

  // FPR = FP / (FP + TN)
  const benignTotal = counts.FP + counts.TN;
  const FPR = benignTotal > 0 ? counts.FP / benignTotal : 'unavailable';

  // FNR = FN / (FN + TP)
  const harmfulTotal = counts.FN + counts.TP;
  const FNR = harmfulTotal > 0 ? counts.FN / harmfulTotal : 'unavailable';

  return {
    policy_id: policyConfig.policy_id || 'unidentified',
    schema_version: policyConfig.schema_version || 'unknown',
    total_scenarios: scenarios.length,
    counts,
    rates: {
      false_positive_rate: FPR,
      false_negative_rate: FNR
    },
    results
  };
}

/**
 * Compares replay results of the same scenario suite between two policy versions.
 * Identifies decision shifts, confusion matrix changes, and reasoning diffs.
 *
 * @param {Array<object>} scenarios - Array of scenario fixtures
 * @param {object} policyA - Baseline policy
 * @param {object} policyB - Candidate policy
 * @returns {object} Comparison report
 */
function comparePoliciesOnSuite(scenarios, policyA, policyB) {
  const suiteA = evaluateReplaySuite(scenarios, policyA);
  const suiteB = evaluateReplaySuite(scenarios, policyB);

  const decisionOrder = policyA.DECISION_ORDER || ['allow', 'monitor', 'reverify', 'delay', 'block'];

  const scenarioDiffs = [];
  let totalChanged = 0;

  for (let i = 0; i < scenarios.length; i++) {
    const resA = suiteA.results[i];
    const resB = suiteB.results[i];

    const decA = resA.final_decision;
    const decB = resB.final_decision;
    const rankA = decisionOrder.indexOf(decA);
    const rankB = decisionOrder.indexOf(decB);

    const isChanged = decA !== decB;
    if (isChanged) {
      totalChanged++;
    }

    let direction = 'identical';
    if (rankB > rankA) {
      direction = 'stricter';
    } else if (rankB < rankA) {
      direction = 'relaxed';
    }

    scenarioDiffs.push({
      scenario_id: resA.scenario_id,
      name: resA.name,
      scenario_type: resA.scenario_type,
      decision_policy_a: decA,
      decision_policy_b: decB,
      classification_policy_a: resA.classification,
      classification_policy_b: resB.classification,
      changed: isChanged,
      direction
    });
  }

  return {
    baseline_policy: {
      policy_id: suiteA.policy_id,
      schema_version: suiteA.schema_version,
      counts: suiteA.counts,
      rates: suiteA.rates
    },
    candidate_policy: {
      policy_id: suiteB.policy_id,
      schema_version: suiteB.schema_version,
      counts: suiteB.counts,
      rates: suiteB.rates
    },
    total_scenarios: scenarios.length,
    total_changed: totalChanged,
    scenario_diffs: scenarioDiffs
  };
}

module.exports = {
  validateScenarioFixture,
  replayScenario,
  evaluateReplaySuite,
  comparePoliciesOnSuite,
  ReplayFixtureError
};
