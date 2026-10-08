/**
 * Pure Deterministic Risk Scoring Engine (Sub-module 6.1)
 *
 * Implements pure mathematical risk scoring and signal breakdown.
 * Pure functions only. Deterministic rounding with Math.round throughout.
 */

const defaultConfig = require('../config/riskConfig');

class RiskInputError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RiskInputError';
  }
}

/**
 * Maps a numeric risk score to its corresponding risk tier.
 *
 * @param {number} score - Integer risk score between 0 and 100
 * @param {object} [config=defaultConfig] - Configuration object
 * @returns {'low'|'medium'|'high'|'critical'}
 */
function tierForScore(score, config = defaultConfig) {
  if (typeof score !== 'number' || !Number.isFinite(score)) {
    throw new RiskInputError(`Invalid score: ${score}. Must be a finite number.`);
  }

  const thresholds = config.TIER_THRESHOLDS || defaultConfig.TIER_THRESHOLDS;
  if (score < thresholds.medium) {
    return 'low';
  }
  if (score < thresholds.high) {
    return 'medium';
  }
  if (score < thresholds.critical) {
    return 'high';
  }
  return 'critical';
}

/**
 * Checks the scoring input payload strictly.
 * Throws RiskInputError on any invalid or missing required field.
 *
 * @param {object} input
 * @param {object} config
 */
function verifyScoringInput(input, config) {
  if (!input || typeof input !== 'object') {
    throw new RiskInputError('Input must be a non-null object.');
  }

  // 1. event_type
  if (typeof input.event_type !== 'string' || !config.BASE_RISK_MAP[input.event_type] && config.BASE_RISK_MAP[input.event_type] !== 0) {
    throw new RiskInputError(
      `Invalid event_type: '${input.event_type}'. Must be one of: ${Object.keys(config.BASE_RISK_MAP).join(', ')}`
    );
  }

  // 2. action_sensitivity
  const sensitivity = input.action_sensitivity !== undefined ? input.action_sensitivity : 'medium';
  if (typeof sensitivity !== 'string' || !Object.prototype.hasOwnProperty.call(config.SENSITIVITY_MODIFIERS, sensitivity)) {
    throw new RiskInputError(
      `Invalid action_sensitivity: '${sensitivity}'. Must be one of: ${Object.keys(config.SENSITIVITY_MODIFIERS).join(', ')}`
    );
  }

  // 3. context flags
  if (!input.context || typeof input.context !== 'object') {
    throw new RiskInputError("Input must include a 'context' object with boolean flags.");
  }
  const contextKeys = ['unrecognized_device', 'unrecognized_country', 'impossible_travel'];
  for (const k of contextKeys) {
    if (typeof input.context[k] !== 'boolean') {
      throw new RiskInputError(`context.${k} must be a boolean. Received: ${typeof input.context[k]}`);
    }
  }

  // 4. sequence
  if (input.sequence !== undefined && input.sequence !== null) {
    if (typeof input.sequence !== 'object' || !Array.isArray(input.sequence.matched_rules)) {
      throw new RiskInputError("sequence must be an object containing a 'matched_rules' array.");
    }
    for (const rule of input.sequence.matched_rules) {
      if (!rule || typeof rule !== 'object') {
        throw new RiskInputError('Each sequence rule must be a non-null object.');
      }
      if (typeof rule.rule_id !== 'string' || rule.rule_id.trim() === '') {
        throw new RiskInputError('Each sequence rule must have a non-empty string rule_id.');
      }
      if (typeof rule.points !== 'number' || !Number.isFinite(rule.points) || rule.points < 0) {
        throw new RiskInputError(`Sequence rule '${rule.rule_id}' has invalid points: ${rule.points}. Must be a non-negative finite number.`);
      }
    }
  }

  // 5. timing
  if (!input.timing || typeof input.timing !== 'object') {
    throw new RiskInputError("Input must include a 'timing' object.");
  }
  if (typeof input.timing.automation_suspected !== 'boolean') {
    throw new RiskInputError(`timing.automation_suspected must be a boolean. Received: ${typeof input.timing.automation_suspected}`);
  }

  // 6. baseline
  if (!input.baseline || typeof input.baseline !== 'object') {
    throw new RiskInputError("Input must include a 'baseline' object.");
  }
  if (typeof input.baseline.evaluated !== 'boolean') {
    throw new RiskInputError(`baseline.evaluated must be a boolean. Received: ${typeof input.baseline.evaluated}`);
  }
  if (typeof input.baseline.has_sufficient_history !== 'boolean') {
    throw new RiskInputError(`baseline.has_sufficient_history must be a boolean. Received: ${typeof input.baseline.has_sufficient_history}`);
  }
  if (input.baseline.evaluated && input.baseline.has_sufficient_history) {
    const dev = input.baseline.deviation_score;
    if (typeof dev !== 'number' || !Number.isFinite(dev) || dev < 0 || dev > 1) {
      throw new RiskInputError(`baseline.deviation_score must be a finite number between 0 and 1. Received: ${dev}`);
    }
  }

  // 7. verification
  if (input.verification !== undefined && input.verification !== null) {
    if (typeof input.verification !== 'object') {
      throw new RiskInputError("verification must be an object or null.");
    }
    const elapsed = input.verification.elapsed_seconds;
    if (typeof elapsed !== 'number' || !Number.isFinite(elapsed) || elapsed < 0) {
      throw new RiskInputError(`verification.elapsed_seconds must be a non-negative finite number. Received: ${elapsed}`);
    }
  }
}

/**
 * Pure scoring function calculating numeric risk score, tier, and exact contributing signals.
 *
 * @param {object} input - Plain input data
 * @param {object} [config=defaultConfig] - Frozen risk configuration
 * @returns {{
 *   status: 'ok',
 *   risk_score: number,
 *   risk_tier: 'low'|'medium'|'high'|'critical',
 *   contributing_signals: Array<{ signal: string, category: string, weight: number }>
 * }}
 */
function scoreRisk(input, config = defaultConfig) {
  verifyScoringInput(input, config);

  const contributing_signals = [];

  // 1. Base Action Term
  const baseValue = config.BASE_RISK_MAP[input.event_type];
  contributing_signals.push({
    signal: `base_action_${input.event_type}`,
    category: 'base_action',
    weight: baseValue
  });

  const sensitivity = input.action_sensitivity || 'medium';
  const sensitivityMod = config.SENSITIVITY_MODIFIERS[sensitivity];
  if (sensitivityMod > 0) {
    contributing_signals.push({
      signal: `action_sensitivity_${sensitivity}`,
      category: 'base_action',
      weight: sensitivityMod
    });
  }

  const baseRaw = baseValue + sensitivityMod;
  let baseEffective = baseRaw;
  const baseCap = config.CATEGORY_CAPS.base_action;
  if (baseRaw > baseCap) {
    const adjustment = -(baseRaw - baseCap);
    contributing_signals.push({
      signal: 'base_action_cap_adjustment',
      category: 'adjustment',
      weight: adjustment
    });
    baseEffective = baseCap;
  }

  // 2. Context Term
  let contextRaw = 0;
  if (input.context.unrecognized_device) {
    const w = config.CONTEXT_WEIGHTS.unrecognized_device;
    contextRaw += w;
    contributing_signals.push({
      signal: 'unrecognized_device',
      category: 'context',
      weight: w
    });
  }
  if (input.context.unrecognized_country) {
    const w = config.CONTEXT_WEIGHTS.unrecognized_country;
    contextRaw += w;
    contributing_signals.push({
      signal: 'unrecognized_country',
      category: 'context',
      weight: w
    });
  }
  if (input.context.impossible_travel) {
    const w = config.CONTEXT_WEIGHTS.impossible_travel;
    contextRaw += w;
    contributing_signals.push({
      signal: 'impossible_travel',
      category: 'context',
      weight: w
    });
  }

  let contextEffective = contextRaw;
  const contextCap = config.CATEGORY_CAPS.context;
  if (contextRaw > contextCap) {
    const adjustment = -(contextRaw - contextCap);
    contributing_signals.push({
      signal: 'context_risk_cap_adjustment',
      category: 'adjustment',
      weight: adjustment
    });
    contextEffective = contextCap;
  }

  // 3. Sequence Term
  let sequenceRaw = 0;
  const matchedRules = (input.sequence && Array.isArray(input.sequence.matched_rules))
    ? input.sequence.matched_rules
    : [];

  for (const rule of matchedRules) {
    sequenceRaw += rule.points;
    contributing_signals.push({
      signal: rule.rule_id,
      category: 'sequence',
      weight: rule.points
    });
  }

  let sequenceEffective = sequenceRaw;
  const sequenceCap = config.CATEGORY_CAPS.sequence;
  if (sequenceRaw > sequenceCap) {
    const adjustment = -(sequenceRaw - sequenceCap);
    contributing_signals.push({
      signal: 'sequence_risk_cap_adjustment',
      category: 'adjustment',
      weight: adjustment
    });
    sequenceEffective = sequenceCap;
  }

  // 4. Timing Term
  let timingRaw = 0;
  if (input.timing && input.timing.automation_suspected) {
    timingRaw += config.TIMING_WEIGHT;
    contributing_signals.push({
      signal: 'automation_timing_burst',
      category: 'timing',
      weight: config.TIMING_WEIGHT
    });
  }

  let timingEffective = timingRaw;
  const timingCap = config.CATEGORY_CAPS.timing;
  if (timingRaw > timingCap) {
    const adjustment = -(timingRaw - timingCap);
    contributing_signals.push({
      signal: 'timing_risk_cap_adjustment',
      category: 'adjustment',
      weight: adjustment
    });
    timingEffective = timingCap;
  }

  // 5. Baseline Deviation Term
  let baselineRaw = 0;
  if (!input.baseline.evaluated || !input.baseline.has_sufficient_history) {
    contributing_signals.push({
      signal: 'baseline_insufficient_history',
      category: 'baseline',
      weight: 0
    });
  } else {
    // Deterministic rounding throughout using Math.round
    const rawPoints = Math.round(input.baseline.deviation_score * config.BASELINE_SCALE);
    if (rawPoints > 0) {
      baselineRaw = rawPoints;
      contributing_signals.push({
        signal: 'behavioral_baseline_deviation',
        category: 'baseline',
        weight: rawPoints
      });
    }
  }

  let baselineEffective = baselineRaw;
  const baselineCap = config.CATEGORY_CAPS.baseline;
  if (baselineRaw > baselineCap) {
    const adjustment = -(baselineRaw - baselineCap);
    contributing_signals.push({
      signal: 'baseline_risk_cap_adjustment',
      category: 'adjustment',
      weight: adjustment
    });
    baselineEffective = baselineCap;
  }

  // 6. Verification Confidence Deduction Term
  let deduction = 0;
  if (input.verification && typeof input.verification.elapsed_seconds === 'number') {
    const elapsed = input.verification.elapsed_seconds;
    const windowSecs = config.VERIFICATION.window_seconds;
    const maxDiscount = config.VERIFICATION.max;

    // Linear decay floored at 0 with Math.round
    const decay = Math.round(maxDiscount * (1 - elapsed / windowSecs));
    deduction = Math.max(0, decay);
    if (deduction > 0) {
      contributing_signals.push({
        signal: 'recent_step_up_verification',
        category: 'verification',
        weight: -deduction
      });
    }
  }

  // 7. Global Ceiling and Floor Bounds
  const rawTotal = baseEffective + contextEffective + sequenceEffective + timingEffective + baselineEffective - deduction;
  let finalScore = rawTotal;

  if (rawTotal > 100) {
    const ceilingAdjustment = -(rawTotal - 100);
    contributing_signals.push({
      signal: 'score_ceiling_adjustment',
      category: 'adjustment',
      weight: ceilingAdjustment
    });
    finalScore = 100;
  } else if (rawTotal < 0) {
    const floorAdjustment = -rawTotal; // Positive value restoring score to 0
    contributing_signals.push({
      signal: 'score_floor_adjustment',
      category: 'adjustment',
      weight: floorAdjustment
    });
    finalScore = 0;
  }

  const riskTier = tierForScore(finalScore, config);

  // 8. Self-Checking Invariant Verification (Defense-in-depth)
  const computedSum = contributing_signals.reduce((acc, s) => acc + s.weight, 0);
  if (computedSum !== finalScore) {
    throw new Error(
      `Risk invariant violation: sum of signal weights (${computedSum}) does not equal risk_score (${finalScore}).`
    );
  }
  if (!Number.isInteger(finalScore) || finalScore < 0 || finalScore > 100) {
    throw new Error(
      `Risk invariant violation: risk_score (${finalScore}) must be an integer between 0 and 100.`
    );
  }
  if (tierForScore(finalScore, config) !== riskTier) {
    throw new Error(
      `Risk invariant violation: risk_tier '${riskTier}' is inconsistent with score ${finalScore}.`
    );
  }

  return {
    status: 'ok',
    risk_score: finalScore,
    risk_tier: riskTier,
    contributing_signals
  };
}

/**
 * Builds deterministic plain-language explanations matching the detect-and-contain security model.
 *
 * @param {object} result - Output of scoreRisk
 * @returns {{ user_facing: string, admin_facing: string }}
 */
function buildExplanation(result) {
  if (!result || typeof result !== 'object') {
    throw new RiskInputError('Result must be a valid scoreRisk output object.');
  }

  const tier = result.risk_tier;

  // User-facing explanations:
  // Strictly no digits, no signal names, no thresholds.
  // Must NOT contain "prevent", "guarantee", "breach", or "hacked".
  const USER_FACING_TEMPLATES = {
    low: 'Activity appears consistent with normal usage patterns.',
    medium: 'Unusual activity attributes observed for this action. Additional confirmation may be requested.',
    high: 'Multiple security context anomalies observed. Additional verification may be required to proceed.',
    critical: 'Elevated risk pattern observed across multiple security indicators. Administrative review or re-authentication may be required.'
  };

  const userFacing = USER_FACING_TEMPLATES[tier] || USER_FACING_TEMPLATES.low;

  // Admin-facing explanations:
  // Formats score, tier, and detailed signals list with weights
  const signals = Array.isArray(result.contributing_signals) ? result.contributing_signals : [];
  const signalDetails = signals.length > 0
    ? signals.map((s) => `${s.signal} (${s.weight > 0 ? '+' : ''}${s.weight})`).join(', ')
    : 'none';

  const adminFacing = `Risk score ${result.risk_score} (tier: ${result.risk_tier}). Contributing signals: ${signalDetails}.`;

  return {
    user_facing: userFacing,
    admin_facing: adminFacing
  };
}

module.exports = {
  RiskInputError,
  tierForScore,
  scoreRisk,
  buildExplanation
};
