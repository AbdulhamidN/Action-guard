const SENSITIVITY_RANKS = Object.freeze({
  low: 0,
  medium: 1,
  high: 2,
  critical: 3
});

const USER_FACING_EXPLANATIONS = Object.freeze({
  allow: 'This action has been approved based on standard security checks.',
  monitor: 'This action has been allowed and recorded for security review.',
  reverify: 'Additional identity verification is required before completing this action.',
  delay: 'This action is temporarily delayed pending security confirmation.',
  block: 'This action has been restricted for security reasons.'
});

function decide(input, config) {
  if (!input || typeof input !== 'object') {
    throw new Error('input must be a non-null object');
  }
  if (!config || typeof config !== 'object') {
    throw new Error('config must be a non-null object');
  }

  const action = input.action || {};
  const actionEventType = action.event_type;
  const providedSensitivity = action.provided_sensitivity;

  const defaultSensitivity =
    (config.DEFAULT_ACTION_SENSITIVITY && config.DEFAULT_ACTION_SENSITIVITY[actionEventType]) ||
    (typeof actionEventType === 'string' && actionEventType.startsWith('login_') ? 'low' : null) ||
    'low';

  let effectiveSensitivity = defaultSensitivity;
  if (
    providedSensitivity &&
    typeof providedSensitivity === 'string' &&
    Object.prototype.hasOwnProperty.call(SENSITIVITY_RANKS, providedSensitivity)
  ) {
    if (SENSITIVITY_RANKS[providedSensitivity] > SENSITIVITY_RANKS[defaultSensitivity]) {
      effectiveSensitivity = providedSensitivity;
    }
  }

  const decisionOrder = config.DECISION_ORDER || ['allow', 'monitor', 'reverify', 'delay', 'block'];

  const risk = input.risk;
  const isRiskAvailable =
    risk &&
    typeof risk === 'object' &&
    risk.status === 'ok' &&
    risk.risk_tier &&
    config.BASE_MATRIX &&
    config.BASE_MATRIX[risk.risk_tier];

  let decision;
  const reasons = [];

  if (!isRiskAvailable) {
    const failSafeMap = config.FAIL_SAFE_BY_SENSITIVITY || {
      low: 'monitor',
      medium: 'monitor',
      high: 'block',
      critical: 'block'
    };
    decision = failSafeMap[effectiveSensitivity] || 'block';
    reasons.push({
      rule_id: 'fail_safe_' + effectiveSensitivity,
      kind: 'fail_safe',
      decision
    });
  } else {
    const baseDecision = config.BASE_MATRIX[risk.risk_tier][effectiveSensitivity];
    reasons.push({
      rule_id: 'matrix_' + risk.risk_tier + '_' + effectiveSensitivity,
      kind: 'matrix',
      decision: baseDecision
    });

    const signalList = Array.isArray(risk.signal_names) ? risk.signal_names : [];
    const signals = new Set(signalList);
    const effRank = SENSITIVITY_RANKS[effectiveSensitivity];
    const accountModTypes = Array.isArray(config.ACCOUNT_MODIFICATION_TYPES)
      ? config.ACCOUNT_MODIFICATION_TYPES
      : [];

    const escalationRules = Array.isArray(config.ESCALATION_RULES) ? config.ESCALATION_RULES : [];
    for (let i = 0; i < escalationRules.length; i++) {
      const rule = escalationRules[i];
      let matches = false;

      switch (rule.id) {
        case 'esc_impossible_travel':
          matches = signals.has('impossible_travel');
          break;
        case 'esc_impossible_travel_sensitive':
          matches = signals.has('impossible_travel') && effRank >= SENSITIVITY_RANKS.medium;
          break;
        case 'esc_travel_and_novelty':
          matches =
            signals.has('impossible_travel') &&
            (signals.has('unrecognized_device') || signals.has('unrecognized_country')) &&
            effRank >= SENSITIVITY_RANKS.high;
          break;
        case 'esc_credential_cascade':
          matches =
            signals.has('seq_rapid_credential_cascade') &&
            (accountModTypes.indexOf(actionEventType) !== -1 ||
              (actionEventType === 'password_reset_request' && accountModTypes.indexOf('password_reset') !== -1));
          break;
        case 'esc_takeover_progression':
          matches =
            signals.has('seq_takeover_progression') && effRank >= SENSITIVITY_RANKS.high;
          break;
        case 'esc_automation':
          matches =
            signals.has('automation_timing_burst') && effRank >= SENSITIVITY_RANKS.medium;
          break;
        case 'esc_double_novelty':
          matches =
            signals.has('unrecognized_device') &&
            signals.has('unrecognized_country') &&
            effRank >= SENSITIVITY_RANKS.medium;
          break;
        default:
          break;
      }

      if (matches) {
        reasons.push({
          rule_id: rule.id,
          kind: 'escalation',
          decision: rule.min_decision
        });
      }
    }

    let maxRank = -1;
    let strictest = decisionOrder[0];
    for (let j = 0; j < reasons.length; j++) {
      const rDecision = reasons[j].decision;
      const rankIdx = decisionOrder.indexOf(rDecision);
      if (rankIdx > maxRank) {
        maxRank = rankIdx;
        strictest = rDecision;
      }
    }
    decision = strictest;
  }

  let hasFailSafeReason = false;
  for (let k = 0; k < reasons.length; k++) {
    if (reasons[k].kind === 'fail_safe') {
      hasFailSafeReason = true;
      break;
    }
  }

  const requires_review = decision === 'delay' || decision === 'block' || hasFailSafeReason;

  const baseRecommended =
    (config.RECOMMENDED_ACTIONS && config.RECOMMENDED_ACTIONS[decision]) || [];
  const recommended_actions = [];
  for (let m = 0; m < baseRecommended.length; m++) {
    recommended_actions.push(baseRecommended[m]);
  }
  if (requires_review && recommended_actions.indexOf('admin_review') === -1) {
    recommended_actions.push('admin_review');
  }

  const enforcement_mode =
    (config.ENFORCEMENT_MODE_BY_DECISION && config.ENFORCEMENT_MODE_BY_DECISION[decision]) ||
    'automatic';

  const user_facing =
    USER_FACING_EXPLANATIONS[decision] ||
    'This action has been evaluated based on standard security checks.';

  const reasonSummaries = [];
  for (let n = 0; n < reasons.length; n++) {
    reasonSummaries.push(reasons[n].rule_id + ' (' + reasons[n].kind + ' -> ' + reasons[n].decision + ')');
  }
  const admin_facing =
    "Policy decision '" + decision + "' reached via reasons: " + reasonSummaries.join(', ') + '.';

  return {
    decision,
    reasons,
    recommended_actions,
    enforcement_mode,
    requires_review,
    explanation: {
      user_facing,
      admin_facing
    }
  };
}

module.exports = {
  decide,
  SENSITIVITY_RANKS
};
