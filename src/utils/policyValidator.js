/**
 * Pure Policy Schema & Semantic Validator (Module 9 - Policy-as-Code)
 *
 * Validates in-memory policy configurations against strict schema and semantic rules.
 * Pure function: contains zero I/O, no database/Redis access, no environment lookups,
 * and no system clock/randomness.
 */

class PolicyValidationError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'PolicyValidationError';
    this.details = details;
  }
}

const VALID_DECISIONS = Object.freeze(['allow', 'monitor', 'reverify', 'delay', 'block']);
const VALID_TIERS = Object.freeze(['low', 'medium', 'high', 'critical']);
const VALID_SENSITIVITIES = Object.freeze(['low', 'medium', 'high', 'critical']);
const VALID_ENFORCEMENT_MODES = Object.freeze(['automatic', 'recommend_only']);

/**
 * Validates a parsed policy data object.
 *
 * @param {any} policyData - Parsed JSON/object representing a security policy
 * @returns {boolean} Returns true if valid, throws PolicyValidationError if invalid
 * @throws {PolicyValidationError}
 */
function validatePolicySchema(policyData) {
  if (!policyData || typeof policyData !== 'object' || Array.isArray(policyData)) {
    throw new PolicyValidationError('Policy must be a non-null object');
  }

  // 1. schema_version and policy_id
  if (typeof policyData.schema_version !== 'string' || policyData.schema_version.trim() === '') {
    throw new PolicyValidationError('Policy must have a non-empty string schema_version');
  }
  if (typeof policyData.policy_id !== 'string' || policyData.policy_id.trim() === '') {
    throw new PolicyValidationError('Policy must have a non-empty string policy_id');
  }

  // 2. DECISION_ORDER
  if (!Array.isArray(policyData.DECISION_ORDER) || policyData.DECISION_ORDER.length !== VALID_DECISIONS.length) {
    throw new PolicyValidationError(
      `DECISION_ORDER must be an array of length ${VALID_DECISIONS.length}: [${VALID_DECISIONS.join(', ')}]`
    );
  }
  for (let i = 0; i < VALID_DECISIONS.length; i++) {
    if (policyData.DECISION_ORDER[i] !== VALID_DECISIONS[i]) {
      throw new PolicyValidationError(
        `DECISION_ORDER index ${i} must be '${VALID_DECISIONS[i]}', received '${policyData.DECISION_ORDER[i]}'`
      );
    }
  }

  // 3. DEFAULT_ACTION_SENSITIVITY
  if (
    !policyData.DEFAULT_ACTION_SENSITIVITY ||
    typeof policyData.DEFAULT_ACTION_SENSITIVITY !== 'object' ||
    Array.isArray(policyData.DEFAULT_ACTION_SENSITIVITY)
  ) {
    throw new PolicyValidationError('DEFAULT_ACTION_SENSITIVITY must be an object');
  }
  const sensitivityKeys = Object.keys(policyData.DEFAULT_ACTION_SENSITIVITY);
  if (sensitivityKeys.length === 0) {
    throw new PolicyValidationError('DEFAULT_ACTION_SENSITIVITY cannot be empty');
  }
  for (const actionKey of sensitivityKeys) {
    const sensVal = policyData.DEFAULT_ACTION_SENSITIVITY[actionKey];
    if (!VALID_SENSITIVITIES.includes(sensVal)) {
      throw new PolicyValidationError(
        `DEFAULT_ACTION_SENSITIVITY['${actionKey}'] has invalid sensitivity '${sensVal}'. Must be one of: ${VALID_SENSITIVITIES.join(', ')}`
      );
    }
  }

  // 4. BASE_MATRIX (4x4 lookup table)
  if (!policyData.BASE_MATRIX || typeof policyData.BASE_MATRIX !== 'object' || Array.isArray(policyData.BASE_MATRIX)) {
    throw new PolicyValidationError('BASE_MATRIX must be an object');
  }
  for (const tier of VALID_TIERS) {
    if (!policyData.BASE_MATRIX[tier] || typeof policyData.BASE_MATRIX[tier] !== 'object') {
      throw new PolicyValidationError(`BASE_MATRIX must contain tier row '${tier}'`);
    }
    for (const sens of VALID_SENSITIVITIES) {
      const decision = policyData.BASE_MATRIX[tier][sens];
      if (!VALID_DECISIONS.includes(decision)) {
        throw new PolicyValidationError(
          `BASE_MATRIX['${tier}']['${sens}'] must be one of [${VALID_DECISIONS.join(', ')}], received '${decision}'`
        );
      }
    }
  }

  // 5. ESCALATION_RULES
  if (!Array.isArray(policyData.ESCALATION_RULES)) {
    throw new PolicyValidationError('ESCALATION_RULES must be an array');
  }
  const seenRuleIds = new Set();
  for (let i = 0; i < policyData.ESCALATION_RULES.length; i++) {
    const rule = policyData.ESCALATION_RULES[i];
    if (!rule || typeof rule !== 'object') {
      throw new PolicyValidationError(`ESCALATION_RULES[${i}] must be an object`);
    }
    if (typeof rule.id !== 'string' || rule.id.trim() === '') {
      throw new PolicyValidationError(`ESCALATION_RULES[${i}] must have a non-empty string id`);
    }
    if (seenRuleIds.has(rule.id)) {
      throw new PolicyValidationError(`Duplicate escalation rule id detected: '${rule.id}'`);
    }
    seenRuleIds.add(rule.id);

    if (!VALID_DECISIONS.includes(rule.min_decision)) {
      throw new PolicyValidationError(
        `ESCALATION_RULES rule '${rule.id}' min_decision '${rule.min_decision}' is invalid. Must be one of: ${VALID_DECISIONS.join(', ')}`
      );
    }
  }

  // 6. FAIL_SAFE_BY_SENSITIVITY
  if (
    !policyData.FAIL_SAFE_BY_SENSITIVITY ||
    typeof policyData.FAIL_SAFE_BY_SENSITIVITY !== 'object' ||
    Array.isArray(policyData.FAIL_SAFE_BY_SENSITIVITY)
  ) {
    throw new PolicyValidationError('FAIL_SAFE_BY_SENSITIVITY must be an object');
  }
  for (const sens of VALID_SENSITIVITIES) {
    const fsDecision = policyData.FAIL_SAFE_BY_SENSITIVITY[sens];
    if (!VALID_DECISIONS.includes(fsDecision)) {
      throw new PolicyValidationError(
        `FAIL_SAFE_BY_SENSITIVITY['${sens}'] must be a valid decision, received '${fsDecision}'`
      );
    }
    if (fsDecision === 'allow') {
      throw new PolicyValidationError(
        `FAIL_SAFE_BY_SENSITIVITY['${sens}'] cannot be 'allow' under zero-trust fail-safe policy`
      );
    }
  }

  // 7. ENFORCEMENT_MODE_BY_DECISION
  if (
    !policyData.ENFORCEMENT_MODE_BY_DECISION ||
    typeof policyData.ENFORCEMENT_MODE_BY_DECISION !== 'object' ||
    Array.isArray(policyData.ENFORCEMENT_MODE_BY_DECISION)
  ) {
    throw new PolicyValidationError('ENFORCEMENT_MODE_BY_DECISION must be an object');
  }
  for (const dec of VALID_DECISIONS) {
    const mode = policyData.ENFORCEMENT_MODE_BY_DECISION[dec];
    if (!VALID_ENFORCEMENT_MODES.includes(mode)) {
      throw new PolicyValidationError(
        `ENFORCEMENT_MODE_BY_DECISION['${dec}'] must be one of [${VALID_ENFORCEMENT_MODES.join(', ')}], received '${mode}'`
      );
    }
  }

  // 8. RECOMMENDED_ACTIONS
  if (
    !policyData.RECOMMENDED_ACTIONS ||
    typeof policyData.RECOMMENDED_ACTIONS !== 'object' ||
    Array.isArray(policyData.RECOMMENDED_ACTIONS)
  ) {
    throw new PolicyValidationError('RECOMMENDED_ACTIONS must be an object');
  }
  for (const dec of VALID_DECISIONS) {
    if (!Array.isArray(policyData.RECOMMENDED_ACTIONS[dec])) {
      throw new PolicyValidationError(`RECOMMENDED_ACTIONS['${dec}'] must be an array of action strings`);
    }
  }

  return true;
}

module.exports = {
  validatePolicySchema,
  PolicyValidationError,
  VALID_DECISIONS,
  VALID_TIERS,
  VALID_SENSITIVITIES,
  VALID_ENFORCEMENT_MODES
};
