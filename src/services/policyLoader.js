/**
 * Policy Loader Service (Module 9 - Policy-as-Code)
 *
 * Responsible for reading versioned policy files from disk, validating them against
 * policyValidator, and caching the active policy reference immutably.
 *
 * Guarantees:
 * 1. Strict schema validation on all loaded policies.
 * 2. Fail-closed: Throws immediately on missing or invalid policy files (never silently falls back).
 * 3. Candidate isolation: loadPolicyFile() loads candidate policies without touching activePolicy.
 * 4. Atomic activation: reloadActivePolicy() validates and freezes the new policy completely
 *    before swapping the in-memory pointer.
 */

const fs = require('fs');
const path = require('path');
const { validatePolicySchema, PolicyValidationError } = require('../utils/policyValidator');
const { ACCOUNT_MODIFICATION_TYPES } = require('../config/riskConfig');

class PolicyLoadError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'PolicyLoadError';
    this.details = details;
  }
}

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

const DEFAULT_POLICY_PATH = path.resolve(__dirname, '../../policies/default-v1.json');

let activePolicy = null;

/**
 * Loads, parses, validates, and freezes a policy file from a specified path.
 * Does NOT alter or mutate activePolicy.
 *
 * @param {string} filePath - Absolute or relative path to policy JSON file
 * @returns {object} Deep-frozen validated policy object
 * @throws {PolicyLoadError|PolicyValidationError}
 */
function loadPolicyFile(filePath) {
  if (!filePath || typeof filePath !== 'string') {
    throw new PolicyLoadError('filePath must be a non-empty string');
  }

  const resolvedPath = path.resolve(process.cwd(), filePath);

  if (!fs.existsSync(resolvedPath)) {
    throw new PolicyLoadError(`Policy file not found: '${resolvedPath}'`);
  }

  let rawContent;
  try {
    rawContent = fs.readFileSync(resolvedPath, 'utf8');
  } catch (err) {
    throw new PolicyLoadError(`Failed to read policy file at '${resolvedPath}': ${err.message}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(rawContent);
  } catch (err) {
    throw new PolicyLoadError(`Malformed JSON in policy file at '${resolvedPath}': ${err.message}`);
  }

  // Validate policy schema & semantics
  validatePolicySchema(parsed);

  // Attach authoritative account modification types if not explicitly set
  if (!Array.isArray(parsed.ACCOUNT_MODIFICATION_TYPES)) {
    parsed.ACCOUNT_MODIFICATION_TYPES = ACCOUNT_MODIFICATION_TYPES;
  }

  return deepFreeze(parsed);
}

/**
 * Resolves and loads the active policy.
 * Caches the active policy as an immutable singleton.
 *
 * @returns {object} The active deep-frozen policy object
 */
function loadActivePolicy() {
  if (activePolicy !== null) {
    return activePolicy;
  }

  const configuredPath = process.env.ACTIONGUARD_POLICY_FILE || process.env.POLICY_FILE || DEFAULT_POLICY_PATH;
  activePolicy = loadPolicyFile(configuredPath);
  return activePolicy;
}

/**
 * Gets the currently active policy, loading it if not yet loaded.
 *
 * @returns {object}
 */
function getActivePolicy() {
  if (activePolicy === null) {
    return loadActivePolicy();
  }
  return activePolicy;
}

/**
 * Atomically reloads the active policy from disk.
 * Loads, validates, and deep-freezes the replacement policy completely BEFORE
 * replacing the active reference. If any step fails, activePolicy remains untouched.
 *
 * @param {string} [filePath] - Optional new policy file path; defaults to configured or default path
 * @returns {object} The newly activated deep-frozen policy object
 */
function reloadActivePolicy(filePath) {
  const targetPath = filePath || process.env.ACTIONGUARD_POLICY_FILE || process.env.POLICY_FILE || DEFAULT_POLICY_PATH;
  
  // 1. Load, parse, validate, and freeze into local reference
  const candidatePolicy = loadPolicyFile(targetPath);

  // 2. Atomic pointer swap (safe in single-threaded JS event loop)
  activePolicy = candidatePolicy;

  return activePolicy;
}

/**
 * Resets active policy cache for testing purposes.
 */
function resetActivePolicy() {
  activePolicy = null;
}

module.exports = {
  loadPolicyFile,
  loadActivePolicy,
  getActivePolicy,
  reloadActivePolicy,
  resetActivePolicy,
  deepFreeze,
  DEFAULT_POLICY_PATH,
  PolicyLoadError,
  PolicyValidationError
};
