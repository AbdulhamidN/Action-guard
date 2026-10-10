const fs = require('fs');
const path = require('path');
const {
  validatePolicySchema,
  PolicyValidationError
} = require('../src/utils/policyValidator');
const {
  loadPolicyFile,
  loadActivePolicy,
  getActivePolicy,
  reloadActivePolicy,
  resetActivePolicy,
  DEFAULT_POLICY_PATH,
  PolicyLoadError
} = require('../src/services/policyLoader');

describe('Module 9 — Policy Loader & Schema Validator Tests', () => {
  const scratchDir = path.resolve(__dirname, '../scratch/test_policies');

  beforeAll(() => {
    if (!fs.existsSync(scratchDir)) {
      fs.mkdirSync(scratchDir, { recursive: true });
    }
  });

  afterAll(() => {
    if (fs.existsSync(scratchDir)) {
      fs.rmSync(scratchDir, { recursive: true, force: true });
    }
  });

  beforeEach(() => {
    resetActivePolicy();
    delete process.env.ACTIONGUARD_POLICY_FILE;
    delete process.env.POLICY_FILE;
  });

  afterEach(() => {
    resetActivePolicy();
    delete process.env.ACTIONGUARD_POLICY_FILE;
    delete process.env.POLICY_FILE;
  });

  describe('1. Pure Schema & Semantic Validation (policyValidator)', () => {
    let validSample;

    beforeEach(() => {
      validSample = {
        schema_version: '1.0.0',
        policy_id: 'sample-v1',
        DECISION_ORDER: ['allow', 'monitor', 'reverify', 'delay', 'block'],
        DEFAULT_ACTION_SENSITIVITY: {
          login_success: 'low',
          password_change: 'high'
        },
        BASE_MATRIX: {
          low: { low: 'allow', medium: 'allow', high: 'monitor', critical: 'monitor' },
          medium: { low: 'allow', medium: 'monitor', high: 'reverify', critical: 'reverify' },
          high: { low: 'monitor', medium: 'reverify', high: 'delay', critical: 'block' },
          critical: { low: 'reverify', medium: 'delay', high: 'block', critical: 'block' }
        },
        ESCALATION_RULES: [
          {
            id: 'rule_1',
            min_decision: 'monitor',
            description: 'Rule 1 test'
          }
        ],
        FAIL_SAFE_BY_SENSITIVITY: {
          low: 'monitor',
          medium: 'monitor',
          high: 'block',
          critical: 'block'
        },
        ENFORCEMENT_MODE_BY_DECISION: {
          allow: 'automatic',
          monitor: 'automatic',
          reverify: 'automatic',
          delay: 'automatic',
          block: 'automatic'
        },
        RECOMMENDED_ACTIONS: {
          allow: ['proceed'],
          monitor: ['log'],
          reverify: ['otp'],
          delay: ['hold'],
          block: ['halt']
        }
      };
    });

    test('valid policy passes schema validation', () => {
      expect(validatePolicySchema(validSample)).toBe(true);
    });

    test('rejects non-object or null input', () => {
      expect(() => validatePolicySchema(null)).toThrow(PolicyValidationError);
      expect(() => validatePolicySchema('string')).toThrow(PolicyValidationError);
      expect(() => validatePolicySchema([])).toThrow(PolicyValidationError);
    });

    test('rejects missing or empty schema_version and policy_id', () => {
      const badVersion = { ...validSample, schema_version: '' };
      expect(() => validatePolicySchema(badVersion)).toThrow(/schema_version/);

      const badId = { ...validSample, policy_id: '   ' };
      expect(() => validatePolicySchema(badId)).toThrow(/policy_id/);
    });

    test('rejects invalid DECISION_ORDER (wrong order, wrong count, unknown decision)', () => {
      const wrongCount = { ...validSample, DECISION_ORDER: ['allow', 'block'] };
      expect(() => validatePolicySchema(wrongCount)).toThrow(/DECISION_ORDER/);

      const wrongOrder = {
        ...validSample,
        DECISION_ORDER: ['monitor', 'allow', 'reverify', 'delay', 'block']
      };
      expect(() => validatePolicySchema(wrongOrder)).toThrow(/DECISION_ORDER/);
    });

    test('rejects invalid sensitivity values in DEFAULT_ACTION_SENSITIVITY', () => {
      const badSensitivity = {
        ...validSample,
        DEFAULT_ACTION_SENSITIVITY: {
          login_success: 'dangerous'
        }
      };
      expect(() => validatePolicySchema(badSensitivity)).toThrow(/invalid sensitivity 'dangerous'/);
    });

    test('rejects incomplete or invalid BASE_MATRIX', () => {
      const missingTier = { ...validSample, BASE_MATRIX: { ...validSample.BASE_MATRIX } };
      delete missingTier.BASE_MATRIX.critical;
      expect(() => validatePolicySchema(missingTier)).toThrow(/critical/);

      const invalidDecision = JSON.parse(JSON.stringify(validSample));
      invalidDecision.BASE_MATRIX.high.critical = 'terminate';
      expect(() => validatePolicySchema(invalidDecision)).toThrow(/terminate/);
    });

    test('rejects duplicate escalation rule IDs', () => {
      const duplicateRules = {
        ...validSample,
        ESCALATION_RULES: [
          { id: 'dup_rule', min_decision: 'monitor', description: 'Rule 1' },
          { id: 'dup_rule', min_decision: 'delay', description: 'Rule 2' }
        ]
      };
      expect(() => validatePolicySchema(duplicateRules)).toThrow(/Duplicate escalation rule id detected: 'dup_rule'/);
    });

    test('rejects invalid escalation rule min_decision', () => {
      const badRuleDecision = {
        ...validSample,
        ESCALATION_RULES: [
          { id: 'rule_bad', min_decision: 'super_block', description: 'Bad rule' }
        ]
      };
      expect(() => validatePolicySchema(badRuleDecision)).toThrow(/super_block/);
    });

    test('rejects allow in FAIL_SAFE_BY_SENSITIVITY under zero-trust requirements', () => {
      const unsafeFailSafe = {
        ...validSample,
        FAIL_SAFE_BY_SENSITIVITY: {
          ...validSample.FAIL_SAFE_BY_SENSITIVITY,
          low: 'allow'
        }
      };
      expect(() => validatePolicySchema(unsafeFailSafe)).toThrow(/cannot be 'allow'/);
    });

    test('rejects invalid ENFORCEMENT_MODE_BY_DECISION modes', () => {
      const badMode = {
        ...validSample,
        ENFORCEMENT_MODE_BY_DECISION: {
          ...validSample.ENFORCEMENT_MODE_BY_DECISION,
          block: 'silent_ignore'
        }
      };
      expect(() => validatePolicySchema(badMode)).toThrow(/silent_ignore/);
    });
  });

  describe('2. Policy File Loading & Candidate Isolation (policyLoader)', () => {
    test('successfully loads default-v1.json policy file and deep-freezes it', () => {
      const policy = loadPolicyFile('policies/default-v1.json');
      expect(policy).toBeDefined();
      expect(policy.policy_id).toBe('default-v1');
      expect(policy.schema_version).toBe('1.0.0');
      expect(Object.isFrozen(policy)).toBe(true);
      expect(Object.isFrozen(policy.BASE_MATRIX)).toBe(true);
      expect(Object.isFrozen(policy.ESCALATION_RULES)).toBe(true);
    });

    test('successfully loads candidate-strict-v1.json policy file', () => {
      const policy = loadPolicyFile('policies/candidate-strict-v1.json');
      expect(policy).toBeDefined();
      expect(policy.policy_id).toBe('candidate-strict-v1');
      expect(Object.isFrozen(policy)).toBe(true);
    });

    test('candidate policy loading preserves active policy isolation', () => {
      const activeBefore = getActivePolicy();
      expect(activeBefore.policy_id).toBe('default-v1');

      // Load candidate policy
      const candidate = loadPolicyFile('policies/candidate-strict-v1.json');
      expect(candidate.policy_id).toBe('candidate-strict-v1');

      // Active policy must NOT be mutated
      const activeAfter = getActivePolicy();
      expect(activeAfter.policy_id).toBe('default-v1');
      expect(activeAfter).toBe(activeBefore);
    });

    test('throws PolicyLoadError for non-existent policy file (fail-closed, no silent fallback)', () => {
      expect(() => loadPolicyFile('policies/non_existent_policy_xyz.json')).toThrow(PolicyLoadError);
      expect(() => loadPolicyFile('policies/non_existent_policy_xyz.json')).toThrow(/Policy file not found/);
    });

    test('throws PolicyLoadError for malformed JSON policy file', () => {
      const malformedPath = path.join(scratchDir, 'malformed.json');
      fs.writeFileSync(malformedPath, '{ "schema_version": "1.0.0", invalid_json');

      expect(() => loadPolicyFile(malformedPath)).toThrow(PolicyLoadError);
      expect(() => loadPolicyFile(malformedPath)).toThrow(/Malformed JSON/);
    });

    test('throws PolicyValidationError for policy file with semantic schema violations', () => {
      const invalidPath = path.join(scratchDir, 'invalid_schema.json');
      fs.writeFileSync(
        invalidPath,
        JSON.stringify({
          schema_version: '1.0.0',
          policy_id: 'bad-policy',
          DECISION_ORDER: ['allow', 'block']
        })
      );

      expect(() => loadPolicyFile(invalidPath)).toThrow(PolicyValidationError);
    });
  });

  describe('3. Active Policy Resolution & Safe Atomic Reload', () => {
    test('loadActivePolicy defaults to default-v1.json when env is unset', () => {
      const active = loadActivePolicy();
      expect(active.policy_id).toBe('default-v1');
    });

    test('loadActivePolicy honors ACTIONGUARD_POLICY_FILE env variable', () => {
      process.env.ACTIONGUARD_POLICY_FILE = 'policies/candidate-strict-v1.json';
      resetActivePolicy();

      const active = loadActivePolicy();
      expect(active.policy_id).toBe('candidate-strict-v1');
    });

    test('reloadActivePolicy performs safe atomic swap to valid candidate policy', () => {
      const initial = loadActivePolicy();
      expect(initial.policy_id).toBe('default-v1');

      const reloaded = reloadActivePolicy('policies/candidate-strict-v1.json');
      expect(reloaded.policy_id).toBe('candidate-strict-v1');
      expect(getActivePolicy().policy_id).toBe('candidate-strict-v1');
    });

    test('reloadActivePolicy retains existing active policy when candidate is invalid or missing', () => {
      const initial = loadActivePolicy();
      expect(initial.policy_id).toBe('default-v1');

      // Attempt reloading non-existent policy
      expect(() => reloadActivePolicy('policies/does_not_exist.json')).toThrow(PolicyLoadError);

      // Active policy must retain initial reference unchanged
      const current = getActivePolicy();
      expect(current).toBe(initial);
      expect(current.policy_id).toBe('default-v1');
    });
  });
});
