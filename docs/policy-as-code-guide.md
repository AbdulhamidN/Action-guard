# ActionGuard — Policy-as-Code & Replay Testing Guide

## 1. Overview & Purpose

Module 9 transitions ActionGuard's Policy Decision Point (PDP) from hardcoded in-memory tables to declarative, version-controlled **Policy-as-Code** and introduces an offline **Replay Testing Harness**.

Security administrators and developers can:
1. Define, review, and version policy matrices and escalation rules as structured JSON files under version control.
2. Load, validate, deep-freeze, and atomically swap policies in production without server restarts or race conditions.
3. Replay historical and synthetic security event sequences offline against candidate policies before deployment.
4. Quantify security impacts using confusion matrix metrics (True Positives, False Positives, False Negatives, False Alarm Rate, Missed Detection Rate).
5. Inspect policy decision diffs side-by-side to detect unexpected escalations or unintended relaxations.

> [!IMPORTANT]
> Replay testing is strictly an offline evaluation harness. It never activates candidate policies in production, performs zero database or cache writes, and does not enforce security decisions.

---

## 2. Policy-as-Code Schema Specification

Policy definitions conform to the JSON schema validated by `src/utils/policyValidator.js`.

### 2.1 File Structure Example

```json
{
  "schema_version": "1.0.0",
  "policy_id": "default-v1",
  "policy_name": "ActionGuard Production Baseline Policy",
  "version": "1.0.0",
  "description": "Authoritative Module 8 baseline policy configuration",
  "decision_hierarchy": ["allow", "monitor", "reverify", "delay", "block"],
  "risk_tiers": ["low", "medium", "high", "critical"],
  "action_sensitivities": ["low", "medium", "high", "critical"],
  "base_matrix": {
    "low": {
      "low": "allow",
      "medium": "allow",
      "high": "reverify",
      "critical": "delay"
    },
    "medium": {
      "low": "allow",
      "medium": "monitor",
      "high": "reverify",
      "critical": "delay"
    },
    "high": {
      "low": "monitor",
      "medium": "reverify",
      "high": "delay",
      "critical": "block"
    },
    "critical": {
      "low": "reverify",
      "medium": "delay",
      "high": "block",
      "critical": "block"
    }
  },
  "escalation_rules": [
    {
      "id": "ESC_TAKEOVER_CASCADE",
      "name": "Rapid Credential Change Cascade",
      "description": "Escalates when rapid password, recovery email, or MFA change sequence is detected",
      "required_signals": ["rapid_credential_cascade"],
      "min_sensitivity": "medium",
      "min_decision": "delay"
    }
  ],
  "fail_safe_defaults": {
    "low": "monitor",
    "medium": "monitor",
    "high": "block",
    "critical": "block"
  },
  "default_sensitivity": {
    "login_success": "low",
    "login_failed": "low",
    "login_prompt": "low",
    "new_device": "low",
    "session_created": "low",
    "session_terminated": "low",
    "verification_success": "low",
    "verification_failed": "low",
    "phone_number_change": "medium",
    "mfa_change": "medium",
    "recovery_email_change": "high",
    "password_change": "high",
    "password_reset": "high",
    "high_impact_action": "critical"
  },
  "cooling_off_defaults": {
    "low": 0,
    "medium": 0,
    "high": 300,
    "critical": 900
  }
}
```

### 2.2 Validation Rules
`policyValidator.validatePolicy(policyObject)` enforces:
- `schema_version`: Must follow Semantic Versioning (`MAJOR.MINOR.PATCH`).
- `decision_hierarchy`: Must strictly equal `["allow", "monitor", "reverify", "delay", "block"]`.
- `base_matrix`: Complete 4x4 matrix for all risk tiers $\times$ sensitivities; every cell must be a valid decision.
- `escalation_rules`: Must be an array of unique rule IDs with valid `min_sensitivity` and `min_decision`.
- `fail_safe_defaults`: Valid response mapping for each sensitivity tier.
- `default_sensitivity`: Mappings for all known standard event types.
- `cooling_off_defaults`: Non-negative integers for each sensitivity tier.

---

## 3. Policy Loader & Atomic Activation

The policy loader (`src/services/policyLoader.js`) manages policy lifecycles.

### 3.1 Initial Loading & Active Policy Isolation
- At application startup or module load, `loadActivePolicy()` loads the policy file designated by `ACTIONGUARD_POLICY_PATH` (defaults to `policies/default-v1.json`).
- If the file is missing or invalid, the loader fails closed and throws an explicit `PolicyLoadError`. It never silently defaults to an unverified or corrupted policy.
- The validated policy is deep-frozen using `deepFreeze()`, guaranteeing immutability across concurrent requests.

### 3.2 Candidate Policy Isolation
- Candidate policies are loaded offline via `loadCandidatePolicy(filePath)` or `loadPolicyFile(filePath)`.
- Loading a candidate policy **never** mutates or activates the active policy pointer.
- Offline replay testing uses candidate policy instances directly without affecting live API requests.

### 3.3 Atomic Reloading (`reloadActivePolicy`)
- Hot-reloading replaces the active policy reference atomically via a pointer swap:
  ```javascript
  const newActive = policyLoader.reloadActivePolicy(newPath);
  ```
- The new policy is fully read, parsed, validated, and deep-frozen before swapping.
- If parsing or validation fails, the existing active policy is completely preserved, and an error is thrown.

---

## 4. Replay Testing Harness

The replay harness (`src/replay/replayHarness.js`) evaluates recorded or synthetic event sequences offline against a specified policy.

### 4.1 Production Parity
Replay evaluation executes identical logic to the live pipeline:
1. **Additive Risk Scoring (`scoreRisk`):** Context signals, baseline deviations, bot timing bursts, and sequence penalties.
2. **Session Context Inheritance:** Inherits device and geographic novelty flags (`unrecognized_device`, `unrecognized_country`, `impossible_travel`) from the session's login event to subsequent actions in the sequence.
3. **Pure Policy Engine (`evaluatePolicy`):** Evaluates the effective action sensitivity, base matrix cell, and escalation rules against the injected policy object.

### 4.2 Replay Fixture Format
Fixtures are maintained in `tests/fixtures/replayScenarios.json`:
- Each scenario defines `scenario_id`, `description`, `expected_classification` (`benign` or `harmful`), `events` sequence, and classification thresholds:
  - Harmful scenarios define `min_protective_decision` (e.g. `delay`).
  - Benign scenarios define `max_acceptable_decision` (e.g. `monitor`).
- Synthetic fixtures are explicitly labeled with `synthetic: true`.

```json
{
  "scenario_id": "scen_harmful_credential_cascade_005",
  "description": "Rapid credential cascade under suspicious new-device context",
  "expected_classification": "harmful",
  "min_protective_decision": "delay",
  "synthetic": true,
  "events": [...]
}
```

### 4.3 Zero-Persistence Guarantee
The replay engine operates purely in-memory:
- Zero database queries or inserts (`risk_assessments` table is never touched).
- Zero Redis cache interactions.
- Zero WebSocket event emissions.
- Zero mutations to active policy configuration.

---

## 5. Metrics & Comparison

### 5.1 Confusion Matrix Definitions
The harness calculates classification metrics across all evaluated scenarios:
- **True Positive (TP):** Harmful scenario where final decision $\ge$ `min_protective_decision`.
- **False Negative (FN):** Harmful scenario where final decision $<$ `min_protective_decision` (missed threat).
- **True Negative (TN):** Benign scenario where final decision $\le$ `max_acceptable_decision`.
- **False Positive (FP):** Benign scenario where final decision $>$ `max_acceptable_decision` (false alarm).

### 5.2 Error Rates & Edge-Case Handling
- **False Positive Rate (FPR):** $\frac{\text{FP}}{\text{FP} + \text{TN}}$
- **False Negative Rate (FNR):** $\frac{\text{FN}}{\text{FN} + \text{TP}}$
- **Zero Denominator Handling:** If a scenario set contains zero benign cases ($\text{FP} + \text{TN} = 0$), `false_positive_rate` is returned as `'unavailable'`. If it contains zero harmful cases ($\text{FN} + \text{TP} = 0$), `false_negative_rate` is returned as `'unavailable'`.

### 5.3 Policy Version Diffing (`comparePolicies`)
Comparing two policy versions yields an actionable change report:
- `decision_changes`: Scenarios where the candidate policy produced a different decision than the baseline.
- `escalations`: Scenarios where the candidate policy was stricter.
- `relaxations`: Scenarios where the candidate policy was more lenient.
- `metrics_diff`: Side-by-side comparison of TP, FP, TN, FN, FPR, and FNR.
