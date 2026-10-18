# ActionGuard Demo Scenarios & Simulation Engine

## Overview

Module 13 provides attack simulation, demonstration scenarios, and false-positive test fixtures for ActionGuard.

The scenario engine provides a reproducible, deterministic environment for demonstrating how ActionGuard evaluates session risk and enforces adaptive Zero Trust security policies in real-time.

Crucially:
- **No Mock Engine**: The scenario runner executes against the **real** ActionGuard pipeline (`eventService`, `sequenceGroupingService`, `riskEngineService`, `sequenceRiskService`, `policyDecision`, and `containmentService`).
- **No Hardcoded Outcomes**: Risk scores, risk tiers, sequence rule matches, policy decisions, and containment actions are calculated dynamically by production logic.
- **Strict Data Isolation & Safety**: All scenarios operate on dedicated, run-scoped demo identities (`demo-<scenario_id>-<run_id>@demo.actionguard.local`). No development, test, or production data is modified or deleted.

---

## Supported Scenarios

### 1. Scenario A — Normal User Activity (`scenario_a`)
* **Purpose**: Demonstrates legitimate session activity from a recognized employee workstation within the expected geographical location.
* **Input Sequence**:
  1. *Baseline seed*: Initial login from corporate workstation (`fp_demo_known_workstation_01`, country `US`, IP `198.51.100.10`).
  2. *Step 1*: Normal login (`login_success`).
  3. *Step 2*: Profile update (`phone_number_change`, medium sensitivity).
  4. *Step 3*: Subsequent routine session activity (`login_success`).
* **Expected System Behavior**:
  - Context signals: Device recognized, country recognized.
  - Risk tier: Evaluated as `low` (scores 5–15).
  - Policy decision: `allow` throughout.
  - User impact: Zero friction or interruptions.

### 2. Scenario B — Simulated Account Takeover (`scenario_b`)
* **Purpose**: Simulates an adversary who has obtained valid credentials attempting account takeover from an unrecognized device and foreign location.
* **Input Sequence**:
  1. *Baseline seed*: Legitimate user's established historical login in `US` from corporate workstation.
  2. *Step 1*: Attacker login (`login_success`) from an unrecognized device (`fp_attacker_external_device_99`) in a foreign country (`RU`).
  3. *Step 2*: Attacker attempts rapid recovery credential change (`recovery_email_change`, high sensitivity).
  4. *Step 3*: Attacker attempts a high-impact operation (`high_impact_action`, critical sensitivity) within the 15-minute correlation window.
* **Expected System Behavior**:
  - Step 1: Detects `unrecognized_device` (+10) and `unrecognized_country` (+10). Score rises to 25 (`low`). Policy allows initial login.
  - Step 2: Context signals persist. Score reaches 41 (`medium`). Escalation rule `esc_double_novelty` triggers `reverify` (step-up challenge).
  - Step 3: Sequence analyzer detects `seq_takeover_progression` (+25 points). Score reaches 70 (`high`). Escalation rule `esc_takeover_progression` mandates `block`.
  - Containment: System immediately triggers session invalidation and locks the account (`locked_until`), recording `enforcement_outcome: 'contained_and_blocked'`.

### 3. False-Positive Validation Fixtures
ActionGuard is designed to avoid unnecessary user disruption. A single novel signal must not trigger premature blocking unless combined with anomalous sequence patterns or policy escalation.

| Fixture ID | Description | Key Signals | Expected Outcome |
| :--- | :--- | :--- | :--- |
| `fp_benign_new_device` | Legitimate user logs in from a newly purchased phone or tablet in their home country. | `unrecognized_device` (+10), low sensitivity | Score 15 (`low`), Decision: `allow` |
| `fp_benign_travel_login` | Legitimate user logs in from the UK 24 hours after a US session (realistic transit time). | `unrecognized_country` (+10), `impossible_travel: false` | Score 15 (`low`), Decision: `allow` |
| `fp_benign_profile_update` | Legitimate user updates phone number from known device. | Single modification (no cascade, no takeover sequence) | Score 15 (`low`), Decision: `allow` |

---

## Execution Guide

### CLI Execution
The scenario runner can be executed directly using the bundled CLI utility:

```bash
# List available scenarios
node src/scenarios/cli.js --list

# Execute Scenario A (Normal user)
node src/scenarios/cli.js --scenario=scenario_a

# Execute Scenario B (Simulated takeover)
node src/scenarios/cli.js --scenario=scenario_b

# Execute with immediate cleanup
node src/scenarios/cli.js --scenario=scenario_b --cleanup

# Run false-positive validation fixtures
node src/scenarios/cli.js --scenario=fp_benign_new_device
node src/scenarios/cli.js --scenario=fp_benign_travel_login
node src/scenarios/cli.js --scenario=fp_benign_profile_update

# Clean up records for a specific run ID
node src/scenarios/cli.js --cleanup --runId=<run_id>
```

### Programmatic API (for Module 13.2 & Testing)
The scenario engine exposes a programmatic interface in `src/scenarios/index.js`:

```javascript
const {
  runScenario,
  compareFalsePositive,
  cleanupScenarioRun,
  listScenarioDefinitions
} = require('./src/scenarios');

// 1. Run Scenario A
const summaryA = await runScenario('scenario_a', {
  runId: 'demo_run_001',
  cleanupBefore: true,
  cleanupAfter: false
});
console.log('Final decision:', summaryA.final_outcome.policy_decision); // 'allow'

// 2. Run Scenario B
const summaryB = await runScenario('scenario_b', {
  runId: 'demo_run_002'
});
console.log('Contained:', summaryB.final_outcome.is_contained); // true

// 3. Evaluate a false-positive scenario
const fpReport = await compareFalsePositive('fp_benign_new_device');
console.log('Non-false-positive confirmed:', fpReport.is_acceptable); // true

// 4. Safe targeted cleanup
await cleanupScenarioRun({ runId: 'demo_run_001' });
```

---

## How to Inspect Events and Policy Decisions

### 1. Via User Portal Endpoints
With the demo user's authentication token:
- `GET /api/v1/me/events` — Inspect chronological security events.
- `GET /api/v1/me/risk-history` — Inspect evaluated risk tiers and timestamps.
- `GET /api/v1/me/decisions` — Inspect policy decisions and user-facing explanations.

### 2. Via Administrator Endpoints
Using an admin session token (`requireAdminToken`):
- `GET /api/v1/admin/users/:id/events` — Complete security event telemetry with context.
- `GET /api/v1/admin/users/:id/risk-history` — Full risk assessment breakdown with numeric scores and weights.
- `GET /api/v1/admin/users/:id/decisions` — Complete PDP decisions, matched rule IDs, contributing signals, and admin explanations.

### 3. Direct Database Queries
```sql
-- Query decisions for a demo user
SELECT id, action_type, risk_score, risk_tier, effective_decision, enforcement_outcome, decided_at
FROM policy_decisions
WHERE user_id = 'usr_...'
ORDER BY decided_at ASC;

-- Query security events
SELECT event_id, event_type, timestamp, JSON_PRETTY(context), JSON_PRETTY(metadata)
FROM security_events
WHERE user_id = 'usr_...'
ORDER BY timestamp ASC;
```

---

## Safety, Repeatability, and Cleanup Rules

1. **Deterministic Run Scope**: Every scenario execution generates or accepts a unique `run_id`. User accounts, sessions, and events are strictly namespaced with this identifier.
2. **Pre-Run Cleanup**: If re-executing a scenario with the same `run_id`, previous records matching that run are safely removed first, preventing database bloat or duplicate event sequences.
3. **Targeted Deletion**: `cleanupScenarioRun` requires an explicit `userId` or `runId`. Broad or unbounded deletions (`DELETE FROM table`) are strictly blocked.
4. **Secret Redaction**: Passwords, raw JWTs, session secrets, and unhashed device fingerprints are never displayed in CLI summaries or execution logs.

---

## Current Detection Capabilities vs Documented Limitations

### Currently Implemented & Verified
- **Device Novelty**: Detects first-time sightings of device fingerprints for users with historical logins (+10 context points).
- **Geographic Novelty**: Detects first-time sightings of foreign countries for users with historical logins (+10 context points).
- **Impossible Travel**: Calculates speed between coordinates; flags travel exceeding 800 km/h (+20 context points).
- **Sequence Pattern Analysis**:
  - `seq_takeover_progression` (Untrusted login → Account modification → High-impact action within 15 min, +25 sequence points).
  - `seq_rapid_credential_cascade` (Multiple credential/recovery changes within 10 min, +20 sequence points).
  - `seq_auth_failure_burst` (Repeated authentication failures followed by login, +15 sequence points).
- **Adaptive Policy Decision & Containment**: Base risk matrix with rule escalations (`esc_takeover_progression` → block; triggers automatic session invalidation and account lock).

### Documented Limitations (MVP Scope)
- **Advanced Behavioral ML**: Behavioral deviations currently use statistical standard score / baseline models rather than deep neural network behavioral modeling.
- **Client Biometrics**: Keystroke dynamics and mouse movement velocity telemetry are not implemented.
- **Third-Party Threat Intel**: External Tor exit node and VPN/proxy IP reputation feeds are simulated locally; external live SaaS threat intelligence lookups are not connected in this module.

---

## Integration with Part 13.2

Part 13.2 connects the scenario runner to the live presentation workflow and frontend demonstration UI:
1. **Runner Module Reuse**: Part 13.2 will import `runScenario`, `getScenarioDefinition`, and `cleanupScenarioRun` directly from `src/scenarios`.
2. **WebSocket Real-Time Broadcasts**: During scenario execution, real-time events (`event:recorded`, `risk:updated`, `decision:recorded`) are automatically broadcast to active Socket.IO clients on the demo dashboard.
3. **Live Demo Reset Button**: The frontend demo dashboard can trigger `cleanupScenarioRun` to reset the demonstration state instantly between conference presentations.
