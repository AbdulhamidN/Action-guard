# ActionGuard — Live Competition Demo Runbook (Module 13.2)

## 1. Demo Objective & Security Problem

### The Problem
Traditional perimeter-based authentication treats successful login as a permanent trust grant. Once an attacker obtains valid credentials or steals a session token, perimeter defenses consider the attacker "trusted." The attacker can then navigate freely, modify recovery contacts, enroll malicious MFA factors, and execute high-impact destructive operations without challenge.

### ActionGuard's Zero Trust Solution
ActionGuard continuously verifies every session and action using an adaptive Zero Trust evaluation pipeline:
- **Never Trust, Always Verify**: Trust assertions are short-lived and continually recalculated based on incoming telemetry.
- **Context & Behavioral Novelty**: Detects first-time sightings of unfamiliar devices and geographical locations.
- **Sequence Pattern Analysis**: Identifies hostile sequences (e.g. untrusted login → rapid credential change → high-impact action) before irreversible damage occurs.
- **Proportional Response & Active Containment**: Escalates from logging (`allow`), to identity challenges (`reverify`), cooling-off periods (`delay`), and immediate session invalidation and account locking (`block` / `contained_and_blocked`).
- **Explainability**: Delivers plain-language explanations to affected users and detailed signal attribution to security administrators.

---

## 2. Prerequisites & Environment Configuration

### Required Dependencies
- **Node.js**: v18.0.0+ (Node 20+ recommended)
- **MySQL**: 8.0+ running on port `3306` (or Docker container)
- **Redis**: 7.0+ running on port `6379` (or Docker container)

### Environment Configuration (`.env`)
Ensure `.env` in the project root includes:
```ini
NODE_ENV=development
PORT=3000

# Database
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=actionguard_dev
DB_USER=root
DB_PASSWORD=rootpassword

# Redis
REDIS_HOST=127.0.0.1
REDIS_PORT=6379

# Security Secrets (Demo development keys)
JWT_SECRET=dev_jwt_secret_key_with_at_least_32_characters_12345
ACTIONGUARD_ADMIN_API_KEY=admin_secret_key_with_at_least_32_characters_12345
SERVICE_API_KEY=service_api_key_32_characters_long_min_12345
```

---

## 3. Verified Setup & Startup Commands

Run the following commands in order:

### 1. Database Migrations
```bash
npm run migrate
```
*Applies all 12 schema migrations including users, sessions, devices, security events, sequences, risk assessments, and policy decisions.*

### 2. Start Backend Service
```bash
npm run dev
# Or production mode:
npm start
```
*Starts the Express and Socket.IO API server on `http://localhost:3000`.*

### 3. Start Frontend Development Server
In a separate terminal:
```bash
npm run dev:frontend
```
*Serves the Vite frontend application on `http://localhost:5173`.*

---

## 4. How to Execute Each Scenario

You can present the demonstration either via the **Admin Web Console** or via the **Interactive CLI**.

### Option A: Via the Admin Web Console (Recommended for Judges)
1. Navigate to `http://localhost:5173/admin/login`.
2. Authenticate using the administrator key:
   - **Admin API Key**: `admin_secret_key_with_at_least_32_characters_12345`
3. Click the **"Live Demo"** tab in the top navigation bar (`/admin/demo`).
4. Select a scenario from the dropdown:
   - `Scenario A: Normal User Activity`
   - `Scenario B: Simulated Account Takeover`
   - `False-Positive Check: Benign New Device`
   - `False-Positive Check: Feasible Travel Login`
   - `False-Positive Check: Routine Account Modification`
5. Click **"Run Live Simulation"**.
6. Observe the real-time execution steps, dynamic risk score, contributing signals, policy decisions, and containment indicators.
7. Click **"View User Activity & Decisions Graph →"** to inspect the live audit trail in the Admin Console.
8. Click **"Reset Demo Data"** to clean up the demo run cleanly.

### Option B: Via the Terminal CLI
```bash
# List all registered scenarios
npm run demo -- --list

# Run Scenario A (Normal User)
npm run demo:scenario-a

# Run Scenario B (Simulated Account Takeover)
npm run demo:scenario-b

# Run False-Positive Validation
npm run demo:fp

# Clean up records for a specific run ID
npm run demo -- --cleanup --runId=<run_id>
```

---

## 5. Expected Scenario Progression vs Observed Results

### Scenario A — Normal User Activity (`scenario_a`)
* **Expected Input**: Corporate workstation in home country (`US`), ordinary login, and profile update.
* **Pipeline Progression**:
  - Step 1 (`login_success`): Base risk 5, recognized workstation. Decision: **`allow`**.
  - Step 2 (`phone_number_change`): Base risk 15, medium sensitivity. No suspicious sequences. Decision: **`allow`**.
  - Step 3 (`login_success`): Known session. Decision: **`allow`**.
* **Observed System Outcome**:
  - Final Risk Score: **5–15** (Risk Tier: **`low`**)
  - Final Decision: **`allow`**
  - Enforcement Outcome: **`allowed`**
  - Containment: **`false`** (Zero friction, no interruption).

### Scenario B — Simulated Account Takeover (`scenario_b`)
* **Expected Input**: Baseline user history established. Attacker logs in from unfamiliar device in Russia (`RU`), alters recovery email, and attempts a high-impact operation.
* **Pipeline Progression**:
  - Step 1 (`login_success`):
    - Novelty flags detected: `unrecognized_device` (+10) and `unrecognized_country` (+10).
    - Score: **25** (Tier: `low`). Decision: **`allow`** (ActionGuard avoids blocking solely on initial context novelty).
  - Step 2 (`recovery_email_change`):
    - Sensitivity: `high`. Context signals persist (+20). Base risk: +18 + 3 = 21.
    - Score: **41** (Tier: `medium`).
    - Policy escalation: `esc_double_novelty` triggers decision **`reverify`** (step-up authentication challenged).
  - Step 3 (`high_impact_action`):
    - Sensitivity: `critical`. Sequence pattern detector triggers rule **`seq_takeover_progression`** (+25 points).
    - Score: **70** (Tier: `high`).
    - Policy escalation: Rule `esc_takeover_progression` mandates decision **`block`**.
    - Containment: Session is immediately invalidated, and the account is locked (`locked_until` set in MySQL).
* **Observed System Outcome**:
  - Final Risk Score: **70** (Risk Tier: **`high`**)
  - Final Decision: **`block`**
  - Enforcement Outcome: **`contained_and_blocked`**
  - Containment: **`true`** (Active session revoked, account locked).

---

## 6. Where to Inspect System Records & Audit Trail

### 1. In the Web Admin Console
- **Live Demo Page** (`/admin/demo`): Inspect step-by-step signals, explanations, and scores.
- **User Detail Page** (`/admin/users/:userId`):
  - **Risk Timeline**: Graphical trend of evaluated risk scores.
  - **Active Sessions**: Displays session termination status.
  - **Security Events**: Filterable audit trail of all JSON contexts.
- **Decision Graph** (`/admin/users/:userId/decisions/:decisionId`): Interactive React Flow diagram showing input signals, active policy version (`default-v1@1.0.0`), matched rules, and output decision.

### 2. In MySQL Database
```sql
-- View generated decisions and containment outcomes
SELECT id, action_type, risk_score, risk_tier, effective_decision, enforcement_outcome, decided_at
FROM policy_decisions
WHERE user_id = '<user_id>'
ORDER BY decided_at ASC;

-- View user lock state
SELECT id, email, locked_until FROM users WHERE id = '<user_id>';

-- View sequence events correlated by the pipeline
SELECT s.id AS sequence_id, se.step_order, e.event_type, e.timestamp
FROM action_sequences s
JOIN sequence_events se ON se.sequence_id = s.id
JOIN security_events e ON e.event_id = se.event_id
WHERE s.user_id = '<user_id>'
ORDER BY se.step_order ASC;
```

---

## 7. Demonstrating Legitimate-but-Unusual Activity (False Positives)

Run each of the three targeted false-positive fixtures:

```bash
# 1. Legitimate user logs in from a newly purchased phone
npm run demo -- --scenario=fp_benign_new_device

# 2. Legitimate user arrives in the UK 24 hours later (feasible travel)
npm run demo -- --scenario=fp_benign_travel_login

# 3. Legitimate user updates phone number from usual workstation
npm run demo -- --scenario=fp_benign_profile_update
```

### Key Talking Points for Judges:
- **Distinguishing Novelty from Attack**: `fp_benign_new_device` generates an `unrecognized_device` (+10) signal, yet the policy returns **`allow`** because there is no hostile sequence or impossible travel.
- **Proportionality**: ActionGuard does not penalize users for buying a new phone or traveling overseas. Security measures escalate only when high-impact actions correlate with hostile patterns.

---

## 8. Safe Data Reset & Repeatability

To clean up records created by a demo run:
```bash
# Clean up using the run ID displayed in output
npm run demo -- --cleanup --runId=<run_id>
```
Or click the **"Reset Demo Data"** button directly in the `/admin/demo` web UI.

### Safety Guarantees:
- Cleanup deletes **only** records belonging to that specific scenario run ID.
- Pre-existing user accounts, sessions, and development seeds (`dev-seed-user@actionguard.test`) are strictly untouched.
- Repeated cleanup is idempotent and safe.

---

## 9. Troubleshooting Guide

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| `ECONNREFUSED 127.0.0.1:3306` | MySQL server is stopped | Start MySQL: `docker compose up -d` or start local MySQL service. |
| `ECONNREFUSED 127.0.0.1:6379` | Redis server is stopped | Start Redis: `docker compose up -d` or start local Redis service. |
| `Admin authentication failed (401)` | Invalid Admin API key | Verify `ACTIONGUARD_ADMIN_API_KEY` matches `.env` (`admin_secret_key_with_at_least_32_characters_12345`). |
| `Table 'actionguard_dev.x' doesn't exist` | Pending migrations | Run `npm run migrate` in the project root. |
| Port 3000 or 5173 in use | Stale process running | Stop existing Node processes: `kill $(lsof -t -i:3000)` or free port. |

---

## 10. Competition Presentation Sequence (5-Minute Script)

1. **Introduction (30s)**:
   - "Welcome to ActionGuard. Traditional IAM trusts user sessions permanently after login. ActionGuard provides continuous Zero Trust session protection."
2. **Scenario A — Normal User Baseline (60s)**:
   - Open `/admin/demo` and select `Scenario A`. Click **"Run Live Simulation"**.
   - "Notice that routine activity from a known device produces Low risk scores (5–15) and Allow decisions. The user experiences zero friction."
3. **Scenario B — Account Takeover Simulation (120s)**:
   - Select `Scenario B`. Click **"Run Live Simulation"**.
   - "Now an attacker logs in with stolen credentials from an unfamiliar device in Russia. Notice that ActionGuard does not block immediately on novel device alone (Score 25, Allow)."
   - "When the attacker modifies recovery credentials, risk escalates to Medium (Score 41) and challenges for identity re-verification."
   - "When the attacker attempts a critical high-impact action, ActionGuard's sequence engine detects `seq_takeover_progression`. Risk jumps to 70 (High). Active policy triggers `block` and executes automated containment: the session is revoked, and the account is locked in real-time."
4. **Explainability & Decision Graph (45s)**:
   - Click **"View User Activity & Decisions Graph →"**.
   - Show the judge the interactive graph displaying input signals, policy version, and explanation rationale.
5. **False-Positive Prevention (45s)**:
   - Return to `/admin/demo` and run `fp_benign_new_device`.
   - "ActionGuard avoids false positives: a legitimate user logging in from a new tablet is permitted without lockouts or disruptive friction."

---

## 11. Current MVP Capabilities vs Known Limitations

### Demonstrated in MVP
- Continuous, event-by-event risk assessment and sequence correlation.
- Deterministic sequence pattern detection (`seq_takeover_progression`, `seq_rapid_credential_cascade`).
- Real-time policy enforcement with automated session revocation and temporary account locking.
- Explainable security decisions for users and administrators.
- Real-time WebSocket telemetry stream to admin consoles.

### Out of Scope / Unsupported in MVP
- Deep-learning neural network behavioral baselines (statistical z-score models are implemented).
- Client-side biometric telemetry (keystroke dynamics, mouse curvature).
- Live third-party commercial threat intelligence subscription feeds (simulated/heuristics used).
- Hardware security key attestation (FIDO2 WebAuthn; TOTP/OTP step-up implemented).
