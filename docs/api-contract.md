# ActionGuard API Contract

## What This Document Answers

How does an external application communicate with ActionGuard?

This document defines the endpoints, request/response formats, authentication, and event/decision structures that a protected application uses to integrate with ActionGuard as implemented in the MVP.

## 1. Base URL and Versioning

All endpoints are versioned under:

```text
https://<host>/api/v1/
```

Breaking changes to request or response structures will increment the version (`/api/v2/...`). Non-breaking additions, such as new optional fields, do not require a version change.

For the MVP, only `v1` exists.

## 2. Authentication

Every request from an integrating application must include a service-level API key issued when the application is registered with ActionGuard.

The key is passed as a bearer token:

```http
Authorization: Bearer <api_key>
```

Requests without a valid key are rejected with `401 Unauthorized`.

The API key identifies the calling application. It is distinct from the end user's own session token, which may also be included in event payloads for user-specific correlation.

**Not yet implemented:** OAuth2/client-credential flows and per-application scoped permissions. The MVP uses a single static API key per integrating application.

## 3. Endpoints

| Method | Path                                     | Purpose                                                                      |
| ------ | ---------------------------------------- | ---------------------------------------------------------------------------- |
| POST   | `/api/v1/events`                         | Submit an external security event for idempotent logging and evaluation      |
| POST   | `/api/v1/risk/evaluate`                  | Request a risk score for a given user/session without submitting a new event |
| POST   | `/api/v1/policy/evaluate`                | Evaluate a proposed action against policy and receive an advisory decision   |
| GET    | `/api/v1/sessions/:id`                   | Retrieve current risk state and metadata for a session                       |
| POST   | `/api/v1/sessions/:id/step-up/challenge` | Issue a session- and scope-bound one-time step-up verification challenge     |
| POST   | `/api/v1/sessions/:id/step-up/verify`    | Verify a step-up OTP code, mint an ES256 ticket, and grant scoped elevation  |
| POST   | `/api/v1/sessions/:id/elevate`           | Exchange an externally issued step-up verification ticket for elevation      |
| GET    | `/api/v1/sessions/:id/elevate/:scope`    | Inspect whether a session currently holds elevated trust for `:scope`        |
| POST   | `/api/v1/account/password`               | Protected sensitive action: change account password (invalidates all sessions)|
| POST   | `/api/v1/account/recovery-email`         | Protected sensitive action: update recovery email address                    |
| POST   | `/api/v1/account/phone`                  | Protected sensitive action: update recovery phone number                     |
| POST   | `/api/v1/account/mfa`                    | Protected sensitive action: update multi-factor authentication state         |
| POST   | `/api/v1/account/high-impact`            | Protected sensitive action: execute a high-impact operation                  |
| GET    | `/api/v1/events`                         | Query historical events by user, session, or time range                      |
| GET    | `/api/v1/sequences/current`              | Retrieve current active sequence/timeline for the authenticated user         |
| POST   | `/api/v1/webhooks`                       | Register an outbound webhook endpoint (Admin API key required)               |
| GET    | `/api/v1/webhooks`                       | List registered webhook endpoints with safe metadata (Admin API key required)|
| GET    | `/api/v1/webhooks/:id`                   | Retrieve a webhook endpoint by ID (Admin API key required)                   |
| PATCH  | `/api/v1/webhooks/:id`                   | Update a webhook endpoint's URL, subscriptions, or status (Admin required)   |
| POST   | `/api/v1/webhooks/:id/activate`          | Explicitly activate a webhook endpoint (Admin API key required)              |
| POST   | `/api/v1/webhooks/:id/deactivate`        | Explicitly deactivate a webhook endpoint (Admin API key required)            |
| DELETE | `/api/v1/webhooks/:id`                   | Delete a webhook endpoint and cascade-delete delivery logs (Admin required)  |

`POST /api/v1/events` is the primary external telemetry ingestion endpoint (Module 11.2b). Internal protected routes (`/api/v1/account/*`) execute through the Policy Enforcement Point (`enforce(actionType)`) middleware, which evaluates live risk, enforces the active policy decision, records an immutable `policy_decisions` audit row, and broadcasts real-time notifications before any account state mutation occurs.

`/risk/evaluate` and `/policy/evaluate` provide narrower advisory operations for applications that want to check current risk or evaluate a hypothetical action without generating a new logged event.

## 4. Request Structure

### POST `/api/v1/events`

Submits an externally observed security event using service-level API key authentication (`Authorization: Bearer <api_key>`).

```json
{
  "user_id": "usr_12345",
  "session_id": "sess_98765",
  "event_type": "password_change",
  "timestamp": "2026-09-26T14:32:00Z",
  "idempotency_key": "idem_ext_001",
  "context": {
    "ip_address": "196.189.45.12",
    "device_fingerprint": "fp_a1b2c3",
    "user_agent": "Mozilla/5.0 ..."
  },
  "metadata": {
    "action_sensitivity": "high",
    "operation": "update_credentials",
    "correlation_id": "corr_98765"
  }
}
```

### Field & Validation Notes

* **Strict Top-Level Allowlist:** Accepts only `user_id`, `session_id` (optional), `event_type`, `timestamp`, `context` (optional), `metadata` (optional), and `idempotency_key` (optional). Any unknown field or attempt to supply computed/authoritative values (`event_id`, `risk_score`, `risk_tier`, `decision`, `policy_decision`, `is_trusted_device`, `trusted_device`, `source`) is rejected with `400 invalid_request`.
* `user_id` — must identify an existing `users` record (`400 invalid_request` otherwise).
* `session_id` — optional; when supplied, must exist in `sessions` and belong to `user_id` (`400 invalid_request` otherwise).
* `event_type` — one of the 13 supported event types defined in `SecurityEvent.SUPPORTED_EVENT_TYPES` (`400 invalid_event_type` otherwise).
* `timestamp` — required strict ISO-8601 date-time string with timezone (`Z` or `±HH:MM`). Must fall within the configurable acceptance window (default: at most 5 minutes in the future via `EXTERNAL_EVENT_MAX_FUTURE_SKEW_MS` and at most 30 days in the past via `EXTERNAL_EVENT_MAX_PAST_AGE_MS`).
* `context` — strict allowlist (`ip_address`, `device_fingerprint`, `user_agent`). Client-supplied geolocation (`geo_country`, `geo_region`) or coordinates (`latitude`, `longitude`, `coordinates`) are rejected; approximate coarse location is derived server-side from the validated `ip_address`.
* `metadata` — strict allowlist (`action_sensitivity`, `operation`, `target`, `resource`, `reason`, `correlation_id`, `external_ref`, `details`, max 8 keys). `action_sensitivity` accepts `low`, `medium`, `high`, or `critical` and is floored at the policy-defined minimum sensitivity for `event_type` (`DEFAULT_ACTION_SENSITIVITY`). Secret-bearing keys are rejected or stripped and secret-bearing values are redacted. Accepted events are server-stamped with `metadata.source = "external_api"` and a one-way `metadata.api_key_fingerprint` (`akfp_<hex>`).
* **Idempotency (`Idempotency-Key` header and/or `idempotency_key` body):** If both are supplied, they must match (`400 invalid_request` on mismatch). Uses atomic Redis leases (`SET ext_event_idem:<apiKeyFp>:<key> ... EX <lease> NX`) paired with a deterministic `event_id` (`evt_idem_<hex>`) and `metadata.idempotency_payload_hash` in MySQL:
  * `201 Created`: First successful ingestion and pipeline evaluation.
  * `200 OK`: Replay with the same idempotency key and identical canonical payload returns the cached decision response without creating a duplicate event.
  * `409 Conflict` (`idempotency_conflict` / `idempotency_in_progress`): Reusing an idempotency key with a different canonical payload, or concurrent submission while a request with the same key is actively in progress.
  * `503 Service Unavailable` (`pipeline_unavailable` / `service_unavailable`): Risk/persistence pipeline or Redis idempotency store is unavailable; the in-progress lease is released so retries recover cleanly without duplicate events.

Supported event types include:

```text
login_success
login_failed
new_device
password_change
password_reset
recovery_email_change
phone_number_change
mfa_change
session_created
session_terminated
high_impact_action
verification_success
verification_failed
```

### POST `/api/v1/risk/evaluate`

Evaluates the risk of a proposed security event on behalf of the authenticated caller without committing the event to persistent storage, sequence logs, or Redis caches.

* **Authentication:** User JWT Bearer token (`Authorization: Bearer <token>`). The `user_id` provided in the request body must match the authenticated user identity (`req.user.id`), otherwise returns `403 Forbidden`.
* **Advisory Only:** This endpoint provides advisory risk assessment only. It generates no state mutations, persists no records to `risk_assessments` or sequence tables, and must never be trusted by authorization or audit enforcement as ground truth.
* **Server Timestamp:** The evaluation timestamp is assigned by the server upon request receipt. Any client-provided timestamp is ignored.

Request body:

```json
{
  "user_id": "usr_12345",
  "event_type": "password_change",
  "session_id": "sess_98765",
  "context": {
    "ip_address": "198.51.100.1",
    "device_fingerprint": "device_fp_abc123"
  },
  "metadata": {
    "action_sensitivity": "critical"
  }
}
```

Success response (`200 OK`):

```json
{
  "risk_score": 84,
  "risk_tier": "critical",
  "contributing_signals": [
    { "signal": "base_action_password_change", "category": "base_action", "weight": 20 },
    { "signal": "action_sensitivity_critical", "category": "base_action", "weight": 5 },
    { "signal": "seq_rapid_credential_cascade", "category": "sequence", "weight": 20 }
  ],
  "explanation": {
    "user_facing": "Elevated risk pattern observed across multiple security indicators. Administrative review or re-authentication may be required.",
    "admin_facing": "Risk score 84 (tier: critical). Contributing signals: base_action_password_change (+20), action_sensitivity_critical (+5), seq_rapid_credential_cascade (+20)."
  },
  "evaluated_at": "2026-10-09T14:00:00.000Z"
}
```

Unavailable response (`503 Service Unavailable`):

```json
{
  "status": "unavailable",
  "risk_score": null,
  "risk_tier": null,
  "contributing_signals": [],
  "error_code": "risk_evaluation_failed",
  "explanation": {
    "user_facing": "Security risk evaluation is temporarily unavailable.",
    "admin_facing": "Risk engine failed to evaluate context: risk_evaluation_failed."
  }
}
```

### POST `/api/v1/policy/evaluate`

```json
{
  "user_id": "usr_12345",
  "session_id": "sess_98765",
  "event_type": "high_impact_action",
  "context": {
    "ip_address": "198.51.100.1",
    "device_fingerprint": "fp_sample_device_hash"
  },
  "metadata": {
    "action_sensitivity": "critical"
  }
}
```

This endpoint checks what response an action would receive without logging it as a real event. It evaluates policy through the pure attribute-rule engine (Module 8) in an **advisory-only** mode.

> [!WARNING]
> **Advisory only:** Results from `/api/v1/policy/evaluate` are never persisted, mutate no sequences or risk tables, and affect no Redis caches. Module 10 enforcement middleware must **never** trust this advisory output for actual authorization or audit decisions.

**Response Structure (Allowlist for JWT Callers):**

```json
{
  "decision": "block",
  "enforcement_mode": "automatic",
  "explanation": {
    "user_facing": "This action has been restricted for security reasons."
  },
  "evaluated_at": "2026-10-10T10:00:00.000Z"
}
```

*Note on Privacy & Fail-Safe:* For JWT callers, technical risk scores, contributing signals, rule IDs, and administrative explanations are withheld to preserve privacy and prevent oracle probing. When risk evaluation is temporarily unavailable, the endpoint returns HTTP 200 with the fail-safe decision for the action's sensitivity tier.

*Note on Policy-as-Code (Module 9):* The underlying Policy Decision Point loads response tables and escalation rules from versioned policy files (`policies/default-v1.json`). The HTTP API request/response schema for `/api/v1/policy/evaluate` remains 100% backward compatible and unchanged. Offline replay evaluation and candidate diffing operate out-of-band via internal test harnesses without HTTP API mutations.

## 5. Response Structure

### Decision Response (Planned External Integration / Events)

Returned by `POST /events` (Planned - Module 11).

```json
{
  "decision": "reverify",
  "risk_score": 68,
  "risk_tier": "high",
  "contributing_signals": [
    {
      "signal": "new_device",
      "weight": 20
    },
    {
      "signal": "new_country",
      "weight": 25
    },
    {
      "signal": "unusual_hour",
      "weight": 10
    },
    {
      "signal": "baseline_deviation",
      "weight": 13
    }
  ],
  "explanation": {
    "user_facing": "We noticed a login from an unfamiliar device and location. Please verify it's you before continuing.",
    "admin_facing": "Risk escalated due to new device fingerprint, login from an unrecognized country, and an access time outside the user's normal pattern."
  },
  "cooling_off_seconds": 0,
  "event_id": "evt_5f9a2c"
}
```

Supported decision values:

```text
allow
monitor
reverify
delay
block
```

`cooling_off_seconds` is populated when the decision is `delay` and indicates the cancellation window before the action is finalized.

### GET `/api/v1/sessions/:id`

Retrieves session metadata and current evaluated risk state for an active or closed session.

* **Authentication:** User JWT Bearer token (`Authorization: Bearer <token>`).
* **Ownership:** A missing session and a session owned by another user both return `404 Not Found` with an identical error body to prevent session enumeration.
* **Privacy:** Raw client IP, device fingerprint, geographic coordinates, and user IDs are never returned.
* **Omissions:** `trusted_device` and `active_restrictions` are omitted from the MVP response (scheduled for Module 11 and Module 8).

Example response (session with risk assessment):

```json
{
  "session_id": "sess_98765",
  "created_at": "2026-09-26T09:00:00.000Z",
  "expires_at": "2026-09-26T09:15:00.000Z",
  "is_active": true,
  "risk": {
    "current_risk_score": 68,
    "risk_tier": "high",
    "contributing_signals": [
      {
        "signal": "base_action_login_success",
        "category": "base_action",
        "weight": 5
      }
    ],
    "evaluated_at": "2026-09-26T09:00:00.000Z"
  }
}
```

Example response (session without risk assessment yet):

```json
{
  "session_id": "sess_98765",
  "created_at": "2026-09-26T09:00:00.000Z",
  "expires_at": "2026-09-26T17:00:00.000Z",
  "is_active": true,
  "risk": {
    "current_risk_score": null,
    "risk_tier": null,
    "contributing_signals": null,
    "evaluated_at": null
  }
}
```

### POST `/api/v1/sessions/:id/elevate`

Requests temporary, scoped privilege elevation for the caller's active session following step-up verification (Module 10a).

* **Authentication:** User JWT Bearer token (`Authorization: Bearer <token>`).
* **Session Ownership:** `:id` must match the caller's active `session_id`; attempts to elevate another session return `403 Forbidden`.
* **Verification Ticket Requirements:**
  * Must be a cryptographically signed single-use ticket verified against the configured step-up verification public key (`STEP_UP_VERIFICATION_PUBLIC_KEY` parsed as an asymmetric `KeyObject`: `RS256` for RSA keys, `ES256` for P-256 EC keys; `HS256` is restricted strictly to `NODE_ENV=test`).
  * Bound to exact `sub` (user ID), `session_id`, allowlisted `scope`, `purpose: 'step_up_verification'`, and unique `jti`.
  * Must contain numeric `iat` and `exp` claims with `iat` not in the future (beyond a 5-second clock-skew allowance) and a total lifetime (`exp - iat`) of **at most 60 seconds**.
  * Parent session existence, active status, ownership, and remaining absolute lifetime are verified atomically inside the Redis Lua grant script **before** claiming `ticket_used:<jti>` (`NX`), so failed session checks never burn a valid ticket; replay attempts return `409 Conflict` (`ticket_already_used`).
* **Production Safeguard:** Because no production MFA/TOTP/WebAuthn provider is built in, if `STEP_UP_VERIFICATION_PUBLIC_KEY` is unconfigured, malformed, or uses an unsupported key type/curve in `NODE_ENV=production`, requests fail closed with `501 Not Implemented` (`verification_provider_unavailable`). Test-only mock ticket generation is strictly restricted to `NODE_ENV=test`.
* **Allowlisted Scopes:** `sensitive_action`, `credential_change`, `account_recovery`, `export_data`, `admin_action`.
* **Duration Clamping:** Defaults to `300s` (5m), capped at `900s` (15m), and clamped so it can never outlive the parent session's absolute `max_expires_at`.

Request body:

```json
{
  "scope": "sensitive_action",
  "verification_ticket": "<signed-step-up-ticket>",
  "duration_seconds": 300
}
```

Response (`200 OK`):

```json
{
  "elevated": true,
  "scope": "sensitive_action",
  "expiresAt": "2026-10-10T10:05:00.000Z",
  "remainingSeconds": 300
}
```

Error responses:
* `400 Bad Request` (`invalid_request` / `invalid_scope`): Missing parameters or unallowlisted scope.
* `401 Unauthorized` (`invalid_ticket`): Untrusted signature, expired ticket, future `iat`, lifetime $> 60\text{ s}$, disallowed/mismatched algorithm, or user/session/scope mismatch.
* `403 Forbidden` (`forbidden` / `session_expired`): Session ID mismatch or parent session expired / reached maximum lifetime.
* `409 Conflict` (`ticket_already_used`): Verification ticket was already consumed.
* `501 Not Implemented` (`verification_provider_unavailable`): No valid step-up verification public key configured in production.

### GET `/api/v1/sessions/:id/elevate/:scope`

Inspects whether the active session currently holds elevated trust for `:scope` (Module 10a).

* **Authentication & Ownership:** User JWT Bearer token; `:id` must match the caller's active `session_id` (`403 Forbidden` otherwise).
* **Expiration & Fail-Closed Behavior:** Validates parent session active status, ownership, and absolute lifetime before checking the scoped elevation key. When the elevation TTL expires, the session automatically reverts to baseline trust (`elevated: false`) without terminating the base session. Any Redis failure or state inconsistency fails closed (`elevated: false`).

Response (`200 OK`):

```json
{
  "elevated": true,
  "scope": "sensitive_action",
  "expiresAt": "2026-10-10T10:05:00.000Z",
  "remainingSeconds": 245
}
```

### POST `/api/v1/sessions/:id/step-up/challenge`

Issues a single-use, session- and scope-bound one-time verification challenge (Module 10b).

* **Authentication & Ownership:** User JWT Bearer token; `:id` must match the caller's active `session_id` (`403 Forbidden` otherwise).
* **Delivery & Privacy:** Delivers the 6-digit OTP to the immutable registration email (`User.email`, never `recovery_email`) and returns a masked address (`masked_destination`). Raw OTP codes are never returned in HTTP responses or written to logs.
* **Challenge Storage:** Stored in Redis under `step_up_challenge:<challengeId>` with a 300-second TTL (`STEP_UP_CHALLENGE_TTL_SECONDS`) and a maximum of 3 verification attempts (`STEP_UP_MAX_ATTEMPTS`). Only the salted HMAC-SHA256 digest bound to `challengeId`, `sessionId`, `scope`, and `code` is persisted.

Request body:

```json
{
  "scope": "credential_change"
}
```

Response (`200 OK`):

```json
{
  "challenge_id": "chl_d290f1ee-6c54-4b01-90e6-d701748f0851",
  "scope": "credential_change",
  "delivery_channel": "registration_email",
  "masked_destination": "a***@example.com",
  "expires_at": "2026-10-10T10:05:00.000Z",
  "ttl_seconds": 300
}
```

### POST `/api/v1/sessions/:id/step-up/verify`

Verifies a one-time challenge code atomically via Redis Lua and in constant time (`crypto.timingSafeEqual`), signs a short-lived (`60s`) ES256 verification ticket server-side, and redeems it through `grantElevation` (Module 10b).

* **Authentication & Ownership:** User JWT Bearer token; `:id` must match the caller's active `session_id` (`403 Forbidden` otherwise).
* **Key Isolation & Production Validation:** Signs the ticket using an asymmetric P-256 EC (`ES256`) key pair (`STEP_UP_VERIFICATION_PRIVATE_KEY` and `STEP_UP_VERIFICATION_PUBLIC_KEY`), separate from `JWT_SECRET`. In `NODE_ENV=production`, missing or mismatched keys fail closed with `501 verification_provider_unavailable`.
* **Side Effects:** On valid code, atomically deletes the challenge key inside Redis Lua (single-use), records a `verification_success` security event (reducing subsequent session risk via Module 6's session-scoped verification confidence discount), grants scoped elevation in Redis (recording `granted_at_risk_tier`), and writes an `elevation_audit_logs` grant entry. On invalid code, atomically increments `attempts` (invalidating the challenge on the 3rd failed attempt), records a `verification_failed` security event, and triggers session containment + a 15-minute protective account lock (`403 session_contained`) upon reaching 3 failed attempts in the session.

Request body:

```json
{
  "challenge_id": "chl_d290f1ee-6c54-4b01-90e6-d701748f0851",
  "code": "123456",
  "duration_seconds": 300
}
```

Response (`200 OK`):

```json
{
  "elevated": true,
  "scope": "credential_change",
  "expiresAt": "2026-10-10T10:05:00.000Z",
  "remainingSeconds": 300
}
```

Error responses:
* `400 Bad Request` (`invalid_request`): Missing `challenge_id` or malformed 6-digit `code`.
* `401 Unauthorized` (`verification_failed`): Incorrect OTP (`remaining_attempts` returned).
* `401 Unauthorized` (`challenge_expired`): Challenge expired, does not exist, or was already consumed.
* `403 Forbidden` (`challenge_mismatch` / `forbidden`): Challenge does not belong to the caller's active session.
* `403 Forbidden` (`session_contained`): 3rd failed verification attempt triggered session containment and a 15-minute protective account lock (`session_contained: true`, `account_locked: true`, `locked_until`, `retry_after_seconds`).
* `501 Not Implemented` (`verification_provider_unavailable`): Step-up ES256 keys missing or invalid in production.

### Protected Sensitive Account Routes (`/api/v1/account/*`)

All five sensitive account routes run `authenticateToken` followed by `enforce(actionType)` before executing any account state mutation (Module 10b):

| Route | Event Type | Route Sensitivity | Required Elevation Scope | Pre-Event Schema & Handler Validation / Mutation on Allow or Monitor |
|---|---|---|---|---|
| `POST /api/v1/account/password` | `password_change` | `high` | `credential_change` | Pre-validates `current_password` and `new_password` (min 8 chars, distinct from `current_password`) before recording an event. Handler verifies `current_password` (marking `action_status: 'rejected'` on mismatch), hashes `new_password`, updates `users.password_hash`, calls `terminateAllUserSessions(userId, 'password_change', { throwOnError: true })` to revoke all sessions and elevations across all devices (`reauthentication_required: true`), and transitions `action_status` to `'completed'`. |
| `POST /api/v1/account/recovery-email` | `recovery_email_change` | `high` | `account_recovery` | Pre-validates `recovery_email` syntax before recording an event. Handler verifies `recovery_email` is distinct from primary registration `email` (marking `action_status: 'rejected'` if identical), updates `users.recovery_email`, and transitions `action_status` to `'completed'`. |
| `POST /api/v1/account/phone` | `phone_number_change` | `medium` | `account_recovery` | Pre-validates strict E.164 `phone_number` (`/^\+[1-9]\d{6,14}$/`) before recording an event, updates `users.phone_number`, and transitions `action_status` to `'completed'`. |
| `POST /api/v1/account/mfa` | `mfa_change` | `high` | `credential_change` | Pre-validates boolean `mfa_enabled` before recording an event, updates `users.mfa_enabled`, and transitions `action_status` to `'completed'`. |
| `POST /api/v1/account/high-impact` | `high_impact_action` | `critical` | `sensitive_action` | Pre-validates non-empty `operation` (1–128 chars, plus optional `target`) before recording an event, executes protected operation, and transitions `action_status` to `'completed'`. |

* **Server-Side Context & Sensitivity Enforcement:** Request context (`ip_address`, `device_fingerprint`, `user_agent`, `geo_country`, `geo_region`) is extracted strictly from server headers/connection state via `extractServerRequestContext(req)`. Any `context`, `timestamp`, or `action_sensitivity` fields in `req.body` or `req.query` are ignored by the PEP.
* **Action Lifecycle States (`security_events.metadata.action_status`):**
  * `attempted`: Recorded when the event is initially created in the PEP.
  * `halted`: Recorded when the PEP halts the request (`reverify` or `block`).
  * `delayed`: Recorded when the PEP halts the request for cooling-off (`delay`) and persists a `DelayedAction`.
  * `cancelled`: Recorded when a user cancels a pending delayed action during its cooling-off window.
  * `expired`: Recorded when a pending delayed action exceeds its `expires_at` grace window without execution.
  * `authorized`: Recorded when the PEP permits execution (`allow`, `monitor`, `elevated_allowed`, `recommend_only_allowed`) before invoking `next()`.
  * `rejected`: Recorded when post-PEP credential/domain validation fails or when Zero Trust pre-execution rechecks reject a delayed action.
  * `failed_execution`: Recorded when a downstream database mutation or session invalidation throws an exception.
  * `completed`: Recorded **only** after the route handler's or delayed action's database mutation has succeeded.
* **Mandatory Decision Audit & Truthful Containment:** Every PEP evaluation persists a row in `policy_decisions` (stamped with `policy_version: "<policy_id>@<schema_version>"`) **before** calling `next()`. For qualifying critical `block` decisions, `containSessionAndLockAccount` executes before finalizing `enforcement_outcome: 'contained_and_blocked'` or emitting `decision:recorded`; if decision persistence, policy evaluation, Redis elevation verification, delayed-action queueing, or containment fails, the PEP fails closed with `503 policy_enforcement_unavailable` and never falsely reports `session_contained: true`.
* **PEP Halted Responses:**
  * `reverify` (without active scoped elevation) $\rightarrow$ `403 Forbidden` (`error.code: "step_up_required"`, `decision: "reverify"`, `decision_id`, `required_scope`, `risk_tier`, `challenge_endpoint`, `verify_endpoint`, `elevate_endpoint`, `explanation`).
  * `delay` (even if elevated) $\rightarrow$ `403 Forbidden` (or `202 Accepted` when `X-Prefer-Status: 202` is passed) (`error.code: "action_delayed"`, `decision: "delay"`, `decision_id`, `risk_tier`, `retry_after_seconds`, `cooling_off_seconds`, `pending_action_id`, `cancellation_token`, `cancel_endpoint`, `status_endpoint`, `execute_at`, `expires_at`, `explanation`).
  * `block` (even if elevated) $\rightarrow$ `403 Forbidden` (`error.code: "action_blocked"`, `decision: "block"`, `decision_id`, `risk_tier`, `session_contained`, `account_locked`, optional `locked_until` and `retry_after_seconds`, `explanation`).

### Cooling-Off Enforcement Endpoints (`/api/v1/cooling-off/*` — Module 10c, FR-32)

When the PEP returns a `delay` decision on an approved sensitive route (`password_change`, `recovery_email_change`, `phone_number_change`, `mfa_change`, `high_impact_action`, or a registered custom executor), `coolingOffService.scheduleDelayedAction` validates and allowlists the action-specific payload, recursively strips any credential/secret/token/OTP fields across nested objects and arrays, and persists the delayed action in `delayed_actions` paired with a single-use cryptographic `cancellation_token` (`ctkn_<64-hex>`, stored only as a SHA-256 hash). For `password_change`, `current_password` is verified against `user.password_hash` before scheduling (`401 invalid_credentials` on mismatch), and `new_password` is bcrypt-hashed (`new_password_hash` is stripped from all public API responses, Redis cache entries, and event broadcasts).

* `GET /api/v1/cooling-off/actions`: Lists active pending delayed actions for the authenticated user (`200 OK`, never exposes `cancellation_token_hash` or sensitive payload digests).
* `GET /api/v1/cooling-off/actions/:id`: Retrieves status and sanitized `action_payload` of a specific delayed action owned by the authenticated user (`403 forbidden` if wrong owner, `404 delayed_action_not_found` if missing).
* `POST /api/v1/cooling-off/actions/:id/cancel`: Cancels a pending delayed action prior to `expires_at` using `cancellation_token` (constant-time SHA-256 comparison). Returns `410 action_expired` (and transitions status to `'expired'`) if `expires_at` has already elapsed, `409 action_already_cancelled` on replay, or `403 invalid_cancellation_token` on mismatch. On valid cancellation, transitions status to `'cancelled'`, updates `security_events.metadata.action_status` to `'cancelled'`, cleans up Redis keys, and emits `cooling_off:cancelled`.
* `POST /api/v1/cooling-off/actions/:id/execute`: Executes an owned delayed action after `execute_at` has elapsed and before `expires_at` (also processed automatically by `coolingOffWorker`, which uses atomic Redis `SET ... NX` lock acquisition and Lua compare-and-delete `executeReleaseLock`, and reconciles stale `'executing'` rows to `'failed'`). Rejects early execution with `409 action_still_cooling_off` (`remaining_seconds`) and expired actions with `410 delayed_action_expired`. Performs **Zero Trust pre-execution rechecks** immediately before mutation:
  1. Verifies the user exists and is not under an active protective account lock (`user_account_locked`).
  2. Requires a valid bound `session_id` and verifies session ownership, active state, and non-expiration across both MySQL and Redis via `validateActiveSession` (`session_invalidated_or_expired`).
  3. Evaluates current risk via `riskEngineService.evaluateRisk`, failing closed if the Risk Engine is unavailable (`risk_engine_unavailable`).
  4. Re-evaluates active policy via `decide(...)`: rejects on `block` (`policy_recheck_blocked`), risk tier increase (`risk_tier_increased`), or `delay` (`policy_recheck_delayed`), and for `reverify` requires an active scoped elevation (`checkElevation`) for the action's required scope (`step_up_elevation_required`).
  5. Executes the approved state mutation (including updating `password_hash` and calling `terminateAllUserSessions` for `password_change`, and enforcing normalization and primary-email collision checks for `recovery_email_change`).

### GET `/api/v1/events`

Supported query parameters:

```text
user_id
session_id
event_type
from
to
limit
offset
```

Example response:

```json
{
  "events": [
    {
      "event_id": "evt_5f9a2c",
      "event_type": "password_change",
      "timestamp": "2026-09-26T14:32:00Z",
      "risk_score": 68,
      "decision": "reverify"
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

### GET `/api/v1/sequences/current`

Retrieves the current active sequence and ordered event timeline for the authenticated user.

* **Authentication:** User JWT Bearer token (`Authorization: Bearer <token>`). The user identity is determined from the verified token and cannot be overridden by request parameters.
* **Storage Path:** Fast read from Redis active sequence cache (`sequence:user:<userId>`) with transparent fallback to MySQL on cache miss or eviction.

Example response (active sequence present):

```json
{
  "sequence": {
    "id": "seq_5f9a2c",
    "started_at": "2026-10-07T12:00:00.000Z",
    "last_event_at": "2026-10-07T12:05:00.000Z",
    "event_count": 2,
    "events": [
      {
        "event_id": "evt_001",
        "event_type": "login_success",
        "timestamp": "2026-10-07T12:00:00.000Z"
      },
      {
        "event_id": "evt_002",
        "event_type": "recovery_email_change",
        "timestamp": "2026-10-07T12:05:00.000Z"
      }
    ]
  }
}
```

Example response (no active sequence):

```json
{
  "sequence": null
}
```

Field notes:
* `events` is strictly ordered by chronological `step_order` ascending.
* Individual events expose strictly `event_id`, `event_type`, and `timestamp` to preserve user privacy (no IP, GPS coordinates, device fingerprints, or raw context/signal blobs).
* Returns HTTP `200` with `{ "sequence": null }` when no active sequence exists within the correlation window.
* Returns HTTP `401` with standard error format for missing, expired, or invalid authorization tokens.

## 6. Error Format

All errors follow a consistent structure:

```json
{
  "error": {
    "code": "invalid_event_type",
    "message": "The event_type 'unknown_action' is not a recognized event type.",
    "status": 400
  }
}
```

### Common Error Codes

| HTTP Status | Code                             | Meaning                                                          |
| ----------- | -------------------------------- | ---------------------------------------------------------------- |
| 400         | `invalid_request`                | Malformed or missing required fields                             |
| 400         | `invalid_event_type`             | Event type is not recognized                                     |
| 400         | `INVALID_SCOPE` / `invalid_scope`| Requested elevation scope is not in the allowlist                |
| 401         | `unauthorized`                   | Missing or invalid authentication token                          |
| 401         | `invalid_otp`                    | Incorrect step-up verification code                              |
| 401         | `invalid_current_password`       | Provided current password did not match during password change   |
| 403         | `forbidden` / `FORBIDDEN`        | Caller is not authorized for the requested user or session       |
| 403         | `step_up_required`               | Policy requires step-up verification for the requested action    |
| 403         | `action_blocked`                 | Policy blocked the requested action due to elevated/critical risk|
| 403         | `account_temporarily_locked`     | Login rejected while 15-minute protective account lock is active |
| 404         | `not_found`                      | Session or resource does not exist                               |
| 410         | `challenge_expired_or_not_found` | Step-up challenge does not exist, expired, or was already used   |
| 429         | `challenge_max_attempts_exceeded`| Step-up challenge exceeded maximum verification attempts (3)     |
| 429         | `rate_limited`                   | Too many requests from this caller                               |
| 202         | `action_delayed`                 | Action halted for cooling-off period (`cooling_off_seconds`)     |
| 500         | `internal_error`                 | Unexpected server failure                                        |
| 501         | `VERIFICATION_PROVIDER_UNAVAILABLE` | Step-up verification keys not configured in production        |
| 503         | `risk_evaluation_failed`         | Risk engine temporarily unavailable                              |
| 503         | `policy_enforcement_unavailable` | PEP failed closed due to policy, Redis, or audit persistence error|

### Fail-Safe Behavior

If the Risk Engine cannot compute a score because of an internal error:

* High or critical actions return `block` (`requires_review: true`).
* Low or medium actions return `monitor` (`requires_review: true`).
* If the Policy Engine, Redis elevation check, or `policy_decisions` audit insert fails during PEP enforcement, the PEP fails closed with `503 policy_enforcement_unavailable` and halts the request before the route handler runs.

## 7. Security-Event Format

Every event submitted to or logged internally by ActionGuard conforms to this structure.

```json
{
  "event_id": "string",
  "user_id": "string",
  "session_id": "string",
  "event_type": "enum",
  "timestamp": "ISO 8601 string",
  "context": {
    "ip_address": "string",
    "device_fingerprint": "string",
    "geo_country": "string",
    "geo_region": "string",
    "user_agent": "string"
  },
  "metadata": {
    "action_sensitivity": "low | medium | high | critical"
  }
}
```

## 8. Risk Decision Format

```json
{
  "risk_score": "number (0-100)",
  "risk_tier": "low | medium | high | critical",
  "decision": "allow | monitor | reverify | delay | block",
  "contributing_signals": [
    {
      "signal": "string",
      "weight": "number"
    }
  ],
  "explanation": {
    "user_facing": "string",
    "admin_facing": "string"
  },
  "cooling_off_seconds": "number, present only when decision = delay"
}
```

## 9. Webhooks — Administrative Endpoint Management & Outbound Delivery (Module 11.2c)

### 9.1 Authorization & Rate Limiting

All `/api/v1/webhooks` endpoints are restricted to platform administrators and protected by the `sensitive_action` rate-limit tier (`sensitiveActionRateLimiter`, default 15 requests / 60s window):

* **Administrator Credential Required (`ACTIONGUARD_ADMIN_API_KEY`):** Callers must authenticate via `Authorization: Bearer <admin_api_key>` or `X-Admin-Api-Key: <admin_api_key>`. The configured `ACTIONGUARD_ADMIN_API_KEY` must be at least 32 characters in length and distinct from the service integration key (`API_KEY` / `ACTIONGUARD_API_KEY`). Keys are verified using constant-time SHA-256 digest comparison (`constantTimeKeyMatch`).
* **Configuration Validation Precedence (`401 Unauthorized`):** After rejecting query-parameter credentials (`?apiKey=...`, `?token=...`) and missing, malformed, or conflicting (`Authorization` + `X-Admin-Api-Key`) headers with `401 unauthorized`, `requireWebhookAdmin` validates administrator configuration (`ACTIONGUARD_ADMIN_API_KEY` present, $\ge 32$ chars, and distinct from `API_KEY` / `ACTIONGUARD_API_KEY`) **before** inspecting non-admin credentials. If administrator configuration is missing or invalid, requests fail closed immediately with `401 unauthorized` without inspecting service keys or user JWTs.
* **Non-Administrator Rejection (`403 Forbidden`):** When administrator configuration is valid, authenticated non-administrator callers — including valid end-user session JWTs (even with `admin_action` elevation) and valid service-level event-ingestion API keys (`API_KEY` / `ACTIONGUARD_API_KEY`, whether supplied in `Authorization: Bearer` or `X-Admin-Api-Key`) — are rejected with `403 forbidden`.

### 9.2 Secret Generation, One-Time Disclosure, Encryption at Rest & Confidentiality

* **Server-Generated Identifiers & Signing Secrets:** On `POST /api/v1/webhooks`, ActionGuard generates the endpoint `id` (`whk_<uuid>`) and a 256-bit cryptographically random signing secret (`whsec_<64 hex chars>`) on the server. Clients cannot supply `id`, `secret`, `signing_secret`, `encrypted_secret`, `secret_iv`, `secret_auth_tag`, or `secret_prefix`.
* **One-Time Creation Disclosure (`signing_secret`):** The full generated `signing_secret` (`whsec_<64 hex chars>`) is returned **once and only once** in the `201 Created` response of `POST /api/v1/webhooks`, strictly after the encrypted endpoint record is persisted to the database. Receiving applications must securely store `signing_secret` upon registration to verify `X-ActionGuard-Webhook-Signature` HMAC-SHA256 signatures when outbound delivery is enabled.
* **Strict Post-Creation Confidentiality:** Subsequent list (`GET /api/v1/webhooks`), retrieve (`GET /api/v1/webhooks/:id`), delivery history (`GET /api/v1/webhooks/:id/deliveries`), update (`PATCH /api/v1/webhooks/:id`), activate (`POST /api/v1/webhooks/:id/activate`), deactivate (`POST /api/v1/webhooks/:id/deactivate`), and delete (`DELETE /api/v1/webhooks/:id`) responses **never** return `signing_secret` (exposing only the 8-hex-character `secret_prefix` on endpoint objects, e.g. `whsec_8f9a1b2c`). Plaintext secrets, `encrypted_secret`, `secret_iv`, `secret_auth_tag`, internal lease lock tokens (`locked_by`, `locked_at`), raw outbound request payloads, receiver response bodies, and encryption keys are never included in logs, audit events, delivery history responses, or error responses, and no secret-retrieval endpoint exists.
* **AES-256-GCM Encryption at Rest & Key Persistence:** The signing secret is encrypted before persistence using AES-256-GCM (`encrypted_secret`, 96-bit `secret_iv`, and 128-bit `secret_auth_tag`) backed by `WEBHOOK_SECRET_ENCRYPTION_KEY` ($\ge 32$ characters; required in both `development` and `production`, i.e. whenever `NODE_ENV !== 'test'` or `REQUIRE_WEBHOOK_ENCRYPTION_KEY=true`). Operators must keep `WEBHOOK_SECRET_ENCRYPTION_KEY` stable across application restarts and all delivery-worker processes; key rotation is not automatically performed in Stage 1/2. If the encryption key is missing outside `NODE_ENV=test` or invalid in any environment, registration fails closed with `503 webhook_encryption_unavailable`.

### 9.3 Destination URL & Subscription Validation

* **HTTPS Required:** `url` must be a valid URL ($\le 512$ chars) using `https://`. In `NODE_ENV=production`, `https://` is unconditionally required. For local development only (`NODE_ENV !== 'production'`), `http://` is permitted only when `ALLOW_INSECURE_HTTP_WEBHOOKS=true` is explicitly set.
* **SSRF & Credential Hardening (Registration, Model & Delivery Layers):** Enforced consistently at the service layer (`webhookEndpointService`), model layer (`WebhookEndpoint` validator), and delivery-time transport layer (`webhookTransport`). Destination URLs must not contain embedded credentials (`user:pass@`), URL fragments (`#...`), whitespace/control characters, single-label internal hostnames, `localhost` / `.local` / `.internal` / `.localdomain` / `.home.arpa` / `.test` / `.invalid` / `.lan` / `.corp` domains, or non-public/special-purpose IPv4 and IPv6 addresses evaluated via byte-level CIDR matching (`0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4`, `::/96` including `::1`, `::` and IPv4-compatible IPv6 `::127.0.0.1` / `::169.254.169.254`, IPv4-mapped `::ffff:0:0/96` for non-public IPv4, IPv4-translated `::ffff:0:0:0/96`, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, Discard-Only `100::/64`, IETF/Teredo/Benchmarking `2001::/23`, Documentation `2001:db8::/32`, 6to4 `2002::/16`, ULA `fc00::/7`, Link-Local `fe80::/10`, Site-Local `fec0::/10`, Multicast `ff00::/8`, and any IPv6 outside Global Unicast `2000::/3`). Local targets are only permitted outside production when `ALLOW_LOCAL_WEBHOOK_TARGETS=true`. At delivery time, `webhookTransport` resolves all DNS records (`dns.lookup(..., { all: true, verbatim: true })`), validates **every** returned IPv4/IPv6 address (rejecting mixed public/private responses), pins the TCP socket to the validated IP via a custom `lookup` callback while preserving TLS SNI (`servername`) and `Host` header verification, and blocks all `3xx` redirects.
* **Supported Events (`subscribed_events`):** Non-empty array of unique values from `WebhookEndpoint.SUPPORTED_WEBHOOK_EVENTS`:
  * `event.processed`
  * `decision.recorded`
  If omitted on `POST /api/v1/webhooks`, defaults to `["event.processed", "decision.recorded"]`.

### 9.4 Endpoint Specifications

#### `POST /api/v1/webhooks` — Register a Webhook Endpoint

Permitted request body fields (`url`, `subscribed_events`, `description`, `is_active`; unknown or internal fields rejected with `400 invalid_request`):

```json
{
  "url": "https://siem.example.com/webhooks/actionguard",
  "subscribed_events": ["event.processed", "decision.recorded"],
  "description": "Production SIEM Receiver",
  "is_active": true
}
```

Response (`201 Created` — includes one-time `signing_secret`):

```json
{
  "webhook": {
    "id": "whk_8b4e1a20-9f88-4c11-a210-4b23901a9901",
    "url": "https://siem.example.com/webhooks/actionguard",
    "subscribed_events": ["event.processed", "decision.recorded"],
    "description": "Production SIEM Receiver",
    "secret_prefix": "whsec_8f9a1b2c",
    "signing_secret": "whsec_8f9a1b2c4d5e6f708192a3b4c5d6e7f80123456789abcdef0123456789abcdef",
    "is_active": true,
    "created_at": "2026-10-12T19:00:00.000Z",
    "updated_at": "2026-10-12T19:00:00.000Z"
  }
}
```
*(Note: `signing_secret` is returned **only once** in the `201 Created` registration response after persistence succeeds. Store it securely in the receiving integration; it is omitted from all subsequent responses.)*

#### `GET /api/v1/webhooks` — List Registered Endpoints

Optional query parameters: `is_active` (`true` | `false`), `limit` (`1..100`, default `50`), `offset` ($\ge 0$, default `0`).

Response (`200 OK`):

```json
{
  "webhooks": [
    {
      "id": "whk_8b4e1a20-9f88-4c11-a210-4b23901a9901",
      "url": "https://siem.example.com/webhooks/actionguard",
      "subscribed_events": ["event.processed", "decision.recorded"],
      "description": "Production SIEM Receiver",
      "secret_prefix": "whsec_8f9a1b2c",
      "is_active": true,
      "created_at": "2026-10-12T19:00:00.000Z",
      "updated_at": "2026-10-12T19:00:00.000Z"
    }
  ],
  "count": 1,
  "total": 1
}
```

#### `GET /api/v1/webhooks/:id` — Retrieve Endpoint by ID

Returns `200 OK` with `{ "webhook": { ... } }` (without `signing_secret`), or `404 webhook_not_found` if no endpoint exists with `:id`.

#### `GET /api/v1/webhooks/:id/deliveries` — List Endpoint Delivery History

Lists safe outbound delivery log records for webhook endpoint `:id`. Requires `requireWebhookAdmin` authorization. Returns `404 webhook_not_found` if the parent webhook endpoint does not exist.

Optional query parameters (unknown query parameters rejected with `400 invalid_request`):
* `status`: `pending` | `delivered` | `failed`
* `event_type`: `event.processed` | `decision.recorded`
* `limit`: integer `1..100` (default `50`)
* `offset`: integer $\ge 0$ (default `0`)

Response (`200 OK`):

```json
{
  "webhook_id": "whk_8b4e1a20-9f88-4c11-a210-4b23901a9901",
  "deliveries": [
    {
      "id": "whdel_2b90c3a4-810e-4f3b-991a-7712e901cc10",
      "webhook_id": "whk_8b4e1a20-9f88-4c11-a210-4b23901a9901",
      "event_type": "event.processed",
      "source_event_id": "evt_12345",
      "status": "delivered",
      "attempt_count": 1,
      "http_status": 200,
      "error_code": null,
      "next_attempt_at": null,
      "last_attempt_at": "2026-10-12T19:01:00.120Z",
      "delivered_at": "2026-10-12T19:01:00.120Z",
      "created_at": "2026-10-12T19:01:00.000Z",
      "updated_at": "2026-10-12T19:01:00.120Z"
    }
  ],
  "count": 1,
  "total": 1
}
```
*(Note: Delivery records expose only safe scheduling and outcome metadata. Signing secrets, encryption keys, internal lease tokens `locked_by` / `locked_at`, outbound request payloads, and receiver response bodies are never returned.)*

#### `PATCH /api/v1/webhooks/:id` — Update Endpoint Settings

Accepts at least one of `url`, `subscribed_events`, `description`, or `is_active`. Returns `200 OK` with `{ "webhook": { ... } }` (without `signing_secret`).

#### `POST /api/v1/webhooks/:id/activate` & `POST /api/v1/webhooks/:id/deactivate`

Explicitly sets `is_active` to `true` or `false` while preserving the endpoint record and historical `webhook_delivery_logs`. Returns `200 OK` with `{ "webhook": { ... } }` (without `signing_secret`).

#### `DELETE /api/v1/webhooks/:id` — Delete Endpoint

Deletes the `WebhookEndpoint` record and cascade-deletes associated `webhook_delivery_logs` rows (`ON DELETE CASCADE`).

Response (`200 OK`):

```json
{
  "deleted": true,
  "id": "whk_8b4e1a20-9f88-4c11-a210-4b23901a9901"
}
```

### 9.5 Outbound Webhook Delivery & Signature Verification (Module 11.2c Stage 2)

* **Asynchronous Durable Scheduling:** When `pipeline:event_processed` (`event.processed`) or `policy:decision_recorded` (`decision.recorded`) fires on the internal event bus, ActionGuard asynchronously enqueues one `WebhookDeliveryLog` row (`status='pending'`, `attempt_count=0`) per active, subscribed `WebhookEndpoint` created on or before the source event's occurrence timestamp (`uniq_webhook_delivery_idempotency` on `(webhook_id, event_type, source_event_id)` prevents duplicates). A startup and periodic reconciliation pass (`reconcileMissingWebhookEnqueues`) recovers any missing delivery rows within a bounded lookback window if the process crashed after committing `SecurityEvent`/`RiskAssessment` or `PolicyDecision` to MySQL.
* **Request Headers & HMAC-SHA256 Signing:**
  * `Content-Type: application/json; charset=utf-8`
  * `User-Agent: ActionGuard-Webhook/1.0`
  * `X-ActionGuard-Webhook-Id: whdel_<sha256_32>`
  * `X-ActionGuard-Webhook-Event: event.processed | decision.recorded`
  * `X-ActionGuard-Webhook-Timestamp: <unix_epoch_seconds>`
  * `X-ActionGuard-Webhook-Signature: v1=<64_lower_hex_hmac_sha256>`
  The signature is computed as `HMAC-SHA256(signing_secret, "${timestamp}.${rawJsonBody}")` over the exact UTF-8 request body bytes. Receivers should verify the signature in constant time and enforce a replay window against `X-ActionGuard-Webhook-Timestamp` (default tolerance $\pm 300\text{s}$).
* **Retry & Terminal Failure Policy:**
  * `2xx`: Marked `delivered` immediately.
  * `408`, `429`, `5xx`, network/TLS/DNS/timeout errors: Retried up to `5` total attempts (`RETRY_DELAYS_SECONDS = [30, 120, 600, 1800]`, plus bounded positive jitter) before transitioning to terminal `failed`.
  * Other `4xx` (`400`, `401`, `403`, `404`, `422`), `3xx` redirects (`REDIRECT_NOT_ALLOWED`), SSRF policy rejections (`SSRF_BLOCKED`), missing source records (`SOURCE_RECORD_MISSING`), deactivated endpoints (`ENDPOINT_INACTIVE`), unsubscribed events (`EVENT_UNSUBSCRIBED`), or missing endpoints (`ENDPOINT_NOT_FOUND`): Marked terminal `failed` immediately without retry.

### 9.6 Webhook Endpoint Error Codes

| HTTP Status | Error Code                       | Meaning                                                                          |
| ----------- | -------------------------------- | -------------------------------------------------------------------------------- |
| 400         | `invalid_request`                | Unknown/privileged field, malformed ID (`whk_...`), bad `description`/`is_active` |
| 400         | `invalid_webhook_url`            | Non-HTTPS URL, malformed URL, embedded credentials, fragment, or SSRF/local host |
| 400         | `invalid_subscribed_events`      | Empty array, duplicate event, or unsupported event name                          |
| 401         | `unauthorized`                   | Missing, malformed, conflicting, or invalid administrator API key or config      |
| 403         | `forbidden`                      | Authenticated non-admin caller (end-user JWT or service integration API key)     |
| 404         | `webhook_not_found`              | Webhook endpoint with the specified `:id` does not exist                         |
| 429         | `rate_limited`                   | `sensitive_action` rate limit exceeded                                           |
| 500         | `internal_error`                 | Unexpected database or runtime failure (internal details masked)                 |
| 503         | `webhook_encryption_unavailable` | `WEBHOOK_SECRET_ENCRYPTION_KEY` is missing outside `NODE_ENV=test` or invalid    |

## 10. Versioning Policy

* The current and only version is `v1`.
* New optional fields may be added to responses without a version bump.
* Removing a field, renaming a field, or changing a field's type requires a new version.
* A future `v2` should maintain `v1` in parallel for a defined deprecation period.
* A formal deprecation policy will be defined before introducing `v2`.

## 11. Real-Time Stream (Socket.IO)

ActionGuard provides a real-time event streaming interface powered by Socket.IO mounted alongside the HTTP application. Connected frontends and dashboards receive live notifications of newly recorded security events and updated risk assessments without polling.

### 11.1 Connection & CORS Configuration

* **Transport & Port:** WebSocket connection mounted on the primary server `PORT` (default: `3000`).
* **CORS Origin:** Controlled by `CORS_ALLOWED_ORIGINS` (comma-delimited list, e.g., `http://localhost:3000,http://localhost:5173`). Wildcard origins (`*`) are strictly prohibited and throw an error at server initialization.
* **Push-Only Protocol:** Sockets are push-only from ActionGuard to connected clients. Inbound client-emitted messages and requests are ignored.

### 11.2 Handshake Authentication

Authentication occurs exclusively during the connection handshake via the `auth` payload object. Credentials passed in URL query parameters (e.g. `?token=...` or `?apiKey=...`) are strictly rejected.

```javascript
// User client connection
const socket = io('http://localhost:3000', {
  auth: { token: '<jwt_token>' }
});

// Admin dashboard connection
const adminSocket = io('http://localhost:3000', {
  auth: { apiKey: '<admin_api_key>' }
});
```

* **User Authentication (`auth.token`):** Validated against JWT secret and the active session stored in Redis. The JWT must carry a valid `session_id`.
* **Admin Authentication (`auth.apiKey`):** Validated in constant time against `ACTIONGUARD_ADMIN_API_KEY`. The configured key must be at least 32 characters in length. If an apiKey is provided, no token fallback is permitted.
* **Dual Credentials:** If both `apiKey` and `token` are supplied in the same handshake, the connection is rejected.

#### Handshake Rejection Error Codes

Failed handshakes emit an error event with one of the following exact string codes:

* `unauthorized`: Missing credentials, invalid token signature, malformed token, wrong admin API key, admin key shorter than 32 characters, credentials provided in query parameters, or both apiKey and token supplied.
* `token_expired`: JWT token has expired based on its `exp` claim.
* `invalid_session`: Token is valid, but the associated session has been revoked, is missing from Redis, or the token lacks a `session_id`.

### 11.3 Rooms & Isolation Boundaries

Rooms are strictly server-managed. Clients cannot join or leave rooms; any client-emitted `join` or `subscribe` events are ignored:

* **User Sockets:** Automatically placed in `user:<userId>` (for account-wide events) and `session:<sessionId>` (for session-specific revocation).
* **Admin Sockets:** Automatically placed in `admin:stream` (for global telemetry).

### 11.4 Event Delivery & Ordering Invariant

When an event is processed by ActionGuard, notifications are broadcast to relevant rooms in a strict sequence:

1. `event:recorded` is emitted **first**.
2. `risk:updated` is emitted **second** (only if the event was scored and an assessment was produced; unscored or failed events emit only `event:recorded`).
3. `decision:recorded` is emitted when a Policy Enforcement Point (PEP) decision is durably persisted in `policy_decisions` (`policy:decision_recorded` on the in-process event bus).

### 11.5 Broadcast Payloads

#### User `event:recorded` Payload
Broadcast to `user:<userId>`:

```json
{
  "event_id": "evt_12345",
  "session_id": "sess_98765",
  "event_type": "login_success",
  "timestamp": "2026-10-10T09:00:00.000Z",
  "coarse_location": {
    "country": "US",
    "region": "CA"
  },
  "is_new_device": true,
  "is_new_country": true
}
```
* `user_id` is omitted.
* `is_new_device` and `is_new_country` are included with value `true` when novelty is detected; if recognized, the key is omitted entirely (never `false`).
* `coarse_location` is `{ country, region }` if geo information is present in the context, or `null` if absent.
* Sensitive context fields (`ip_address`, `device_fingerprint`, coordinates, `password_hash`) are strictly excluded.

#### Admin `event:recorded` Payload
Broadcast to `admin:stream`:

```json
{
  "event_id": "evt_12345",
  "user_id": "usr_12345",
  "session_id": "sess_98765",
  "event_type": "login_success",
  "timestamp": "2026-10-10T09:00:00.000Z",
  "coarse_location": {
    "country": "US",
    "region": "CA"
  },
  "is_new_device": true,
  "is_new_country": true
}
```

#### User `risk:updated` Payload
Broadcast to `user:<userId>` (tier-only format):

```json
{
  "event_id": "evt_12345",
  "session_id": "sess_98765",
  "risk_tier": "low | medium | high | critical",
  "evaluated_at": "2026-10-10T09:00:00.000Z",
  "explanation": {
    "user_facing": "Activity appears consistent with normal usage patterns."
  }
}
```
* Contains no numeric score (`risk_score`), no signal breakdown or weights (`contributing_signals`), no `user_id`, and no `admin_facing` explanation.

#### Admin `risk:updated` Payload
Broadcast to `admin:stream`:

```json
{
  "event_id": "evt_12345",
  "user_id": "usr_12345",
  "session_id": "sess_98765",
  "risk_score": 84,
  "risk_tier": "critical",
  "contributing_signals": [
    {
      "signal": "base_action_password_change",
      "category": "action",
      "weight": 20
    },
    {
      "signal": "seq_rapid_credential_cascade",
      "category": "sequence",
      "weight": 20
    }
  ],
  "evaluated_at": "2026-10-10T09:00:00.000Z",
  "explanation": {
    "user_facing": "Elevated risk pattern observed across multiple security indicators.",
    "admin_facing": "Action sequence triggered rapid credential cascade."
  }
}
```

#### User `decision:recorded` Payload
Broadcast to `user:<userId>` (privacy-sanitized tier-only format):

```json
{
  "decision_id": "dec_98765",
  "event_id": "evt_12345",
  "session_id": "sess_98765",
  "action_type": "password_change",
  "decision": "reverify",
  "enforcement_outcome": "reverify_required",
  "risk_tier": "high",
  "decided_at": "2026-10-10T09:00:00.000Z",
  "explanation": {
    "user_facing": "Additional verification is required before completing this sensitive action."
  }
}
```
* Contains no numeric `risk_score`, `contributing_signals`, `reasons`, `policy_version`, `user_id`, or `admin_facing` explanation.

#### Admin `decision:recorded` Payload
Broadcast to `admin:stream`:

```json
{
  "decision_id": "dec_98765",
  "event_id": "evt_12345",
  "risk_assessment_id": "ass_54321",
  "user_id": "usr_12345",
  "session_id": "sess_98765",
  "action_type": "password_change",
  "action_sensitivity": "critical",
  "risk_score": 68,
  "risk_tier": "high",
  "recommended_decision": "reverify",
  "effective_decision": "reverify",
  "enforcement_outcome": "reverify_required",
  "enforcement_mode": "automatic",
  "policy_version": "default-v1@1.0.0",
  "reasons": [
    {
      "source": "base_matrix",
      "rule_id": "base_matrix.high.critical",
      "decision": "delay"
    }
  ],
  "contributing_signals": [
    {
      "signal": "base_action_password_change",
      "category": "action",
      "weight": 20
    }
  ],
  "decided_at": "2026-10-10T09:00:00.000Z",
  "explanation": {
    "user_facing": "Additional verification is required before completing this sensitive action.",
    "admin_facing": "Policy decision detail..."
  }
}
```

### 11.6 Disconnection & Revocation Semantics

* **Session Invalidation (`session:terminated`):** When a session is invalidated via `sessionService.invalidateSession` (e.g. on logout or administrative revocation), a `session:terminated` event is emitted to `session:<sessionId>` immediately:
  ```json
  {
    "session_id": "sess_98765",
    "reason": "session_invalidated",
    "terminated_at": "2026-10-10T09:00:00.000Z"
  }
  ```
  The client socket receives `session:terminated` **before** the transport disconnect event fires.
* **Token Expiration Disconnection:** User sockets establish an unreferenced one-shot timer upon connection matching the JWT's `exp` claim. Sockets automatically disconnect when the token expires.
* **Periodic Revalidation:** A background interval revalidates all connected user sockets against active Redis sessions every `SOCKET_SESSION_REVALIDATION_INTERVAL_SECONDS` (default: 30 seconds). Sockets whose Redis session has expired or been revoked are forcefully disconnected.

## Summary

An integrating application will communicate with ActionGuard primarily through `POST /api/v1/events` *(Planned - Module 11)*. Today, advisory policy checks are available via `POST /api/v1/policy/evaluate`.

When implemented, the application will send a structured security event with relevant context and receive:

* a security decision,
* a risk score,
* contributing signals,
* a user-facing explanation,
* an administrator-facing explanation, and
* any required cooling-off information.

Session state and historical events can be queried separately, while webhooks *(Planned - Module 11)* and Socket.IO real-time streams allow decisions and telemetry to be pushed live to the integrating application and dashboard instead of being repeatedly polled.

The MVP uses a static API key per integrating application. More advanced authentication, signed webhook payloads, and additional versioning controls can be added later.

