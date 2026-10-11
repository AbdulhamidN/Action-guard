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
| POST   | `/api/v1/events`                         | *(Planned - Module 11)* Submit a security event for logging and evaluation   |
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
| POST   | `/api/v1/webhooks`                       | *(Planned - Module 11)* Register a webhook URL for decision/event alerts     |

In practice, `POST /events` is planned as a primary external integration point (Module 11). Internal protected routes (`/api/v1/account/*`) execute through the Policy Enforcement Point (`enforce(actionType)`) middleware, which evaluates live risk, enforces the active policy decision, records an immutable `policy_decisions` audit row, and broadcasts real-time notifications before any account state mutation occurs.

`/risk/evaluate` and `/policy/evaluate` provide narrower advisory operations for applications that want to check current risk or evaluate a hypothetical action without generating a new logged event.

## 4. Request Structure

### POST `/api/v1/events` *(Planned - Module 11)*

```json
{
  "user_id": "usr_12345",
  "session_id": "sess_98765",
  "event_type": "password_change",
  "timestamp": "2026-09-26T14:32:00Z",
  "context": {
    "ip_address": "196.189.45.12",
    "device_fingerprint": "fp_a1b2c3",
    "user_agent": "Mozilla/5.0 ..."
  },
  "metadata": {
    "action_sensitivity": "high"
  }
}
```

### Field Notes

* `event_type` — one of the event types defined in the security-event schema.
* `context` — provides information used for signal collection. Missing fields reduce risk-scoring accuracy but do not necessarily reject the request.
* `metadata.action_sensitivity` — one of `low`, `medium`, `high`, or `critical`. It is used by the Policy Engine together with the risk score.

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
  * `halted`: Recorded when the PEP halts the request (`reverify`, `delay`, or `block`).
  * `authorized`: Recorded when the PEP permits execution (`allow`, `monitor`, `elevated_allowed`, `recommend_only_allowed`) before invoking `next()`.
  * `rejected`: Recorded when post-PEP credential or domain validation fails (e.g. incorrect `current_password` or `recovery_email` matching primary `email`).
  * `failed_execution`: Recorded when a downstream database mutation or session invalidation throws an exception.
  * `completed`: Recorded **only** after the route handler's database mutation (and post-mutation session invalidation) has succeeded.
* **Mandatory Decision Audit & Truthful Containment:** Every PEP evaluation persists a row in `policy_decisions` (stamped with `policy_version: "<policy_id>@<schema_version>"`) **before** calling `next()`. For qualifying critical `block` decisions, `containSessionAndLockAccount` executes before finalizing `enforcement_outcome: 'contained_and_blocked'` or emitting `decision:recorded`; if decision persistence, policy evaluation, Redis elevation verification, or containment fails, the PEP fails closed with `503 policy_enforcement_unavailable` and never falsely reports `session_contained: true`.
* **PEP Halted Responses:**
  * `reverify` (without active scoped elevation) $\rightarrow$ `403 Forbidden` (`error.code: "step_up_required"`, `decision: "reverify"`, `decision_id`, `required_scope`, `risk_tier`, `challenge_endpoint`, `verify_endpoint`, `elevate_endpoint`, `explanation`).
  * `delay` (even if elevated) $\rightarrow$ `403 Forbidden` (`error.code: "action_delayed"`, `decision: "delay"`, `decision_id`, `risk_tier`, `retry_after_seconds`, `explanation`).
  * `block` (even if elevated) $\rightarrow$ `403 Forbidden` (`error.code: "action_blocked"`, `decision: "block"`, `decision_id`, `risk_tier`, `session_contained`, `account_locked`, optional `locked_until` and `retry_after_seconds`, `explanation`).

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

## 9. Webhooks *(Planned - Module 11)*

### POST `/api/v1/webhooks` *(Planned - Module 11)*

Registers a URL to receive asynchronous notifications when a decision is made.

```json
{
  "url": "https://banking-app.example.com/actionguard-webhook",
  "events": [
    "decision.reverify",
    "decision.block",
    "decision.delay"
  ]
}
```

### Webhook Payload

```json
{
  "event": "decision.block",
  "user_id": "usr_12345",
  "session_id": "sess_98765",
  "decision": "block",
  "risk_score": 92,
  "timestamp": "2026-09-26T14:32:05Z"
}
```

Webhook delivery is best-effort in the MVP. Failed deliveries are logged but not automatically retried.

Signed webhook payloads, allowing the receiving application to verify that a request genuinely came from ActionGuard, are a near-term extension and are not yet implemented.

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

