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

| Method | Path                      | Purpose                                                                      |
| ------ | ------------------------- | ---------------------------------------------------------------------------- |
| POST   | `/api/v1/events`          | Submit a security event for logging and evaluation                           |
| POST   | `/api/v1/risk/evaluate`   | Request a risk score for a given user/session without submitting a new event |
| POST   | `/api/v1/policy/evaluate` | Evaluate a proposed action against policy and receive a decision             |
| GET    | `/api/v1/sessions/:id`      | Retrieve current risk state and metadata for a session                       |
| GET    | `/api/v1/events`            | Query historical events by user, session, or time range                      |
| GET    | `/api/v1/sequences/current` | Retrieve current active sequence/timeline for the authenticated user         |
| POST   | `/api/v1/webhooks`          | Register a webhook URL to receive decision/event notifications               |

In practice, `POST /events` is the primary integration point. Submitting an event triggers signal collection, risk scoring, and policy evaluation in one call and returns a decision.

`/risk/evaluate` and `/policy/evaluate` provide narrower operations for applications that want to check current risk or evaluate a hypothetical action without generating a new logged event.

## 4. Request Structure

### POST `/api/v1/events`

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
  "action_type": "high_impact_action",
  "action_sensitivity": "critical"
}
```

This endpoint checks what response an action would receive without logging it as a real event. It can be used as a "simulate before execute" check by the integrating application.

## 5. Response Structure

### Decision Response

Returned by `/events` and `/policy/evaluate`.

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
  "expires_at": "2026-09-26T09:15:00.000Z",
  "is_active": true,
  "risk": {
    "current_risk_score": null,
    "risk_tier": null,
    "contributing_signals": null,
    "evaluated_at": null
  }
}
```

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

| HTTP Status | Code                 | Meaning                                         |
| ----------- | -------------------- | ----------------------------------------------- |
| 400         | `invalid_request`    | Malformed or missing required fields            |
| 400         | `invalid_event_type` | Event type is not recognized                    |
| 401         | `unauthorized`       | Missing or invalid authentication token         |
| 403         | `forbidden`          | Caller is not authorized for the requested user |
| 404         | `not_found`          | Session or resource does not exist              |
| 429         | `rate_limited`       | Too many requests from this caller              |
| 500         | `internal_error`     | Unexpected server failure                       |
| 503         | `risk_evaluation_failed` | Risk engine temporarily unavailable        |

### Fail-Safe Behavior

If the Risk Engine cannot compute a score because of an internal error:

* High or critical actions should return `block`.
* Low or medium actions should return `monitor`.
* The response should indicate the internal failure with an appropriate error status.

This behavior represents ActionGuard failing closed on sensitive actions rather than silently allowing them.

**Note:** This fail-safe behavior is a near-term addition and may not be fully implemented in early MVP builds.

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

## 9. Webhooks

### POST `/api/v1/webhooks`

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

## Summary

An integrating application communicates with ActionGuard primarily through `POST /api/v1/events`.

The application sends a structured security event with relevant context and receives:

* a security decision,
* a risk score,
* contributing signals,
* a user-facing explanation,
* an administrator-facing explanation, and
* any required cooling-off information.

Session state and historical events can be queried separately, while webhooks allow decisions to be pushed to the integrating application instead of being repeatedly requested.

The MVP uses a static API key per integrating application. More advanced authentication, signed webhook payloads, and additional versioning controls can be added later.
