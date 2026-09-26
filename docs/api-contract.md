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
| GET    | `/api/v1/sessions/:id`    | Retrieve current risk state and metadata for a session                       |
| GET    | `/api/v1/events`          | Query historical events by user, session, or time range                      |
| POST   | `/api/v1/webhooks`        | Register a webhook URL to receive decision/event notifications               |

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

```json
{
  "session_id": "sess_98765",
  "user_id": "usr_12345",
  "current_risk_score": 68,
  "risk_tier": "high",
  "created_at": "2026-09-26T09:00:00Z",
  "last_activity_at": "2026-09-26T14:32:00Z",
  "trusted_device": false,
  "active_restrictions": [
    "high_impact_action_blocked"
  ]
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
| 401         | `unauthorized`       | Missing or invalid API key                      |
| 404         | `not_found`          | Session or resource does not exist              |
| 429         | `rate_limited`       | Too many requests from this API key             |
| 500         | `internal_error`     | Unexpected failure in the Risk or Policy Engine |

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
