# ActionGuard Architecture

## What This Document Answers

How is ActionGuard actually structured? This document describes the real components, data flow, storage, and APIs as built for the MVP — not the target platform vision. Where a capability is designed for but not yet implemented, it is marked explicitly rather than left ambiguous.

## 1. Architecture Overview

ActionGuard is a single, self-hosted Node.js/Express application that sits alongside a protected application's own authentication and account-management routes. It receives security-relevant events as they happen, collects contextual signals about them, computes a risk score, evaluates that score against configured policy, and enforces the resulting decision directly within the same application — allowing, challenging, delaying, or blocking the action before it completes.

For the MVP, ActionGuard is built as a monolith: the Risk Engine, Policy Engine, and enforcement logic run as separate internal modules within one Express process, not as independently deployed services. This keeps the system simple to build, run, and demonstrate within the project timeline. Splitting these into independently scalable services is a future direction, not part of this build (see Section 9).

## 2. Architecture Goals (MVP Scope)

* Continuous, post-authentication risk monitoring
* Per-action authorization rather than one-time login trust
* Real-time risk scoring and response
* Session and account compromise protection
* Explainable, inspectable decisions (no black-box scoring)
* Self-hosted deployment via Docker
* Clear separation between decision-making (PDP) and enforcement (PEP) in code, even within a single process

Not yet in scope for this build: multi-tenant isolation, a third-party plugin system, and independently scalable services — these are documented in the requirements analysis as future work.

## 3. High-Level Architecture

```text
           Protected Application
                    │
                    ▼
               ActionGuard
                    │
        ┌───────────┴───────────┐
        │                       │
        ▼                       ▼
 Signal Collectors        Event Logging
        │                  & Correlation
        │                      Engine
        │                  (event schema,
        │                 action sequences)
        │                       │
        └───────────┬───────────┘
                    ▼
             Risk Engine (PDP)
       (additive score: context + sequence
        + timing + baseline deviation
        − verification confidence)
                    │
                    ▼
             Policy Engine (PDP)
       (risk score + action sensitivity
              → response tier)
                    │
                    ▼
                   PEP
       (Express enforcement middleware)
                    │
          ┌─────────┼──────────┐
          ▼         ▼          ▼
        Allow     Reverify   Delay / Block
                              │
                              ▼
                    Session containment
                    (if risk is critical)
```

All decisions and events are written to MySQL and cached in Redis at each stage, and pushed live to the dashboard over Socket.IO (see Sections 5 and 8).

## 4. Main Components

### Signal Collectors

Attach device fingerprint (FingerprintJS), IP/geo data (MaxMind GeoLite2), and impossible-travel calculations (Haversine distance/time) to each incoming event. Also perform basic bot/automation detection based on request timing.

### Event Logging & Correlation Engine

Writes every sensitive action as a structured record to MySQL, following a defined event schema. Groups related events into time-windowed sequences (e.g., login → recovery email change → password change) so that a chain of actions can be evaluated together, not just individually. Active sequences are cached in Redis for fast reads; full history is persisted in MySQL.

### Personal Behavioral Baseline

Computes each user's typical patterns — usual login hours, usual devices, usual countries — from their own event history, using basic mean/standard-deviation statistics. Flags meaningful deviation from that individual baseline. Recalculated on a schedule via node-cron.

### Risk Engine (PDP — part 1)

Combines signal data, sequence data, and baseline deviation into a single additive risk score per session/action:

`Risk = Base Action Risk + Context Risk + Sequence Risk + Timing Risk + Baseline Deviation − Verification Confidence`

Weights and thresholds are configurable rather than hardcoded permanently, and are moved into versioned policy files (see Policy Management below).

### Policy Engine (PDP — part 2)

Maps a given risk score and action sensitivity to a response tier — allow, monitor, reverify, delay, or block — using Attribute-Based Access Control rules (via Casbin, or a simpler hand-rolled lookup table). Escalates more aggressively when multiple risk signals combine than when only one fires.

### Policy Enforcement Point (PEP)

Express middleware that calls the Policy Engine before a sensitive route executes, and applies its decision directly: allowing the request, triggering step-up verification (OTP via email), delaying execution with a cancel window, or blocking the action outright. On critical risk, can force session containment (logout / restrict further actions).

### Session Security Module

Manages session lifecycle in Redis: idle timeout, maximum session age, and automatic expiration of any elevated privilege granted through step-up verification.

### Policy Management

Stores risk-engine weights and policy-engine rules as versioned YAML/JSON files rather than buried constants, so changes can be reviewed like code. Includes a replay-testing harness (Jest) that runs recorded event sequences against a policy file before it goes live, reporting false-positive/false-negative impact.

### Explainability & Dashboard

A React/Tailwind frontend that displays current risk state, active sessions, the incident timeline, and an interactive signal graph (React Flow) showing which signals contributed to a given decision and how they combined. Provides a plain-language explanation for the affected user and a more detailed, signal-level explanation for administrators. Updates live via Socket.IO as new events and risk changes occur.

### Audit & Event Storage

MySQL holds all persistent state: users, sessions, events, action sequences, baselines, policy versions, and decisions — forming the audit trail used for both the dashboard and replay testing.

**Not built in this MVP:** a third-party plugin loader/registry (Signal Collectors are hardcoded, not pluggable), and multi-tenant data isolation (no `tenant_id` boundary — this is a single-organization deployment).

## 5. Data Flow

```text
User performs a sensitive action
                ↓
Express route receives the request
                ↓
Event is written to MySQL (event schema)
                ↓
Signal Collectors attach device / IP-geo / travel data
                ↓
Correlation Engine groups it into the active sequence
(Redis + MySQL)
                ↓
Baseline module scores deviation from the user's own history
                ↓
Risk Engine computes the additive risk score
                ↓
Policy Engine maps score + action sensitivity → response tier
                ↓
PEP enforces the decision on the route
                ↓
Decision + updated risk state pushed live via Socket.IO
                ↓
Event, signals, and decision are logged for audit and replay testing
```

## 6. Security Decision Flow

```text
       Sensitive action requested
                  │
                  ▼
          Collect signals
    (device, IP/geo, travel,
      baseline deviation)
                  │
                  ▼
            Risk scoring
                  │
                  ▼
          Policy evaluation
                  │
        ┌─────────┼─────────┐
        ▼         ▼         ▼
      Allow    Reverify   Restrict
                            │
                            ▼
                       Delay / Block
                            │
                            ▼
                   Session containment
                   (only on critical risk)
```

A single signal rarely triggers a strong response on its own — a new device, a new IP, or an unusual hour is common and often legitimate. Risk escalates meaningfully when signals combine (e.g., new device + new country + odd hour together), which is what drives the system toward reverify, delay, or block rather than allow.

## 7. Data Architecture

All data lives in MySQL, organized around these entities:

```text
Users
  │
  ├── Devices (fingerprints, trusted-device flags)
  │
  ├── Sessions (Redis-backed, persisted on close)
  │
  ├── Behavioral Baselines (per-user stats)
  │
  └── Security Events
          │
          ▼
    Action Sequences (correlated groups of events)
          │
          ▼
    Risk Scores (computed per event/session)
          │
          ▼
    Policy Decisions (allow / reverify / delay / block)
          │
          ▼
    Audit Logs (full event + decision history)

    Policy Files (versioned YAML/JSON, stored alongside
    the codebase, not in the database)
```

Flexible, variable-shaped signal payloads (e.g., differing metadata per signal type) are stored as JSON columns within MySQL rather than introducing a separate database, keeping the system on a single storage technology.

## 8. Integration Architecture

```text
┌────────────────────┐
│ Protected          │
│ Application        │
└──────────┬─────────┘
           │
           │ API call (sensitive action)
           ▼
┌────────────────────┐
│    ActionGuard     │
│  (single Express   │
│    application)    │
└──────────┬─────────┘
           │
           │ Decision (allow / reverify / delay / block)
           ▼
┌────────────────────┐
│ Protected          │
│ Application        │
│ Enforces Result    │
└────────────────────┘
```

For the MVP, ActionGuard is built and demonstrated as one integrated application (auth + protected actions + risk engine together), but the Risk Engine, Policy Engine, and PEP middleware are structured as separable internal modules with a defined interface, so that in principle they could sit in front of a different host application's routes. This has not been tested against a real external application in this build. Serving multiple separate organizations from one shared ActionGuard instance (multi-tenancy) is not implemented.

## 9. Deployment Architecture

```text
             Internet
                │
                ▼
          ActionGuard
     (Express app container)
                │
       ┌────────┴────────┐
       ▼                 ▼
Application Routes    Dashboard
                      (React)
       │              served statically
       ├── Risk Engine (PDP)
       ├── Policy Engine (PDP)
       └── PEP middleware
                │
         ┌──────┴──────┐
         ▼             ▼
       MySQL          Redis
    (events, users,  (sessions, active
     sequences,       sequences, rate
     policy history,  limiting, cooling-off
     audit)            timers)
```

Deployed via Docker Compose: one container for the Express application, one for MySQL, one for Redis. The Risk Engine and Policy Engine run inside the same application container as internal modules — they are not deployed as separate scalable services in this build. Running them as independently deployable components, scaling separately from the enforcement layer, is a future architectural direction rather than part of the current deployment.

## 10. Security Architecture

* Authentication via JWT; passwords hashed with bcrypt
* Short-lived, signed tokens for session and trust state — nothing persists as valid indefinitely
* HTTPS/TLS for all API communication
* Rate limiting (express-rate-limit + Redis) and secure headers (helmet) on all routes
* Input validation (express-validator/zod) on every endpoint
* Immutable-style audit logging of every event and decision
* GPS-based precise location, where supported, is opt-in only and never collected by default

**Not yet implemented:** encryption of stored data at rest, tamper-evident (hash-chained) audit logs, and secure sandboxing for third-party plugin code — all flagged as near-term or future work rather than part of this build.

## 11. Scalability & Reliability (Current State)

* The application runs as a single Express process; Risk Engine and Policy Engine do not currently scale independently of the enforcement layer.
* Redis is used to keep session and sequence lookups fast under load.
* Policy changes are read from versioned files at runtime, so updating thresholds does not require rebuilding the application.
* Defined fail-safe/fail-secure behavior if the Risk Engine fails mid-request (e.g., defaulting to block for high-sensitivity actions) is a near-term addition, not yet built.

Independent service scaling, asynchronous/queued event processing at scale, and formalized failure-mode guarantees are documented as future architectural work, consistent with the requirements analysis.

## Summary

ActionGuard's actual architecture, as built, is a single self-hosted Express application with clearly separated internal modules — signal collection, correlation, risk scoring (PDP), policy decisioning (PDP), and enforcement (PEP) — backed by MySQL for persistence and Redis for fast session/sequence state, with a React dashboard for live visibility. This is a deliberately monolithic MVP: the separation that matters for the project's security claims exists at the code level today, with service-level separation and scaling as an explicit next step rather than a current property of the deployed system.
