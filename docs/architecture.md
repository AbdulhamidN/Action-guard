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
                    │
          ┌─────────┼──────────┐
          ▼         ▼          ▼
        Allow     Reverify   Delay / Block
                              │
                              ▼
                    Session containment
                    (if risk is critical)
                              │
                              ▼
                    In-Process Event Bus
                 (pipeline:event_processed)
                              │
                              ▼
                   Socket.IO Server
          ┌───────────────────┴───────────────────┐
          ▼                                       ▼
     User Rooms                               Admin Room
 (tier-only, sanitized)                 (full risk telemetry)
```

All decisions and events are written to MySQL and cached in Redis at each stage, and pushed live to connected clients over Socket.IO via an in-process Event Bus (see Sections 4, 5, and 8).

## 4. Main Components

### Signal Collectors

Attach device fingerprint (FingerprintJS), IP/geo data (MaxMind GeoLite2), and impossible-travel calculations (Haversine distance/time) to each incoming event. Also perform basic bot/automation detection based on request timing.

### Event Logging & Correlation Engine

Writes every sensitive action as a structured record to MySQL, following a defined event schema. Groups related events into time-windowed sequences (e.g., login → recovery email change → password change) so that a chain of actions can be evaluated together, not just individually. Active sequences are cached in Redis under the `sequence:user:<userId>` key pattern for fast reads, featuring write-through synchronization upon grouping, automatic TTL expiration matching the correlation window, and transparent fallback to MySQL (which remains the durable, authoritative source of truth) on cache miss. MySQL persists the full sequence history.

### Personal Behavioral Baseline

Computes each user's typical patterns — usual login hours, usual devices, usual countries — from their own event history, using basic mean/standard-deviation statistics. Flags meaningful deviation from that individual baseline. Recalculated on a schedule via node-cron.

### Risk Engine (PDP — part 1)

Combines signal data, sequence data, and baseline deviation into a single additive risk score per session/action:

`Risk = Base Action Risk + Context Risk + Sequence Risk + Timing Risk + Baseline Deviation − Verification Confidence`

Weights and thresholds are configurable rather than hardcoded permanently, and are moved into versioned policy files (see Policy Management below).

### Policy Engine (PDP — part 2)

The Policy Engine (`src/utils/policyDecision.js`, `src/services/policyService.js`, `src/config/policyConfig.js`) determines what security response should occur for an action based on evaluated risk attributes, action sensitivity, and signal combinations.

Rather than introducing external policy engines such as Casbin, ABAC is implemented as a lightweight, strictly pure in-memory attribute-rule engine with zero external dependencies:

* **Ordered Response Tiers:** Decisions follow a strict hierarchy: `allow` < `monitor` < `reverify` < `delay` < `block`.
* **Base Matrix:** Maps the evaluated risk tier (`low`, `medium`, `high`, `critical`) and effective action sensitivity (`low`, `medium`, `high`, `critical`) to a baseline decision. Effective action sensitivity is the maximum of the server default for the event type and any caller-provided sensitivity (callers can raise sensitivity, but can never lower it).
* **Escalation Rules:** Evaluate specific risk signal combinations (such as impossible travel with novel devices or countries, credential change cascades, takeover progressions, or automation timing bursts). Escalation rules can only raise a decision, never lower a stricter base matrix decision.
* **Deterministic Output Invariant:** The overall decision is strictly the maximum (strictest) decision among all fired reasons (`decision === max(reason.decision)`).
* **Fail-Safe Mode:** When risk evaluation is temporarily unavailable, the engine applies fail-safe decisions based on action sensitivity (low/medium → `monitor`, high/critical → `block`), setting `requires_review: true`.
* **Recommended Actions & Explanations:** Derives deterministic recommended actions (e.g., `require_step_up`, `delay_with_cancel`, `notify_user`, `admin_review`), `enforcement_mode` (`automatic` or `recommend_only`), user-facing explanations free of raw metrics or breach claims, and administrative reason traces.
* **Separation of Concerns:** Module 8 decides only; it enforces nothing (enforcement middleware is in Module 10b), persists no decisions (decision audit persistence in Module 10b), and delegates policy configuration to the versioned Policy-as-Code loader (`src/services/policyLoader.js`). Advisory decisions are exposed via `POST /api/v1/policy/evaluate`, which enforcement components must never trust as authorization truth.

### Policy Enforcement Point (PEP) & Containment

Express middleware (`src/middleware/pep.js` — `enforce(actionType, options)`) that runs after `authenticateToken` and before any sensitive route handler (`src/routes/accountActions.js` mounted at `/api/v1/account`).
* **Server-Side Context Extraction:** Uses `extractServerRequestContext(req)` (`src/utils/requestContext.js`) to extract IP, device fingerprint, user-agent, and geolocation strictly from server headers and socket state; client-supplied `context`, `timestamp`, and `action_sensitivity` in `req.body` are never trusted.
* **Scoped Elevation & Decision Binding:** Maps `actionType` to its required elevation scope (`ACTION_ELEVATION_SCOPE_MAP`). Active scoped elevation can satisfy `reverify` (downgrading `effective_decision` to `allow`), but never bypasses `delay` or `block`.
* **Mandatory Decision Audit & Fail-Closed Execution:** Persists a `PolicyDecision` row (`policy_decisions` table) stamped with the exact `policy_id` and `policy_version` from the active policy snapshot before calling `next()`. If policy evaluation, Redis elevation check, delayed-action queueing, or `PolicyDecision.create` fails, the PEP fails closed with `503 policy_enforcement_unavailable` and never executes the route handler.
* **Cooling-Off Enforcement (`src/services/coolingOffService.js`, `src/jobs/coolingOffWorker.js`, `src/routes/coolingOff.js` — Module 10c, FR-32):** Connected via the PEP's `setDelayHandler` contract and started automatically by `src/index.js`. When an approved sensitive action receives a `delay` decision, `scheduleDelayedAction` validates and allowlists the action-specific payload, recursively strips secrets across nested structures, verifies `current_password` and bcrypt-hashes `new_password` for `password_change` (hiding the digest from API/Redis/event outputs), and persists the action in MySQL (`delayed_actions`) and Redis with a single-use `cancellation_token` (`ctkn_<64-hex>`, stored as a SHA-256 hash). Cancellation (`POST /api/v1/cooling-off/actions/:id/cancel`) enforces `expires_at` (`410 action_expired`). Once `execute_at` elapses, manual execution (`POST /api/v1/cooling-off/actions/:id/execute`) or `coolingOffWorker` (using atomic Redis `SET ... NX` lock acquisition, atomic Lua compare-and-delete lock release `executeReleaseLock`, and stale `'executing'` crash reconciliation to `'failed'`) performs **Zero Trust pre-execution rechecks** (verifying user lock status, bound session ownership/expiry/active state in MySQL and Redis via `validateActiveSession`, fail-closed fresh risk evaluation, and active policy/scoped elevation re-verification) before executing the deferred mutation.
* **Containment (`src/services/containmentService.js`):** When an action is blocked at `critical` risk tier (or via critical sequence escalation rules), the PEP invalidates the session (`critical_risk_containment`) and writes a 15-minute protective account lock to both Redis (`account_lock:<userId>`) and MySQL (`users.locked_until`), which `POST /api/v1/auth/login` enforces (`403 account_temporarily_locked`).

### Session Security & Local Step-Up Verification Module

Manages session lifecycle and scoped privilege elevation in Redis (`src/services/sessionService.js`, `src/services/elevationService.js`, `src/services/stepUpService.js`):
* **Session Lifecycle (Module 10a):** Sliding idle timeout (`900s` with `30s` write-throttle) and immutable maximum session age (`8h`) enforced via atomic Redis Lua scripts (`validateAndTouchSession`).
* **Local Step-Up Provider (Module 10b):** Issues session- and scope-bound 6-digit OTP challenges (`POST /api/v1/sessions/:id/step-up/challenge`) stored as `SHA-256(challengeId + ':' + otp)` in Redis (`300s` TTL, max 3 attempts) and delivered to the immutable registration email (`User.email`). Verification (`POST /api/v1/sessions/:id/step-up/verify`) compares hashes in constant time, signs a short-lived (`60s`) `ES256` ticket using an asymmetric P-256 key pair (`STEP_UP_VERIFICATION_PRIVATE_KEY` / `STEP_UP_VERIFICATION_PUBLIC_KEY`, separate from `JWT_SECRET`), and redeems it via `grantElevation`.
  * **ES256 Key Generation:**
    ```bash
    openssl ecparam -name prime256v1 -genkey -noout -out step-up-private.pem
    openssl ec -in step-up-private.pem -pubout -out step-up-public.pem
    ```
* **Dynamic Elevation Revocation:** Elevations record `granted_at_risk_tier` upon grant and are automatically revoked when a newly persisted risk assessment exceeds that tier (`risk_tier_increased`), on logout (`logout`), on session invalidation (`session_invalidated`), or across all user sessions on password change (`password_change`).

### Policy Management (Policy-as-Code & Replay Testing)

Stores risk-engine response matrices, escalation rules, fail-safe fallbacks, and action sensitivity mappings as versioned JSON policy files (`policies/default-v1.json`, `policies/candidate-strict-v1.json`) validated by a pure schema validator (`src/utils/policyValidator.js`).
The policy loader (`src/services/policyLoader.js`) loads, validates, deep-freezes, and atomically hot-reloads the active policy reference (`reloadActivePolicy`) without server restarts, and maintains strict candidate isolation during offline evaluations.
Includes a Jest-based offline replay testing harness (`src/replay/replayHarness.js`) that evaluates historical and synthetic event sequences against candidate policies in-memory with zero database/Redis persistence, reporting confusion matrix metrics (TP, FP, TN, FN, FPR, FNR) and decision diffs before live activation.

### Explainability & Dashboard

A React/Tailwind frontend that displays current risk state, active sessions, the incident timeline, and an interactive signal graph (React Flow) showing which signals contributed to a given decision and how they combined. Provides a plain-language explanation for the affected user and a more detailed, signal-level explanation for administrators. Updates live via Socket.IO as new events and risk changes occur.

### Audit & Event Storage

MySQL holds all persistent state: users (including `recovery_email`, `phone_number`, `mfa_enabled`, `locked_until`), sessions, security events, action sequences, behavioral baselines, risk assessments (`risk_assessments`), policy decisions (`policy_decisions`), delayed cooling-off actions (`delayed_actions`), and elevation audit logs (`elevation_audit_logs`) — forming the audit trail used for both the dashboard and replay testing.

### In-Process Event Bus

A centralized, synchronous EventEmitter wrapper (`src/events/eventBus.js`) that provides isolated event dispatching (`safeEmit`) across the application. When security events are committed and scored in the post-commit pipeline, the event bus emits `pipeline:event_processed`; when a PEP policy decision is persisted, it emits `policy:decision_recorded`, decoupling enforcement and risk scoring from real-time streaming and ensuring broadcaster errors cannot break request or persistence flows.

### Real-Time WebSocket Server (Socket.IO)

A real-time push streaming server (`src/realtime/socketServer.js`) mounted on the shared HTTP server. It authenticates client handshakes using user JWT tokens or a constant-time verified `ACTIONGUARD_ADMIN_API_KEY` (minimum 32 characters, header/payload only). Clients are partitioned into isolated rooms (`user:<userId>`, `session:<sessionId>`, and `admin:stream`). Sockets continuously revalidate session status against Redis, receive immediate `session:terminated` disconnect notifications upon logout, invalidation, or critical containment, and receive live sanitized broadcasts (`event:recorded`, `risk:updated`, `decision:recorded`). End-user payloads are strictly tier-only and privacy-sanitized (no raw IP addresses, no hardware fingerprints, no GPS coordinates, no raw numeric risk scores); administrators receive full signal telemetry, score breakdowns, and policy rule traces.

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
Correlation Engine groups it into the active sequence (Redis + MySQL)
                ↓
Baseline module scores deviation from the user's own history
                ↓
Risk Engine computes the additive risk score
                ↓
Policy Engine maps score + action sensitivity → response tier
                ↓
PEP enforces the decision on the route
                ↓
Event Bus receives post-commit notification: eventBus.safeEmit('pipeline:event_processed')
                ↓
Socket.IO broadcaster dispatches sanitized risk:updated and event:recorded payloads
(Tier-only to user:<userId>, full telemetry to admin room)
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
  ├── Sessions (Redis-backed, persisted on creation)
  │
  ├── Behavioral Baselines (per-user stats)
  │
  └── Security Events
          │
          ▼
    Action Sequences (correlated groups of events; active sequences cached in Redis via sequence:user:<userId>, full history persisted in MySQL)
          │
          ▼
    Risk Assessments (persisted risk scores, tiers, contributing signals, and explanations in risk_assessments table)
          │
          ▼
    Policy Decisions (allow / reverify / delay / block)
          │
          ▼
    Audit Logs (full event + decision history)

    Policy Files (versioned YAML/JSON, stored alongside
    the codebase, not in the database)
```

MySQL remains the durable, authoritative source of truth for all persistent state. Redis provides fast-read caching for active sessions and active user action sequences (`sequence:user:<userId>`). Write-through synchronization updates Redis whenever an event is grouped into a sequence, with a TTL matching the correlation time window. On cache miss or TTL expiration, the system falls back to MySQL and repopulates the Redis cache if the sequence remains within the active correlation window. When a session is deleted, any cached active sequence referencing it is automatically updated to `session_id: null` in Redis to match MySQL's `ON DELETE SET NULL` behavior.

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
* Defined fail-safe/fail-secure behavior is enforced across both the PDP and PEP: if the Risk Engine fails mid-request, high/critical actions default to `block` and low/medium actions default to `monitor` (`requires_review: true`); if policy evaluation, Redis elevation verification, or `policy_decisions` persistence fails, the PEP fails closed with `503 policy_enforcement_unavailable` before route execution.

Independent service scaling, asynchronous/queued event processing at scale, and formalized failure-mode guarantees are documented as future architectural work, consistent with the requirements analysis.

## 12. Dashboard API & Admin Session Token Architecture (Module 12a)

Module 12a establishes the foundational backend API for the operator dashboard:
* **Admin Session Token & Zero-Secret Persistence**: Administrative login (`POST /api/v1/admin/auth/login`) accepts `ACTIONGUARD_ADMIN_API_KEY` (enforcing $\ge 32$ characters) once and returns a short-lived opaque admin session token (`agadm_<32 random bytes base64url>`). The raw token is never stored in Redis (only its SHA-256 hash is persisted). The raw admin key is never accepted on administrative read endpoints.
* **Dual TTL Lifecycles**: Tokens enforce a sliding idle TTL (30 minutes default, sliding on valid read requests) and a hard absolute cap (4 hours default) measured from token creation.
* **Pure Payload Builders**: Real-time broadcasts (`socketServer.js`) and REST endpoints (`src/routes/admin.js`, `src/routes/me.js`, `src/routes/sessions.js`, `src/routes/risk.js`) share identical pure serialization builders from `src/realtime/payloads.js`.
* **Zero Trust Privacy Boundary & Tier-Only Contract**: Responses to standard JWT callers strip technical numeric scores, contributing signals, rule IDs, and administrative explanations. Full details are strictly restricted to authenticated operator endpoints (`/api/v1/admin/*`).
* **Covering Indexes & Pure SQL Aggregates**: Dashboard metrics (`GET /api/v1/admin/overview`) and user search/listing execute bounded SQL aggregates and MySQL 8 window functions without N+1 query loops, backed by migration 011 covering indexes (`idx_policy_decisions_outcome_decided_session`, `idx_risk_assessments_tier_evaluated`, `idx_sessions_active_expires_user`).

## Summary

ActionGuard's actual architecture, as built, is a single self-hosted Express application with clearly separated internal modules — signal collection, correlation, risk scoring (PDP), policy decisioning (PDP), and enforcement (PEP) — backed by MySQL for persistence and Redis for fast session/sequence state, with a React dashboard for live visibility. This is a deliberately monolithic MVP: the separation that matters for the project's security claims exists at the code level today, with service-level separation and scaling as an explicit next step rather than a current property of the deployed system.

## 13. Frontend Architecture & Real-Time Application Shell (Module 12b)

Module 12b implements the app shell foundation, establishing a strict separation between user-facing interactions and administrative operations without weakening Zero Trust guarantees:

* **Dual Shell Isolation**:
  * **User Shell (`/app/*`)**: Authenticates via `POST /api/v1/auth/login` with validated device fingerprints. The user session JWT is held strictly in `sessionStorage` (`ag_user_token`) and cleared on logout or session revocation.
  * **Admin Shell (`/admin/*`)**: Authenticates via `POST /api/v1/admin/auth/login` with the administrative key. The key is typed once, sent once, and immediately discarded from the DOM and component memory. The issued operator session token (`agadm_...`) is held strictly in JavaScript memory; refreshing the browser clears memory and forces re-authentication to the admin login.
  * Neither boundary ever stores credentials in `localStorage` or URL query parameters.
* **Real-Time Telemetry Streaming (`useLiveStream`)**:
  * Real-time telemetry is consumed via Socket.IO client connections mounted at `/socket.io`.
  * Stream segregation is strictly enforced: `mode === 'user'` passes strictly `auth: { token }` and receives account-scoped rooms (`user:<userId>`, `session:<sessionId>`), while `mode === 'admin'` passes strictly `auth: { adminToken }` and receives the global operator stream (`admin:stream`). The user stream never sends admin credentials, and vice versa.
  * In-memory bounded ring buffers capture the latest 200 events (`event:recorded`, `risk:updated`, `decision:recorded`) and automatically invalidate corresponding TanStack React Query caches.
  * Session termination (`session:terminated`) or authentication failure (`connect_error` with `unauthorized`) immediately displays an explanatory notice, purges credentials, and redirects to the login route.
* **Dynamic Content Security Policy (CSP) & Static Serving**:
  * When `SERVE_FRONTEND=true` is enabled, Express serves the compiled Single Page Application (`frontend/dist`) with an SPA fallback for non-API GET requests.
  * Unmapped API routes (`/api/*`) strictly return JSON 404 responses.
  * Helmet Content Security Policy is dynamically adjusted when `SERVE_FRONTEND=true` to permit `'self'` scripts, styles, connections, and fonts, while preserving anti-clickjacking (`frame-ancestors 'none'`) and object restrictions (`object-src 'none'`). When `SERVE_FRONTEND` is disabled, the strict API-only CSP (`default-src 'none'`) remains unconditionally in effect.
* **DEV-Only Fingerprint Override Tree-Shaking**:
  * To support multi-device security simulation across different browser profiles, development builds allow an explicit `localStorage` override key (`ag_fp_override`).
  * In production builds, this override branch is eliminated at compile time via dead code elimination, ensuring that production clients strictly derive hardware visitor IDs.

## 14. Admin Console & Interactive Explanation Graph (Module 12c-1)

Module 12c-1 completes the administrative user interface and causal explainability layer:

* **Operator Navigation & Sub-Routing**:
  * Sub-routing is mounted under `/admin/*` within the `AdminShell` layout:
    * `/admin` / `/admin/overview`: Security telemetry overview with 24h/7d window toggling, Recharts KPI distributions (risk tiers and decisions by outcome), and an interactive live console feed. The feed maintains a bounded ring buffer of 200 items (newest-first), provides a pause/resume stream toggle that freezes the display, and offers real-time filtering by risk tier, decision, and user ID substring.
    * `/admin/users`: User directory featuring 300ms debounced prefix search, offset/limit pagination, active session counts, risk tier badges, and account containment lock flags (`locked_until`).
    * `/admin/users/:id`: Comprehensive user investigation view with 4 distinct tabs: a unified chronologically sorted Timeline (merging security events, risk evaluations, decisions, and active sequence steps), Risk score time series with tier reference threshold bands (Low: 0-29, Medium: 30-59, High: 60-79, Critical: 80-100), Decisions list with rule evaluations and graph links, and Sessions state inspection.
    * `/admin/users/:userId/decisions/:decisionId`: Interactive Decision Explanation Graph fulfilling FR-35.
    * `/admin/policy`: Read-only inspection of the active 4x4 baseline decision matrix, escalation override rules, fail-safe fallback boundaries, and action sensitivity catalog.
* **Deterministic 5-Column Explanation Graph (`@xyflow/react`)**:
  * Employs deterministic positioning along 5 functional columns (Signals $\to$ Risk Assessment $\to$ Policy Reasons $\to$ Effective Decision $\to$ Enforcement Outcome) with fixed X coordinates.
  * Evaluates signal weights and assigns distinct text labels (`Mitigating signal` vs `Aggravating signal`) alongside border styling, ensuring full accessibility without relying on color alone.
  * Conducts mathematical weight-to-score reconciliation: if $\sum \text{signal.weight} \neq \text{risk\_score}$, a prominent warning banner is rendered explaining that baseline floor/ceiling thresholds or policy normalizations account for the divergence.
  * Provides an accessible "Why this decision?" WCAG summary table for screen readers and keyboard navigation, breaking down each signal, its category, weight, and influence on the decision.
  * Renders dual user-facing and administrator audit explanation panels.
* **Accessible Slide-Over Detail Drawer**:
  * Selecting any event from the live console or user timeline opens the `EventDetailDrawer`, declaring `role="dialog"`, `aria-modal="true"`, and `aria-labelledby="drawer-title"`.
  * Traps focus on open, listens for `Escape` to close, and restores focus back to the triggering element upon closure.
* **Code Splitting & Performance Hygiene**:
  * Heavy chart and graph libraries (`recharts`, `@xyflow/react`) are imported only within their respective sub-page modules.
  * All five sub-pages are lazy-loaded via `React.lazy` and `Suspense`, ensuring the core frontend bundle remains light (~317 kB) and unaffected by administrative visualization dependencies.
  * All external strings are rendered strictly as plain text; `dangerouslySetInnerHTML` is prohibited across all frontend source files.
