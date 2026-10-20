# ActionGuard Security Model

## What This Document Answers

What security model does ActionGuard follow, and how does it protect an application?

This document explains the security principles that govern every decision ActionGuard makes. Where the architecture documentation describes *how* the system is built and the requirements analysis describes *what* it must do, this document explains *why* it is designed the way it is — the reasoning a reviewer needs in order to trust the design, independent of any specific implementation detail.

## 1. Zero Trust: Never Trust, Always Verify

Traditional security treats authentication as a single gate: once a user passes it, they are trusted for the rest of the session. ActionGuard rejects that assumption. A session is never automatically trusted because it was trusted a moment ago — trust is continuously re-earned, not granted once and carried forward.

This matters because successful authentication does not guarantee that the legitimate account owner remains in control. An attacker using stolen but valid credentials looks identical to a genuine user at the moment of login. The risk that matters is not "did this person log in correctly," but "does what is happening now still look like the person who logged in."

## 2. Continuous Verification

Rather than checking risk once and stopping, ActionGuard re-evaluates risk on every sensitive action and on an ongoing basis throughout a session's lifetime. Risk is not a fixed label assigned at login — it is a live state that rises, falls, or stabilizes as new evidence appears. This allows the system to catch a takeover that develops gradually, action by action, rather than only catching an attacker at the door.

## 3. Assume-Breach Approach

ActionGuard is designed as though a breach has already happened. Instead of asking "how do we stop every possible intrusion," it asks "given that credentials can be stolen and attackers can authenticate successfully, how do we limit the damage once they're inside." This shifts the design goal from prevention to containment: the objective is to keep the blast radius of any single compromised account as small as possible, not to claim that compromise can never occur.

This is a deliberate and honest framing. No system, including ActionGuard, can guarantee that every takeover attempt will be caught — an attacker with valid credentials who mimics normal behavior closely enough and moves slowly enough can evade any risk-based system. ActionGuard's real claim is narrower and more defensible: it detects and contains risky action sequences before they reach an irreversible, high-impact outcome. It does not claim to prevent account takeover outright.

## 4. Least Privilege and Per-Action Authorization

Rather than granting broad access once a session is trusted, ActionGuard authorizes each sensitive action individually, at the moment it is requested, against the current risk state. Passing a step-up verification for one action does not restore blanket trust for every other action in the session. A password change, a payment, and a profile edit each carry their own sensitivity and are evaluated independently — this is what "least privilege" means at the level of individual actions rather than whole sessions.

## 5. Risk-Based Access and Attribute-Based Access Control (ABAC)

Access decisions are not binary allow/block outcomes tied to fixed roles. ActionGuard evaluates access using attributes — who the user is, what action is being requested, what resource is involved, and what context surrounds the request (device, location, timing, recent history) — and produces a proportionate response. Low-risk activity flows with minimal friction; higher-risk activity draws stronger scrutiny. This is Attribute-Based Access Control applied dynamically, rather than a static permissions table.

## 6. Session Protection and Dynamic Privilege Revocation

A session is monitored for as long as it remains open, not only at creation. This includes sliding idle timeouts (`900s` with a `30s` renewal write-throttle), a hard maximum session age (`8h`) regardless of activity, mid-session re-verification for sensitive areas (`step-up/challenge` and `step-up/verify`), and automatic expiration of any elevated privilege once its validity window ends. Furthermore, elevated trust is bound to the session's risk tier at the moment of grant (`granted_at_risk_tier`): if a subsequent event causes the session's evaluated risk tier to rise above that ceiling, all active elevations for the session are immediately revoked (`risk_tier_increased`). Similarly, a completed password change revokes all sessions and elevations across every device for the user (`password_change`), requiring fresh authentication.
* **Step-Up Challenge Multi-Dimensional Limits:** To protect step-up verification channels against brute-force harassment and OTP flooding, `stepUpService.js` atomically evaluates three distinct rate limits via Redis Lua (`-- ATOMIC_CHECK_STEP_UP_CHALLENGE_LIMITS`): (1) a 30-second cooldown per session and scope, (2) at most 3 challenges per 10-minute window per session and scope, and (3) at most 6 challenges per 10-minute window per user across all active sessions. When limited, the endpoint responds `429 challenge_limited` with `retry_after_seconds` and the delivery channel/outbox is never invoked.
* **Production Secret Enforcement:** Outside automated test mode (`NODE_ENV !== 'test'`), `assertRequiredSecrets()` enforces at startup (`src/index.js`) that `JWT_SECRET` is set and contains at least 32 characters, failing closed without leaking secret material; hardcoded fallback secrets are prohibited.

## 7. Account and Session Compromise Protection and Containment

The central threat ActionGuard is built around is not the login event itself, but the progression that can follow a successful login: a new device, followed by a recovery email change, followed by a password reset, followed by a high-impact action. Individually, each of these actions can be legitimate. ActionGuard's protection comes from treating them as a connected sequence and recognizing when that sequence, taken together, represents an escalating risk — intervening before the final, most damaging action completes rather than only reacting after the fact.

When the Policy Enforcement Point (PEP) blocks an action at the `critical` risk tier (or when escalation rules such as `rule_takeover_sequence_block` or `rule_rapid_credential_cascade_high_block` fire), ActionGuard triggers **protective containment**:
1. The offending session and all of its elevations are immediately invalidated (`critical_risk_containment`), emitting `session:terminated` to connected sockets before disconnecting.
2. A **15-minute protective account lock** is written to both Redis (`account_lock:<userId>`) and MySQL (`users.locked_until`). To prevent user enumeration and timing side-channels, `POST /api/v1/auth/login` checks account lock status strictly **after** validating password credentials with `bcrypt.compare`. Wrong passwords, unknown emails, and unlocked accounts return identical generic 401 responses. During an active hold, valid credentials from a recognized device fingerprint (with prior successful login history for this user derived via `deriveNoveltyFlags`) are allowed to authenticate; attempts from unrecognized or missing fingerprints are refused with `403 account_temporarily_locked`. If Redis evicts the key or restarts, login enforcement falls back to `users.locked_until` in MySQL and repopulates Redis for the remaining lock window.

## 8. PDP and PEP: Separation of Decision and Enforcement

ActionGuard separates the component that decides what should happen (the Policy Decision Point) from the component that actually carries it out (the Policy Enforcement Point). This separation is itself a security property, not just an organizational convenience: it means the logic that computes risk and chooses a response (`riskScoring.js`, `policyDecision.js`) is isolated from the middleware that gates application routes (`src/middleware/pep.js`).
* **Server-Derived Context Only:** The PEP extracts IP, device fingerprint, user-agent, and geolocation strictly from server-side headers and connection metadata (`extractServerRequestContext`), ignoring any client-supplied `context`, `timestamp`, or `action_sensitivity` in the request body.
* **Elevation Boundary:** Scoped step-up elevation can satisfy a `reverify` decision, downgrading the effective enforcement outcome to `allow`, but it can **never** bypass `delay` or `block`.
* **Fail-Safe Enforcement under recommend_only:** When the Risk Engine is unavailable (`isFailSafe === true`), fail-safe decisions (reverify/block) are strictly enforced by the PEP and cannot be bypassed or downgraded to `monitor`/`allow` even when policy is configured in `recommend_only` mode.
* **Constant-Time Service API Key Authentication:** In `authenticateApiKey`, service authentication keys are compared in constant time by hashing provided and configured keys with SHA-256 and evaluating via `crypto.timingSafeEqual` (`constantTimeKeyMatch`), preventing timing leaks.
* **Cooling-Off Enforcement & Zero Trust Pre-Execution Rechecks (FR-32):** When the PEP returns a `delay` decision, the action is not immediately executed; instead, `scheduleDelayedAction` validates and allowlists the action-specific payload (recursively stripping nested secrets, verifying `current_password` and pre-hashing `new_password` with bcrypt for `password_change` while stripping the digest from public responses) and queues the action in `delayed_actions` for a mandatory cooling-off period (`cooling_off_seconds`, default `300s`) paired with a single-use cryptographic `cancellation_token` (`ctkn_<64-hex>`, stored as a SHA-256 hash and verified with `crypto.timingSafeEqual` prior to `expires_at`). Because trust is never static, a delayed action is **not** blindly executed when its timer expires: immediately prior to execution, ActionGuard performs **Zero Trust pre-execution rechecks** verifying that (1) the user account is not locked, (2) a valid bound session exists and remains active, unexpired, and owned by the user in both MySQL and Redis (`validateActiveSession`), (3) the Risk Engine is available (`status === 'ok'`, failing closed with `risk_engine_unavailable` otherwise) and the risk tier has not increased, and (4) active policy re-evaluation does not return `block` or `delay`, and any `reverify` decision is satisfied by an active scoped elevation (`checkElevation`) for the action's required scope. Stale `'executing'` rows left behind by a worker crash are reconciled to `'failed'` (`worker_execution_timeout_or_crash`) and never blindly re-executed.
* **Fail-Closed & Audit-First Execution:** No protected route handler executes unless the PEP has evaluated the active policy snapshot and durably persisted the decision in `policy_decisions` (stamped with `policy_id` and `policy_version`). Any unexpected failure in policy evaluation, Redis elevation verification, delayed-action queueing, or decision-audit persistence fails closed with `503 policy_enforcement_unavailable`.

## 9. Detecting and Responding to Suspicious Activity

Detection draws on multiple signal categories — device fingerprinting, IP/geolocation and impossible-travel checks, behavioral deviation from a user's own personal baseline, and the correlated sequence of recent actions. No single signal is treated as conclusive on its own: a new device alone, a new IP alone, or an unusual login hour alone is common and often legitimate. Risk rises meaningfully when signals combine — a new device and a new country and an unusual hour, together, represent a materially different situation than any one of them in isolation.

Response scales with that risk rather than following a fixed rule: low risk is logged and allowed, moderate risk draws additional monitoring or a step-up verification, and high risk can delay or block a high-impact action while notifying the user. Every automated decision produces a plain-language explanation for the affected user and a more detailed, signal-level explanation for administrators — the goal is a system whose reasoning can always be inspected, not a black box that simply allows or denies.

## 10. Known Limitations

Any authenticated caller, including a hijacked session, can read its own risk breakdown and probe the advisory endpoint; the scoring rules are open source, so the exposure is probing volume rather than secrecy; mitigations are rate limiting on both endpoints (Module 11) and role-gating the full breakdown for administrators (Module 12). Additionally, administrative access to real-time telemetry currently relies on a static pre-shared key (`ACTIONGUARD_ADMIN_API_KEY`) that reads every user's security telemetry across the platform; fine-grained administrative roles and tenant segregation are not yet implemented. Furthermore:
* **Account-wide room exposure:** Account-wide rooms (`user:<userId>`) are visible to any socket holding that account's credentials, including a hijacker's session. This includes the victim's coarse locations (`coarse_location`), novelty flags (`is_new_device`, `is_new_country`), and sanitized `decision:recorded` notifications.
* **REST vs Socket payload alignment:** Fully resolved in Module 12a. Both user REST endpoints (`GET /api/v1/sessions/:id`, `POST /api/v1/risk/evaluate`, `GET /api/v1/me/*`) and user Socket.IO rooms enforce the tier-only contract (`risk_tier`, `evaluated_at`, `explanation.user_facing`). Full numeric scores, signal weights, and administrative explanations are strictly restricted to authenticated operator endpoints (`/api/v1/admin/*`) and the `admin:stream` real-time channel.
* **Best-Effort Elevation Lifecycle Audit vs Mandatory Decision Audit:** While `policy_decisions` persistence is strictly mandatory before any protected route executes (failing closed on DB error), `elevation_audit_logs` writes (grants, revocations, expirations) are best-effort so that a transient MySQL outage does not prevent Redis-backed session/elevation revocation during containment or logout.
* **Transient Redis errors during socket revalidation:** Sockets skip a revalidation tick when Redis errors or becomes temporarily unreachable, leaving connected sockets open until the next successful tick (new connection handshakes and PEP route checks, however, fail closed).

## 11. Admin Session Token & Privacy Boundary Model (Module 12a)

ActionGuard separates administrative dashboard access from external application integration through a dedicated session token architecture and strict tier-only privacy boundaries:

### 11.1 Admin Session Token Architecture
1. **Single-Type Raw Key Submission:** The raw `ACTIONGUARD_ADMIN_API_KEY` (enforcing $\ge 32$ characters) is typed once during login (`POST /api/v1/admin/auth/login`) and validated using constant-time comparison (`crypto.timingSafeEqual`). It is **never** accepted by administrative read endpoints (`/api/v1/admin/*`) neither via `Authorization: Bearer` nor `X-Admin-Api-Key`.
2. **Opaque Token Generation & Zero Raw Secret Persistence:** Upon successful authentication, ActionGuard generates an opaque session token (`agadm_<32 random bytes base64url>`). The raw token is **never** stored in Redis; only its SHA-256 hash (`admin_token:<hash>`) is persisted.
3. **Dual TTL Lifecycles (Sliding Idle + Hard Absolute Cap):**
   * **Sliding Idle TTL:** Admin tokens have a configurable idle timeout (default: 30 minutes, `ADMIN_TOKEN_IDLE_TTL_SECONDS`). Every valid authenticated read request slides the idle expiration.
   * **Absolute Lifetime Cap:** To prevent indefinite persistence, tokens have a strict maximum lifetime (default: 4 hours, `ADMIN_TOKEN_MAX_LIFETIME_SECONDS`) measured from `created_at`. Once the cap is reached, the token expires immediately and cannot be renewed.
4. **Immediate Revocation on Logout:** `POST /api/v1/admin/auth/logout` deletes the token hash immediately from Redis.
5. **Real-Time Token Revalidation:** Sockets connected to `admin:stream` revalidate their admin session token against Redis on every periodic tick (default: 30 seconds). If the token has expired, been revoked, or exceeded its absolute cap, the socket is forcefully disconnected.

### 11.2 Privacy Model & Oracle Probing Defense
* **Tier-Only Contract for JWT Callers:** Normal user callers and compromised user sessions only observe coarse risk classifications (`low`, `medium`, `high`, `critical`), timestamp, and user-facing explanations. Technical numeric scores ($0-100$), granular contributing signals (`unrecognized_device`, `seq_rapid_credential_cascade`), and administrative explanations are completely stripped across all user-facing endpoints (`/api/v1/sessions/:id`, `/api/v1/risk/evaluate`, `/api/v1/me/*`). This prevents attackers from systematically probing the model to discover exact threshold boundaries or trigger conditions.
* **Single Source of Truth Sanitization:** REST endpoints and Socket.IO broadcasts share identical pure serialization builders in `src/realtime/payloads.js`, guaranteeing that data sanitization and privacy guarantees cannot diverge across protocols.

## Summary

ActionGuard's security model can be stated in one sentence: **trust is continuous, granular, and revocable, and the system's job is to detect and contain risky account activity before it becomes irreversible — not to guarantee that compromise never happens.** Every principle above exists in service of that one honest, testable claim.

