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

## 6. Session Protection

A session is monitored for as long as it remains open, not only at creation. This includes idle timeouts, a hard maximum session age regardless of activity, mid-session re-verification for sensitive areas, and automatic expiration of any elevated privilege once its validity window ends. A session that goes quiet, runs unusually long, or attempts something sensitive can all trigger renewed scrutiny independent of the original login decision.

## 7. Account and Session Compromise Protection

The central threat ActionGuard is built around is not the login event itself, but the progression that can follow a successful login: a new device, followed by a recovery email change, followed by a password reset, followed by a high-impact action. Individually, each of these actions can be legitimate. ActionGuard's protection comes from treating them as a connected sequence and recognizing when that sequence, taken together, represents an escalating risk — intervening before the final, most damaging action completes rather than only reacting after the fact.

## 8. PDP and PEP: Separation of Decision and Enforcement

ActionGuard separates the component that decides what should happen (the Policy Decision Point) from the component that actually carries it out (the Policy Enforcement Point). This separation is itself a security property, not just an organizational convenience: it means the logic that computes risk and chooses a response is isolated from the code path that executes application requests, reducing the chance that a flaw in one compromises the other, and making each independently reviewable, testable, and replaceable.

## 9. Detecting and Responding to Suspicious Activity

Detection draws on multiple signal categories — device fingerprinting, IP/geolocation and impossible-travel checks, behavioral deviation from a user's own personal baseline, and the correlated sequence of recent actions. No single signal is treated as conclusive on its own: a new device alone, a new IP alone, or an unusual login hour alone is common and often legitimate. Risk rises meaningfully when signals combine — a new device and a new country and an unusual hour, together, represent a materially different situation than any one of them in isolation.

Response scales with that risk rather than following a fixed rule: low risk is logged and allowed, moderate risk draws additional monitoring or a step-up verification, and high risk can delay or block a high-impact action while notifying the user. Every automated decision produces a plain-language explanation for the affected user and a more detailed, signal-level explanation for administrators — the goal is a system whose reasoning can always be inspected, not a black box that simply allows or denies.

## 10. Known Limitations

Any authenticated caller, including a hijacked session, can read its own risk breakdown and probe the advisory endpoint; the scoring rules are open source, so the exposure is probing volume rather than secrecy; mitigations are rate limiting on both endpoints (Module 11) and role-gating the full breakdown for administrators (Module 12). Additionally, administrative access to real-time telemetry currently relies on a static pre-shared key (ACTIONGUARD_ADMIN_API_KEY) that reads every user's security telemetry across the platform; fine-grained administrative roles and tenant segregation are not yet implemented.

## Summary

ActionGuard's security model can be stated in one sentence: **trust is continuous, granular, and revocable, and the system's job is to detect and contain risky account activity before it becomes irreversible — not to guarantee that compromise never happens.** Every principle above exists in service of that one honest, testable claim.
