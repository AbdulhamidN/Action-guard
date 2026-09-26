# ActionGuard — Development Plan

## 1. Development Overview

ActionGuard will be developed incrementally through independent modules. Each module provides a functional capability that becomes a dependency for later modules.

Development will proceed from the core application foundation toward event collection, risk analysis, policy decisions, enforcement, integration, explainability, and attack simulation.

Each module should be completed and tested before dependent modules are started.

---

# 2. Module Development Plan

## Module 1 — Foundation

**Status:** Not Started

### Objectives

Establish the basic application, authentication, account, and session infrastructure.

### Tasks

* [ ] Implement user registration and login.
* [ ] Implement secure password hashing.
* [ ] Implement JWT issuance.
* [ ] Create the basic account and session data model.
* [ ] Store active sessions using Redis.
* [ ] Create the core Express application structure.
* [ ] Keep the route structure separated so that the Policy Decision Point (PDP) and Policy Enforcement Point (PEP) can be separated later.

### Deliverable

Users can register, log in, and obtain a valid session. No risk-analysis logic is implemented at this stage.

### Dependencies

None.

---

## Module 2 — Event Logging and Audit Trail

**Status:** Not Started

### Objectives

Create the event infrastructure required for later risk analysis.

### Tasks

* [ ] Define the security-event schema for events such as login, password change, recovery email change, phone change, and high-impact actions.
* [ ] Implement the event-writing pipeline.
* [ ] Record sensitive actions as structured, tamper-resistant-style records.
* [ ] Store event records in MySQL.
* [ ] Provide an API for querying events by user, session, and time range.

### Deliverable

Application activity produces traceable security events that can be consumed by later modules.

### Dependencies

Module 1.

---

## Module 3 — Signal Collectors

**Status:** Not Started

### Objectives

Collect contextual security signals and attach them to relevant events.

### Tasks

* [ ] Collect device fingerprints.
* [ ] Resolve IP addresses to geographic country or region information.
* [ ] Calculate impossible-travel conditions using distance and time between relevant activities.
* [ ] Generate basic bot or automation signals using request behavior.
* [ ] Attach collected signals to relevant sessions and events.

### Deliverable

Security events contain available device, location, travel-anomaly, and automation-related metadata.

### Dependencies

Module 2.

---

## Module 4 — Personal Behavioral Baseline

**Status:** Not Started

### Objectives

Establish an individual baseline of normal user activity.

### Tasks

* [ ] Calculate typical login times for each user.
* [ ] Calculate commonly used devices.
* [ ] Calculate commonly observed countries or regions.
* [ ] Calculate statistical deviation from the user's baseline.
* [ ] Recalculate user baselines periodically.

### Deliverable

The system can identify when new activity significantly differs from a user's established behavioral pattern.

### Dependencies

Module 3.

---

## Module 5 — Action Correlation Engine

**Status:** Not Started

### Objectives

Transform individual security events into connected sequences of activity.

### Tasks

* [ ] Group related events within configurable time windows.
* [ ] Create sequences such as login → recovery email change → password change.
* [ ] Store active sequences for fast access.
* [ ] Persist relevant sequences for later investigation.
* [ ] Provide an API for retrieving a user's active sequence or timeline.

### Deliverable

Individual events become a connected and queryable activity timeline.

### Dependencies

Module 3.

---

## Module 6 — Risk Scoring Engine

**Status:** Not Started

### Objectives

Create the core Policy Decision Point risk-evaluation capability.

### Tasks

* [ ] Calculate risk using action, context, sequence, timing, and behavioral signals.
* [ ] Include verification confidence when evaluating risk.
* [ ] Define configurable risk weights and thresholds.
* [ ] Provide a risk evaluation API.
* [ ] Return the current risk score together with its contributing signals.
* [ ] Recalculate risk when relevant events or signals change.

### Deliverable

The system provides an explainable risk assessment for a session or action.

### Dependencies

Modules 4 and 5.

---

## Module 7 — Real-Time Layer

**Status:** Not Started

### Objectives

Provide real-time security information to connected applications and dashboards.

### Tasks

* [ ] Implement real-time server communication.
* [ ] Push risk-score changes to connected clients.
* [ ] Push new security events in real time.
* [ ] Connect the frontend to the real-time event stream.

### Deliverable

Security dashboards can display changing risk and event information without requiring page refreshes.

### Dependencies

Module 6.

---

## Module 8 — Policy Engine and Response Tiers

**Status:** Not Started

### Objectives

Convert risk assessments into security decisions.

### Tasks

* [ ] Implement Attribute-Based Access Control (ABAC).
* [ ] Map risk level and action sensitivity to response tiers.
* [ ] Support the following response tiers:

  * Allow
  * Monitor
  * Re-verify
  * Delay
  * Block
* [ ] Implement signal-combination escalation logic.
* [ ] Consider individual signals together when determining the appropriate response.

### Deliverable

Given a security context, risk assessment, and requested action, the Policy Decision Point determines the appropriate response.

### Dependencies

Module 6.

---

## Module 9 — Policy-as-Code and Replay Testing

**Status:** Not Started

### Objectives

Make security policies versionable and testable before deployment.

### Tasks

* [ ] Move configurable policy rules into versioned policy files.
* [ ] Implement policy validation.
* [ ] Create a replay-testing mechanism.
* [ ] Replay recorded security-event sequences against proposed policies.
* [ ] Report policy outcomes and relevant false-positive or false-negative results.

### Deliverable

Security policies can be changed and tested against historical activity before being deployed.

### Dependencies

Module 8.

---

## Module 10 — Enforcement Layer

**Status:** Not Started

### Objectives

Turn Policy Decision Point decisions into actual application enforcement.

### Tasks

* [ ] Implement enforcement middleware.
* [ ] Check the Policy Decision Point before sensitive operations.
* [ ] Implement step-up verification.
* [ ] Support password, OTP, or email-based verification where applicable.
* [ ] Implement delayed high-impact actions.
* [ ] Provide cancellation during applicable cooling-off periods.
* [ ] Support session containment for critical security conditions.
* [ ] Support actions such as forced logout or restriction of sensitive operations.

### Deliverable

ActionGuard can enforce policy decisions by allowing, monitoring, requiring verification, delaying, or blocking sensitive actions.

### Dependencies

Module 8.

---

## Module 11 — Hardening and Integration

**Status:** Not Started

### Objectives

Strengthen the platform and provide practical integration capabilities.

### Tasks

* [ ] Implement rate limiting.
* [ ] Implement secure HTTP headers.
* [ ] Apply input validation across application routes.
* [ ] Provide API and webhook integration.
* [ ] Document the open security-event schema.
* [ ] Implement trusted-device enrollment.
* [ ] Provide appropriate user and organization security/friction settings.

### Deliverable

A hardened and externally integrable ActionGuard platform with the core open-source security capabilities exposed.

### Dependencies

Module 10.

---

## Module 12 — Dashboard and Explainability

**Status:** Not Started

### Objectives

Provide clear security visibility for users and administrators.

### Tasks

* [ ] Display current risk state.
* [ ] Display active sessions.
* [ ] Display incident and activity timelines.
* [ ] Provide simple explanations for users.
* [ ] Provide detailed explanations for administrators.
* [ ] Provide an interactive representation of signals contributing to security decisions.
* [ ] Display relevant real-time security updates.

### Deliverable

A functional security dashboard that demonstrates risk evaluation, activity monitoring, and explainable security decisions.

### Dependencies

Module 6 and Module 7.

---

## Module 13 — Attack Simulation and Demonstration

**Status:** Not Started

### Objectives

Demonstrate ActionGuard using controlled security scenarios.

### Tasks

* [ ] Create a normal-user activity scenario.
* [ ] Create a simulated account-takeover scenario.
* [ ] Generate controlled security events for demonstrations.
* [ ] Create representative data for testing normal and suspicious behavior.
* [ ] Demonstrate how ActionGuard detects and responds to suspicious activity.
* [ ] Demonstrate relevant false-positive testing.

### Deliverable

A reproducible demonstration showing how ActionGuard evaluates normal activity and responds to a simulated account-takeover scenario.

### Dependencies

All required preceding modules.

---

# 3. Module Dependency Flow

The primary development dependency is:

```text
Module 1 — Foundation
        ↓
Module 2 — Event Logging
        ↓
Module 3 — Signal Collectors
        ↓
   ┌────┴─────┐
   ↓          ↓
Module 4   Module 5
Behavior   Correlation
   └────┬─────┘
        ↓
Module 6 — Risk Engine
        ↓
   ┌────┴─────┐
   ↓          ↓
Module 7   Module 8
Real-Time  Policy Engine
              ↓
          Module 9
       Policy Replay
              ↓
          Module 10
         Enforcement
              ↓
          Module 11
       Hardening/Integration

Module 6 + Module 7
        ↓
Module 12 — Dashboard

All required modules
        ↓
Module 13 — Attack Simulation
```

---

# 4. Planned Technology Stack

The following technologies are the current implementation plan. They may be changed during development if a different solution provides better security, maintainability, or reliability.

## 4.1 Frontend

* React with Vite
* Tailwind CSS
* Recharts for risk trends and incident timelines
* React Flow for interactive security explanations
* Socket.IO Client for real-time updates

## 4.2 Backend

* Node.js
* Express
* Socket.IO Server

## 4.3 Database and State

* MySQL for persistent application and security data
* Redis for active sessions, temporary state, fast-access sequences, rate limiting, and cooling-off mechanisms

## 4.4 Signal Collection

* FingerprintJS for device fingerprinting
* MaxMind GeoLite2 or an equivalent solution for IP-based geographic information
* Haversine calculation for impossible-travel detection

## 4.5 Risk, Policy, and Behavioral Analysis

* Node.js-based risk-scoring logic
* Statistical calculations for behavioral deviation
* Scheduled jobs for baseline updates
* ABAC or an equivalent policy mechanism
* YAML or JSON for policy-as-code

## 4.6 Authentication and Security

* bcrypt for password hashing
* JWT for authentication and short-lived trust assertions
* Rate limiting
* Secure HTTP headers
* Input validation
* Email-based OTP for step-up verification where required

## 4.7 Testing

* Jest
* Supertest
* Playwright where end-to-end testing is required

## 4.8 Documentation and Demonstration

* OpenAPI/Swagger for API documentation
* Faker or an equivalent tool for generating demonstration data

## 4.9 DevOps

* Docker
* Docker Compose
* GitHub Actions for continuous integration

---

# 5. Development Principles

The development process shall follow these principles:

* Build and validate one module at a time.
* Complete required dependencies before starting dependent modules.
* Keep security decision-making separate from enforcement.
* Keep security policies configurable rather than hardcoded where practical.
* Avoid unnecessary coupling between modules.
* Test security-sensitive functionality before integration.
* Document public APIs and security events.
* Prefer open standards and self-hostable components.
* Keep implementation decisions changeable when they are not fundamental requirements.
* Do not claim that the system guarantees prevention; evaluate and demonstrate its ability to detect, verify, contain, and respond to suspicious activity.

---

# 6. Module Completion Criteria

A module is considered complete when:

* Its required functionality has been implemented.
* Its defined dependencies are functioning.
* Relevant tests pass.
* Security-sensitive behavior has been reviewed.
* The module can communicate correctly with dependent components.
* Its documentation is updated where necessary.
* The module's deliverable can be demonstrated independently where practical.

The development status of each module should be updated from **Not Started → In Progress → Completed** as development proceeds.
