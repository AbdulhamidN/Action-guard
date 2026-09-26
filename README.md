# ActionGuard

ActionGuard is an open-source Zero Trust security platform that helps applications continuously detect, evaluate, and contain suspicious user and account activity.

## Getting Started

```bash
npm install
docker compose up
```


Instead of trusting a user or session after authentication, ActionGuard continuously evaluates the security context of sessions and sensitive actions using signals such as device, location, behavior, timing, and recent activity.

Based on the current risk, ActionGuard can allow, monitor, require re-verification, delay, or block an action. It also provides explainable security decisions for both users and administrators.

## Core Principles

* **Never Trust, Always Verify** — authentication does not create permanent trust.
* **Continuous Verification** — security risk is continuously evaluated throughout a session.
* **Per-Action Authorization** — sensitive actions are individually evaluated.
* **Assume Breach** — the system limits the impact of compromised accounts and sessions.
* **Risk-Based Access Control** — security requirements increase as risk increases.
* **Least Privilege** — elevated access is limited to what is needed and for a limited time.
* **Explainable Security** — security decisions provide understandable reasons.
* **Open Integration** — applications can integrate with ActionGuard through APIs and security events.
* **Self-Hosted** — organizations can deploy and control their own ActionGuard instance.

## How ActionGuard Works

```text
Protected Application
        │
        │ Security Events
        ▼
┌─────────────────────────────┐
│         ActionGuard         │
│                             │
│   Event Logging             │
│          ↓                  │
│   Signal Collection         │
│          ↓                  │
│   Behavioral Analysis       │
│          ↓                  │
│   Risk Scoring              │
│          ↓                  │
│   Policy Decision (PDP)     │
│          ↓                  │
│   Policy Enforcement (PEP)  │
└─────────────┬───────────────┘
              │
              ▼
      Security Decision

 Allow │ Monitor │ Reverify │ Delay │ Block
```

## Main Capabilities

### Zero Trust & Access Control

* Continuous verification and risk monitoring
* Per-action authorization
* Risk-based and adaptive access control
* Attribute-Based Access Control (ABAC)
* Action-level security controls
* Just-in-time privilege elevation
* Short-lived trust and authorization
* Trusted-device and trusted-network support

### Risk & Threat Intelligence

* Risk scoring
* Device fingerprinting
* IP and geolocation intelligence
* Impossible-travel detection
* Personal behavioral baselines
* Bot and automation detection
* Cross-session anomaly detection
* Cross-platform risk intelligence
* Attack-pattern and campaign correlation
* Blast-radius awareness
* Combined-signal risk escalation

### Session Protection

* Idle-session timeout
* Maximum session lifetime
* Continuous session monitoring
* Sensitive-action re-verification
* Automatic expiration of temporary trust and privileges

### Security Response

ActionGuard adapts its response to the current risk:

```text
Low Risk
   ↓
Allow / Minimal Friction

Medium Risk
   ↓
Monitor / Re-verify

High Risk
   ↓
Delay / Strong Verification

Critical Risk
   ↓
Block / Contain
```

Administrators can configure responses for individual signals and combinations of signals.

### Explainability & Security Operations

* Simple explanations for users
* Detailed explanations for administrators
* Interactive security-decision and signal visualization
* Proactive threat hunting
* Security event and decision auditing

### Integration & Extensibility

* REST APIs
* Webhooks
* Open security-event schema
* Policy-as-code
* Historical policy replay testing
* Community risk-signal plugins
* Self-hosted deployment
* Signed short-lived trust assertions

## Account-Takeover Protection

ActionGuard is designed to help detect and contain suspicious activity after an attacker obtains valid account credentials.

For example:

```text
Valid Login
     ↓
New Device
     ↓
Unusual Location
     ↓
Recovery Email Change
     ↓
Password Change
     ↓
High-Impact Action
```

ActionGuard does not necessarily treat these events as isolated incidents. It can correlate them into a sequence and evaluate the overall risk.

As suspicious evidence increases, ActionGuard can increase the required security response and intervene before a high-impact action becomes irreversible.

ActionGuard does not claim to guarantee prevention of every account takeover. Its goal is to **detect and contain risky account activity before significant damage occurs**.

## Architecture

ActionGuard separates security decision-making from security enforcement.

```text
                    ActionGuard
                         │
          ┌──────────────┴──────────────┐
          │                             │
   Policy Decision Point          Policy Enforcement Point
          │                             │
    ┌─────┴─────┐                 ┌─────┴─────┐
    │            │                 │           │
Risk Engine  Policy Engine     Middleware  Verification
    │            │                 │           │
    └─────┬──────┘                 └─────┬─────┘
          │                              │
          └────────── Decision ──────────┘
```

The separation allows risk evaluation and policy decisions to remain independent from the application enforcement layer.

## Project Structure

```text
ActionGuard/
│
├── docs/
│   ├── requirements.md
│   ├── architecture.md
│   ├── security-model.md
│   ├── api-contract.md
│   └── development-plan.md
│
├── AGENTS.md
├── README.md
│
├── frontend/
├── backend/
├── detection-service/
├── database/
├── docker/
└── ...
```

The implementation structure may evolve during development.

## Development Modules

Development is organized into the following modules:

1. **Foundation**
2. **Event Logging & Audit Trail**
3. **Signal Collectors**
4. **Personal Behavioral Baseline**
5. **Action Correlation Engine**
6. **Risk Scoring Engine**
7. **Real-Time Layer**
8. **Policy Engine & Response Tiers**
9. **Policy-as-Code & Replay Testing**
10. **Enforcement Layer**
11. **Hardening & Integration**
12. **Dashboard & Explainability**
13. **Attack Simulation & Demo Scenarios**

Each module builds on the capabilities established by the previous modules.

## Technology

### Frontend

* React
* Vite
* Tailwind CSS
* Recharts
* React Flow
* Socket.IO Client

### Backend

* Node.js
* Express
* Socket.IO

### Database & State

* MySQL
* Redis

### Security & Risk Analysis

* Device fingerprinting
* IP/geolocation analysis
* Behavioral baseline analysis
* Risk scoring
* Policy evaluation

### Authentication & Security

* JWT
* bcrypt
* Helmet
* Rate limiting
* Input validation
* Step-up verification

### Testing

* Jest
* Supertest
* Playwright

### DevOps

* Docker
* Docker Compose
* GitHub Actions

## Documentation

Detailed documentation is available in the `docs/` directory.

| Document              | Description                                              |
| --------------------- | -------------------------------------------------------- |
| `requirements.md`     | Defines the functional and non-functional requirements   |
| `architecture.md`     | Describes the system architecture and components         |
| `security-model.md`   | Describes the security principles and protection model   |
| `api-contract.md`     | Defines the API and integration contract                 |
| `development-plan.md` | Defines the development modules and implementation order |

## Project Status

**Active Development**

ActionGuard is being developed as an open-source security project with an incremental implementation approach.

The project focuses on continuous security evaluation, account and session compromise detection, risk-based decisions, policy enforcement, explainability, and integration with existing applications.

## Security Scope

ActionGuard is designed to detect, evaluate, and contain suspicious activity within protected applications.

It is intended to work alongside existing security controls such as:

* Strong authentication
* Multi-factor authentication
* Secure credential management
* Secure application development
* Network and endpoint security
* Organizational security policies
* Incident response processes

ActionGuard is not intended to replace these security controls.

## Open Source

ActionGuard is designed to be self-hosted, extensible, and reusable by applications that need continuous security evaluation.

The project aims to provide reusable security components, documented integration interfaces, extensible risk signals, and explainable security decisions.

## Team

Developed by **Group 2**, INSA Summer Camp 2026 — Jimma, Ethiopia

- Abdulhamid Nuri Abasimal
- Adnan Muslim Juma
- Hayidar Taju Jemal

## License

License information will be added when the project license is finalized.
