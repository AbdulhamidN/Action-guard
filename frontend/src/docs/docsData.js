/**
 * ActionGuard Comprehensive Documentation Content Database.
 * Sourced directly from ActionGuard repository:
 * - docs/api-contract.md
 * - docs/architecture.md
 * - docs/security-model.md
 * - docs/policy-as-code-guide.md
 * - docs/requirements.md
 * - src/engine/risk-engine.js
 * - src/engine/policy-engine.js
 * - src/middleware/action-guard.js
 * - src/middleware/auth.js
 * - config/policy.json
 */

export const DOCS_CATEGORIES = [
  {
    id: 'getting-started',
    title: 'A. Getting Started',
    pages: [
      { id: 'introduction', title: 'Introduction to ActionGuard' },
      { id: 'what-it-does', title: 'What ActionGuard Does' },
      { id: 'key-features', title: 'Key Features' },
      { id: 'installation-guide', title: 'Installation Guide' },
      { id: 'environment-configuration', title: 'Environment Configuration' },
      { id: 'quick-start', title: 'Quick Start' },
      { id: 'first-time-setup', title: 'First-Time Setup' }
    ]
  },
  {
    id: 'core-concepts',
    title: 'B. Core Concepts',
    pages: [
      { id: 'continuous-trust', title: 'Continuous Trust Evaluation' },
      { id: 'zero-trust-principles', title: 'Zero Trust Principles' },
      { id: 'session-security', title: 'Session Security' },
      { id: 'device-trust', title: 'Device Trust & Fingerprinting' },
      { id: 'risk-signals', title: 'Contextual & Behavioral Signals' },
      { id: 'risk-scoring-tiers', title: 'Risk Scoring & Tiers' },
      { id: 'policy-authorization', title: 'Policy-Based Authorization' },
      { id: 'step-up-verification', title: 'Step-Up Verification' },
      { id: 'cooling-off-delays', title: 'Cooling-Off Delays' },
      { id: 'containment', title: 'Session Blocking & Containment' }
    ]
  },
  {
    id: 'architecture',
    title: 'C. Architecture',
    pages: [
      { id: 'architecture-overview', title: 'System Architecture Overview' },
      { id: 'frontend-backend', title: 'Frontend & Backend Architecture' },
      { id: 'policy-decision-point', title: 'Policy Decision Point (PDP)' },
      { id: 'policy-enforcement-point', title: 'Policy Enforcement Point (PEP)' },
      { id: 'decision-flow', title: 'Risk Evaluation & Decision Flow' },
      { id: 'auth-session-lifecycle', title: 'Authentication & Session Lifecycle' },
      { id: 'database-redis', title: 'Database & Redis Architecture' },
      { id: 'system-data-flow', title: 'System Data Flow' }
    ]
  },
  {
    id: 'security',
    title: 'D. Security',
    pages: [
      { id: 'security-model', title: 'Security Model' },
      { id: 'threat-model', title: 'Threat Model' },
      { id: 'account-takeover', title: 'Account Takeover Scenarios' },
      { id: 'device-location-risk', title: 'Device & Location Risk' },
      { id: 'impossible-travel', title: 'Impossible Travel Detection' },
      { id: 'behavioral-bot-detection', title: 'Behavioral & Bot Detection' },
      { id: 'audit-logs', title: 'Security Events & Audit Logs' },
      { id: 'privacy-protection', title: 'Privacy & Data Protection' },
      { id: 'limitations-assumptions', title: 'Security Limitations & Assumptions' }
    ]
  },
  {
    id: 'user-guides',
    title: 'E. User Guides',
    pages: [
      { id: 'user-registration-login', title: 'User Registration & Login' },
      { id: 'user-dashboard', title: 'User Dashboard' },
      { id: 'session-device-management', title: 'Session & Device Management' },
      { id: 'trusted-devices', title: 'Trusted Devices & Networks' },
      { id: 'understanding-decisions', title: 'Understanding Security Decisions' },
      { id: 'responding-reverification', title: 'Responding to Re-Verification' },
      { id: 'account-security-actions', title: 'Account Security Actions' }
    ]
  },
  {
    id: 'admin-guides',
    title: 'F. Administrator Guides',
    pages: [
      { id: 'admin-console-overview', title: 'Admin Console Overview' },
      { id: 'admin-auth-access', title: 'Authentication & Access' },
      { id: 'user-session-monitoring', title: 'User & Session Monitoring' },
      { id: 'security-event-monitoring', title: 'Security Event Monitoring' },
      { id: 'policy-management', title: 'Policy Management' },
      { id: 'risk-configuration', title: 'Risk Configuration' },
      { id: 'security-response', title: 'Security Response & Investigation' }
    ]
  },
  {
    id: 'developer-guides',
    title: 'G. Developer Guides',
    pages: [
      { id: 'project-structure', title: 'Project Structure' },
      { id: 'local-dev-setup', title: 'Local Development Setup' },
      { id: 'running-with-docker', title: 'Running with Docker' },
      { id: 'migrations-seeding', title: 'Database Migrations & Seeding' },
      { id: 'frontend-development', title: 'Frontend Development' },
      { id: 'backend-development', title: 'Backend Development' },
      { id: 'testing-guide', title: 'Testing' },
      { id: 'build-production', title: 'Build & Production Deployment' },
      { id: 'troubleshooting', title: 'Troubleshooting' },
      { id: 'contributing', title: 'Contributing' }
    ]
  },
  {
    id: 'api-reference',
    title: 'H. API Reference',
    pages: [
      { id: 'api-overview', title: 'API Overview' },
      { id: 'api-auth', title: 'Authentication Endpoints' },
      { id: 'api-users', title: 'User Endpoints' },
      { id: 'api-sessions', title: 'Session Endpoints' },
      { id: 'api-security-events', title: 'Security Event Endpoints' },
      { id: 'api-admin', title: 'Admin Endpoints' },
      { id: 'api-examples', title: 'Request & Response Examples' },
      { id: 'api-errors', title: 'Error Responses' },
      { id: 'api-websocket', title: 'WebSocket Events' },
      { id: 'api-rate-limits', title: 'Rate Limits & Security Considerations' }
    ]
  }
];

export const DOCS_PAGES = {
  // A. GETTING STARTED
  'introduction': {
    id: 'introduction',
    title: 'ActionGuard Developer Documentation',
    category: 'A. Getting Started',
    lead: 'ActionGuard is an open-source, self-hosted Zero Trust security platform designed to continuously protect authenticated user sessions and high-impact actions.',
    sections: [
      {
        id: 'overview',
        title: 'Project Overview',
        content: `ActionGuard evaluates security context such as device identity, IP location changes, behavioral timing, and action sensitivity in real time to detect account compromise and session takeover. Developed by Group 2 during the INSA Summer Camp 2026 in Jimma, Ethiopia, ActionGuard operates under the Apache-2.0 open source license.`
      },
      {
        id: 'security-philosophy',
        title: 'Core Philosophy: Never Trust, Always Verify',
        content: `Standard perimeter authentication assumes that once a user provides valid login credentials or passes MFA at 09:00, their session is trusted unconditionally until expiration. Infostealer malware, browser cookie exfiltration, and credential stuffing exploit this exact gap. ActionGuard shifts trust from a single login timestamp to continuous per-action authorization.`
      },
      {
        id: 'stack-summary',
        title: 'Technology Stack',
        content: `Built with Node.js and Express 4 for the backend API, MySQL 8.0 with Sequelize for durable audit persistence, Redis 7 for sub-millisecond session state and sliding-window rate limiting, and React 18 with Vite and Tailwind CSS for the user and administrative interfaces.`
      }
    ]
  },

  'what-it-does': {
    id: 'what-it-does',
    title: 'What ActionGuard Does',
    category: 'A. Getting Started',
    lead: 'ActionGuard bridges the critical gap between initial authentication and irreversible application actions.',
    sections: [
      {
        id: 'continuous-defense',
        title: 'Continuous Post-Login Authorization',
        content: `Instead of trusting a bearer token blindly, ActionGuard intercepts every sensitive HTTP request. It evaluates whether the current context (device hardware fingerprint, geographic location, request cadence, recent sequences) matches the authenticated owner's historical baseline.`
      },
      {
        id: 'proportional-response-system',
        title: 'Proportional Security Friction',
        content: `ActionGuard produces five graded response tiers:
1. Allow: Routine action with low risk score runs without friction.
2. Monitor: Action proceeds while generating high-priority telemetry for administrator review.
3. Re-verify: Requires out-of-band 6-digit OTP verification sent to the immutable primary registration email.
4. Delay: Places high-impact actions in a 300-second cooling-off queue with emergency cancellation tokens.
5. Block: Instantly purges active Redis sessions and locks the account for 15 minutes.`
      }
    ]
  },

  'key-features': {
    id: 'key-features',
    title: 'Key Features',
    category: 'A. Getting Started',
    lead: 'Explore the modular security capabilities included in the ActionGuard engine.',
    sections: [
      {
        id: 'signals-and-detection',
        title: 'Signals & Detection Engines',
        content: `- Device Fingerprinting: Hardware and browser canvas/audio attribute hashing.
- Impossible Travel: Great-circle Haversine velocity calculation between consecutive requests (> 900 km/h threshold).
- Behavioral Baselines: Per-user rolling 30-day nocturnal and geographic deviation tracking.
- Automation Bursts: Request interval variance analysis detecting non-human burst rates.`
      },
      {
        id: 'explainability',
        title: 'Zero Black-Box Explainability',
        content: `Every point in the calculated 0–100 risk score traces directly to named additive terms. Security administrators can inspect full causal attribution graphs, while users receive privacy-preserving plain-language explanations.`
      }
    ]
  },

  'installation-guide': {
    id: 'installation-guide',
    title: 'Installation & Deployment',
    category: 'A. Getting Started',
    lead: 'Deploy ActionGuard on your local development machine or production infrastructure.',
    sections: [
      {
        id: 'docker-deployment',
        title: 'Docker Compose Deployment (Recommended)',
        content: `The fastest way to run ActionGuard is using Docker Compose, which automatically configures MySQL 8, Redis 7, and the Express application container:`
      },
      {
        id: 'docker-commands',
        title: 'Commands',
        code: `# 1. Clone repository\ngit clone https://github.com/AbdulhamidN/Action-guard.git\ncd Action-guard\n\n# 2. Setup environment\ncp .env.example .env\n\n# 3. Start services\ndocker compose up -d --build\n\n# 4. Check service health\ncurl http://localhost:3000/health`,
        language: 'bash'
      },
      {
        id: 'native-deployment',
        title: 'Native Node.js Installation',
        content: `Ensure you have Node.js 20+, MySQL 8.0, and Redis 7 installed locally:\n\n\`\`\`bash\nnpm ci\ncd frontend && npm ci && cd ..\nnode src/database/migrate.js\nnode src/database/seed.js\nnpm start\n\`\`\``
      }
    ]
  },

  'environment-configuration': {
    id: 'environment-configuration',
    title: 'Configuration Reference (.env)',
    category: 'A. Getting Started',
    lead: 'ActionGuard configures secrets, database connections, and operational modes via environment variables.',
    sections: [
      {
        id: 'core-variables',
        title: 'Core Environment Variables Table',
        content: `| Variable | Default | Required | Purpose |
|---|---|---|---|
| PORT | 3000 | Optional | HTTP server listening port |
| NODE_ENV | development | Recommended | Runtime environment: development, test, production |
| DB_HOST | localhost / mysql | Required | MySQL database host |
| DB_PORT | 3306 / 3307 | Optional | MySQL listening port |
| DB_USER | actionguard | Required | Database user |
| DB_PASSWORD | actionguard_secret | Required | Database password |
| DB_NAME | actionguard | Required | Database schema name |
| REDIS_URL | redis://redis:6379 | Required | Redis connection string |
| JWT_SECRET | None | Required | Minimum 32-character secret for HMAC-SHA256 user tokens |
| ACTIONGUARD_ADMIN_API_KEY | None | Required | Minimum 32-character secret for administrator authentication |
| WEBHOOK_SECRET_ENCRYPTION_KEY | None | Required | 64-hex AES-256-GCM key for encrypting webhook secrets |
| SERVE_FRONTEND | true | Optional | Serves compiled static frontend from Express |
| ACTIONGUARD_DEMO_MODE | false | Optional | Enables testing step-up OTP inspection endpoints |`
      },
      {
        id: 'secrets-hygiene',
        title: 'Secret Key Generation',
        content: `Generate high-entropy secrets using OpenSSL or Node.js crypto:\n\n\`\`\`bash\nnode -e "console.log(require('crypto').randomBytes(32).toString('hex'))"\n\`\`\``
      }
    ]
  },

  'quick-start': {
    id: 'quick-start',
    title: 'Quick Start',
    category: 'A. Getting Started',
    lead: 'Spin up the platform and make your first authenticated request in under 5 minutes.',
    sections: [
      {
        id: 'bootstrap-steps',
        title: 'Step-by-Step Bootstrap',
        content: `1. Start Docker containers via \`docker compose up -d --build\`.
2. Open \`http://localhost:3000\` in your browser to view the homepage.
3. Sign up for a user account at \`/signup\`.
4. Log in at \`/login\` to enter the User Portal.
5. Log in to the Operator Console at \`/admin/login\` using the configured \`ACTIONGUARD_ADMIN_API_KEY\`.`
      }
    ]
  },

  'first-time-setup': {
    id: 'first-time-setup',
    title: 'First-Time Setup',
    category: 'A. Getting Started',
    lead: 'Post-installation tasks and security verification procedures.',
    sections: [
      {
        id: 'database-seeding',
        title: 'Database Migrations & Initial Seed',
        content: `If running outside Docker, initialize database schema tables:\n\n\`\`\`bash\nnpm run migrate\nnpm run seed\n\`\`\`\nThis populates the \`policies\` table with the initial baseline policy rules defined in \`config/policy.json\`.`
      }
    ]
  },

  // B. CORE CONCEPTS
  'continuous-trust': {
    id: 'continuous-trust',
    title: 'Continuous Trust Evaluation',
    category: 'B. Core Concepts',
    lead: 'Understand why point-in-time authentication fails against modern session hijacking.',
    sections: [
      {
        id: 'trust-decay',
        title: 'Trust Decay and Renewal',
        content: `In ActionGuard, trust is dynamic and decaying. A session starts with baseline trust upon successful login with an enrolled device. As time passes or if contextual anomalies occur (IP changes, new User-Agent, unusual timing), trust decays. High-impact operations trigger evaluation and renewal requirements.`
      }
    ]
  },

  'zero-trust-principles': {
    id: 'zero-trust-principles',
    title: 'Zero Trust Principles',
    category: 'B. Core Concepts',
    lead: 'The architectural foundations derived from NIST SP 800-207.',
    sections: [
      {
        id: 'principles-list',
        title: 'ActionGuard Tenets',
        content: `1. Never Trust, Always Verify: Re-authorize sensitive actions using current security context.
2. Assume Compromise: Design controls assuming valid credentials may already be stolen by infostealer trojans.
3. Least Privilege per Action: Elevation tokens are short-lived (<= 300s) and scoped strictly to target operations.
4. Independent Policy Enforcement: Policy decisions (PDP) are decoupled from application enforcement (PEP).`
      }
    ]
  },

  'session-security': {
    id: 'session-security',
    title: 'Session Security',
    category: 'B. Core Concepts',
    lead: 'Session binding, lifecycle, and revocation mechanisms.',
    sections: [
      {
        id: 'session-binding',
        title: 'Contextual Session Binding',
        content: `Each active session is bound to an initial device fingerprint, IP subnet, and user agent. When incoming requests exhibit mismatched fingerprint affinity, risk scores rise immediately, thwarting cookie exfiltration replay attacks.`
      }
    ]
  },

  'device-trust': {
    id: 'device-trust',
    title: 'Device Trust & Fingerprinting',
    category: 'B. Core Concepts',
    lead: 'How ActionGuard recognizes client hardware without invading user privacy.',
    sections: [
      {
        id: 'device-fingerprint',
        title: 'Fingerprint Collection',
        content: `Client browsers generate a non-invasive device identifier using FingerprintJS. This fingerprint hashes hardware attributes (Canvas rendering, WebGL vendor, audio context, screen dimensions, CPU cores) into a stable 32-character hex hash submitted via the \`x-device-fingerprint\` HTTP header.`
      },
      {
        id: 'trusted-lifecycle',
        title: '30-Day Device Trust Lifecycle',
        content: `New devices default to untrusted. Once verified, devices are enrolled into the \`devices\` database table with a 30-day trust expiry. Users can inspect and revoke recognized hardware from the Security Portal.`
      }
    ]
  },

  'risk-signals': {
    id: 'risk-signals',
    title: 'Contextual & Behavioral Signals',
    category: 'B. Core Concepts',
    lead: 'The telemetry inputs that feed the Policy Decision Point.',
    sections: [
      {
        id: 'signal-breakdown',
        title: 'Active Signal Collectors',
        content: `- Base Action Sensitivity: Inherent impact of the requested route (low: 10, medium: 30, high: 60, critical: 80).
- Device Novelty: Unenrolled or altered client hardware (+25 risk).
- IP Geolocation & Impossible Travel: Haversine velocity between successive locations exceeding 900 km/h (+55 risk).
- Sequence Correlation: Hostile cascades such as password change immediately following recovery email update (+35 risk).
- Nocturnal & Interval Anomaly: Requests during unusual hours or with microsecond machine regularity (+20 risk).
- Verification Credit: Active valid ES256 step-up ticket (-20 risk offset).`
      }
    ]
  },

  'risk-scoring-tiers': {
    id: 'risk-scoring-tiers',
    title: 'Risk Scoring & Tiers',
    category: 'B. Core Concepts',
    lead: 'Additive integer scoring mapping to five ordered operational tiers.',
    sections: [
      {
        id: 'formula',
        title: 'Deterministic Risk Formula',
        content: `Risk Score = Base Action Risk + Context Risk + Sequence Risk + Timing Risk + Baseline Deviation - Verification Confidence`
      },
      {
        id: 'tiers-table',
        title: 'Five Response Tiers',
        content: `| Tier | Score Range | Default Response | User Friction |
|---|---|---|---|
| Tier 1: Allow | 0 – 29 | Execute route handler | None |
| Tier 2: Monitor | 30 – 59 | Execute route + priority audit | None |
| Tier 3: Re-verify | 60 – 74 | HTTP 403 step_up_required | 6-Digit OTP |
| Tier 4: Delay | 75 – 84 | Enqueue for 300s cooling-off | Notification & holding |
| Tier 5: Block | 85 – 100 | Invalidate session + 15m lock | Hard lockout |`
      }
    ]
  },

  'policy-authorization': {
    id: 'policy-authorization',
    title: 'Policy-Based Authorization',
    category: 'B. Core Concepts',
    lead: 'Declarative JSON matrices and escalation rules.',
    sections: [
      {
        id: 'policy-structure',
        title: 'Policy Schema Structure',
        content: `Policies reside in \`config/policy.json\` and the MySQL \`policies\` table. They define a Base Decision Matrix cross-referencing action sensitivities against evaluated risk levels, augmented by escalation rules that force specific tiers when critical signals occur.`
      }
    ]
  },

  'step-up-verification': {
    id: 'step-up-verification',
    title: 'Step-Up Verification',
    category: 'B. Core Concepts',
    lead: 'Out-of-band cryptographic identity verification.',
    sections: [
      {
        id: 'stepup-mechanics',
        title: 'Challenge and Elevation Flow',
        content: `1. PEP returns HTTP 403 \`step_up_required\` with challenge ID.
2. System generates a cryptographically random 6-digit OTP stored in Redis with 300-second TTL.
3. OTP is delivered exclusively to the immutable primary registration email.
4. Client submits OTP via \`POST /api/v1/sessions/:id/step-up/verify\`.
5. Upon 3 failed attempts, account enters protective lockout.
6. Successful verification issues an asymmetric NIST P-256 (ES256) signed elevation ticket granting temporary privilege.`
      }
    ]
  },

  'cooling-off-delays': {
    id: 'cooling-off-delays',
    title: 'Cooling-Off Delays',
    category: 'B. Core Concepts',
    lead: 'Quarantine window for irreversible high-impact actions.',
    sections: [
      {
        id: 'cooling-off-flow',
        title: 'Holding Queue Mechanics',
        content: `Delayed actions are persisted to the \`delayed_actions\` table with status \`pending\` and an execution timestamp (default +300 seconds). A single-use cancellation token is issued to the authentic owner. Prior to execution, the system re-evaluates whether the account is locked or the session compromised.`
      }
    ]
  },

  'containment': {
    id: 'containment',
    title: 'Session Blocking & Containment',
    category: 'B. Core Concepts',
    lead: 'Neutralizing threats in real time.',
    sections: [
      {
        id: 'lockout-rules',
        title: 'Protective Lockout & Session Eviction',
        content: `When critical risk or repeated verification failures occur, ActionGuard instantly purges active Redis sessions, emits revocation events over Socket.IO, and applies a 15-minute protective lock. Generic 401 responses prevent username enumeration, while recognized devices retain legitimate recovery access.`
      }
    ]
  },

  // C. ARCHITECTURE
  'architecture-overview': {
    id: 'architecture-overview',
    title: 'System Architecture Overview',
    category: 'C. Architecture',
    lead: 'Decoupled Policy Decision Point (PDP) and Policy Enforcement Point (PEP) topology.',
    sections: [
      {
        id: 'nist-decoupling',
        title: 'NIST SP 800-207 Alignment',
        content: `ActionGuard enforces strict boundary separation between policy decision and enforcement:
- PEP (Policy Enforcement Point): Express middleware intercepting incoming requests, extracting context headers, and executing PDP verdicts.
- PDP (Policy Decision Point): Pure decision engine comprising the Risk Engine and Policy Loader that evaluates rules without touching request sockets.`
      }
    ]
  },

  'frontend-backend': {
    id: 'frontend-backend',
    title: 'Frontend & Backend Architecture',
    category: 'C. Architecture',
    lead: 'How the React SPA communicates with the Express backend.',
    sections: [
      {
        id: 'components-map',
        title: 'Subsystem Breakdown',
        content: `- Backend: Express 4 server providing REST endpoints under \`/api/v1\` and health checks under \`/health\`.
- Frontend: Single-Page Application (SPA) built with Vite, Tailwind CSS, React Router 7, and React Query.
- Production Serving: When \`SERVE_FRONTEND=true\`, Express serves the compiled \`frontend/dist\` bundle with strict Content Security Policy headers.`
      }
    ]
  },

  'policy-decision-point': {
    id: 'policy-decision-point',
    title: 'Policy Decision Point (PDP)',
    category: 'C. Architecture',
    lead: 'The core risk and policy evaluation logic.',
    sections: [
      {
        id: 'pdp-internals',
        title: 'PDP Modules',
        content: `- \`src/engine/risk-engine.js\`: Calculates deterministic signal values.
- \`src/engine/policy-engine.js\`: Evaluates the active policy matrix and escalation rules.
- \`src/services/policyLoader.js\`: Loads policy configurations from MySQL with JSON file fallback.`
      }
    ]
  },

  'policy-enforcement-point': {
    id: 'policy-enforcement-point',
    title: 'Policy Enforcement Point (PEP)',
    category: 'C. Architecture',
    lead: 'Express middleware that intercepts and gates incoming traffic.',
    sections: [
      {
        id: 'pep-middleware',
        title: 'Enforcement Pipeline',
        content: `Implemented in \`src/middleware/action-guard.js\`. Intercepts incoming requests, validates security envelopes, executes rate limiting, invokes the PDP, and enforces the verdict before downstream route handlers execute.`
      }
    ]
  },

  'decision-flow': {
    id: 'decision-flow',
    title: 'Risk Evaluation & Decision Flow',
    category: 'C. Architecture',
    lead: 'The 6-stage lifecycle of every incoming request.',
    sections: [
      {
        id: 'flow-steps',
        title: 'Request Lifecycle',
        content: `1. Interception: PEP catches request and extracts tokens/fingerprints.
2. Context Collection: Queries GeoLite2, timestamps, and device hash.
3. Correlation: Checks sliding-window sequence and rolling baseline.
4. Scoring: PDP sums signal terms into an integer score (0–100).
5. Verdict: Strictest response selected between base matrix and escalation rules.
6. Enforcement & Audit: Action executed, delayed, challenged, or blocked; event recorded in MySQL.`
      }
    ]
  },

  'auth-session-lifecycle': {
    id: 'auth-session-lifecycle',
    title: 'Authentication & Session Lifecycle',
    category: 'C. Architecture',
    lead: 'JWT issuance, session storage in Redis, and revocation.',
    sections: [
      {
        id: 'lifecycle-details',
        title: 'Tokens & Sessions',
        content: `Users authenticate via \`POST /api/v1/auth/login\`. A signed HMAC-SHA256 JWT is issued containing user ID and session UUID. The session is cached in Redis (\`sess:<id>\`) and tracked in the MySQL \`sessions\` table with bound device fingerprints.`
      }
    ]
  },

  'database-redis': {
    id: 'database-redis',
    title: 'Database & Redis Architecture',
    category: 'C. Architecture',
    lead: 'Durable persistence combined with in-memory caching.',
    sections: [
      {
        id: 'storage-roles',
        title: 'Storage Separation',
        content: `- MySQL 8.0: Immutable audit logs, user credentials (bcrypt hashed), enrolled devices, behavioral baselines, delayed action queue.
- Redis 7: Low-latency active session keys, OTP challenge state, ES256 elevation tokens, sliding-window rate limit counters.`
      }
    ]
  },

  'system-data-flow': {
    id: 'system-data-flow',
    title: 'System Data Flow',
    category: 'C. Architecture',
    lead: 'End-to-end telemetry and state synchronization flow.',
    sections: [
      {
        id: 'diagram',
        title: 'Architectural Data Flow Diagram',
        content: `Client Browser  ──[ HTTP Request + x-device-fingerprint ]──>  PEP Middleware
                                                              │
                                                ┌─────────────┴─────────────┐
                                                ▼                           ▼
                                          Context Engine              Redis 7 Cache
                                                │                           │
                                                ▼                           ▼
                                          PDP Risk Engine             Session State
                                                │
                                                ▼
                                          Decision Verdict
                                                │
                       ┌────────────────────────┼────────────────────────┐
                       ▼                        ▼                        ▼
                 [ Allow / Exec ]        [ Step-Up 403 ]          [ Containment ]
                       │                        │                        │
                       └────────────────────────┼────────────────────────┘
                                                ▼
                                         MySQL Audit Log
                                                │
                                                ▼
                                        Socket.IO Stream`
      }
    ]
  },

  // D. SECURITY
  'security-model': {
    id: 'security-model',
    title: 'Security Model',
    category: 'D. Security',
    lead: 'Cryptographic boundaries, trust domains, and fail-closed design.',
    sections: [
      {
        id: 'crypto-boundaries',
        title: 'Cryptographic Standards',
        content: `- Password Hashing: bcrypt with configured salt rounds (>= 10).
- User Tokens: HMAC-SHA256 JWT signed with high-entropy \`JWT_SECRET\`.
- Step-Up Elevation: Asymmetric NIST P-256 (ES256) ECDSA signatures kept separate from the JWT secret.
- Webhook Secrets: AES-256-GCM authenticated encryption at rest.
- Cancellation Tokens: Stored strictly as SHA-256 hashes.`
      }
    ]
  },

  'threat-model': {
    id: 'threat-model',
    title: 'Threat Model',
    category: 'D. Security',
    lead: 'The attack vectors ActionGuard is engineered to defend against.',
    sections: [
      {
        id: 'vectors',
        title: 'Mitigated Threat Classes',
        content: `1. Infostealer Malware: Extracts valid cookies from browser memory.
2. Credential Stuffing: Automated validation of leaked credentials.
3. Hostile Credential Cascades: Rapid-fire changes to email and password to lock out true owners.
4. Geographic Session Replay: Concurrent use of active session tokens across distant regions.`
      }
    ]
  },

  'account-takeover': {
    id: 'account-takeover',
    title: 'Account Takeover Scenarios',
    category: 'D. Security',
    lead: 'Simulating and interrupting hostile account takeovers.',
    sections: [
      {
        id: 'takeover-interruption',
        title: 'How Takeovers Are Interrupted',
        content: `When an attacker attempts to update the recovery email, the PEP flags the action sensitivity as HIGH. If baseline deviation or unfamiliar device context is present, the Policy Decision Point mandates REVERIFY. The verification OTP is sent to the original primary registration email, defeating the attack.`
      }
    ]
  },

  'device-location-risk': {
    id: 'device-location-risk',
    title: 'Device & Location Risk',
    category: 'D. Security',
    lead: 'Evaluating location velocity and hardware attributes.',
    sections: [
      {
        id: 'geo-evaluation',
        title: 'Geolocation Resolution',
        content: `ActionGuard integrates MaxMind GeoLite2 City database to map IP addresses to latitude/longitude coordinates and country codes. Unrecognized country codes elevate risk based on the user's historical login baseline.`
      }
    ]
  },

  'impossible-travel': {
    id: 'impossible-travel',
    title: 'Impossible Travel Detection',
    category: 'D. Security',
    lead: 'Haversine velocity calculation between consecutive requests.',
    sections: [
      {
        id: 'haversine-calc',
        title: 'Velocity Formula',
        content: `For consecutive requests from locations (lat1, lon1) at time t1 and (lat2, lon2) at time t2:
Velocity = HaversineDistance(loc1, loc2) / (t2 - t1).
If Velocity > 900 km/h, the \`IMPOSSIBLE_TRAVEL\` flag triggers an immediate +55 risk score.`
      }
    ]
  },

  'behavioral-bot-detection': {
    id: 'behavioral-bot-detection',
    title: 'Behavioral & Bot Detection',
    category: 'D. Security',
    lead: 'Detecting automated script bursts and abnormal diurnal timing.',
    sections: [
      {
        id: 'bot-heuristics',
        title: 'Interval Regularity',
        content: `Automated curl scripts and credential bots execute requests with sub-millisecond regular intervals. ActionGuard computes the coefficient of variation (CV) of request intervals. Low variance with high volume triggers automated bot detection heuristics.`
      }
    ]
  },

  'audit-logs': {
    id: 'audit-logs',
    title: 'Security Events & Audit Logs',
    category: 'D. Security',
    lead: 'Tamper-evident audit logging and telemetry dispatch.',
    sections: [
      {
        id: 'audit-schema',
        title: 'Event Schema',
        content: `Every decision logs a \`security_events\` record containing: \`user_id\`, \`session_id\`, \`action\`, \`ip_address\`, \`risk_score\`, \`decision\`, \`signals\`, and \`policy_version\`. Audit tables are append-only.`
      }
    ]
  },

  'privacy-protection': {
    id: 'privacy-protection',
    title: 'Privacy & Data Protection',
    category: 'D. Security',
    lead: 'Strict privacy boundaries between user-facing views and administrative telemetry.',
    sections: [
      {
        id: 'privacy-boundary',
        title: 'Privacy Guarantees',
        content: `Users see only their risk tier, coarse country/city location, and plain-language security explanations. Raw numerical scores, internal rule weights, and administrative forensic explanations are strictly compiled out of user session telemetry.`
      }
    ]
  },

  'limitations-assumptions': {
    id: 'limitations-assumptions',
    title: 'Security Limitations & Assumptions',
    category: 'D. Security',
    lead: 'Architectural scope and operational assumptions.',
    sections: [
      {
        id: 'disclaimer',
        title: 'Threat Boundary Scope',
        content: `ActionGuard detects and contains suspicious activity based on observable runtime telemetry. It does not claim guaranteed prevention against zero-day endpoint kernel rootkits or physical device theft where the local hardware is fully compromised.`
      }
    ]
  },

  // E. USER GUIDES
  'user-registration-login': {
    id: 'user-registration-login',
    title: 'User Registration & Login',
    category: 'E. User Guides',
    lead: 'How user accounts are created and authenticated.',
    sections: [
      {
        id: 'auth-walkthrough',
        title: 'Registration & Login Steps',
        content: `1. Visit \`/signup\` to register with an email and password (minimum 6 characters).
2. Visit \`/login\` to sign in. The frontend generates a hardware fingerprint and sends it with credentials.
3. On successful authentication, a JWT is stored in session storage.`
      }
    ]
  },

  'user-dashboard': {
    id: 'user-dashboard',
    title: 'User Dashboard',
    category: 'E. User Guides',
    lead: 'Navigating the user security overview and active sessions.',
    sections: [
      {
        id: 'dashboard-features',
        title: 'Portal Capabilities',
        content: `The User Dashboard at \`/app\` displays current session status, risk tier, enrolled trusted devices, and recent account activity with plain-language explanations.`
      }
    ]
  },

  'session-device-management': {
    id: 'session-device-management',
    title: 'Session & Device Management',
    category: 'E. User Guides',
    lead: 'Inspecting active sessions and revoking unfamiliar devices.',
    sections: [
      {
        id: 'device-management',
        title: 'Revoking Unrecognized Sessions',
        content: `From the Sessions tab in the user portal, users can review all active login tokens, their approximate location, and click 'Terminate' to immediately revoke any session in Redis.`
      }
    ]
  },

  'trusted-devices': {
    id: 'trusted-devices',
    title: 'Trusted Devices & Networks',
    category: 'E. User Guides',
    lead: 'Device enrollment and trust renewal.',
    sections: [
      {
        id: 'trust-renewal',
        title: 'Maintaining Enrolled Hardware',
        content: `Devices remain trusted for 30 days after verification. Logging in from a recognized device avoids step-up challenges on routine actions.`
      }
    ]
  },

  'understanding-decisions': {
    id: 'understanding-decisions',
    title: 'Understanding Security Decisions',
    category: 'E. User Guides',
    lead: 'How to read security prompts and understand risk explanations.',
    sections: [
      {
        id: 'user-explanations',
        title: 'Plain-Language Prompts',
        content: `When a step-up challenge appears, ActionGuard displays a clear reason, such as: "We noticed an unrecognized device or unfamiliar location. Please verify your identity."`
      }
    ]
  },

  'responding-reverification': {
    id: 'responding-reverification',
    title: 'Responding to Re-Verification',
    category: 'E. User Guides',
    lead: 'Entering OTP codes to authorize sensitive actions.',
    sections: [
      {
        id: 'otp-entry',
        title: 'Completing Step-Up Challenges',
        content: `Check your primary registration email for the 6-digit verification code. Enter the code in the prompt. You have 3 attempts before account lockout.`
      }
    ]
  },

  'account-security-actions': {
    id: 'account-security-actions',
    title: 'Account Security Actions',
    category: 'E. User Guides',
    lead: 'Cancelling delayed actions and locking down accounts.',
    sections: [
      {
        id: 'emergency-cancel',
        title: 'Aborting Delayed Actions',
        content: `If you receive an email regarding an action you did not initiate, click the emergency cancellation link in the notice to instantly abort the pending action and lock your account.`
      }
    ]
  },

  // F. ADMINISTRATOR GUIDES
  'admin-console-overview': {
    id: 'admin-console-overview',
    title: 'Admin Console Overview',
    category: 'F. Administrator Guides',
    lead: 'Operating the security monitoring center at /admin.',
    sections: [
      {
        id: 'console-layout',
        title: 'Operator Console Sections',
        content: `- Overview: Real-time 24h/7d KPIs, response tier distributions, and live event stream.
- Users: User list with risk tier badges, session counts, and search filter.
- User Detail: Forensic timeline, causal decision graph, and active sessions.
- Policies: Active policy matrix inspector and escalation rules.`
      }
    ]
  },

  'admin-auth-access': {
    id: 'admin-auth-access',
    title: 'Authentication & Access',
    category: 'F. Administrator Guides',
    lead: 'Logging in with single-use administrative keys.',
    sections: [
      {
        id: 'admin-key-login',
        title: 'Single-Use Key Protocol',
        content: `Administrators authenticate at \`/admin/login\` by entering the \`ACTIONGUARD_ADMIN_API_KEY\`. The key is transmitted once to generate an in-memory operator session and cleared immediately from DOM memory.`
      }
    ]
  },

  'user-session-monitoring': {
    id: 'user-session-monitoring',
    title: 'User & Session Monitoring',
    category: 'F. Administrator Guides',
    lead: 'Investigating high-risk users and active sessions.',
    sections: [
      {
        id: 'session-monitoring',
        title: 'Session Forensics',
        content: `Inspect bound device fingerprints, GeoLite2 IP coordinates, last active timestamps, and terminate compromised sessions with a single click.`
      }
    ]
  },

  'security-event-monitoring': {
    id: 'security-event-monitoring',
    title: 'Security Event Monitoring',
    category: 'F. Administrator Guides',
    lead: 'Real-time telemetry streaming and audit search.',
    sections: [
      {
        id: 'event-stream',
        title: 'Live WebSocket Telemetry',
        content: `The console connects to Socket.IO room \`admin\` to stream incoming security decisions with sub-second latency.`
      }
    ]
  },

  'policy-management': {
    id: 'policy-management',
    title: 'Policy Management',
    category: 'F. Administrator Guides',
    lead: 'Inspecting versioned policy matrices and escalation rules.',
    sections: [
      {
        id: 'policy-inspection',
        title: 'Viewing Active Policy',
        content: `Inspect the 4x4 Base Decision Matrix mapping action sensitivity (low, medium, high, critical) against risk levels (low, medium, high, critical) to authoritative response tiers.`
      }
    ]
  },

  'risk-configuration': {
    id: 'risk-configuration',
    title: 'Risk Configuration',
    category: 'F. Administrator Guides',
    lead: 'Tuning signal weights and anomaly thresholds.',
    sections: [
      {
        id: 'weight-tuning',
        title: 'Configurable Weights in policy.json',
        content: `Signal weights (base sensitivity, device novelty, impossible travel, burst timing) can be tuned in \`config/policy.json\` and reloaded dynamically.`
      }
    ]
  },

  'security-response': {
    id: 'security-response',
    title: 'Security Response & Investigation',
    category: 'F. Administrator Guides',
    lead: 'Incident containment and forensic causal graph analysis.',
    sections: [
      {
        id: 'causal-graph',
        title: 'Deterministic Causal Graph',
        content: `The User Detail view renders a 5-column causal graph connecting User -> Session -> Trigger Event -> Contributing Risk Signals -> Final Policy Verdict.`
      }
    ]
  },

  // G. DEVELOPER GUIDES
  'project-structure': {
    id: 'project-structure',
    title: 'Project Structure',
    category: 'G. Developer Guides',
    lead: 'Codebase organization across backend and frontend modules.',
    sections: [
      {
        id: 'directory-tree',
        title: 'Directory Tree',
        content: `\`\`\`
Action-guard/
├── config/              # policy.json and configuration files
├── docs/                # Authoritative architectural specifications
├── frontend/            # React 18 SPA (Vite + Tailwind CSS)
│   ├── src/
│   │   ├── components/  # Common, layout, landing, and dashboard components
│   │   ├── pages/       # Public and authenticated route views
│   │   ├── services/    # API client and authentication storage
│   │   └── tests/       # Vitest unit and integration suites
├── src/                 # Express backend application
│   ├── controllers/     # Route handlers
│   ├── database/        # Sequelize models, migrations, and seeds
│   ├── engine/          # Risk Engine and Policy Engine (PDP)
│   ├── middleware/      # PEP enforcement, auth, and rate limiters
│   ├── routes/          # API route definitions
│   └── services/        # GeoIP, fingerprint, and telemetry services
└── tests/               # Backend Jest integration test suites
\`\`\``
      }
    ]
  },

  'local-dev-setup': {
    id: 'local-dev-setup',
    title: 'Local Development Setup',
    category: 'G. Developer Guides',
    lead: 'Setting up a local development environment with hot-reloading.',
    sections: [
      {
        id: 'local-commands',
        title: 'Running in Development Mode',
        code: `# Terminal 1: Backend with file watching\nnpm run dev\n\n# Terminal 2: Frontend Vite dev server\nnpm --prefix frontend run dev`,
        language: 'bash'
      }
    ]
  },

  'running-with-docker': {
    id: 'running-with-docker',
    title: 'Running with Docker',
    category: 'G. Developer Guides',
    lead: 'Containerized development and testing environment.',
    sections: [
      {
        id: 'docker-compose-details',
        title: 'Docker Compose Topology',
        content: `The \`docker-compose.yml\` file provisions:
- \`mysql\`: MySQL 8.0 on container port 3306 (mapped to 3307 on host).
- \`redis\`: Redis 7 Alpine on port 6379.
- \`app\`: ActionGuard Express/React container on port 3000.`
      }
    ]
  },

  'migrations-seeding': {
    id: 'migrations-seeding',
    title: 'Database Migrations & Seeding',
    category: 'G. Developer Guides',
    lead: 'Managing MySQL schema migrations and initial test data.',
    sections: [
      {
        id: 'migration-scripts',
        title: 'Migration Commands',
        code: `# Run database migrations\nnode src/database/migrate.js\n\n# Seed baseline policy and test data\nnode src/database/seed.js`,
        language: 'bash'
      }
    ]
  },

  'frontend-development': {
    id: 'frontend-development',
    title: 'Frontend Development',
    category: 'G. Developer Guides',
    lead: 'Building components, managing state, and styling with Tailwind CSS.',
    sections: [
      {
        id: 'frontend-stack',
        title: 'Frontend Guidelines',
        content: `Uses Tailwind CSS with customized space navy tokens (\`space-950\`, \`space-900\`, \`space-850\`), React Router 7, and React Query for server state. All custom animations respect \`prefers-reduced-motion\`.`
      }
    ]
  },

  'backend-development': {
    id: 'backend-development',
    title: 'Backend Development',
    category: 'G. Developer Guides',
    lead: 'Writing Express routes, controllers, and middleware.',
    sections: [
      {
        id: 'backend-rules',
        title: 'PEP Middleware Convention',
        content: `Every sensitive endpoint wraps its controller with \`actionGuard({ actionName: '...', sensitivity: '...' })\` middleware to ensure automatic context collection and risk evaluation.`
      }
    ]
  },

  'testing-guide': {
    id: 'testing-guide',
    title: 'Testing',
    category: 'G. Developer Guides',
    lead: 'Running automated unit, integration, and security tests.',
    sections: [
      {
        id: 'test-commands',
        title: 'Running Test Suites',
        code: `# Run frontend Vitest test suite (86 tests)\nnpm --prefix frontend test -- --run\n\n# Run backend Jest integration test suite\nnpm test`,
        language: 'bash'
      }
    ]
  },

  'build-production': {
    id: 'build-production',
    title: 'Build & Production Deployment',
    category: 'G. Developer Guides',
    lead: 'Compiling production assets and running standalone servers.',
    sections: [
      {
        id: 'prod-build-cmd',
        title: 'Compiling Frontend Bundle',
        code: `# Compile Vite production bundle to frontend/dist\nnpm --prefix frontend run build\n\n# Start backend in production with SERVE_FRONTEND=true\nNODE_ENV=production SERVE_FRONTEND=true npm start`,
        language: 'bash'
      }
    ]
  },

  'troubleshooting': {
    id: 'troubleshooting',
    title: 'Troubleshooting',
    category: 'G. Developer Guides',
    lead: 'Common installation issues, port conflicts, and resolution steps.',
    sections: [
      {
        id: 'common-issues',
        title: 'Common Problems & Fixes',
        content: `- Port Conflict (3306/3307): In \`docker-compose.yml\`, MySQL is mapped to host port \`3307\` to avoid collisions with local MySQL instances.
- Missing JWT Secret: Ensure \`JWT_SECRET\` has at least 32 characters in \`.env\`.
- Redis Connection Refused: Verify Redis container is running via \`docker compose ps\`.`
      }
    ]
  },

  'contributing': {
    id: 'contributing',
    title: 'Contributing',
    category: 'G. Developer Guides',
    lead: 'Guidelines for submitting pull requests and community contributions.',
    sections: [
      {
        id: 'pr-guidelines',
        title: 'Contribution Principles',
        content: `Follow the development guidelines in \`AGENTS.md\`: write unit tests for security behavior, preserve PEP/PDP decoupling, never store credentials in plaintext, and adhere to fail-closed principles.`
      }
    ]
  },

  // H. API REFERENCE
  'api-overview': {
    id: 'api-overview',
    title: 'API Overview & Standards',
    category: 'H. API Reference',
    lead: 'General conventions, authentication envelopes, and security headers.',
    sections: [
      {
        id: 'conventions',
        title: 'REST API Standards',
        content: `All endpoints are prefixed with \`/api/v1\` (except health checks at \`/health\`). Endpoints expect JSON payloads with \`Content-Type: application/json\` and return standardized JSON envelopes.`
      },
      {
        id: 'auth-headers',
        title: 'Required Headers',
        content: `- \`Authorization: Bearer <jwt_token>\` for authenticated user requests.
- \`x-device-fingerprint: <32_char_hex_hash>\` for device binding and impossible travel evaluation.
- \`Authorization: Bearer <operator_token>\` for administrative operations.`
      }
    ]
  },

  'api-auth': {
    id: 'api-auth',
    title: 'Authentication Endpoints',
    category: 'H. API Reference',
    lead: 'User registration, login, and session logout contracts.',
    sections: [
      {
        id: 'signup-contract',
        title: 'POST /api/v1/auth/signup',
        content: `Register a new user account with validated email and high-entropy password.\n\n**Payload:**\n\`\`\`json\n{\n  "email": "user@example.com",\n  "password": "SecurePassword123!"\n}\n\`\`\`\n**Response (201 Created):**\n\`\`\`json\n{\n  "id": "c0a8012e-84b2-4d1e-9f37-123456789abc",\n  "email": "user@example.com"\n}\n\`\`\``
      },
      {
        id: 'login-contract',
        title: 'POST /api/v1/auth/login',
        content: `Authenticate user credentials and bind the session to client hardware.\n\n**Headers:** \`x-device-fingerprint: <hash>\`\n\n**Payload:**\n\`\`\`json\n{\n  "email": "user@example.com",\n  "password": "SecurePassword123!"\n}\n\`\`\`\n**Response (200 OK):**\n\`\`\`json\n{\n  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",\n  "user": {\n    "id": "c0a8012e-84b2-4d1e-9f37-123456789abc",\n    "email": "user@example.com"\n  }\n}\n\`\`\``
      },
      {
        id: 'logout-contract',
        title: 'POST /api/v1/auth/logout',
        content: `Invalidate active session JWT and evict corresponding session key from Redis.\n\n**Response (200 OK):**\n\`\`\`json\n{\n  "message": "Successfully logged out"\n}\n\`\`\``
      }
    ]
  },

  'api-users': {
    id: 'api-users',
    title: 'User Endpoints',
    category: 'H. API Reference',
    lead: 'User profile retrieval and sensitive account modifications.',
    sections: [
      {
        id: 'get-me',
        title: 'GET /api/v1/me',
        content: `Retrieve authenticated user profile, registration timestamps, and verification status.\n\n**Response (200 OK):**\n\`\`\`json\n{\n  "id": "c0a8012e-...",\n  "email": "user@example.com",\n  "created_at": "2026-10-15T08:30:00.000Z"\n}\n\`\`\``
      },
      {
        id: 'recovery-email-contract',
        title: 'POST /api/v1/account/recovery-email',
        content: `High-impact sensitive action. Gated by PEP: requires elevation if session risk is medium or higher.\n\n**Payload:**\n\`\`\`json\n{\n  "recovery_email": "new-recovery@example.com"\n}\n\`\`\`\n**Response (200 OK if elevated or 403 step_up_required).**`
      }
    ]
  },

  'api-sessions': {
    id: 'api-sessions',
    title: 'Session Endpoints',
    category: 'H. API Reference',
    lead: 'List and revoke active sessions and device bindings.',
    sections: [
      {
        id: 'list-sessions',
        title: 'GET /api/v1/me/sessions',
        content: `List active sessions for current user with bound device fingerprints, locations, and risk tiers.\n\n**Response (200 OK):**\n\`\`\`json\n[\n  {\n    "session_id": "sess_9f81a...",\n    "is_current": true,\n    "risk_tier": "low",\n    "created_at": "2026-10-30T09:00:00.000Z"\n  }\n]\n\`\`\``
      },
      {
        id: 'delete-session',
        title: 'DELETE /api/v1/me/sessions/:sessionId',
        content: `Explicitly revoke and terminate a specific active session in Redis.\n\n**Response (200 OK):**\n\`\`\`json\n{\n  "message": "Session terminated"\n}\n\`\`\``
      }
    ]
  },

  'api-security-events': {
    id: 'api-security-events',
    title: 'Security Event Endpoints',
    category: 'H. API Reference',
    lead: 'Querying tamper-evident security audit logs and causal graphs.',
    sections: [
      {
        id: 'events-list',
        title: 'GET /api/v1/admin/events',
        content: `Paginated security events with contributing risk signals, calculated scores, and policy decisions.\n\n**Query Parameters:** \`limit\`, \`offset\`, \`decision\`, \`user_id\`.`
      }
    ]
  },

  'api-admin': {
    id: 'api-admin',
    title: 'Admin Endpoints',
    category: 'H. API Reference',
    lead: 'Operator console authentication, overview KPIs, and user management.',
    sections: [
      {
        id: 'admin-login',
        title: 'POST /api/v1/admin/auth/login',
        content: `Authenticate operator console using the raw single-use administrative key.\n\n**Payload:**\n\`\`\`json\n{\n  "admin_key": "64_character_hex_key"\n}\n\`\`\`\n**Response (200 OK):**\n\`\`\`json\n{\n  "admin_token": "operator_jwt_token",\n  "expires_at": "2026-10-30T18:30:00.000Z"\n}\n\`\`\``
      },
      {
        id: 'admin-overview',
        title: 'GET /api/v1/admin/overview',
        content: `Global security overview containing 24h and 7d KPIs, risk tier distributions, and recent audit events.\n\n**Response (200 OK):**\n\`\`\`json\n{\n  "kpis": {\n    "total_events": 1420,\n    "step_up_count": 84,\n    "delayed_count": 12,\n    "blocked_count": 3\n  }\n}\n\`\`\``
      }
    ]
  },

  'api-examples': {
    id: 'api-examples',
    title: 'Request & Response Examples',
    category: 'H. API Reference',
    lead: 'Real-world curl request examples and JSON responses.',
    sections: [
      {
        id: 'curl-login',
        title: 'cURL: Authenticating with Device Fingerprint',
        code: `curl -X POST http://localhost:3000/api/v1/auth/login \\\n  -H "Content-Type: application/json" \\\n  -H "x-device-fingerprint: a1b2c3d4e5f60718293a4b5c6d7e8f90" \\\n  -d '{"email":"user@example.com","password":"SecurePassword123!"}'`,
        language: 'bash'
      },
      {
        id: 'curl-stepup',
        title: 'cURL: Submitting Step-Up Verification OTP',
        code: `curl -X POST http://localhost:3000/api/v1/sessions/sess_123/step-up/verify \\\n  -H "Content-Type: application/json" \\\n  -H "Authorization: Bearer <jwt_token>" \\\n  -d '{"challenge_id":"chal_83bd2a","otp":"123456"}'`,
        language: 'bash'
      }
    ]
  },

  'api-errors': {
    id: 'api-errors',
    title: 'Error Responses',
    category: 'H. API Reference',
    lead: 'Standardized HTTP status codes and error envelope schema.',
    sections: [
      {
        id: 'error-schema',
        title: 'Standard Error Format',
        content: `All error responses return JSON objects with \`error\` and optional \`code\`:\n\n\`\`\`json\n{\n  "error": "Step-up verification required to perform this action.",\n  "code": "STEP_UP_REQUIRED",\n  "challenge_id": "chal_83bd2a",\n  "expires_in_seconds": 300\n}\n\`\`\``
      },
      {
        id: 'status-codes',
        title: 'Status Code Conventions',
        content: `- 200 OK: Request succeeded.\n- 201 Created: Resource provisioned.\n- 400 Bad Request: Malformed payload or validation error.\n- 401 Unauthorized: Invalid credentials or expired session token (generic format blocks account enumeration).\n- 403 Forbidden: Action blocked or \`step_up_required\`.\n- 404 Not Found: Resource does not exist.\n- 429 Too Many Requests: Rate limit exceeded.\n- 500 Internal Server Error: Unexpected failure (fails closed).`
      }
    ]
  },

  'api-websocket': {
    id: 'api-websocket',
    title: 'WebSocket Events',
    category: 'H. API Reference',
    lead: 'Real-time telemetry events streamed over Socket.IO.',
    sections: [
      {
        id: 'ws-events',
        title: 'Socket.IO Channel Events',
        content: `- User Room (\`user:<userId>\`): Streams sanitized event notifications (\`session:tier_update\`, \`session:revoked\`).\n- Admin Room (\`admin\`): Streams full forensic telemetry (\`security:decision\`, \`security:containment\`, \`kpi:update\`).`
      }
    ]
  },

  'api-rate-limits': {
    id: 'api-rate-limits',
    title: 'Rate Limits & Security Considerations',
    category: 'H. API Reference',
    lead: 'Sliding-window rate limiters and operational hardening.',
    sections: [
      {
        id: 'rate-limits-table',
        title: 'Rate Limiting Rules',
        content: `- Login Endpoint: Maximum 10 attempts per minute per IP.\n- Step-Up Verification: Maximum 3 attempts per challenge; 3rd failure locks account for 15 minutes.\n- General API Endpoints: 120 requests per minute per authenticated session.`
      }
    ]
  }
};
