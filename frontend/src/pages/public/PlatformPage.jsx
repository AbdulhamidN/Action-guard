import React from 'react';
import { Link } from 'react-router-dom';
import { PublicLayout } from '../../components/public/PublicLayout.jsx';
import { AmbientBackground } from '../../components/common/AmbientBackground.jsx';
import { ExpandableCard } from '../../components/common/ExpandableCard.jsx';

const PIPELINE_STAGES = [
  {
    step: '01',
    title: 'Request Interception (PEP)',
    badge: 'Policy Enforcement Point',
    badgeColor: 'bg-brand-luminous/15 text-brand-cyan border-brand-cyan/30',
    summary: 'Every sensitive incoming request is intercepted by Express middleware before reaching application business logic.',
    details: 'The Policy Enforcement Point (PEP) runs at the gateway layer. It extracts session JWTs, parses custom headers including `x-device-fingerprint`, and binds the request envelope to target action metadata. If basic envelope criteria fail, execution terminates prior to business handlers.',
    tags: ['Express Middleware', 'Header Extraction', 'Strict Envelope Validation', 'Pre-Route Guard']
  },
  {
    step: '02',
    title: 'Context & Signal Collection',
    badge: 'Context Collectors',
    badgeColor: 'bg-brand-blue/30 text-brand-cyan border-brand-luminous/40',
    summary: 'The platform gathers device fingerprints (FingerprintJS), IP and geolocation (MaxMind GeoLite2), timestamps, and request sequences.',
    details: 'Context collectors extract client characteristics without collecting invasive personal identity data. Coarse location coordinates, IP subnet groupings, and high-precision microsecond timestamps are assembled into a normalized runtime context envelope.',
    tags: ['FingerprintJS Pro/Open', 'GeoLite2 City Database', 'Microsecond Timestamps', 'Privacy-Preserving']
  },
  {
    step: '03',
    title: 'Sequence & Baseline Analysis',
    badge: 'Pattern Analyzers',
    badgeColor: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
    summary: 'Activity is correlated against the user’s rolling 30-day behavioral baseline and checked for rapid-fire credential modification cascades.',
    details: 'The Sequence Analyzer inspects the sliding 15-minute action window in Redis to detect aggressive credential cascade attacks (e.g. login -> recovery email update -> password change). The Baseline Analyzer queries MySQL baselines to detect geographic or nocturnal deviations.',
    tags: ['Redis Sliding Window', 'Hostile Cascade Interruption', '30-Day Baselines', 'Personal Variance']
  },
  {
    step: '04',
    title: 'Risk Scoring & Policy Evaluation',
    badge: 'Policy Decision Point (PDP)',
    badgeColor: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    summary: 'An explainable 0–100 risk score is computed and evaluated against versioned JSON policy matrices to produce an authoritative decision.',
    details: 'Following NIST SP 800-207, the Risk Engine deterministically sums additive signal components into a 0–100 score. The Policy Loader evaluates the active policy version, checks the Base Decision Matrix, and applies escalation rules to output one of five ordered tiers.',
    tags: ['NIST SP 800-207 PDP', 'Additive Scoring', 'Versioned JSON Policies', 'Escalation Rules']
  },
  {
    step: '05',
    title: 'Adaptive Enforcement',
    badge: 'Proportional Response',
    badgeColor: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    summary: 'The PEP enforces the exact decision: allowing normal traffic, logging monitor events, issuing step-up challenges, delaying high-impact actions, or containing compromised sessions.',
    details: 'Enforcement applies proportional friction. If Step-Up is required, an HTTP 403 step_up_required challenge is issued. If Delay is demanded, the action is enqueued for a 300s cooling-off period. If Block is triggered, the session is revoked and the account protected.',
    tags: ['Proportional Friction', 'HTTP 403 Step-Up', 'Cooling-Off Holding', 'Session Eviction']
  },
  {
    step: '06',
    title: 'Audit & Telemetry Broadcasting',
    badge: 'Audit & Telemetry',
    badgeColor: 'bg-brand-cyan/15 text-brand-cyan border-brand-cyan/40',
    summary: 'Decisions are recorded in durable MySQL audit tables, active session states are updated in Redis, and real-time telemetry is streamed over WebSockets.',
    details: 'Immutable security events are logged with causal signal explanations and policy hashes. Telemetry is streamed in real time via Socket.IO: privacy-sanitized tier summaries to users, and comprehensive forensic telemetry to operator consoles.',
    tags: ['MySQL Audit Trail', 'Redis Active State', 'Socket.IO Streaming', 'HMAC SIEM Webhooks']
  }
];

const CAPABILITIES = [
  {
    id: 'device-context',
    title: 'Device & Session Context',
    badge: 'Device Lifecycle',
    badgeColor: 'bg-brand-luminous/15 text-brand-cyan border-brand-cyan/30',
    tag: 'Authentication & Session Binding',
    summary: 'Identifies unfamiliar devices using browser and client attributes. Tracks session activity and binds sessions to device fingerprints.',
    details: 'Maintains an auditable 30-day device registry per user. First-seen devices incur contextual risk penalties until verified. Users can inspect enrolled hardware and remotely revoke compromised devices directly from their user portal.',
    tags: ['Fingerprint Affinity', '30-Day Device Registry', 'Remote Revocation', 'Session Binding']
  },
  {
    id: 'impossible-travel',
    title: 'Impossible Travel Detection',
    badge: 'Location Intelligence',
    badgeColor: 'bg-brand-blue/30 text-brand-cyan border-brand-luminous/40',
    tag: 'Location Intelligence',
    summary: 'Calculates the physical distance and elapsed time between consecutive actions using the Haversine formula and GeoLite2 databases.',
    details: 'When consecutive requests arrive from geographically separated IP coordinates, ActionGuard computes great-circle distance divided by elapsed seconds. If calculated velocity exceeds 900 km/h, the impossible travel flag triggers an immediate +55 risk spike.',
    tags: ['Haversine Formula', 'Great-Circle Velocity', 'Threshold: 900 km/h', 'Session Hijacking Defense']
  },
  {
    id: 'behavioral-signals',
    title: 'Behavioral & Automation Signals',
    badge: 'Heuristics & Baselines',
    badgeColor: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
    tag: 'Heuristics & Baselines',
    summary: 'Detects bot bursts and rapid automation by analyzing request interval regularity and coefficient of variation.',
    details: 'Differentiates automated scripts from natural human interaction by analyzing the coefficient of variation (CV) in request timing intervals. Baselines update via nightly cron jobs calculating personal hourly distributions and typical country codes.',
    tags: ['Burst Detection', 'Coefficient of Variation', 'Rolling 30-Day Cron', 'Nocturnal Anomaly']
  },
  {
    id: 'step-up',
    title: 'Step-Up Identity Re-verification',
    badge: 'Dynamic Challenge',
    badgeColor: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    tag: 'Dynamic Verification',
    summary: 'Generates single-use 6-digit cryptographic OTPs dispatched exclusively to the primary registration email.',
    details: 'Challenges expire after 300 seconds and permit 3 attempts before account lockout. Successfully verified challenges generate a cryptographic NIST P-256 (ES256) signed elevation ticket granting temporary privilege (default 300s, max 900s).',
    tags: ['6-Digit OTP', 'Primary Email Dispatch', 'ES256 Asymmetric Signature', '3-Attempt Lockout']
  },
  {
    id: 'cooling-off',
    title: 'Cooling-Off Delays',
    badge: 'Holding Window',
    badgeColor: 'bg-brand-luminous/20 text-white border-brand-luminous/50',
    tag: 'High-Impact Containment',
    summary: 'Places irreversible, high-impact actions into a quarantine holding window (default 300s) with a single-use SHA-256 cancellation token.',
    details: 'Irreversible sensitive operations (e.g., account deletion, financial transfers) are placed in a delayed state. The legitimate owner receives a notification and cancellation URL. Before execution, the system re-verifies session validity and risk tiers.',
    tags: ['300s Quarantine Window', 'SHA-256 Token Hash', 'Pre-Execution Re-verification', 'Immediate Abort URL']
  },
  {
    id: 'containment',
    title: 'Protective Account Containment',
    badge: 'Threat Neutralization',
    badgeColor: 'bg-red-500/15 text-red-300 border-red-500/30',
    tag: 'Threat Neutralization',
    summary: 'When critical risk or repeated verification failures occur, ActionGuard instantly invalidates active Redis sessions and locks the account for 15 minutes.',
    details: 'Protective containment isolates compromised sessions without leaking account existence. Standardized 401 Unauthorized responses prevent username enumeration. Legitimate account owners with enrolled devices retain recovery access.',
    tags: ['15-Minute Lockout', 'Redis Session Eviction', 'Anti-Enumeration 401', 'Trusted Device Recovery']
  }
];

const ARCH_COMPONENTS = [
  {
    name: 'Frontend Application',
    tech: 'React 18 · Vite · Tailwind CSS',
    role: 'Provides user security portal, admin monitoring console, live telemetry visualizer, and interactive policy simulators.'
  },
  {
    name: 'PEP Middleware & API Gateway',
    tech: 'Node.js · Express 4 · Helmet',
    role: 'Policy Enforcement Point. Intercepts requests, validates envelopes, rate-limits endpoints, and enforces PDP security verdicts.'
  },
  {
    name: 'Policy Decision Point (PDP)',
    tech: 'Risk Engine · Policy Loader',
    role: 'Independent decision layer. Computes deterministic scores from collected signals and evaluates versioned JSON policy matrices.'
  },
  {
    name: 'Durable Data Storage',
    tech: 'MySQL 8.0 · Sequelize ORM',
    role: 'Immutable source of truth for security audit events, user accounts, trusted devices, behavioral baselines, and webhook deliveries.'
  },
  {
    name: 'Fast In-Memory Cache & State',
    tech: 'Redis 7 · ioredis',
    role: 'Manages low-latency active sessions, atomic rate-limiting counters, sequence groupings, step-up challenges, and elevation tokens.'
  },
  {
    name: 'Real-Time Streaming & Webhooks',
    tech: 'Socket.IO · HMAC-SHA256 Delivery',
    role: 'Streams sanitized telemetry to user portals and full audit data to admin consoles. Dispatches signed webhooks to external SIEMs.'
  }
];

export function PlatformPage() {
  return (
    <PublicLayout>
      {/* Platform Hero */}
      <div className="relative overflow-hidden pt-12 pb-16 lg:pt-20 lg:pb-24 border-b border-white/10">
        <AmbientBackground variant="hero" />
        <div className="max-w-[1400px] mx-auto px-6 sm:px-8 lg:px-12 relative">
          <div className="max-w-3xl">
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-semibold bg-brand-luminous/15 border border-brand-luminous/35 text-brand-cyan mb-5 shadow-[0_0_20px_rgba(37,141,235,0.25)]">
              <span className="w-2 h-2 rounded-full bg-brand-cyan animate-ping" />
              Platform Architecture & Capabilities
            </div>
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-white leading-[1.12]">
              A Decoupled Zero Trust Engine for Continuous Action Security
            </h1>
            <p className="mt-6 text-lg text-ink-300 leading-relaxed">
              ActionGuard separates security decisions from application business logic. Following NIST SP 800-207 guidelines,
              our platform dynamically scores session context and enforces proportional controls across every sensitive interaction.
            </p>
            <div className="mt-8 flex flex-wrap gap-4">
              <a
                href="#how-it-works"
                className="px-6 py-3 rounded-xl text-sm font-semibold text-white bg-gradient-to-r from-brand-blue via-brand-luminous to-brand-cyan shadow-lg shadow-brand-luminous/30 hover:brightness-110 transition-all hover:scale-[1.02]"
              >
                Explore How It Works
              </a>
              <a
                href="#architecture"
                className="px-6 py-3 rounded-xl text-sm font-medium border border-white/20 hover:border-brand-luminous/50 bg-white/[0.03] hover:bg-white/[0.08] text-white transition-all"
              >
                View System Topology
              </a>
              <Link
                to="/docs#installation"
                className="px-6 py-3 rounded-xl text-sm font-medium bg-brand-luminous/10 border border-brand-luminous/30 hover:bg-brand-luminous/20 text-brand-cyan transition-colors"
              >
                Docker Quickstart &rarr;
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* 1. Overview Section */}
      <section id="overview" className="max-w-[1400px] mx-auto px-6 sm:px-8 lg:px-12 py-20 scroll-mt-20 border-b border-white/10">
        <div className="grid lg:grid-cols-12 gap-12 items-center">
          <div className="lg:col-span-6 space-y-6">
            <span className="text-xs uppercase tracking-widest text-brand-cyan font-bold font-mono">01 / Security Philosophy</span>
            <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
              Why Login-Time Authentication Is No Longer Enough
            </h2>
            <p className="text-ink-300 text-base leading-relaxed">
              Modern cyberattacks—including session hijacking, infostealer malware, and credential stuffing—routinely bypass login perimeters.
              Once an attacker obtains a valid session cookie, traditional applications grant unconditional access until token expiry.
            </p>
            <p className="text-ink-300 text-base leading-relaxed">
              ActionGuard operates on the Zero Trust principle of <strong className="text-white">"Never Trust, Always Verify."</strong> Instead of
              assuming an authenticated session is permanently safe, ActionGuard evaluates the security context of each sensitive action:
            </p>
            <ul className="space-y-3 text-sm text-ink-100">
              <li className="flex items-start gap-3">
                <span className="text-brand-cyan font-bold text-base">&check;</span>
                <span><strong className="text-white">Continuous & Granular:</strong> Trust decays over time and is re-verified per action sensitivity.</span>
              </li>
              <li className="flex items-start gap-3">
                <span className="text-brand-cyan font-bold text-base">&check;</span>
                <span><strong className="text-white">Assume Breach:</strong> Preemptively contains suspicious lateral movement before irreversible changes take effect.</span>
              </li>
              <li className="flex items-start gap-3">
                <span className="text-brand-cyan font-bold text-base">&check;</span>
                <span><strong className="text-white">Proportional Response:</strong> Avoids indiscriminate account lockouts by offering graded friction (Step-Up or Cooling-off).</span>
              </li>
              <li className="flex items-start gap-3">
                <span className="text-brand-cyan font-bold text-base">&check;</span>
                <span><strong className="text-white">100% Explainable:</strong> Every decision traces back to transparent, named signals and versioned policy rules.</span>
              </li>
            </ul>
          </div>

          <div className="lg:col-span-6 bg-space-850/90 border border-white/10 hover:border-brand-luminous/40 rounded-2xl p-6 sm:p-8 shadow-2xl relative overflow-hidden transition-colors">
            <div className="absolute top-0 right-0 w-40 h-40 bg-brand-cyan/15 rounded-full blur-3xl pointer-events-none" />
            <h3 className="text-lg font-bold text-white mb-5 flex items-center justify-between">
              <span>Point-in-Time Auth vs. Continuous Zero Trust</span>
              <span className="text-xs font-mono px-2.5 py-1 rounded bg-brand-luminous/20 text-brand-cyan border border-brand-cyan/30">NIST SP 800-207</span>
            </h3>

            <div className="space-y-4 text-xs sm:text-sm">
              <div className="p-4 rounded-xl bg-space-900/90 border border-red-500/30">
                <div className="font-semibold text-red-400 mb-1.5 flex items-center gap-2">
                  <span className="font-mono text-base">&times;</span> Traditional Perimeter Model
                </div>
                <p className="text-ink-300 leading-relaxed">
                  User passes MFA at 09:00. Session token is valid for 7 days. At 14:30, infostealer malware extracts cookies; attacker in a different continent changes recovery email and drains funds without friction.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-space-900/90 border border-emerald-500/40">
                <div className="font-semibold text-emerald-400 mb-1.5 flex items-center gap-2">
                  <span className="font-mono text-base">&check;</span> ActionGuard Continuous Protection
                </div>
                <p className="text-ink-300 leading-relaxed">
                  User passes MFA at 09:00. At 14:30, the request arrives from an unrecognized device and distant IP. The PEP intercepts the recovery email update, detects an Impossible Travel anomaly, evaluates risk as HIGH, and blocks the action pending primary-email OTP verification.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 2. How It Works Section */}
      <section id="how-it-works" className="max-w-[1400px] mx-auto px-6 sm:px-8 lg:px-12 py-20 scroll-mt-20 border-b border-white/10">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <span className="text-xs uppercase tracking-widest text-brand-cyan font-bold font-mono">02 / Pipeline Architecture</span>
          <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white mt-2">
            The 6-Stage Security Decision & Enforcement Flow
          </h2>
          <p className="mt-4 text-ink-300 leading-relaxed text-base">
            Requests pass through an orderly evaluation pipeline ensuring fast in-memory execution, strict isolation, and auditable outcomes. Click any card to inspect implementation details.
          </p>
        </div>

        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {PIPELINE_STAGES.map((stage) => (
            <ExpandableCard
              key={stage.step}
              title={stage.title}
              badge={`Stage ${stage.step} · ${stage.badge}`}
              badgeColor={stage.badgeColor}
              summary={stage.summary}
              details={stage.details}
              tags={stage.tags}
            />
          ))}
        </div>
      </section>

      {/* 3. Capabilities Section */}
      <section id="capabilities" className="max-w-[1400px] mx-auto px-6 sm:px-8 lg:px-12 py-20 scroll-mt-20 border-b border-white/10">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <span className="text-xs uppercase tracking-widest text-brand-cyan font-bold font-mono">03 / Platform Capabilities</span>
          <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white mt-2">
            Modular Signals, Scoring, and Containment Tools
          </h2>
          <p className="mt-4 text-ink-300 leading-relaxed text-base">
            Engineered for high accuracy without black-box opacity. Signals combine deterministically to produce actionable security outcomes. Click any capability to view operational parameters.
          </p>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {CAPABILITIES.map((cap) => (
            <ExpandableCard
              key={cap.id}
              title={cap.title}
              badge={cap.badge}
              badgeColor={cap.badgeColor}
              summary={cap.summary}
              details={cap.details}
              tags={cap.tags}
            />
          ))}
        </div>
      </section>

      {/* 4. Architecture Section */}
      <section id="architecture" className="max-w-[1400px] mx-auto px-6 sm:px-8 lg:px-12 py-20 scroll-mt-20">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <span className="text-xs uppercase tracking-widest text-brand-cyan font-bold font-mono">04 / System Topology</span>
          <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white mt-2">
            PDP & PEP Separation Across Modular Components
          </h2>
          <p className="mt-4 text-ink-300 leading-relaxed text-base">
            By keeping policy decisions strictly independent of enforcement, ActionGuard integrates cleanly into existing Node.js architectures
            without intrusive rewrites or single points of failure.
          </p>
        </div>

        {/* Visual Component Diagram Card */}
        <div className="mb-12 p-6 sm:p-10 rounded-2xl bg-space-850/90 border border-white/10 shadow-2xl relative overflow-hidden">
          <AmbientBackground variant="subtle" />
          <h3 className="relative text-sm font-bold text-white uppercase tracking-wider text-center mb-8 font-mono">
            Component Interaction & Data Flow
          </h3>

          <div className="relative grid sm:grid-cols-3 gap-4 text-center text-xs">
            <div className="p-5 rounded-xl bg-space-900/90 border border-brand-luminous/40 flex flex-col items-center justify-center shadow-md">
              <span className="font-bold text-brand-cyan text-sm mb-1">Incoming Client Request</span>
              <span className="text-ink-300">Session JWT + Device Hash + Action Payload</span>
            </div>
            <div className="p-5 rounded-xl bg-space-900/90 border border-brand-luminous/60 flex flex-col items-center justify-center shadow-md">
              <span className="font-bold text-white text-sm mb-1">Policy Enforcement Point (PEP)</span>
              <span className="text-ink-300">Express Middleware · Rate Limiters · Envelope Guard</span>
            </div>
            <div className="p-5 rounded-xl bg-space-900/90 border border-amber-500/40 flex flex-col items-center justify-center shadow-md">
              <span className="font-bold text-amber-400 text-sm mb-1">Policy Decision Point (PDP)</span>
              <span className="text-ink-300">Risk Engine · Signal Aggregator · Policy Matrix</span>
            </div>
          </div>

          <div className="relative my-5 flex justify-center text-brand-cyan text-xs font-mono font-bold">
            <span>&darr; State Synchronization & Durable Audit &darr;</span>
          </div>

          <div className="relative grid sm:grid-cols-2 gap-4 text-center text-xs">
            <div className="p-5 rounded-xl bg-space-900/80 border border-white/10">
              <span className="font-bold text-white text-sm block mb-1">Redis 7 (In-Memory State)</span>
              <span className="text-ink-300">Active sessions, sequence caches, challenge OTPs, rate-limit windows</span>
            </div>
            <div className="p-5 rounded-xl bg-space-900/80 border border-white/10">
              <span className="font-bold text-white text-sm block mb-1">MySQL 8.0 (Durable Records)</span>
              <span className="text-ink-300">Audit events, risk assessments, user profiles, device registry, webhooks</span>
            </div>
          </div>
        </div>

        {/* Detailed Component Breakdown */}
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {ARCH_COMPONENTS.map((comp) => (
            <div key={comp.name} className="p-6 rounded-2xl bg-space-850/60 border border-white/10 hover:border-brand-luminous/40 transition-colors">
              <span className="text-xs font-mono text-brand-cyan font-semibold">{comp.tech}</span>
              <h4 className="text-base font-bold text-white mt-1.5 mb-2">{comp.name}</h4>
              <p className="text-xs text-ink-300 leading-relaxed">{comp.role}</p>
            </div>
          ))}
        </div>

        {/* Platform Bottom CTA */}
        <div className="mt-16 p-8 sm:p-10 rounded-2xl bg-gradient-to-r from-space-850 via-space-800 to-space-850 border border-brand-luminous/30 text-center flex flex-col sm:flex-row items-center justify-between gap-6 shadow-xl">
          <div className="text-left">
            <h3 className="text-xl font-bold text-white">Ready to examine the API contract?</h3>
            <p className="text-sm text-ink-300 mt-1">Review the complete REST specifications and installation guide.</p>
          </div>
          <div className="flex items-center gap-3">
            <Link
              to="/docs"
              className="px-6 py-3 rounded-xl text-sm font-semibold text-white bg-gradient-to-r from-brand-blue via-brand-luminous to-brand-cyan hover:brightness-110 transition-all shadow-md hover:scale-[1.02]"
            >
              Explore Documentation
            </Link>
            <Link
              to="/solutions"
              className="px-6 py-3 rounded-xl text-sm font-medium border border-white/20 hover:border-brand-luminous/50 bg-white/[0.03] hover:bg-white/[0.08] text-white transition-colors"
            >
              View Solutions &rarr;
            </Link>
          </div>
        </div>
      </section>
    </PublicLayout>
  );
}

export default PlatformPage;
