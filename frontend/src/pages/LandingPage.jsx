import React, { useRef } from 'react';
import { Link } from 'react-router-dom';
import { PublicNavbar } from '../components/public/PublicNavbar.jsx';
import { PublicFooter } from '../components/public/PublicFooter.jsx';
import { ShieldCanvas } from '../components/landing/ShieldCanvas.jsx';
import { PolicyInspector } from '../components/landing/PolicyInspector.jsx';
import { AmbientBackground } from '../components/common/AmbientBackground.jsx';
import { ExpandableCard } from '../components/common/ExpandableCard.jsx';
import { DECISION_ORDER, TIER_META } from '../components/landing/tiers.js';
import { useReducedMotion, usePointerGlow } from '../components/landing/hooks.js';

const GLASS = 'bg-space-850/70 backdrop-blur-md border border-white/10 hover:border-brand-luminous/40 rounded-2xl shadow-[0_4px_30px_-8px_rgba(37,141,235,0.2)] ring-1 ring-inset ring-white/5 transition-all duration-300';

const PRINCIPALS = ['Service Account \u00B7 prod-api', 'Machine Principal \u00B7 ci-runner', 'Enterprise Identity \u00B7 corp-idp', 'Client Token \u00B7 partner-gateway'];

const STEPS = [
  {
    n: 1,
    title: 'Collect signals',
    badge: 'Stage 01',
    summary: 'Device fingerprint (FingerprintJS), IP and GeoIP, impossible travel from Haversine distance over time, and request timing are attached to every sensitive action.',
    details: 'The Policy Enforcement Point (PEP) runs prior to route execution, gathering contextual telemetry without storing invasive personal credentials. Fingerprints identify hardware variance while GeoLite2 provides coarse coordinate positioning.',
    tags: ['Device Fingerprint', 'GeoLite2', 'Haversine Velocity', 'Telemetry Envelope']
  },
  {
    n: 2,
    title: 'Score the risk',
    badge: 'Stage 02',
    summary: 'An additive, explainable score compares the action with the user’s own baseline and recent sequence of actions.',
    details: 'The Risk Engine aggregates base sensitivity, device novelty, behavioral distance, and automation burst heuristics into a deterministic 0–100 integer. Every score component is auditable with zero black-box obscurity.',
    tags: ['Additive Heuristics', '30-Day Baselines', 'Deterministic Scoring']
  },
  {
    n: 3,
    title: 'Decide by policy',
    badge: 'Stage 03',
    summary: 'Versioned policy-as-code maps risk and action sensitivity to one of five ordered responses.',
    details: 'The Policy Decision Point (PDP) evaluates declarative JSON policy matrices. It compares action sensitivity against the computed risk tier and enforces escalation rules (e.g., impossible travel escalates to critical block).',
    tags: ['Policy-as-Code', 'NIST SP 800-207', 'Decoupled PDP']
  },
  {
    n: 4,
    title: 'Enforce and explain',
    badge: 'Stage 04',
    summary: 'Middleware enforces the decision before the route runs, then explains it to the user and to the administrator.',
    details: 'Enforcement middleware executes the verdict: quiet allow, priority audit logging, cryptographic step-up challenge, cooling-off quarantine, or instantaneous Redis session revocation.',
    tags: ['PEP Middleware', 'Proportional Friction', 'Auditable Explanations']
  }
];

const TERMS = [
  {
    name: 'Base Action Risk',
    value: 45,
    badge: 'Inherent Impact',
    summary: 'The inherent sensitivity of the action: low, medium, high or critical.',
    details: 'Actions that alter identity credentials (e.g. recovery email updates, password resets, API key generation) carry high base risk regardless of location.',
    color: '#258DEB'
  },
  {
    name: 'Context Risk',
    value: 53,
    badge: 'Environment Novelty',
    summary: 'Device, IP and GeoIP, and impossible travel (Haversine distance over elapsed time).',
    details: 'Calculates physical speed between consecutive requests. If velocity exceeds 900 km/h or requests arrive from an un-enrolled device, risk score spikes.',
    color: '#35C5E8'
  },
  {
    name: 'Sequence Risk',
    value: 35,
    badge: 'Cascade Detection',
    summary: 'Correlated recent actions in a time window, such as sign-in, recovery email change, then password change.',
    details: 'Rapid consecutive account modifications typical of hostile takeovers are flagged as hostile cascades and trigger preemptive friction.',
    color: '#F97316'
  },
  {
    name: 'Timing Risk',
    value: 20,
    badge: 'Anomaly Heuristics',
    summary: 'Unusual hours and automation bursts detected from request timing.',
    details: 'Identifies non-human micro-second request cadence and actions executed outside the user’s established diurnal baseline.',
    color: '#F59E0B'
  },
  {
    name: 'Baseline Deviation',
    value: 13,
    badge: 'Personal Variance',
    summary: 'Distance from the user’s own usual hours, devices and countries.',
    details: 'Compares runtime metadata against rolling 30-day behavioral baselines computed periodically via scheduled background jobs.',
    color: '#38BDF8'
  },
  {
    name: 'Verification Confidence',
    value: -20,
    badge: 'Negative Risk Credit',
    summary: 'A recent successful step-up reduces risk.',
    details: 'Completing an ES256-signed step-up challenge grants temporary elevation that offsets contextual risk for up to 300 seconds.',
    color: '#10B981'
  }
];

const PILLARS = [
  ['Never trust, always verify', 'Trust is continuous, granular, and revocable.'],
  ['Assume breach', 'Detect and contain risky account activity before it becomes irreversible.'],
  ['Least privilege per action', 'Elevation is scoped and expires; it never overrides delay or block.'],
  ['Explainable', 'Every decision traces to signals, rules and a policy version.'],
  ['Self-hosted and open source', 'Run it on your own infrastructure with three containers.']
];

function Section({ id, eyebrow, title, intro, children, tone = 'text-brand-cyan' }) {
  return (
    <section id={id} className="max-w-[1400px] mx-auto px-6 sm:px-8 lg:px-12 py-16 sm:py-20 scroll-mt-20">
      {eyebrow && <p className={`text-xs uppercase tracking-widest font-bold ${tone}`}>{eyebrow}</p>}
      <h2 className="mt-2 text-2xl sm:text-3xl lg:text-4xl font-extrabold tracking-tight text-white">{title}</h2>
      {intro && <p className="mt-3 max-w-3xl text-ink-300 text-base leading-relaxed">{intro}</p>}
      <div className="mt-8">{children}</div>
    </section>
  );
}

function Flow({ items, accent = '#258DEB' }) {
  return (
    <ol className="flex flex-col md:flex-row md:flex-wrap items-stretch gap-3">
      {items.map((item, i) => (
        <li key={item} className="flex items-center gap-3">
          <span className={`${GLASS} px-4 py-3 text-sm font-medium text-white`} style={{ borderColor: `${accent}66` }}>{item}</span>
          {i < items.length - 1 && <span aria-hidden="true" className="text-ink-500 hidden md:inline font-mono font-bold">&rarr;</span>}
        </li>
      ))}
    </ol>
  );
}

/**
 * Public landing page (/). Complete, multi-section showcase of the ActionGuard model.
 * All facts follow project documentation; the policy simulator is an
 * educational mirror of the server decision logic.
 */
export function LandingPage() {
  const heroRef = useRef(null);
  const reduced = useReducedMotion();
  usePointerGlow(heroRef, !reduced);
  const rise = (i) => (reduced ? undefined : { animationDelay: `${i * 0.12}s` });
  const riseClass = reduced ? '' : 'animate-ag-rise';

  return (
    <div className="min-h-screen bg-space-950 text-ink-100 flex flex-col" data-testid="landing-page">
      <PublicNavbar />

      <main id="top" className="flex-1">
        {/* 2. Hero */}
        <div
          ref={heroRef}
          className="relative overflow-hidden pt-6 pb-12 sm:pb-20 border-b border-white/10"
          style={{ '--mx': '50%', '--my': '30%' }}
        >
          <AmbientBackground variant="hero" />
          <div className="pointer-events-none absolute inset-0" aria-hidden="true" style={{ background: 'radial-gradient(400px circle at var(--mx) var(--my), rgba(37,141,235,0.14), transparent 70%)' }} />
          
          <section className="relative max-w-[1400px] mx-auto px-6 sm:px-8 lg:px-12 pt-10 sm:pt-16 pb-12 grid lg:grid-cols-12 gap-12 items-center">
            <div className={`lg:col-span-7 ${riseClass}`}>
              <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-white leading-[1.12]" data-testid="landing-title">
                Never trust a session. <br />
                <span className="bg-gradient-to-r from-brand-luminous via-brand-cyan to-white bg-clip-text text-transparent">
                  Verify every action.
                </span>
              </h1>
              <p className="mt-6 max-w-xl text-ink-300 text-base sm:text-lg leading-relaxed">
                ActionGuard re-evaluates each sensitive action against its current context, scores the risk, and responds in
                proportion: quiet for normal activity, firm when signals combine. Open source, self-hosted, and explainable.
              </p>
              <div className="mt-8 flex flex-wrap items-center gap-4">
                <Link
                  to="/login"
                  className="px-6 py-3 rounded-xl font-semibold text-white bg-gradient-to-r from-brand-blue via-brand-luminous to-brand-cyan shadow-lg shadow-brand-luminous/30 hover:brightness-110 transition-all hover:scale-[1.02]"
                  data-testid="cta-login"
                >
                  Sign in
                </Link>
                <Link
                  to="/platform"
                  className="px-6 py-3 rounded-xl font-medium border border-white/20 hover:border-brand-luminous/60 bg-white/[0.03] hover:bg-white/[0.08] text-white transition-all"
                >
                  Explore Platform
                </Link>
                <Link
                  to="/signup"
                  className="text-sm font-medium text-ink-300 hover:text-brand-cyan underline-offset-4 hover:underline transition-colors"
                  data-testid="cta-signup"
                >
                  Access provisioned by your organization &rarr;
                </Link>
              </div>
            </div>
            
            <div className="lg:col-span-5 flex justify-center">
              <div className="w-full max-w-md">
                <ShieldCanvas />
              </div>
            </div>
          </section>

          <div className="relative max-w-[1400px] mx-auto px-6 sm:px-8 lg:px-12 pb-6">
            <p className="text-xs uppercase tracking-widest text-ink-500 font-semibold font-mono">Principal types ActionGuard evaluates</p>
            <ul className="mt-3 flex flex-wrap gap-2.5">
              {PRINCIPALS.map((p) => (
                <li key={p} className="px-3.5 py-1.5 rounded-full border border-white/10 bg-space-850/80 text-xs font-mono text-ink-300 hover:border-brand-luminous/40 hover:text-brand-cyan transition-colors">
                  {p}
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* 3. Policy inspector & visual security experience */}
        <div className="relative border-b border-white/10">
          <Section id="inspector" eyebrow="Continuous Security Pipeline" title="See risk change in real time" intro="Session signals feed continuous risk analysis and policy decisions. Watch the pipeline adapt in real time and loop back to monitor.">
            <PolicyInspector />
          </Section>
        </div>

        {/* 4. How it works */}
        <div className="relative border-b border-white/10">
          <Section id="how" eyebrow="Pipeline Architecture" title="How ActionGuard works in 4 stages" intro="Incoming requests pass through a strictly decoupled inspection sequence prior to route handler execution. Click any stage to inspect complete technical specifications.">
            <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-5">
              {STEPS.map((s, i) => (
                <ExpandableCard
                  key={s.n}
                  title={s.title}
                  badge={s.badge}
                  badgeColor="bg-brand-luminous/15 text-brand-cyan border-brand-cyan/30"
                  summary={s.summary}
                  details={s.details}
                  tags={s.tags}
                  className={riseClass}
                  style={rise(i)}
                />
              ))}
            </div>
          </Section>
        </div>

        {/* 5. Five ordered responses */}
        <div className="relative border-b border-white/10">
          <Section id="tiers" eyebrow="Graded friction" title="Five ordered responses" intro="The stronger the combined signals, the firmer the response. The final decision is always the strictest of the base decision and every fired escalation rule.">
            <ul className="grid md:grid-cols-5 gap-4" data-testid="tier-list">
              {DECISION_ORDER.map((id, i) => {
                const t = TIER_META[id];
                return (
                  <li
                    key={id}
                    className={`${GLASS} p-5 flex flex-col justify-between`}
                    style={{ borderColor: `${t.color}66` }}
                  >
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-mono font-bold text-ink-500 uppercase">Level {i + 1}</span>
                        <span
                          className="h-2 w-2 rounded-full"
                          style={{ backgroundColor: t.color, boxShadow: `0 0 10px ${t.color}` }}
                          aria-hidden="true"
                        />
                      </div>
                      <p className="font-extrabold text-lg tracking-tight" style={{ color: t.color }}>{id}</p>
                      <p className="mt-2 text-xs text-ink-300 leading-relaxed">{t.behavior}</p>
                    </div>
                    <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-between text-[11px] font-mono text-ink-500">
                      <span>Response Tier</span>
                      <span className="font-bold text-white">Tier {i + 1}</span>
                    </div>
                  </li>
                );
              })}
            </ul>
            <div className="mt-8" aria-hidden="true">
              <div className="h-2.5 rounded-full overflow-hidden p-0.5 bg-space-850 border border-white/10" style={{ background: `linear-gradient(90deg, ${DECISION_ORDER.map((id) => TIER_META[id].color).join(',')})` }} />
              <div className="mt-2 flex justify-between text-xs font-mono text-ink-500">
                <span>&larr; Least friction (Allow)</span>
                <span>Most friction (Containment / Block) &rarr;</span>
              </div>
            </div>
          </Section>
        </div>

        {/* 6. Risk formula */}
        <div className="relative border-b border-white/10">
          <Section id="formula" eyebrow="Explainable Scoring" title="An additive, explainable risk score" intro="No black-box model. Every point of the score traces back to a named signal. A single weak signal does not prove compromise; risk rises meaningfully when signals combine. Click any signal card to examine detection mechanisms.">
            <div className={`${GLASS} p-6 font-mono text-sm sm:text-base text-brand-cyan border-brand-luminous/30`}>
              Risk Score = Base Action Risk + Context Risk + Sequence Risk + Timing Risk + Baseline Deviation &minus; Verification Confidence
            </div>
            <div className="mt-6 grid md:grid-cols-2 lg:grid-cols-3 gap-5">
              {TERMS.map((t, i) => (
                <ExpandableCard
                  key={t.name}
                  title={t.name}
                  badge={t.badge}
                  badgeColor="bg-brand-blue/30 text-white border-brand-luminous/40"
                  summary={t.summary}
                  details={t.details}
                  tags={[`Impact Weight: ${t.value > 0 ? `+${t.value}` : t.value}`, 'Additive Term']}
                  className={riseClass}
                  style={rise(i)}
                />
              ))}
            </div>
            <p className="mt-4 text-xs font-mono text-ink-500">Bar values are illustrative examples, not fixed weights. Weights live in versioned policy files.</p>
          </Section>
        </div>

        {/* 7. Step-up */}
        <div className="relative border-b border-white/10">
          <Section id="stepup" eyebrow="Reverify" title="Resilient step-up verification" tone="text-state-warn" intro="A 6-digit one-time code is sent to the immutable primary registration email, never the recovery email, so an attacker who changes the recovery address cannot receive it.">
            <Flow accent="#F59E0B" items={['OTP Challenge', 'Primary Email Dispatch', 'Verify (3 attempts max)', 'ES256 Ticket (60s)', 'Scoped Elevation (\u2264300s, max 900s)']} />
            <ul className="mt-6 grid md:grid-cols-3 gap-5 text-sm text-ink-300">
              <li className={`${GLASS} p-5`}>
                <strong className="text-white block mb-1">Challenge Expiry & Retries</strong>
                Challenges expire after 300 seconds and allow 3 attempts. Three consecutive failures trigger containment and a 15-minute account lock.
              </li>
              <li className={`${GLASS} p-5`}>
                <strong className="text-white block mb-1">Asymmetric P-256 Signatures</strong>
                Tickets are signed with an asymmetric NIST P-256 (ES256) key pair kept strictly separate from the user session JWT secret.
              </li>
              <li className={`${GLASS} p-5`}>
                <strong className="text-white block mb-1">Elevation Invariants</strong>
                Elevation satisfies <b className="text-state-warn">reverify</b> but can never bypass <b className="text-state-caution">delay</b> or <b className="text-state-alert">block</b>.
              </li>
            </ul>
          </Section>
        </div>

        {/* 8. Cooling-off */}
        <div className="relative border-b border-white/10">
          <Section id="cooling" eyebrow="Delay" title="Cooling-off for high-impact actions" tone="text-state-caution" intro="A delayed action is queued for a cooling-off window (default 300 seconds) with a single-use cancellation token, stored only as a SHA-256 hash.">
            <Flow accent="#F97316" items={['Action Delayed', 'Cancellation Window (300s)', 'Pre-execution Rechecks', 'Execute or Cancel']} />
            <p className="mt-6 max-w-3xl text-sm text-ink-300 leading-relaxed">
              Before a delayed action runs, Zero Trust rechecks confirm the account is not locked, the bound session is still active,
              the risk tier has not increased, and the policy does not now require block or delay.
            </p>
          </Section>
        </div>

        {/* 9. Containment */}
        <div className="relative border-b border-white/10">
          <Section id="containment" eyebrow="Block" title="Containment at critical risk" tone="text-state-alert" intro="A block at the critical tier invalidates the session immediately and applies a 15-minute protective lock to the account.">
            <div className="grid md:grid-cols-3 gap-5 text-sm text-ink-300">
              <div className={`${GLASS} p-5 border-state-alert/40`}>
                <strong className="text-white block mb-1">Zero Enumeration Leakage</strong>
                Wrong password, unknown email and a locked account all return the same generic 401, so attackers cannot enumerate accounts.
              </div>
              <div className={`${GLASS} p-5 border-state-alert/40`}>
                <strong className="text-white block mb-1">Trusted Device Recovery</strong>
                During a protective lock, valid credentials from an enrolled, recognized device can still authenticate.
              </div>
              <div className={`${GLASS} p-5 border-state-alert/40`}>
                <strong className="text-white block mb-1">Untrusted Hardware Block</strong>
                Unrecognized or missing device fingerprints are refused immediately until the 15-minute lock expires.
              </div>
            </div>
          </Section>
        </div>

        {/* 10. Architecture */}
        <div className="relative border-b border-white/10">
          <Section id="architecture" eyebrow="Architecture" title="Decision and enforcement, separated" intro="Following NIST SP 800-207, the Risk and Policy Engines only decide. Express middleware enforces.">
            <div className="flex flex-col gap-3 items-stretch">
              <Flow items={['Signal Collectors', 'Risk Engine (PDP)', 'Policy Engine (PDP)', 'PEP Middleware']} />
              <Flow accent="#258DEB" items={['Allow', 'Monitor', 'Reverify', 'Delay', 'Block \u2192 Containment (Critical)']} />
            </div>
            <div className="mt-6 grid md:grid-cols-3 gap-5 text-sm text-ink-300">
              <div className={`${GLASS} p-5`}><b className="text-white">MySQL 8.0</b> is the durable source of truth for events, decisions and audit.</div>
              <div className={`${GLASS} p-5`}><b className="text-white">Redis 7</b> holds fast session, sequence, and cooling-off state.</div>
              <div className={`${GLASS} p-5`}><b className="text-white">Socket.IO</b> streams tier-only updates to users and full telemetry to administrators.</div>
            </div>
            <div className="mt-6 rounded-2xl border border-brand-cyan/40 bg-brand-cyan/5 p-5 text-sm text-ink-300">
              <b className="text-brand-cyan">Privacy boundary.</b> Users see only their risk tier, coarse location and a plain-language explanation.
              Numeric scores, signal weights and administrator explanations are never sent to user sessions.
            </div>
          </Section>
        </div>

        {/* 11. Principles */}
        <div className="relative border-b border-white/10">
          <Section id="principles" eyebrow="Core Principles" title="What the platform stands on">
            <ul className="grid sm:grid-cols-2 lg:grid-cols-5 gap-4">
              {PILLARS.map(([title, text]) => (
                <li key={title} className={`${GLASS} p-5`}>
                  <p className="font-bold text-sm text-white">{title}</p>
                  <p className="mt-2 text-xs text-ink-300 leading-relaxed">{text}</p>
                </li>
              ))}
            </ul>
          </Section>
        </div>

        {/* 12. Final CTA */}
        <section className="max-w-[1400px] mx-auto px-6 sm:px-8 lg:px-12 py-20">
          <div className={`${GLASS} relative overflow-hidden p-10 sm:p-16 text-center border-brand-luminous/30`}>
            <div className="pointer-events-none absolute -bottom-24 left-1/2 -translate-x-1/2 h-80 w-80 rounded-full bg-brand-cyan/20 blur-[120px] animate-ag-glow" aria-hidden="true" />
            <h2 className="relative text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
              Verify every action. Contain every takeover.
            </h2>
            <p className="relative mt-3 max-w-xl mx-auto text-ink-300 text-sm sm:text-base">
              Deploy continuous Zero Trust authorization to your applications today with Docker Compose.
            </p>
            <div className="relative mt-8 flex flex-wrap justify-center items-center gap-4">
              <Link
                to="/login"
                className="px-6 py-3 rounded-xl font-semibold text-white bg-gradient-to-r from-brand-blue via-brand-luminous to-brand-cyan shadow-lg shadow-brand-luminous/30 hover:brightness-110 transition-all hover:scale-[1.02]"
                data-testid="final-cta-login"
              >
                Sign in
              </Link>
              <Link
                to="/signup"
                className="text-sm font-medium text-ink-300 hover:text-white hover:underline underline-offset-4 transition-colors"
                data-testid="final-cta-signup"
              >
                Access provisioned by your organization
              </Link>
              <Link
                to="/admin/login"
                className="text-sm font-semibold text-brand-cyan hover:underline underline-offset-4 transition-colors"
                data-testid="final-cta-admin"
              >
                Operator console &rarr;
              </Link>
            </div>
          </div>
        </section>
      </main>

      <PublicFooter />
    </div>
  );
}

export default LandingPage;
