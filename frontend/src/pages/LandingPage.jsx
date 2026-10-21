import React, { useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { ShieldCanvas } from '../components/landing/ShieldCanvas.jsx';
import { PolicyInspector } from '../components/landing/PolicyInspector.jsx';
import { DECISION_ORDER, TIER_META } from '../components/landing/tiers.js';
import { useReducedMotion, usePointerGlow } from '../components/landing/hooks.js';

const NAV = [
  ['Architecture', '#architecture'],
  ['How it works', '#how']
];

const GLASS = 'bg-white/[0.04] backdrop-blur-md border border-white/10 rounded-2xl shadow-[0_0_40px_-12px_rgba(99,102,241,0.25)] ring-1 ring-inset ring-white/5';

const PRINCIPALS = ['Service Account \u00B7 prod-api', 'Machine Principal \u00B7 ci-runner', 'Enterprise Identity \u00B7 corp-idp', 'Client Token \u00B7 partner-gateway'];

const STEPS = [
  { n: 1, title: 'Collect signals', text: 'Device fingerprint (FingerprintJS), IP and GeoIP, impossible travel from Haversine distance over time, and request timing are attached to every sensitive action.' },
  { n: 2, title: 'Score the risk', text: 'An additive, explainable score compares the action with the user\u2019s own baseline and recent sequence of actions.' },
  { n: 3, title: 'Decide by policy', text: 'Versioned policy-as-code maps risk and action sensitivity to one of five ordered responses.' },
  { n: 4, title: 'Enforce and explain', text: 'Middleware enforces the decision before the route runs, then explains it to the user and to the administrator.' }
];

const TERMS = [
  { name: 'Base Action Risk', value: 45, text: 'The inherent sensitivity of the action: low, medium, high or critical.', color: '#6366F1' },
  { name: 'Context Risk', value: 53, text: 'Device, IP and GeoIP, and impossible travel (Haversine distance over elapsed time).', color: '#06B6D4' },
  { name: 'Sequence Risk', value: 35, text: 'Correlated recent actions in a time window, such as sign-in, recovery email change, then password change.', color: '#F97316' },
  { name: 'Timing Risk', value: 20, text: 'Unusual hours and automation bursts detected from request timing.', color: '#F59E0B' },
  { name: 'Baseline Deviation', value: 13, text: 'Distance from the user\u2019s own usual hours, devices and countries.', color: '#38BDF8' },
  { name: 'Verification Confidence', value: -20, text: 'A recent successful step-up reduces risk.', color: '#10B981' }
];

const PILLARS = [
  ['Never trust, always verify', 'Trust is continuous, granular, and revocable.'],
  ['Assume breach', 'Detect and contain risky account activity before it becomes irreversible.'],
  ['Least privilege per action', 'Elevation is scoped and expires; it never overrides delay or block.'],
  ['Explainable', 'Every decision traces to signals, rules and a policy version.'],
  ['Self-hosted and open source', 'Run it on your own infrastructure with three containers.']
];

function Section({ id, eyebrow, title, intro, children, tone = 'text-neon-cyan' }) {
  return (
    <section id={id} className="max-w-6xl mx-auto px-6 py-16 scroll-mt-20">
      {eyebrow && <p className={`text-xs uppercase tracking-widest ${tone}`}>{eyebrow}</p>}
      <h2 className="mt-2 text-2xl sm:text-3xl font-extrabold tracking-tight">{title}</h2>
      {intro && <p className="mt-3 max-w-3xl text-ink-300">{intro}</p>}
      <div className="mt-8">{children}</div>
    </section>
  );
}

function Flow({ items, accent = '#06B6D4' }) {
  return (
    <ol className="flex flex-col md:flex-row md:flex-wrap items-stretch gap-3">
      {items.map((item, i) => (
        <li key={item} className="flex items-center gap-3">
          <span className={`${GLASS} px-4 py-3 text-sm`} style={{ borderColor: `${accent}55` }}>{item}</span>
          {i < items.length - 1 && <span aria-hidden="true" className="text-ink-500 hidden md:inline">&rarr;</span>}
        </li>
      ))}
    </ol>
  );
}

/**
 * Public landing page (/). Long, multi-section showcase of the ActionGuard model.
 * All facts follow the project documentation; the policy simulator is an
 * educational mirror of the server decision logic, not live traffic.
 */
export function LandingPage() {
  const [menuOpen, setMenuOpen] = useState(false);
  const heroRef = useRef(null);
  const reduced = useReducedMotion();
  usePointerGlow(heroRef, !reduced);
  const rise = (i) => (reduced ? undefined : { animationDelay: `${i * 0.12}s` });
  const riseClass = reduced ? '' : 'animate-ag-rise';

  return (
    <div className="min-h-screen bg-space-900 text-ink-100 overflow-x-hidden" data-testid="landing-page">
      <header className="sticky top-0 z-50 backdrop-blur-md bg-space-900/70 border-b border-white/10">
        <div className="max-w-6xl mx-auto px-6 py-3 flex items-center justify-between gap-4">
          <a href="#top" className="flex items-center gap-2 font-semibold tracking-tight">
            <span className="h-8 w-8 rounded-lg bg-neon-indigo flex items-center justify-center text-sm font-bold" aria-hidden="true">AG</span>
            ActionGuard
          </a>
          <nav className="hidden md:flex items-center gap-5 text-sm text-ink-300" aria-label="Primary">
            {NAV.map(([label, href]) => <a key={label} href={href} className="hover:text-white">{label}</a>)}
            <Link to="/admin/login" className="hover:text-white" data-testid="nav-admin">Admin</Link>
            <Link to="/login" className="px-3 py-1.5 rounded-lg border border-white/15 hover:border-white/40 text-ink-100" data-testid="nav-login">Sign in</Link>
          </nav>
          <button
            type="button"
            className="md:hidden px-3 py-1.5 rounded-lg border border-white/15 text-sm"
            aria-label="Toggle navigation menu"
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen((o) => !o)}
          >
            {menuOpen ? 'Close' : 'Menu'}
          </button>
        </div>
        {menuOpen && (
          <nav className="md:hidden border-t border-white/10 px-6 py-3 flex flex-col gap-3 text-sm" aria-label="Mobile">
            {NAV.map(([label, href]) => <a key={label} href={href} onClick={() => setMenuOpen(false)}>{label}</a>)}
            <Link to="/admin/login" data-testid="mobile-nav-admin">Admin</Link>
            <Link to="/login" data-testid="mobile-nav-login">Sign in</Link>
          </nav>
        )}
      </header>

      <main id="top">
        {/* 2. Hero */}
        <div
          ref={heroRef}
          className="relative overflow-hidden"
          style={{ '--mx': '50%', '--my': '30%' }}
        >
          <div className="pointer-events-none absolute -top-24 left-1/2 -translate-x-1/2 h-80 w-80 rounded-full bg-neon-indigo/20 blur-[120px] animate-ag-glow" aria-hidden="true" />
          <div className="pointer-events-none absolute inset-0" aria-hidden="true" style={{ background: 'radial-gradient(320px circle at var(--mx) var(--my), rgba(99,102,241,0.12), transparent 70%)' }} />
          <section className="relative max-w-6xl mx-auto px-6 pt-14 pb-12 grid md:grid-cols-2 gap-10 items-center">
            <div className={riseClass}>
              <p className="text-xs uppercase tracking-widest text-neon-cyan">Zero Trust after login</p>
              <h1 className="mt-3 text-4xl sm:text-5xl font-extrabold tracking-tight leading-tight" data-testid="landing-title">
                Never trust a session. Verify every action.
              </h1>
              <p className="mt-5 max-w-lg text-ink-300">
                ActionGuard re-evaluates each sensitive action against its current context, scores the risk, and responds in
                proportion: quiet for normal activity, firm when signals combine. Open source, self-hosted and explainable.
              </p>
              <div className="mt-8 flex flex-wrap items-center gap-3">
                <Link to="/login" className="px-5 py-2.5 rounded-lg font-semibold text-white bg-gradient-to-r from-neon-indigo to-neon-cyan shadow-lg shadow-neon-indigo/30 hover:brightness-110" data-testid="cta-login">
                  Sign in
                </Link>
                <a href="#architecture" className="px-5 py-2.5 rounded-lg font-medium border border-white/20 hover:border-white/50">
                  Explore Architecture
                </a>
                <Link to="/signup" className="text-sm text-ink-300 hover:text-white underline-offset-4 hover:underline" data-testid="cta-signup">
                  Access provisioned by your organization &rarr;
                </Link>
              </div>
            </div>
            <ShieldCanvas />
          </section>

          <div className="relative max-w-6xl mx-auto px-6 pb-10">
            <p className="text-xs uppercase tracking-widest text-ink-500">Principal types ActionGuard evaluates</p>
            <ul className="mt-3 flex flex-wrap gap-2">
              {PRINCIPALS.map((p) => <li key={p} className="px-3 py-1 rounded-full border border-white/10 bg-white/[0.04] text-xs text-ink-300">{p}</li>)}
            </ul>
          </div>
        </div>

        {/* 3. Policy inspector */}
        <Section id="inspector" eyebrow="Interactive" title="Test the decision engine, live" intro="Change the signals and watch the risk score, tier and response update. This is an educational mirror of the server Policy Decision Point.">
          <PolicyInspector />
        </Section>

        {/* 4. How it works */}
        <Section id="how" eyebrow="Pipeline" title="How it works">
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {STEPS.map((s, i) => (
              <div key={s.n} className={`${GLASS} p-5 ${riseClass}`} style={rise(i)}>
                <span className="h-8 w-8 rounded-full bg-neon-indigo/20 text-neon-indigo flex items-center justify-center text-sm font-bold">{s.n}</span>
                <h3 className="mt-3 font-semibold">{s.title}</h3>
                <p className="mt-2 text-sm text-ink-300">{s.text}</p>
              </div>
            ))}
          </div>
        </Section>

        {/* 5. Five ordered responses */}
        <Section id="tiers" eyebrow="Graded friction" title="Five ordered responses" intro="The stronger the combined signals, the firmer the response. The final decision is always the strictest of the base decision and every fired escalation rule.">
          <ul className="grid md:grid-cols-5 gap-3" data-testid="tier-list">
            {DECISION_ORDER.map((id, i) => {
              const t = TIER_META[id];
              return (
                <li key={id} className={`${GLASS} p-4`} style={{ borderColor: `${t.color}66` }}>
                  <p className="text-xs text-ink-500">Level {i + 1}</p>
                  <p className="mt-1 font-bold" style={{ color: t.color }}>{id}</p>
                  <p className="mt-2 text-xs text-ink-300">{t.behavior}</p>
                </li>
              );
            })}
          </ul>
          <div className="mt-6" aria-hidden="true">
            <div className="h-2 rounded-full" style={{ background: `linear-gradient(90deg, ${DECISION_ORDER.map((id) => TIER_META[id].color).join(',')})` }} />
            <div className="mt-1 flex justify-between text-[11px] text-ink-500"><span>Least friction</span><span>Most friction</span></div>
          </div>
        </Section>

        {/* 6. Risk formula */}
        <Section id="formula" eyebrow="Scoring" title="An additive, explainable risk score" intro="No black-box model. Every point of the score traces back to a named signal. A single weak signal does not prove compromise; risk rises meaningfully when signals combine.">
          <div className={`${GLASS} p-5 font-mono text-sm sm:text-base`}>
            Risk Score = Base Action Risk + Context Risk + Sequence Risk + Timing Risk + Baseline Deviation &minus; Verification Confidence
          </div>
          <ul className="mt-6 grid md:grid-cols-2 gap-4">
            {TERMS.map((t, i) => (
              <li key={t.name} className={`${GLASS} p-4 ${riseClass}`} style={rise(i)}>
                <div className="flex justify-between text-sm font-semibold"><span>{t.name}</span><span style={{ color: t.color }}>{t.value > 0 ? `+${t.value}` : t.value}</span></div>
                <div className="mt-2 h-2 rounded-full bg-space-800 overflow-hidden" aria-hidden="true">
                  <div className="h-full rounded-full" style={{ width: `${Math.min(Math.abs(t.value), 60) / 60 * 100}%`, background: t.color }} />
                </div>
                <p className="mt-2 text-xs text-ink-300">{t.text}</p>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-xs text-ink-500">Bar values are illustrative examples, not fixed weights. Weights live in versioned policy files.</p>
        </Section>

        {/* 7. Step-up */}
        <Section id="stepup" eyebrow="Reverify" title="Resilient step-up verification" tone="text-state-warn" intro="A 6-digit one-time code is sent to the immutable primary registration email, never the recovery email, so an attacker who changes the recovery address cannot receive it.">
          <Flow accent="#F59E0B" items={['OTP', 'Primary email', 'Verify (3 attempts)', 'ES256 ticket (60s)', 'Scoped elevation (\u2264300s, max 900s)']} />
          <ul className="mt-6 grid md:grid-cols-3 gap-4 text-sm text-ink-300">
            <li className={`${GLASS} p-4`}>Challenges expire after 300 seconds and allow 3 attempts. Three failures trigger containment and a 15-minute account lock.</li>
            <li className={`${GLASS} p-4`}>Tickets are signed with an asymmetric P-256 key pair kept separate from the JWT secret.</li>
            <li className={`${GLASS} p-4`}>Elevation satisfies <b className="text-state-warn">reverify</b> but can never bypass <b className="text-state-caution">delay</b> or <b className="text-state-alert">block</b>.</li>
          </ul>
        </Section>

        {/* 8. Cooling-off */}
        <Section id="cooling" eyebrow="Delay" title="Cooling-off for high-impact actions" tone="text-state-caution" intro="A delayed action is queued for a cooling-off window (default 300 seconds) with a single-use cancellation token, stored only as a SHA-256 hash.">
          <Flow accent="#F97316" items={['Action delayed', 'Cancellation window', 'Pre-execution rechecks', 'Execute or cancel']} />
          <p className="mt-6 max-w-3xl text-sm text-ink-300">
            Before a delayed action runs, Zero Trust rechecks confirm the account is not locked, the bound session is still active,
            the risk tier has not increased, and the policy does not now require block or delay.
          </p>
        </Section>

        {/* 9. Containment */}
        <Section id="containment" eyebrow="Block" title="Containment at critical risk" tone="text-state-alert" intro="A block at the critical tier invalidates the session immediately and applies a 15-minute protective lock to the account.">
          <div className="grid md:grid-cols-3 gap-4 text-sm text-ink-300">
            <div className={`${GLASS} p-4 border-state-alert/40`}>Wrong password, unknown email and a locked account all return the same generic 401, so attackers cannot enumerate accounts.</div>
            <div className={`${GLASS} p-4 border-state-alert/40`}>During a lock, valid credentials from a recognized device can still authenticate.</div>
            <div className={`${GLASS} p-4 border-state-alert/40`}>Unrecognized or missing device fingerprints are refused until the lock expires.</div>
          </div>
        </Section>

        {/* 10. Architecture */}
        <Section id="architecture" eyebrow="Architecture" title="Decision and enforcement, separated" intro="Following NIST SP 800-207, the Risk and Policy Engines only decide. Express middleware enforces.">
          <div className="flex flex-col gap-3 items-stretch">
            <Flow items={['Signal collectors', 'Risk Engine (PDP)', 'Policy Engine (PDP)', 'PEP middleware']} />
            <Flow accent="#6366F1" items={['allow', 'monitor', 'reverify', 'delay', 'block \u2192 containment (critical)']} />
          </div>
          <div className="mt-6 grid md:grid-cols-3 gap-4 text-sm text-ink-300">
            <div className={`${GLASS} p-4`}><b className="text-ink-100">MySQL</b> is the durable source of truth for events, decisions and audit.</div>
            <div className={`${GLASS} p-4`}><b className="text-ink-100">Redis</b> holds fast session, sequence and cooling-off state.</div>
            <div className={`${GLASS} p-4`}><b className="text-ink-100">Socket.IO</b> streams tier-only updates to users and full telemetry to administrators.</div>
          </div>
          <div className="mt-4 rounded-2xl border border-neon-cyan/40 bg-neon-cyan/5 p-4 text-sm text-ink-300">
            <b className="text-neon-cyan">Privacy boundary.</b> Users see only their risk tier, coarse location and a plain-language explanation.
            Numeric scores, signal weights and administrator explanations are never sent to user sessions.
          </div>
        </Section>

        {/* 11. Principles */}
        <Section id="principles" eyebrow="Principles" title="What the platform stands on">
          <ul className="grid sm:grid-cols-2 lg:grid-cols-5 gap-4">
            {PILLARS.map(([title, text]) => (
              <li key={title} className={`${GLASS} p-4`}>
                <p className="font-semibold text-sm">{title}</p>
                <p className="mt-2 text-xs text-ink-300">{text}</p>
              </li>
            ))}
          </ul>
        </Section>

        {/* 12. Final CTA */}
        <section className="max-w-6xl mx-auto px-6 pb-20">
          <div className={`${GLASS} relative overflow-hidden p-10 text-center`}>
            <div className="pointer-events-none absolute -bottom-24 left-1/2 -translate-x-1/2 h-64 w-64 rounded-full bg-neon-cyan/20 blur-[100px] animate-ag-glow" aria-hidden="true" />
            <h2 className="relative text-3xl font-extrabold tracking-tight">Verify every action. Contain every takeover.</h2>
            <div className="relative mt-6 flex flex-wrap justify-center items-center gap-3">
              <Link to="/login" className="px-5 py-2.5 rounded-lg font-semibold text-white bg-gradient-to-r from-neon-indigo to-neon-cyan hover:brightness-110" data-testid="final-cta-login">Sign in</Link>
              <Link to="/signup" className="text-sm text-ink-300 hover:text-white hover:underline underline-offset-4" data-testid="final-cta-signup">Access provisioned by your organization</Link>
              <Link to="/admin/login" className="text-sm text-neon-cyan hover:underline underline-offset-4" data-testid="final-cta-admin">Operator console &rarr;</Link>
            </div>
          </div>
        </section>
      </main>

      {/* 13. Footer */}
      <footer className="border-t border-white/10 px-6 py-10">
        <div className="max-w-6xl mx-auto grid sm:grid-cols-3 gap-6 text-sm">
          <div>
            <p className="font-semibold">ActionGuard</p>
            <p className="mt-2 text-xs text-ink-500">Self-hosted, open source Zero Trust.</p>
          </div>
          <nav aria-label="Product" className="flex flex-col gap-2 text-ink-300">
            <span className="text-xs uppercase tracking-widest text-ink-500">Product</span>
            <a href="#how" className="hover:text-white">How it works</a>
            <a href="#tiers" className="hover:text-white">Response tiers</a>
            <a href="#inspector" className="hover:text-white">Decision engine</a>
          </nav>
          <nav aria-label="Resources" className="flex flex-col gap-2 text-ink-300">
            <span className="text-xs uppercase tracking-widest text-ink-500">Resources</span>
            <a href="#architecture" className="hover:text-white">Architecture</a>
            <a href="#stepup" className="hover:text-white">Step-up model</a>
            <a href="#containment" className="hover:text-white">Security model</a>
          </nav>
        </div>
        <p className="mt-8 text-center text-xs text-ink-500">ActionGuard &middot; INSA Jimma Branch, 5th Cyber Talent Batch</p>
      </footer>
    </div>
  );
}

export default LandingPage;
