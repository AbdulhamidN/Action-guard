import React from 'react';
import { Link } from 'react-router-dom';
import { PublicLayout } from '../../components/public/PublicLayout.jsx';
import { AmbientBackground } from '../../components/common/AmbientBackground.jsx';
import { ExpandableCard } from '../../components/common/ExpandableCard.jsx';

const RESPONSES = [
  {
    tier: 'Allow',
    level: 'Tier 1',
    color: '#10B981',
    badgeColor: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    when: 'Low risk score (< 30) & routine action sensitivity',
    action: 'Executes route handler immediately without user-facing friction. Normal operational logging.',
    details: 'Standard actions from enrolled devices with low risk score run with zero friction. The PEP attaches request telemetry and passes execution to downstream controllers. Decisions are committed to durable audit logs.',
    tags: ['Zero Friction', 'Risk < 30', 'Automatic Permit', 'Standard Audit']
  },
  {
    tier: 'Monitor',
    level: 'Tier 2',
    color: '#258DEB',
    badgeColor: 'bg-brand-luminous/15 text-brand-cyan border-brand-cyan/30',
    when: 'Medium risk (30–59) or sensitive read actions',
    action: 'Allows action execution but tags security event with high-priority audit metadata. Streams live to admin console.',
    details: 'Execution proceeds without blocking the user, but the request is flagged with forensic metadata and highlighted in real-time operator feeds via Socket.IO for administrative oversight.',
    tags: ['Forensic Audit', 'Risk 30–59', 'Socket.IO Alert', 'Passive Inspection']
  },
  {
    tier: 'Re-verify (Step-Up)',
    level: 'Tier 3',
    color: '#8B5CF6',
    badgeColor: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
    when: 'Elevated risk (60–74) on sensitive account actions',
    action: 'Halts execution (HTTP 403 step_up_required). Issues 6-digit OTP to primary email. Redeems short-lived ES256 ticket.',
    details: 'Halts execution and returns an HTTP 403 step_up_required envelope. A 6-digit one-time code is sent to the primary registration email. Upon successful verification, an ES256-signed ticket grants temporary elevation for 300 seconds.',
    tags: ['HTTP 403 Step-Up', 'Risk 60–74', 'Primary Email OTP', 'ES256 Elevation Ticket']
  },
  {
    tier: 'Delay (Cooling-Off)',
    level: 'Tier 4',
    color: '#F59E0B',
    badgeColor: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    when: 'High risk (75–84) or irreversible high-impact actions',
    action: 'Enqueues request into delayed_actions table (default 300s). Returns cancellation token to genuine owner.',
    details: 'Places high-impact actions into a 300-second holding window in the MySQL delayed_actions queue. An emergency cancellation token is provided to the genuine account owner. Before execution, the system re-evaluates session health.',
    tags: ['Cooling-Off Holding', 'Risk 75–84', 'SHA-256 Token Hash', 'Pre-Execution Verification']
  },
  {
    tier: 'Block & Contain',
    level: 'Tier 5',
    color: '#EF4444',
    badgeColor: 'bg-red-500/15 text-red-300 border-red-500/30',
    when: 'Critical risk (85+) or repeated verification failures',
    action: 'Rejects request immediately. Evicts active Redis session and locks the account for 15 minutes.',
    details: 'Terminates connection immediately. The active session is purged from Redis and the account enters a 15-minute protective lock. Generic 401 responses block enumeration while recognized enrolled devices retain recovery access.',
    tags: ['Session Eviction', 'Risk 85+', '15-Minute Lockout', 'Anti-Enumeration']
  }
];

export function SolutionsPage() {
  return (
    <PublicLayout>
      {/* Solutions Hero */}
      <div className="relative overflow-hidden pt-12 pb-16 lg:pt-20 lg:pb-24 border-b border-white/10">
        <AmbientBackground variant="hero" />
        <div className="max-w-[1400px] mx-auto px-6 sm:px-8 lg:px-12 relative">
          <div className="max-w-3xl">
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-semibold bg-brand-cyan/15 border border-brand-cyan/35 text-brand-cyan mb-5 shadow-[0_0_20px_rgba(53,197,232,0.25)]">
              <span className="w-2 h-2 rounded-full bg-brand-cyan animate-ping" />
              Real-World Threat Containment
            </div>
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-white leading-[1.12]">
              Proactive Defense Against Account Takeover & Session Hijacking
            </h1>
            <p className="mt-6 text-lg text-ink-300 leading-relaxed">
              When authentication perimeters fail, ActionGuard steps in. Explore how continuous Zero Trust evaluation
              detects and neutralizes compromised credentials and hijacked tokens before irreversible damage occurs.
            </p>
            <div className="mt-8 flex flex-wrap gap-4">
              <a
                href="#account-takeover"
                className="px-6 py-3 rounded-xl text-sm font-semibold text-white bg-gradient-to-r from-brand-blue via-brand-luminous to-brand-cyan shadow-lg shadow-brand-luminous/30 hover:brightness-110 transition-all hover:scale-[1.02]"
              >
                Account Takeover Defense
              </a>
              <a
                href="#session-security"
                className="px-6 py-3 rounded-xl text-sm font-medium border border-white/20 hover:border-brand-luminous/50 bg-white/[0.03] hover:bg-white/[0.08] text-white transition-all"
              >
                Session Security
              </a>
              <a
                href="#adaptive-authorization"
                className="px-6 py-3 rounded-xl text-sm font-medium bg-brand-cyan/10 border border-brand-cyan/30 hover:bg-brand-cyan/20 text-brand-cyan transition-colors"
              >
                Adaptive Authorization
              </a>
            </div>
          </div>
        </div>
      </div>

      {/* 1. Account Takeover Protection */}
      <section id="account-takeover" className="max-w-[1400px] mx-auto px-6 sm:px-8 lg:px-12 py-20 scroll-mt-20 border-b border-white/10">
        <div className="grid lg:grid-cols-12 gap-12 items-center">
          <div className="lg:col-span-6 space-y-6">
            <span className="text-xs uppercase tracking-widest text-brand-cyan font-bold font-mono">Use Case 01</span>
            <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
              Account Takeover (ATO) Protection
            </h2>
            <p className="text-ink-300 text-base leading-relaxed">
              Credential stuffing databases contain billions of leaked username/password pairs. When an attacker tests stolen credentials,
              they often succeed at login. Their immediate next step is almost always a <strong>hostile credential cascade</strong>: changing
              the account recovery email and password to permanently lock out the true owner.
            </p>
            <div className="space-y-3 text-sm text-ink-100">
              <div className="p-6 rounded-2xl bg-space-850/80 border border-white/10 space-y-3">
                <h4 className="font-bold text-white text-base">How ActionGuard Intercepts ATO:</h4>
                <ol className="text-xs sm:text-sm text-ink-300 leading-relaxed space-y-2 list-decimal list-inside">
                  <li>The login originates from an unrecognized device and unfamiliar IP geolocation.</li>
                  <li>Baseline deviation raises the session risk tier from LOW to MEDIUM.</li>
                  <li>When the attacker attempts to update the recovery email, the PEP classifies this as a HIGH-sensitivity action.</li>
                  <li>The Policy Decision Point requires REVERIFY. The verification OTP is dispatched exclusively to the user’s original primary registration email, which the attacker does not control.</li>
                  <li>After 3 invalid OTP attempts, the account enters protective lockout and active sessions are revoked.</li>
                </ol>
              </div>
            </div>
          </div>

          <div className="lg:col-span-6 space-y-5">
            <h3 className="text-xs font-mono uppercase tracking-wider text-ink-500 mb-2 font-bold">Scenario Comparison</h3>
            
            {/* Without ActionGuard */}
            <div className="p-6 rounded-2xl bg-space-850/90 border border-red-500/30 space-y-2.5">
              <span className="text-xs font-bold text-red-400 uppercase tracking-wider font-mono">Without ActionGuard</span>
              <p className="text-base font-bold text-white">Unrestricted Post-Login Account Drain</p>
              <p className="text-xs sm:text-sm text-ink-300 leading-relaxed">
                The login endpoint returns a valid token. The application trusts the bearer token unconditionally. The attacker updates the recovery address in 10 seconds. The user is locked out before receiving notice.
              </p>
            </div>

            {/* With ActionGuard */}
            <div className="p-6 rounded-2xl bg-space-850/90 border border-emerald-500/40 space-y-2.5 shadow-lg">
              <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider font-mono">With ActionGuard</span>
              <p className="text-base font-bold text-white">Automated Containment & Hostile Sequence Interruption</p>
              <p className="text-xs sm:text-sm text-ink-300 leading-relaxed">
                The recovery email change is gated by the PEP (HTTP 403 step_up_required). The OTP challenge is sent to the authentic primary email with clear security context warnings. The takeover attempt fails without impacting the legitimate account owner.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* 2. Session Security */}
      <section id="session-security" className="max-w-[1400px] mx-auto px-6 sm:px-8 lg:px-12 py-20 scroll-mt-20 border-b border-white/10">
        <div className="grid lg:grid-cols-12 gap-12 items-center">
          <div className="lg:col-span-6 order-2 lg:order-1 space-y-4">
            <h3 className="text-xs font-mono uppercase tracking-wider text-ink-500 mb-2 font-bold">Threat Vector: Infostealer Malware</h3>
            
            <div className="p-5 rounded-2xl bg-space-850/80 border border-white/10 space-y-2.5">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-brand-cyan font-bold">Legitimate Session A</span>
                <span className="text-emerald-400 font-semibold">New York (09:15)</span>
              </div>
              <p className="text-xs sm:text-sm text-ink-300 leading-relaxed">
                User logs in from their enrolled macOS laptop on Chrome. Canvas/WebGL fingerprint matches known device profile. Risk: <strong>LOW (Tier 1)</strong>.
              </p>
            </div>

            <div className="flex justify-center text-xs text-brand-cyan font-mono font-bold py-1">
              <span>&darr; 8 minutes later: Session cookie exfiltrated via malware &darr;</span>
            </div>

            <div className="p-5 rounded-2xl bg-space-850/80 border border-state-alert/50 space-y-2.5 shadow-lg">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-state-alert font-bold">Hijacked Request</span>
                <span className="text-red-400 font-semibold">Frankfurt (09:23)</span>
              </div>
              <p className="text-xs sm:text-sm text-ink-300 leading-relaxed">
                Attacker injects stolen cookie into automated curl script. Haversine distance indicates 6,200 km traversed in 480 seconds (speed &gt; 46,000 km/h). <strong>IMPOSSIBLE_TRAVEL</strong> triggered (+55 risk). Device fingerprint missing (+25 risk). Risk: <strong>CRITICAL (80+)</strong>.
              </p>
            </div>
          </div>

          <div className="lg:col-span-6 order-1 lg:order-2 space-y-6">
            <span className="text-xs uppercase tracking-widest text-brand-cyan font-bold font-mono">Use Case 02</span>
            <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
              Session Hijacking & Cookie Theft Defense
            </h2>
            <p className="text-ink-300 text-base leading-relaxed">
              Infostealer trojans (such as Lumma Stealer and RedLine) steal active session tokens straight from browser memory, completely bypassing
              traditional multi-factor authentication (MFA). Because the stolen token is cryptographically valid, standard backends allow the attacker in.
            </p>
            <p className="text-ink-300 text-base leading-relaxed">
              ActionGuard protects sessions post-authentication through continuous contextual binding:
            </p>
            <ul className="space-y-3 text-sm text-ink-100">
              <li className="flex items-start gap-3">
                <span className="text-brand-cyan font-bold text-base">&bull;</span>
                <span><strong>Impossible Travel:</strong> Real-time distance-over-time verification stops cookie replay across geographic boundaries.</span>
              </li>
              <li className="flex items-start gap-3">
                <span className="text-brand-cyan font-bold text-base">&bull;</span>
                <span><strong>Fingerprint Affinity:</strong> Detects when a desktop-issued session token is suddenly replayed from an unrecognized browser environment.</span>
              </li>
              <li className="flex items-start gap-3">
                <span className="text-brand-cyan font-bold text-base">&bull;</span>
                <span><strong>Instant Containment:</strong> Invalidates compromised sessions in Redis and broadcasts revocation across Socket.IO in milliseconds.</span>
              </li>
            </ul>
          </div>
        </div>
      </section>

      {/* 3. Adaptive Authorization */}
      <section id="adaptive-authorization" className="max-w-[1400px] mx-auto px-6 sm:px-8 lg:px-12 py-20 scroll-mt-20">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <span className="text-xs uppercase tracking-widest text-brand-cyan font-bold font-mono">Use Case 03</span>
          <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white mt-2">
            Adaptive, Risk-Proportional Authorization
          </h2>
          <p className="mt-4 text-ink-300 leading-relaxed text-base">
            Static Role-Based Access Control (RBAC) treats an "Admin" as universally authorized. ActionGuard implements Attribute-Based and Risk-Adaptive
            Access Control (ABAC/RAdAC) where requests receive tailored security decisions based on contextual risk and blast radius.
          </p>
        </div>

        {/* 5 Ordered Responses Cards with Interactive Expandable Cards */}
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {RESPONSES.map((r) => (
            <ExpandableCard
              key={r.tier}
              title={r.tier}
              badge={`${r.level} · Trigger: ${r.when}`}
              badgeColor={r.badgeColor}
              summary={r.action}
              details={r.details}
              tags={r.tags}
            />
          ))}
        </div>

        {/* Explicit Security Scope Disclaimer */}
        <div className="mt-16 p-6 sm:p-8 rounded-2xl bg-space-850/60 border border-white/10 max-w-4xl mx-auto text-xs text-ink-400 leading-relaxed text-center shadow-lg">
          <strong className="text-white uppercase tracking-wider block mb-2 font-mono text-xs">Architectural Scope & Threat Boundary Disclaimer</strong>
          ActionGuard continuously evaluates session, device, and behavioral evidence to contain suspicious activity in real time. It does not claim guaranteed account-takeover prevention against every novel vector or physical device compromise. Security decisions remain proportional to configured policy thresholds and observable runtime telemetry.
        </div>
      </section>
    </PublicLayout>
  );
}

export default SolutionsPage;
