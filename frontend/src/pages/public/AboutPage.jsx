import React from 'react';
import { PublicLayout } from '../../components/public/PublicLayout.jsx';
import { AmbientBackground } from '../../components/common/AmbientBackground.jsx';
import { ExpandableCard } from '../../components/common/ExpandableCard.jsx';

const PRINCIPLES = [
  {
    title: 'Never Trust, Always Verify',
    badge: 'Principle 01',
    badgeColor: 'bg-brand-luminous/15 text-brand-cyan border-brand-cyan/30',
    summary: 'Authentication is not a permanent pass. Trust is continuous, granular, and revocable. Sensitive operations require fresh security context.',
    details: 'Login-time authentication establishes initial identity, but cannot guard against post-authentication session theft. ActionGuard continuously verifies contextual attributes (IP, device fingerprint, sequence velocity) throughout the active session lifetime.',
    tags: ['Continuous Verification', 'Decaying Trust', 'Contextual Evaluation']
  },
  {
    title: 'Assume Breach',
    badge: 'Principle 02',
    badgeColor: 'bg-brand-blue/30 text-brand-cyan border-brand-luminous/40',
    summary: 'Systems should be designed assuming credentials or session tokens may already be compromised. ActionGuard detects and contains hostile movement before high-impact changes succeed.',
    details: 'Rather than assuming a valid bearer JWT guarantees safety, ActionGuard treats every sensitive route request as potentially adversary-controlled. Protective locks and cooling-off queues prevent irreversible harm before unauthorized changes finalize.',
    tags: ['Lateral Movement Containment', 'Blast Radius Minimization', 'Zero Trust Posture']
  },
  {
    title: 'Proportional & Graded Response',
    badge: 'Principle 03',
    badgeColor: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
    summary: 'Security controls should fit evaluated risk. Proportional responses (Allow, Monitor, Re-verify, Delay, Block) avoid paralyzing benign users with aggressive false positives.',
    details: 'Indiscriminate blocking degrades user experience. ActionGuard uses 5 ordered response tiers to introduce friction strictly when needed: quiet execution for trusted devices, step-up MFA for anomalies, and hard containment for critical threats.',
    tags: ['5 Response Tiers', 'Adaptive Friction', 'False Positive Reduction']
  },
  {
    title: 'Explainable Security (No Black Boxes)',
    badge: 'Principle 04',
    badgeColor: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    summary: 'Every security decision must be traceable to named signals, weights, and versioned policy rules. Administrators and users receive clear explanations without secret obscurity.',
    details: 'ActionGuard avoids opaque ML inference models. Decisions stem from additive scores where every single point corresponds to an auditable signal term. Telemetry streams full forensic causal graphs to administrators and plain-language summaries to users.',
    tags: ['Deterministic Heuristics', 'Causal Telemetry Graph', 'Auditable Decisions']
  },
  {
    title: 'Architectural Decoupling (PEP & PDP)',
    badge: 'Principle 05',
    badgeColor: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    summary: 'Following NIST SP 800-207 guidelines, the Policy Decision Point is decoupled from the Policy Enforcement Point, ensuring testability and modular adoption.',
    details: 'Decoupling ensures policy changes never require modifying Express route logic. The PDP operates as an isolated decision function evaluated across versioned JSON matrices, allowing simulated replay in CI test suites.',
    tags: ['NIST SP 800-207', 'Modular Microservices', 'CI Policy Replay']
  },
  {
    title: 'Fail-Closed Security Posture',
    badge: 'Principle 06',
    badgeColor: 'bg-red-500/15 text-red-300 border-red-500/30',
    summary: 'If verification keys, cryptographic components, or vital dependencies are missing or misconfigured in production, the platform strictly fails closed to protect protected assets.',
    details: 'During runtime startup, the platform checks required cryptographic secrets (JWT_SECRET, ACTIONGUARD_ADMIN_API_KEY, database credentials). Missing or weak secrets immediately halt initialization rather than falling back to unauthenticated bypass modes.',
    tags: ['Strict Initialization Gates', 'Zero Silent Degradation', 'Cryptographic Assurance']
  }
];

export function AboutPage() {
  return (
    <PublicLayout>
      {/* About Hero */}
      <div className="relative overflow-hidden pt-12 pb-16 lg:pt-20 lg:pb-24 border-b border-white/10">
        <AmbientBackground variant="hero" />
        <div className="max-w-[1400px] mx-auto px-6 sm:px-8 lg:px-12 relative">
          <div className="max-w-3xl">
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-semibold bg-brand-luminous/15 border border-brand-luminous/35 text-brand-cyan mb-5 shadow-[0_0_20px_rgba(37,141,235,0.25)]">
              <span className="w-2 h-2 rounded-full bg-brand-cyan animate-ping" />
              Project Origin & Mission
            </div>
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-white leading-[1.12]">
              Building Open-Source Zero Trust for Continuous Session Defense
            </h1>
            <p className="mt-6 text-lg text-ink-300 leading-relaxed">
              ActionGuard was founded to address a critical blind spot in modern web architectures: the unmonitored window of vulnerability that opens immediately after a user successfully logs in.
            </p>
          </div>
        </div>
      </div>

      <div className="max-w-[1400px] mx-auto px-6 sm:px-8 lg:px-12 py-16 space-y-20">
        {/* 1. About the Project */}
        <section id="about" className="grid lg:grid-cols-12 gap-12 items-center">
          <div className="lg:col-span-6 space-y-6">
            <span className="text-xs uppercase tracking-widest text-brand-cyan font-bold font-mono">Project Background</span>
            <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
              What Is ActionGuard?
            </h2>
            <p className="text-ink-300 text-base leading-relaxed">
              ActionGuard is an open-source, self-hosted Zero Trust security platform developed by <strong className="text-white">Group 2 during the INSA Summer Camp 2026</strong> in Jimma, Ethiopia.
            </p>
            <p className="text-ink-300 text-base leading-relaxed">
              While conventional identity solutions focus heavily on the perimeter (login forms, initial multi-factor challenges), modern threats such as infostealer malware, browser cookie exfiltration, and credential stuffing operate entirely post-authentication. Once an attacker obtains a valid session cookie, traditional applications grant unconditional trust.
            </p>
            <p className="text-ink-300 text-base leading-relaxed">
              ActionGuard provides integrated applications with continuous, context-aware authorization. It evaluates device identity, IP location changes, request velocity, and behavioral deviation in real time to contain suspicious activity before irreversible damage occurs.
            </p>
          </div>

          <div className="lg:col-span-6 p-8 sm:p-10 rounded-2xl bg-space-850/90 border border-white/10 shadow-2xl space-y-5">
            <h3 className="text-lg font-bold text-white mb-3">Verified Project Details</h3>
            <div className="space-y-3.5 text-xs sm:text-sm font-mono text-ink-300">
              <div className="flex justify-between border-b border-white/5 pb-2.5">
                <span className="text-ink-500">Project Initiative:</span>
                <span className="text-white font-bold">INSA Summer Camp 2026 (Group 2)</span>
              </div>
              <div className="flex justify-between border-b border-white/5 pb-2.5">
                <span className="text-ink-500">Project Location:</span>
                <span className="text-white font-bold">Jimma, Ethiopia</span>
              </div>
              <div className="flex justify-between border-b border-white/5 pb-2.5">
                <span className="text-ink-500">License:</span>
                <span className="text-brand-cyan font-bold">Apache-2.0 Open Source License</span>
              </div>
              <div className="flex justify-between border-b border-white/5 pb-2.5">
                <span className="text-ink-500">Source Repository:</span>
                <a
                  href="https://github.com/AbdulhamidN/Action-guard"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-brand-luminous hover:underline font-bold"
                >
                  github.com/AbdulhamidN/Action-guard &nearr;
                </a>
              </div>
              <div className="flex justify-between">
                <span className="text-ink-500">Architecture Standard:</span>
                <span className="text-white font-bold">NIST SP 800-207 (PDP/PEP Decoupling)</span>
              </div>
            </div>
          </div>
        </section>

        {/* 2. Mission & Philosophy */}
        <section id="mission" className="space-y-10">
          <div className="text-center max-w-3xl mx-auto">
            <span className="text-xs uppercase tracking-widest text-brand-cyan font-bold font-mono">Guiding Philosophy</span>
            <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white mt-2">
              Core Principles of ActionGuard
            </h2>
            <p className="mt-3 text-ink-300 leading-relaxed text-base">
              Every feature in the ActionGuard codebase adheres to strict Zero Trust tenets designed for transparency and defense-in-depth. Click any principle to view technical specifications.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {PRINCIPLES.map((p) => (
              <ExpandableCard
                key={p.title}
                title={p.title}
                badge={p.badge}
                badgeColor={p.badgeColor}
                summary={p.summary}
                details={p.details}
                tags={p.tags}
              />
            ))}
          </div>
        </section>

        {/* 3. Open Source Direction & Transparency */}
        <section id="philosophy" className="p-8 sm:p-12 rounded-2xl bg-gradient-to-r from-space-850 via-space-800 to-space-850 border border-brand-luminous/30 space-y-6 shadow-xl relative overflow-hidden">
          <AmbientBackground variant="subtle" />
          <div className="relative max-w-3xl space-y-3">
            <span className="text-xs uppercase tracking-widest text-brand-cyan font-bold font-mono">Open Source Governance</span>
            <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white">
              Transparent, Self-Hostable, and Extensible
            </h2>
            <p className="text-ink-300 text-sm sm:text-base leading-relaxed">
              ActionGuard is built for software engineers and cybersecurity teams who want total control over their authorization logic without vendor lock-in or proprietary cloud dependencies.
            </p>
            <p className="text-ink-300 text-sm leading-relaxed">
              Because trust policies, signal weights, and detection heuristics are defined as versioned JSON files (<code className="text-brand-cyan">config/policy.json</code>), teams can audit, test, and replay real-world threat telemetry locally using our automated Jest and Vitest test harnesses.
            </p>
          </div>
        </section>

        {/* 4. Contact & Community */}
        <section id="contact" className="space-y-8 border-t border-white/10 pt-16">
          <div className="text-center max-w-2xl mx-auto space-y-2">
            <span className="text-xs uppercase tracking-widest text-brand-cyan font-bold font-mono">Community & Collaboration</span>
            <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
              Get Involved with ActionGuard
            </h2>
            <p className="text-sm text-ink-300 leading-relaxed">
              ActionGuard welcomes community contributions, vulnerability reports, and architectural feedback.
            </p>
          </div>

          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6 max-w-5xl mx-auto pt-4 text-sm">
            <div className="p-6 rounded-2xl bg-space-850/70 border border-white/10 hover:border-brand-luminous/40 transition-colors space-y-3">
              <h3 className="font-bold text-white text-base">Code & Contributions</h3>
              <p className="text-xs text-ink-300 leading-relaxed">
                Submit pull requests, browse the codebase, or report bugs directly on our GitHub repository.
              </p>
              <a
                href="https://github.com/AbdulhamidN/Action-guard"
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-brand-cyan font-semibold hover:underline inline-block pt-1"
              >
                Open GitHub Issues &rarr;
              </a>
            </div>

            <div className="p-6 rounded-2xl bg-space-850/70 border border-white/10 hover:border-brand-luminous/40 transition-colors space-y-3">
              <h3 className="font-bold text-white text-base">Security Vulnerability Reporting</h3>
              <p className="text-xs text-ink-300 leading-relaxed">
                If you discover a security vulnerability or bypass, please report it responsibly via GitHub Security Advisories.
              </p>
              <span className="text-xs text-ink-500 block pt-1 font-mono">
                Report via repository security tab
              </span>
            </div>

            <div className="p-6 rounded-2xl bg-space-850/70 border border-white/10 hover:border-brand-luminous/40 transition-colors space-y-3">
              <h3 className="font-bold text-white text-base">Community Contact</h3>
              <p className="text-xs text-ink-300 leading-relaxed">
                For general project inquiries regarding Group 2's development at INSA Summer Camp 2026.
              </p>
              <span className="text-xs font-mono text-ink-400 block pt-1">
                [Inquiries via GitHub Repository]
              </span>
            </div>
          </div>
        </section>
      </div>
    </PublicLayout>
  );
}

export default AboutPage;
