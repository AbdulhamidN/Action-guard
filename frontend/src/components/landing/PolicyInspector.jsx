import React, { useMemo, useState } from 'react';
import { DECISION_ORDER, TIER_META } from './tiers.js';
import { VisualSecurityFlow } from './VisualSecurityFlow.jsx';

// Client-side mirror of the server Policy Decision Point for education;
// the server remains authoritative. Weights and thresholds are illustrative.

export const SENSITIVITY_ORDER = ['low', 'medium', 'high', 'critical'];

// Mirrors DEFAULT_ACTION_SENSITIVITY in policies/default-v1.json.
export const ACTIONS = [
  { id: 'login_success', label: 'Sign-in', sensitivity: 'low' },
  { id: 'phone_number_change', label: 'Phone number change', sensitivity: 'medium' },
  { id: 'password_change', label: 'Password change', sensitivity: 'high' },
  { id: 'recovery_email_change', label: 'Recovery email change', sensitivity: 'high' },
  { id: 'mfa_change', label: 'MFA change', sensitivity: 'high' },
  { id: 'high_impact_action', label: 'High-impact action', sensitivity: 'critical' }
];

const ACCOUNT_MODIFICATION = ['password_change', 'recovery_email_change', 'mfa_change', 'phone_number_change'];

// Mirrors BASE_MATRIX[sensitivity][riskTier].
export const BASE_MATRIX = {
  low: { low: 'allow', medium: 'allow', high: 'monitor', critical: 'monitor' },
  medium: { low: 'allow', medium: 'monitor', high: 'reverify', critical: 'reverify' },
  high: { low: 'monitor', medium: 'reverify', high: 'delay', critical: 'block' },
  critical: { low: 'reverify', medium: 'delay', high: 'block', critical: 'block' }
};

const BASE_RISK = { low: 10, medium: 25, high: 45, critical: 60 };
const MAX_CONFIDENCE_DISCOUNT = 30;

export const DEFAULT_INPUTS = {
  action: 'login_success',
  sensitivityOverride: 'low',
  newDevice: false,
  newCountry: false,
  impossibleTravel: false,
  timing: 'normal', // normal | unusual_hour | automation_burst
  sequence: 'none', // none | credential_cascade | takeover_progression
  baselineDeviation: false,
  confidence: 0
};

export const PRESETS = [
  { id: 'normal', label: 'Normal login', inputs: { ...DEFAULT_INPUTS, confidence: 40 } },
  {
    id: 'unfamiliar',
    label: 'Unfamiliar sign-in',
    inputs: { ...DEFAULT_INPUTS, newDevice: true, newCountry: true }
  },
  {
    id: 'novelty',
    label: 'New device + new country',
    inputs: { ...DEFAULT_INPUTS, action: 'phone_number_change', sensitivityOverride: 'medium', newDevice: true, newCountry: true, confidence: 20 }
  },
  {
    id: 'travel',
    label: 'Impossible travel on password change',
    inputs: { ...DEFAULT_INPUTS, action: 'password_change', sensitivityOverride: 'high', impossibleTravel: true }
  },
  {
    id: 'takeover',
    label: 'Takeover sequence',
    inputs: { ...DEFAULT_INPUTS, action: 'recovery_email_change', sensitivityOverride: 'high', newDevice: true, newCountry: true, sequence: 'takeover_progression' }
  }
];

const rank = (list, value) => list.indexOf(value);
const maxOf = (list, a, b) => (rank(list, a) >= rank(list, b) ? a : b);

export function tierForScore(score) {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  return 'low';
}

/** Pure, deterministic evaluation of one scenario. */
export function evaluateScenario(inputs) {
  const action = ACTIONS.find((a) => a.id === inputs.action) || ACTIONS[0];
  const sensitivity = maxOf(SENSITIVITY_ORDER, action.sensitivity, inputs.sensitivityOverride || action.sensitivity);

  const signals = [];
  const add = (label, category, weight) => signals.push({ label, category, weight });

  const base = BASE_RISK[sensitivity];
  add(`Base action risk (${sensitivity} sensitivity)`, 'base', base);

  let context = 0;
  if (inputs.newDevice) { context += 25; add('Unrecognized device', 'context', 25); }
  if (inputs.newCountry) { context += 25; add('Unrecognized country', 'context', 25); }
  if (inputs.impossibleTravel) { context += 28; add('Impossible travel', 'context', 28); }

  let sequence = 0;
  if (inputs.sequence === 'credential_cascade') { sequence = 35; add('Rapid credential-change cascade', 'sequence', 35); }
  if (inputs.sequence === 'takeover_progression') { sequence = 50; add('Takeover progression', 'sequence', 50); }

  let timing = 0;
  if (inputs.timing === 'unusual_hour') { timing = 10; add('Unusual hour', 'timing', 10); }
  if (inputs.timing === 'automation_burst') { timing = 20; add('Automation timing burst', 'timing', 20); }

  const baseline = inputs.baselineDeviation ? 13 : 0;
  if (baseline) add('Deviation from personal baseline', 'baseline', 13);

  const clampedConfidence = Math.min(100, Math.max(0, Number(inputs.confidence) || 0));
  const confidence = Math.round((clampedConfidence / 100) * MAX_CONFIDENCE_DISCOUNT);
  if (confidence) add('Recent verification confidence', 'confidence', -confidence);

  const raw = base + context + sequence + timing + baseline - confidence;
  const score = Math.min(100, Math.max(0, raw));
  const riskTier = tierForScore(score);

  const baseDecision = BASE_MATRIX[sensitivity][riskTier];
  const sensIdx = rank(SENSITIVITY_ORDER, sensitivity);
  const atLeast = (level) => sensIdx >= rank(SENSITIVITY_ORDER, level);
  const novelty = inputs.newDevice || inputs.newCountry;

  const fired = [];
  const rule = (id, min, description, when) => when && fired.push({ id, decision: min, description });
  rule('esc_impossible_travel', 'monitor', 'Impossible travel present: at least monitor', inputs.impossibleTravel);
  rule('esc_impossible_travel_sensitive', 'reverify', 'Impossible travel on a medium or higher sensitivity action: at least reverify', inputs.impossibleTravel && atLeast('medium'));
  rule('esc_travel_and_novelty', 'delay', 'Impossible travel with a new device or country on a high sensitivity action: at least delay', inputs.impossibleTravel && novelty && atLeast('high'));
  rule('esc_credential_cascade', 'reverify', 'Credential-change cascade on an account-modification action: at least reverify', inputs.sequence === 'credential_cascade' && ACCOUNT_MODIFICATION.includes(inputs.action));
  rule('esc_takeover_progression', 'block', 'Takeover progression on a high sensitivity action: block', inputs.sequence === 'takeover_progression' && atLeast('high'));
  rule('esc_automation', 'reverify', 'Automation burst on a medium or higher sensitivity action: at least reverify', inputs.timing === 'automation_burst' && atLeast('medium'));
  rule('esc_double_novelty', 'reverify', 'New device and new country on a medium or higher sensitivity action: at least reverify', inputs.newDevice && inputs.newCountry && atLeast('medium'));

  // Escalations can only raise the decision; the final decision is the strictest of all reasons.
  const decision = fired.reduce((acc, r) => maxOf(DECISION_ORDER, acc, r.decision), baseDecision);

  const concerns = [];
  if (inputs.newDevice || inputs.newCountry) concerns.push('a sign-in from an unfamiliar device or location');
  if (inputs.impossibleTravel) concerns.push('activity from places too far apart to be possible in the time');
  if (inputs.timing !== 'normal') concerns.push('unusual timing');
  if (inputs.sequence !== 'none') concerns.push('a sequence of account changes in a short period');
  const explanations = {
    allow: 'This action has been approved based on standard security checks.',
    monitor: 'This action was allowed and is being recorded for security review.',
    reverify: 'Additional identity verification is required before completing this action.',
    delay: 'For your protection this action will be held for a short cooling-off period. You can cancel it before it completes.',
    block: 'This action was stopped to protect your account.'
  };
  const userFacing = concerns.length ? `${explanations[decision]} We noticed ${concerns.join(', ')}.` : explanations[decision];

  return {
    sensitivity,
    score,
    riskTier,
    baseDecision,
    decision,
    fired,
    signals,
    terms: { base, context, sequence, timing, baseline, confidence },
    userFacing
  };
}

const GAUGE_COLOR = { low: '#10B981', medium: '#F59E0B', high: '#F97316', critical: '#EF4444' };

const checkboxClass = 'h-4 w-4 rounded border-white/20 bg-space-800 text-brand-cyan focus:ring-brand-cyan focus:ring-offset-space-900 cursor-pointer accent-[#35C5E8]';
const selectClass = 'mt-1.5 w-full rounded-xl bg-space-850/80 border border-white/10 px-3.5 py-2 text-sm text-ink-100 focus:border-brand-cyan focus:ring-1 focus:ring-brand-cyan transition-colors';

export function PolicyInspector() {
  const [inputs, setInputs] = useState(DEFAULT_INPUTS);
  const set = (patch) => setInputs((prev) => ({ ...prev, ...patch }));
  const result = useMemo(() => evaluateScenario(inputs), [inputs]);
  const tierMeta = TIER_META[result.decision];
  const defaultSensitivity = ACTIONS.find((a) => a.id === inputs.action)?.sensitivity || 'low';
  const { terms } = result;

  const onActionChange = (id) => {
    const next = ACTIONS.find((a) => a.id === id);
    set({ action: id, sensitivityOverride: next.sensitivity });
  };

  return (
    <div className="space-y-8" data-testid="policy-inspector">
      {/* 1. PRIMARY VISUAL STORYTELLING: Central 5-Stage Animated Security Pipeline */}
      <VisualSecurityFlow inputs={inputs} result={result} />

      {/* 2. COMPACT INTERACTIVE SIMULATOR COCKPIT & CONTROLS */}
      <div className="rounded-3xl border border-white/10 bg-space-900/60 backdrop-blur-xl p-6 sm:p-8 space-y-6">
        
        {/* Presets Quick Selector */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-5 border-b border-white/10">
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Simulate Real Attack &amp; Activity Scenarios
            </h3>
            <p className="text-xs text-ink-300 mt-0.5">Click any preset to see the 5-stage pipeline react in real time.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            {PRESETS.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => setInputs(p.inputs)}
                className="text-xs px-3 py-1.5 rounded-full border border-white/15 hover:border-brand-cyan hover:text-white text-ink-300 bg-white/[0.03] hover:bg-white/[0.08] transition-all"
                data-testid={`preset-${p.id}`}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        {/* 3-Column Compact Control Deck */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          
          {/* Column A: Action & Sensitivity */}
          <div className="rounded-2xl border border-white/5 bg-space-850/50 p-4 space-y-4">
            <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-brand-cyan">Action &amp; Target</h4>
            
            <label className="block text-xs font-medium text-ink-200">
              Requested Action
              <select value={inputs.action} onChange={(e) => onActionChange(e.target.value)} className={selectClass} data-testid="input-action">
                {ACTIONS.map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}
              </select>
            </label>

            <label className="block text-xs font-medium text-ink-200">
              Sensitivity Override <span className="text-[11px] text-ink-400 font-normal">(can only raise)</span>
              <select value={inputs.sensitivityOverride} onChange={(e) => set({ sensitivityOverride: e.target.value })} className={selectClass} data-testid="input-sensitivity">
                {SENSITIVITY_ORDER.map((s) => (
                  <option key={s} value={s} disabled={rank(SENSITIVITY_ORDER, s) < rank(SENSITIVITY_ORDER, defaultSensitivity)}>{s}</option>
                ))}
              </select>
            </label>

            <label className="block text-xs font-medium text-ink-200">
              Verification confidence: <span className="text-brand-cyan font-bold font-mono">{inputs.confidence}%</span>
              <input
                type="range"
                min="0"
                max="100"
                value={inputs.confidence}
                onChange={(e) => set({ confidence: Number(e.target.value) })}
                className="mt-2 w-full accent-[#35C5E8] cursor-pointer"
                data-testid="input-confidence"
              />
            </label>
          </div>

          {/* Column B: Session Signals */}
          <div className="rounded-2xl border border-white/5 bg-space-850/50 p-4 space-y-4">
            <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-brand-cyan">Session Signals</h4>
            
            <div className="space-y-3 pt-1">
              <label className="flex items-center justify-between text-xs text-ink-200 cursor-pointer p-1.5 rounded-lg hover:bg-white/5 transition-colors">
                <span>Unrecognized Device (+25)</span>
                <input type="checkbox" className={checkboxClass} checked={inputs.newDevice} onChange={(e) => set({ newDevice: e.target.checked })} data-testid="input-new-device" />
              </label>

              <label className="flex items-center justify-between text-xs text-ink-200 cursor-pointer p-1.5 rounded-lg hover:bg-white/5 transition-colors">
                <span>Unrecognized Country (+25)</span>
                <input type="checkbox" className={checkboxClass} checked={inputs.newCountry} onChange={(e) => set({ newCountry: e.target.checked })} data-testid="input-new-country" />
              </label>

              <label className="flex items-center justify-between text-xs text-ink-200 cursor-pointer p-1.5 rounded-lg hover:bg-white/5 transition-colors">
                <span>Impossible Travel Velocity (+28)</span>
                <input type="checkbox" className={checkboxClass} checked={inputs.impossibleTravel} onChange={(e) => set({ impossibleTravel: e.target.checked })} data-testid="input-travel" />
              </label>

              <label className="flex items-center justify-between text-xs text-ink-200 cursor-pointer p-1.5 rounded-lg hover:bg-white/5 transition-colors">
                <span>Deviates from User Baseline (+13)</span>
                <input type="checkbox" className={checkboxClass} checked={inputs.baselineDeviation} onChange={(e) => set({ baselineDeviation: e.target.checked })} data-testid="input-baseline" />
              </label>
            </div>
          </div>

          {/* Column C: Timing & Sequence */}
          <div className="rounded-2xl border border-white/5 bg-space-850/50 p-4 space-y-4">
            <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-brand-cyan">Timing &amp; Sequence</h4>
            
            <label className="block text-xs font-medium text-ink-200">
              Timing Anomaly Heuristics
              <select value={inputs.timing} onChange={(e) => set({ timing: e.target.value })} className={selectClass} data-testid="input-timing">
                <option value="normal">Normal (Typical user cadence)</option>
                <option value="unusual_hour">Unusual hour (+10)</option>
                <option value="automation_burst">Automation timing burst (+20)</option>
              </select>
            </label>

            <label className="block text-xs font-medium text-ink-200">
              Sequence Correlation
              <select value={inputs.sequence} onChange={(e) => set({ sequence: e.target.value })} className={selectClass} data-testid="input-sequence">
                <option value="none">None (Isolated action)</option>
                <option value="credential_cascade">Rapid credential cascade (+35)</option>
                <option value="takeover_progression">Takeover progression (+50)</option>
              </select>
            </label>
          </div>

        </div>

        {/* 3. EXPANDABLE TECHNICAL DETAILS & AUDIT BREAKDOWN */}
        <div className="pt-4 border-t border-white/10" aria-live="polite" data-testid="inspector-result">
          
          {/* Summary Verdict Bar */}
          <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-2xl bg-space-850/60 border border-white/10">
            <div className="flex items-center gap-4">
              <div>
                <span className="text-[10px] font-mono uppercase tracking-widest text-ink-400">Final Decision</span>
                <div className="flex items-center gap-2 mt-0.5">
                  <span
                    key={result.decision}
                    className="px-3.5 py-1 rounded-full text-base font-extrabold uppercase tracking-wide border shadow-sm"
                    style={{ color: tierMeta.color, borderColor: tierMeta.color, background: `${tierMeta.color}18` }}
                    data-testid="inspector-decision"
                  >
                    {tierMeta.label}
                  </span>
                  <span className="text-xs font-mono text-ink-400 capitalize" data-testid="inspector-risk-tier">
                    ({result.riskTier} risk tier)
                  </span>
                </div>
              </div>
            </div>

            <div className="text-right">
              <span className="text-[10px] font-mono uppercase tracking-widest text-ink-400">Computed Score</span>
              <div className="text-xl font-extrabold font-mono" style={{ color: GAUGE_COLOR[result.riskTier] }} data-testid="inspector-score">
                {result.score} / 100
              </div>
            </div>
          </div>

          {/* Expandable Technical Accordion */}
          <div className="mt-4 space-y-3">
            
            {/* Accordion Item 1: Why this decision? */}
            <details className="group rounded-2xl border border-white/10 bg-space-850/40 p-4 transition-all" open>
              <summary className="cursor-pointer font-semibold text-sm text-brand-cyan flex items-center justify-between select-none">
                <span>Why this decision? (PDP Rule Breakdown)</span>
                <span className="text-xs font-mono text-ink-400 group-open:rotate-180 transition-transform">&darr;</span>
              </summary>
              <div className="mt-3 space-y-2 text-xs text-ink-300 pt-2 border-t border-white/5">
                <p>
                  Base matrix (<span className="text-white font-medium">{result.sensitivity}</span> sensitivity, <span className="text-white font-medium">{result.riskTier}</span> risk): <b style={{ color: TIER_META[result.baseDecision].color }}>{result.baseDecision}</b>
                </p>
                {result.fired.length === 0 ? (
                  <p className="text-emerald-400">No escalation rules fired. Baseline matrix verdict governs.</p>
                ) : (
                  <ul className="space-y-1.5" data-testid="inspector-rules">
                    {result.fired.map((r) => (
                      <li key={r.id} className="p-2 rounded-lg bg-space-900/60 border border-white/5 flex items-baseline gap-2">
                        <code className="text-[11px] font-mono text-brand-cyan">{r.id}</code>
                        <span>&rarr; enforces minimum <b className="text-white uppercase">{r.decision}</b>. {r.description}</span>
                      </li>
                    ))}
                  </ul>
                )}
                <p className="text-[11px] text-ink-400">
                  Policies determine the final response: the verdict is the strictest of the base decision and every fired rule.
                </p>
              </div>
            </details>

            {/* Accordion Item 2: User Explanation */}
            <details className="group rounded-2xl border border-white/10 bg-space-850/40 p-4 transition-all">
              <summary className="cursor-pointer font-semibold text-sm text-ink-200 hover:text-brand-cyan flex items-center justify-between select-none">
                <span>What the user sees (PEP User Notice)</span>
                <span className="text-xs font-mono text-ink-400 group-open:rotate-180 transition-transform">&darr;</span>
              </summary>
              <div className="mt-3 text-xs text-ink-200 pt-2 border-t border-white/5 leading-relaxed" data-testid="inspector-explanation">
                {result.userFacing}
              </div>
            </details>

            {/* Accordion Item 3: Contributing Signals */}
            <details className="group rounded-2xl border border-white/10 bg-space-850/40 p-4 transition-all">
              <summary className="cursor-pointer font-semibold text-sm text-ink-200 hover:text-brand-cyan flex items-center justify-between select-none">
                <span>Contributing signals &amp; additive weights</span>
                <span className="text-xs font-mono text-ink-400 group-open:rotate-180 transition-transform">&darr;</span>
              </summary>
              <div className="mt-3 pt-2 border-t border-white/5">
                <ul className="space-y-1.5 text-xs" data-testid="inspector-signals">
                  {result.signals.map((s) => (
                    <li key={s.label} className="flex justify-between items-center py-1 border-b border-white/5 last:border-0">
                      <span className="text-ink-200 font-medium">{s.label} <span className="text-[11px] text-ink-400 font-mono">({s.category})</span></span>
                      <span className={`font-mono font-bold ${s.weight < 0 ? 'text-state-ok' : 'text-amber-400'}`}>
                        {s.weight > 0 ? `+${s.weight}` : s.weight}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            </details>

            {/* Accordion Item 4: Scoring Formula */}
            <details className="group rounded-2xl border border-white/10 bg-space-850/40 p-4 transition-all">
              <summary className="cursor-pointer font-semibold text-sm text-ink-200 hover:text-brand-cyan flex items-center justify-between select-none">
                <span>Mathematical scoring equation</span>
                <span className="text-xs font-mono text-ink-400 group-open:rotate-180 transition-transform">&darr;</span>
              </summary>
              <div className="mt-3 pt-2 border-t border-white/5">
                <div className="rounded-xl bg-space-900/80 border border-white/10 p-3 font-mono text-xs text-ink-300">
                  Score = <b className="text-brand-cyan">{terms.base}</b> base + <b className="text-brand-cyan">{terms.context}</b> context + <b className="text-brand-cyan">{terms.sequence}</b> sequence + <b className="text-brand-cyan">{terms.timing}</b> timing + <b className="text-brand-cyan">{terms.baseline}</b> baseline &minus; <b className="text-emerald-400">{terms.confidence}</b> confidence = <b className="text-white">{result.score}</b>
                </div>
              </div>
            </details>

          </div>

          <p className="mt-4 text-[11px] text-ink-500 font-mono">
            Educational mirror of the server Policy Decision Point. The server policy engine remains authoritative.
          </p>
        </div>

      </div>
    </div>
  );
}

export default PolicyInspector;
