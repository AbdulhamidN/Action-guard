import React, { useMemo, useState } from 'react';
import { DECISION_ORDER, TIER_META } from './tiers.js';

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

const checkboxClass = 'h-4 w-4 accent-cyan-500';
const selectClass = 'mt-1 w-full rounded-lg bg-space-800 border border-white/10 px-3 py-2 text-sm text-ink-100 focus:border-neon-cyan';

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
    <div className="grid lg:grid-cols-5 gap-6" data-testid="policy-inspector">
      <div className="lg:col-span-2 rounded-2xl border border-white/10 bg-white/[0.04] backdrop-blur-md p-5 space-y-4">
        <div>
          <p className="text-xs uppercase tracking-widest text-ink-300">Presets</p>
          <div className="mt-2 flex flex-wrap gap-2">
            {PRESETS.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => setInputs(p.inputs)}
                className="text-xs px-3 py-1.5 rounded-full border border-white/15 hover:border-neon-cyan hover:text-white text-ink-300"
                data-testid={`preset-${p.id}`}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        <label className="block text-sm">
          Action
          <select value={inputs.action} onChange={(e) => onActionChange(e.target.value)} className={selectClass} data-testid="input-action">
            {ACTIONS.map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}
          </select>
        </label>

        <label className="block text-sm">
          Action sensitivity (can only be raised)
          <select value={inputs.sensitivityOverride} onChange={(e) => set({ sensitivityOverride: e.target.value })} className={selectClass} data-testid="input-sensitivity">
            {SENSITIVITY_ORDER.map((s) => (
              <option key={s} value={s} disabled={rank(SENSITIVITY_ORDER, s) < rank(SENSITIVITY_ORDER, defaultSensitivity)}>{s}</option>
            ))}
          </select>
        </label>

        <fieldset className="space-y-2 text-sm">
          <legend className="text-xs uppercase tracking-widest text-ink-300 mb-1">Signals</legend>
          <label className="flex items-center justify-between gap-3"><span>New device</span><input type="checkbox" className={checkboxClass} checked={inputs.newDevice} onChange={(e) => set({ newDevice: e.target.checked })} data-testid="input-new-device" /></label>
          <label className="flex items-center justify-between gap-3"><span>New country</span><input type="checkbox" className={checkboxClass} checked={inputs.newCountry} onChange={(e) => set({ newCountry: e.target.checked })} data-testid="input-new-country" /></label>
          <label className="flex items-center justify-between gap-3"><span>Impossible travel</span><input type="checkbox" className={checkboxClass} checked={inputs.impossibleTravel} onChange={(e) => set({ impossibleTravel: e.target.checked })} data-testid="input-travel" /></label>
          <label className="flex items-center justify-between gap-3"><span>Deviates from personal baseline</span><input type="checkbox" className={checkboxClass} checked={inputs.baselineDeviation} onChange={(e) => set({ baselineDeviation: e.target.checked })} data-testid="input-baseline" /></label>
        </fieldset>

        <label className="block text-sm">
          Timing
          <select value={inputs.timing} onChange={(e) => set({ timing: e.target.value })} className={selectClass} data-testid="input-timing">
            <option value="normal">Normal</option>
            <option value="unusual_hour">Unusual hour</option>
            <option value="automation_burst">Automation burst</option>
          </select>
        </label>

        <label className="block text-sm">
          Sequence
          <select value={inputs.sequence} onChange={(e) => set({ sequence: e.target.value })} className={selectClass} data-testid="input-sequence">
            <option value="none">None</option>
            <option value="credential_cascade">Rapid credential cascade</option>
            <option value="takeover_progression">Takeover progression</option>
          </select>
        </label>

        <label className="block text-sm">
          Verification confidence: {inputs.confidence}%
          <input type="range" min="0" max="100" value={inputs.confidence} onChange={(e) => set({ confidence: Number(e.target.value) })} className="mt-2 w-full accent-cyan-500" data-testid="input-confidence" />
        </label>
      </div>

      <div className="lg:col-span-3 rounded-2xl border border-white/10 bg-white/[0.04] backdrop-blur-md p-5" aria-live="polite" data-testid="inspector-result">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-xs uppercase tracking-widest text-ink-300">Decision</p>
            <p
              key={result.decision}
              className="mt-1 inline-block px-4 py-1.5 rounded-full border text-lg font-extrabold animate-ag-rise"
              style={{ color: tierMeta.color, borderColor: tierMeta.color, background: `${tierMeta.color}1A` }}
              data-testid="inspector-decision"
            >
              {tierMeta.label}
            </p>
          </div>
          <div className="text-right text-sm">
            <p className="text-ink-300">Risk tier</p>
            <p className="font-semibold capitalize" data-testid="inspector-risk-tier">{result.riskTier}</p>
          </div>
        </div>

        <div className="mt-5">
          <div className="flex justify-between text-xs text-ink-300">
            <span>Risk score (illustrative)</span>
            <span data-testid="inspector-score">{result.score} / 100</span>
          </div>
          <div className="mt-1 h-3 rounded-full bg-space-800 overflow-hidden" role="img" aria-label={`Risk score ${result.score} out of 100, ${result.riskTier} tier`}>
            <div className="h-full rounded-full transition-all duration-500" style={{ width: `${result.score}%`, background: GAUGE_COLOR[result.riskTier] }} />
          </div>
        </div>

        <p className="mt-5 rounded-lg bg-space-900/70 border border-white/10 p-3 font-mono text-xs text-ink-300">
          Score = <b className="text-neon-cyan">{terms.base}</b> base + <b className="text-neon-cyan">{terms.context}</b> context + <b className="text-neon-cyan">{terms.sequence}</b> sequence + <b className="text-neon-cyan">{terms.timing}</b> timing + <b className="text-neon-cyan">{terms.baseline}</b> baseline &minus; <b className="text-neon-cyan">{terms.confidence}</b> confidence
        </p>

        <div className="mt-5">
          <p className="text-xs uppercase tracking-widest text-ink-300">What the user would see</p>
          <p className="mt-1 text-sm text-ink-100" data-testid="inspector-explanation">{result.userFacing}</p>
        </div>

        <div className="mt-5">
          <p className="text-xs uppercase tracking-widest text-ink-300">Contributing signals</p>
          <ul className="mt-2 space-y-1 text-sm" data-testid="inspector-signals">
            {result.signals.map((s) => (
              <li key={s.label} className="flex justify-between gap-3">
                <span className="text-ink-100">{s.label} <span className="text-xs text-ink-500">({s.category})</span></span>
                <span className={s.weight < 0 ? 'text-state-ok' : 'text-ink-300'}>{s.weight > 0 ? `+${s.weight}` : s.weight}</span>
              </li>
            ))}
          </ul>
        </div>

        <details className="mt-5 text-sm">
          <summary className="cursor-pointer text-neon-cyan">Why this decision?</summary>
          <div className="mt-2 space-y-2 text-ink-300">
            <p>Base matrix ({result.sensitivity} sensitivity, {result.riskTier} risk): <b style={{ color: TIER_META[result.baseDecision].color }}>{result.baseDecision}</b></p>
            {result.fired.length === 0 ? (
              <p>No escalation rules fired.</p>
            ) : (
              <ul className="space-y-1" data-testid="inspector-rules">
                {result.fired.map((r) => (
                  <li key={r.id}><code className="text-xs text-neon-indigo">{r.id}</code> &rarr; min {r.decision}. {r.description}</li>
                ))}
              </ul>
            )}
            <p>Final decision is the strictest of the base decision and every fired rule. Rules can only raise it.</p>
          </div>
        </details>

        <p className="mt-5 text-xs text-ink-500">Educational client-side mirror of the server Policy Decision Point. Weights and thresholds are illustrative; the server remains authoritative.</p>
      </div>
    </div>
  );
}

export default PolicyInspector;
