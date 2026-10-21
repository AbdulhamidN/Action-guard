// Single source of truth for the five ordered responses and their colors.
// Mirrors DECISION_ORDER and RECOMMENDED_ACTIONS in policies/default-v1.json.
export const DECISION_ORDER = ['allow', 'monitor', 'reverify', 'delay', 'block'];

export const TIER_META = {
  allow: { color: '#10B981', label: 'Allow', behavior: 'Unchecked execution. The action proceeds normally.' },
  monitor: { color: '#38BDF8', label: 'Monitor', behavior: 'The action proceeds, and it is logged and audited for telemetry.' },
  reverify: { color: '#F59E0B', label: 'Reverify', behavior: 'Step-up OTP required. A scoped, ES256-signed elevation completes the action.' },
  delay: { color: '#F97316', label: 'Delay', behavior: 'Held in a cooling-off queue with a single-use cancellation token.' },
  block: { color: '#EF4444', label: 'Block', behavior: 'Request blocked. At critical risk the session is invalidated and the account is locked for 15 minutes.' }
};
