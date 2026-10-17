import React from 'react';

/**
 * @typedef {'low' | 'medium' | 'high' | 'critical'} RiskTier
 */

/**
 * TierBadge displays a risk tier with an explicit text label and an icon.
 * In accordance with accessibility principles, it never relies on color alone.
 *
 * @param {{ tier: RiskTier | string }} props
 */
export function TierBadge({ tier }) {
  const normalized = typeof tier === 'string' ? tier.toLowerCase().trim() : 'unknown';

  let config = {
    label: 'Unknown',
    badgeClass: 'bg-gray-100 text-gray-800 border-gray-300',
    icon: (
      <svg className="w-3.5 h-3.5 mr-1 inline-block" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    )
  };

  switch (normalized) {
    case 'low':
      config = {
        label: 'Low',
        badgeClass: 'bg-emerald-50 text-emerald-800 border-emerald-300',
        icon: (
          <svg className="w-3.5 h-3.5 mr-1 inline-block text-emerald-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true" data-testid="tier-icon-low">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        )
      };
      break;
    case 'medium':
      config = {
        label: 'Medium',
        badgeClass: 'bg-amber-50 text-amber-800 border-amber-300',
        icon: (
          <svg className="w-3.5 h-3.5 mr-1 inline-block text-amber-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true" data-testid="tier-icon-medium">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        )
      };
      break;
    case 'high':
      config = {
        label: 'High',
        badgeClass: 'bg-orange-50 text-orange-800 border-orange-300',
        icon: (
          <svg className="w-3.5 h-3.5 mr-1 inline-block text-orange-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true" data-testid="tier-icon-high">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        )
      };
      break;
    case 'critical':
      config = {
        label: 'Critical',
        badgeClass: 'bg-red-50 text-red-800 border-red-300',
        icon: (
          <svg className="w-3.5 h-3.5 mr-1 inline-block text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true" data-testid="tier-icon-critical">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
          </svg>
        )
      };
      break;
    default:
      break;
  }

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${config.badgeClass}`}
      data-testid={`tier-badge-${normalized}`}
      role="status"
      aria-label={`Risk tier: ${config.label}`}
    >
      {config.icon}
      <span>{config.label}</span>
    </span>
  );
}
