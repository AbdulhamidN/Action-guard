import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiRequest } from '../../services/apiClient.js';
import { Spinner } from '../../components/common/Spinner.jsx';
import { ErrorBanner } from '../../components/common/ErrorBanner.jsx';

const DECISION_BADGES = {
  allow: 'bg-emerald-100 text-emerald-800 border-emerald-300',
  monitor: 'bg-blue-100 text-blue-800 border-blue-300',
  reverify: 'bg-purple-100 text-purple-800 border-purple-300',
  delay: 'bg-amber-100 text-amber-800 border-amber-300',
  block: 'bg-red-100 text-red-800 border-red-300'
};

const TIERS = ['low', 'medium', 'high', 'critical'];
const SENSITIVITIES = ['low', 'medium', 'high', 'critical'];

/**
 * Read-Only Policy Rules and Matrix Page (/admin/policy).
 *
 * Visualizes the authoritative zero-trust decision matrix, escalation overrides,
 * fail-safe fallbacks, and enforcement mode configuration.
 */
export function PolicyPage() {
  const { data: policy, isLoading, error } = useQuery({
    queryKey: ['policy'],
    queryFn: () => apiRequest('/admin/policy', { authMode: 'admin' })
  });

  if (isLoading) {
    return (
      <div className="p-16 flex justify-center items-center" data-testid="policy-loading">
        <Spinner />
      </div>
    );
  }

  if (error || !policy) {
    return (
      <div className="space-y-4">
        <ErrorBanner
          message={error?.message || 'Failed to load policy definition.'}
          onDismiss={() => {}}
        />
      </div>
    );
  }

  const baseMatrix = policy.BASE_MATRIX || {};
  const escalationRules = policy.ESCALATION_RULES || [];
  const failSafeRules = policy.FAIL_SAFE_BY_SENSITIVITY || {};
  const enforcementModes = policy.ENFORCEMENT_MODE_BY_DECISION || {};
  const defaultSensitivities = policy.DEFAULT_ACTION_SENSITIVITY || {};
  const recommendedActions = policy.RECOMMENDED_ACTIONS || {};

  return (
    <div className="space-y-8" data-testid="admin-policy-page">
      {/* Header & Meta */}
      <div>
        <h2 className="text-xl font-bold text-gray-900" data-testid="policy-title">
          Authoritative Security Policy Rules
        </h2>
        <p className="mt-0.5 text-xs text-gray-500">
          Inspection of active zero-trust decision matrix, escalation predicates, and fail-safe boundaries.
        </p>

        <div className="mt-4 flex flex-wrap items-center gap-3 text-xs">
          <span className="inline-flex items-center px-2.5 py-1 rounded bg-indigo-50 text-indigo-700 font-mono font-bold border border-indigo-200">
            Policy ID: {policy.policy_id}
          </span>
          <span className="inline-flex items-center px-2.5 py-1 rounded bg-gray-100 text-gray-700 font-mono">
            Schema Version: {policy.schema_version}
          </span>
          <span className="text-gray-500 italic">
            {policy.description}
          </span>
        </div>
      </div>

      {/* 4x4 Decision Base Matrix */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden" data-testid="policy-matrix-card">
        <div className="p-4 bg-gray-50 border-b border-gray-200">
          <h3 className="text-sm font-bold text-gray-900">4x4 Baseline Decision Matrix</h3>
          <p className="text-xs text-gray-500 mt-0.5">
            Intersects evaluated Risk Tier (vertical) with Action Sensitivity (horizontal).
          </p>
        </div>

        <div className="overflow-x-auto p-4">
          <table className="min-w-full text-center text-xs border-collapse" data-testid="base-matrix-table">
            <thead>
              <tr>
                <th className="p-3 text-left font-bold text-gray-500 uppercase bg-gray-50 border border-gray-200">
                  Risk Tier \ Sensitivity
                </th>
                {SENSITIVITIES.map((s) => (
                  <th key={s} className="p-3 font-bold text-gray-700 uppercase bg-gray-50 border border-gray-200">
                    {s} Sensitivity
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {TIERS.map((tier) => (
                <tr key={tier} className="hover:bg-gray-50/50">
                  <td className="p-3 text-left font-bold uppercase text-gray-800 bg-gray-50 border border-gray-200">
                    {tier} Risk
                  </td>
                  {SENSITIVITIES.map((sensitivity) => {
                    const outcome = baseMatrix[tier]?.[sensitivity] || 'allow';
                    const badgeClass = DECISION_BADGES[outcome] || 'bg-gray-100 text-gray-800 border-gray-300';

                    return (
                      <td key={sensitivity} className="p-3 border border-gray-200">
                        <span
                          className={`inline-flex items-center px-2.5 py-1 rounded text-xs font-bold uppercase border ${badgeClass}`}
                          data-testid={`matrix-cell-${tier}-${sensitivity}`}
                        >
                          {outcome}
                        </span>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Escalation Rules & Fail-Safe Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Escalation Overrides */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden" data-testid="escalation-rules-card">
          <div className="p-4 bg-gray-50 border-b border-gray-200">
            <h3 className="text-sm font-bold text-gray-900">Escalation Override Rules</h3>
            <p className="text-xs text-gray-500 mt-0.5">
              Specific threat signals or behavioral sequences that elevate baseline decisions.
            </p>
          </div>

          <div className="divide-y divide-gray-100 max-h-96 overflow-y-auto">
            {escalationRules.map((rule) => {
              const badgeClass = DECISION_BADGES[rule.min_decision] || 'bg-gray-100 text-gray-800';

              return (
                <div key={rule.id} className="p-4 hover:bg-gray-50 text-xs space-y-1.5" data-testid="escalation-rule-item">
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-gray-900">{rule.id}</span>
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold uppercase border ${badgeClass}`}>
                      Min: {rule.min_decision}
                    </span>
                  </div>
                  <p className="text-gray-600 font-mono text-[11px]">{rule.description}</p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Fail-Safe & Enforcement Modes */}
        <div className="space-y-6">
          {/* Fail-Safe Defaults */}
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden" data-testid="fail-safe-card">
            <div className="p-4 bg-gray-50 border-b border-gray-200">
              <h3 className="text-sm font-bold text-gray-900">Fail-Safe Boundaries by Sensitivity</h3>
              <p className="text-xs text-gray-500 mt-0.5">
                Default fallback responses applied when telemetry or risk scoring is interrupted.
              </p>
            </div>
            <div className="p-4">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {Object.entries(failSafeRules).map(([sensitivity, decision]) => {
                  const badgeClass = DECISION_BADGES[decision] || 'bg-gray-100 text-gray-800 border-gray-300';
                  return (
                    <div key={sensitivity} className="p-3 bg-gray-50 rounded border border-gray-200 text-center text-xs">
                      <div className="text-gray-500 uppercase font-semibold text-[10px]">{sensitivity}</div>
                      <div className="mt-1.5">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold uppercase border ${badgeClass}`}>
                          {decision}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Enforcement Modes */}
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden" data-testid="enforcement-modes-card">
            <div className="p-4 bg-gray-50 border-b border-gray-200">
              <h3 className="text-sm font-bold text-gray-900">Enforcement Modes</h3>
              <p className="text-xs text-gray-500 mt-0.5">
                Execution strategy per decision (automatic vs manual operator confirmation).
              </p>
            </div>
            <div className="p-4">
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs">
                {Object.entries(enforcementModes).map(([decision, mode]) => (
                  <div key={decision} className="p-2.5 bg-gray-50 rounded border border-gray-200 text-center">
                    <div className="font-bold uppercase text-gray-700 text-[10px]">{decision}</div>
                    <div className="font-mono text-indigo-600 font-semibold mt-1">{mode}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Action Sensitivity Catalog */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden" data-testid="sensitivities-catalog-card">
        <div className="p-4 bg-gray-50 border-b border-gray-200">
          <h3 className="text-sm font-bold text-gray-900">Default Action Sensitivity Catalog</h3>
          <p className="text-xs text-gray-500 mt-0.5">
            Initial baseline sensitivity assigned to each platform action.
          </p>
        </div>
        <div className="p-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3 text-xs">
            {Object.entries(defaultSensitivities).map(([action, sensitivity]) => (
              <div key={action} className="p-2.5 bg-gray-50 rounded border border-gray-200 flex items-center justify-between">
                <span className="font-mono text-[11px] text-gray-800 truncate mr-2" title={action}>
                  {action}
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    sensitivity === 'critical'
                      ? 'bg-red-100 text-red-800'
                      : sensitivity === 'high'
                      ? 'bg-orange-100 text-orange-800'
                      : sensitivity === 'medium'
                      ? 'bg-amber-100 text-amber-800'
                      : 'bg-emerald-100 text-emerald-800'
                  }`}
                >
                  {sensitivity}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
export default PolicyPage;
