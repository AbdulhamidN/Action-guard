import React, { useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  ReactFlow,
  Background,
  Controls,
  MarkerType
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import { apiRequest } from '../../services/apiClient.js';
import { TierBadge } from '../../components/common/TierBadge.jsx';
import { Spinner } from '../../components/common/Spinner.jsx';
import { ErrorBanner } from '../../components/common/ErrorBanner.jsx';
import { EmptyState } from '../../components/common/EmptyState.jsx';

/**
 * Builds deterministic 5-column causal graph nodes and edges for React Flow.
 * Pure mapping from decision model to { nodes, edges }.
 *
 * @param {any} decision
 * @returns {{ nodes: any[], edges: any[] }}
 */
export function buildDecisionGraph(decision) {
  if (!decision) return { nodes: [], edges: [] };

  const signals = decision.contributing_signals || [];
  const flowNodes = [];
  const flowEdges = [];

  // Column X positions
  const COL_SIGNALS = 40;
  const COL_ASSESSMENT = 340;
  const COL_REASONS = 640;
  const COL_DECISION = 940;
  const COL_OUTCOME = 1240;

  // Center Y position for downstream nodes
  const signalsCount = Math.max(signals.length, 1);
  const centerY = Math.max(60, (signalsCount * 85) / 2);

  // 1. Column 1: Signal Nodes
  if (signals.length === 0) {
    flowNodes.push({
      id: 'node-signal-none',
      position: { x: COL_SIGNALS, y: centerY },
      data: {
        label: (
          <div className="p-3 text-xs text-gray-500 bg-gray-50 border border-gray-200 rounded-md shadow-sm">
            <span className="font-semibold">Baseline Action</span>
            <p className="text-[10px] text-gray-400">No anomalous signals triggered</p>
          </div>
        )
      },
      style: { width: 220 }
    });
    flowEdges.push({
      id: 'edge-signal-none-ra',
      source: 'node-signal-none',
      target: 'node-assessment',
      animated: true,
      markerEnd: { type: MarkerType.ArrowClosed }
    });
  } else {
    signals.forEach((sig, idx) => {
      const nodeId = `node-signal-${idx}`;
      const weight = Number(sig.weight || 0);
      const isMitigating = weight < 0;
      const posY = 30 + idx * 85;

      flowNodes.push({
        id: nodeId,
        position: { x: COL_SIGNALS, y: posY },
        data: {
          label: (
            <div
              className={`p-3 text-xs rounded-md shadow-sm border ${
                isMitigating
                  ? 'bg-emerald-50 border-emerald-300 text-emerald-950'
                  : 'bg-red-50 border-red-300 text-red-950'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-mono font-bold truncate max-w-[140px]" title={sig.signal}>
                  {sig.signal}
                </span>
                <span
                  className={`font-mono text-xs font-bold px-1.5 py-0.5 rounded ${
                    isMitigating ? 'bg-emerald-200 text-emerald-800' : 'bg-red-200 text-red-800'
                  }`}
                >
                  {weight > 0 ? `+${weight}` : weight}
                </span>
              </div>
              <div className="mt-1 flex items-center justify-between text-[10px]">
                <span className="text-gray-500 uppercase font-semibold">{sig.category || 'signal'}</span>
                <span className="font-medium italic">
                  {isMitigating ? 'Mitigating signal' : 'Aggravating signal'}
                </span>
              </div>
            </div>
          )
        },
        style: { width: 240 }
      });

      // Edge to Assessment
      flowEdges.push({
        id: `edge-${nodeId}-assessment`,
        source: nodeId,
        target: 'node-assessment',
        label: isMitigating ? `Mitigating (${weight})` : `Aggravating (+${weight})`,
        labelStyle: { fill: isMitigating ? '#047857' : '#b91c1c', fontSize: 10, fontWeight: 600 },
        style: { stroke: isMitigating ? '#10b981' : '#ef4444', strokeWidth: 2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: isMitigating ? '#10b981' : '#ef4444' }
      });
    });
  }

  // 2. Column 2: Risk Assessment Node
  flowNodes.push({
    id: 'node-assessment',
    position: { x: COL_ASSESSMENT, y: centerY },
    data: {
      label: (
        <div className="p-4 bg-white border-2 border-indigo-500 rounded-lg shadow-md text-xs space-y-2">
          <div className="text-[10px] font-bold uppercase tracking-wider text-indigo-600">
            Risk Assessment
          </div>
          <div className="flex items-center justify-between">
            <span className="text-gray-600">Score:</span>
            <span className="font-mono text-base font-extrabold text-gray-900" data-testid="graph-node-risk-score">
              {decision.risk_score}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-gray-600">Tier:</span>
            <TierBadge tier={decision.risk_tier} />
          </div>
          {decision.risk_assessment_id && (
            <div className="font-mono text-[9px] text-gray-400 truncate max-w-[170px]" title={decision.risk_assessment_id}>
              {decision.risk_assessment_id}
            </div>
          )}
        </div>
      )
    },
    style: { width: 220 }
  });

  // 3. Column 3: Policy Reasons Node
  const reasons = decision.reasons || [];
  flowNodes.push({
    id: 'node-reasons',
    position: { x: COL_REASONS, y: centerY },
    data: {
      label: (
        <div className="p-4 bg-white border border-gray-300 rounded-lg shadow-sm text-xs space-y-2">
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-700">
            Policy Evaluation Rules
          </div>
          <div className="space-y-1.5 max-h-36 overflow-y-auto">
            {reasons.length > 0 ? (
              reasons.map((r, i) => (
                <div key={i} className="bg-gray-50 p-1.5 rounded border border-gray-200 text-[11px]">
                  <span className="font-semibold text-gray-800">{r.rule_id || r.source}</span>
                  {r.reason && <p className="text-[10px] text-gray-600 mt-0.5">{r.reason}</p>}
                </div>
              ))
            ) : (
              <div className="text-gray-500 italic text-[11px]">Base matrix evaluation</div>
            )}
          </div>
          {decision.policy_version && (
            <div className="font-mono text-[9px] text-gray-400">Policy: {decision.policy_version}</div>
          )}
        </div>
      )
    },
    style: { width: 220 }
  });

  // Edge Assessment -> Reasons
  flowEdges.push({
    id: 'edge-assessment-reasons',
    source: 'node-assessment',
    target: 'node-reasons',
    label: 'Policy Input',
    labelStyle: { fill: '#4f46e5', fontSize: 10, fontWeight: 600 },
    style: { stroke: '#6366f1', strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#6366f1' }
  });

  // 4. Column 4: Effective Decision Node
  flowNodes.push({
    id: 'node-decision',
    position: { x: COL_DECISION, y: centerY },
    data: {
      label: (
        <div className="p-4 bg-white border-2 border-indigo-600 rounded-lg shadow-md text-xs space-y-2">
          <div className="text-[10px] font-bold uppercase tracking-wider text-indigo-600">
            Effective Decision
          </div>
          <div>
            <span
              className="inline-flex items-center px-2.5 py-1 rounded text-xs font-extrabold uppercase bg-indigo-50 text-indigo-700 border border-indigo-200"
              data-testid="graph-node-effective-decision"
            >
              {decision.effective_decision}
            </span>
          </div>
          <div className="text-[11px] text-gray-600">
            Sensitivity:{' '}
            <span className="font-semibold uppercase text-gray-900">{decision.action_sensitivity || 'N/A'}</span>
          </div>
          {decision.recommended_decision && decision.recommended_decision !== decision.effective_decision && (
            <div className="text-[10px] text-amber-700 bg-amber-50 p-1 rounded">
              Recommended: {decision.recommended_decision}
            </div>
          )}
        </div>
      )
    },
    style: { width: 200 }
  });

  // Edge Reasons -> Decision
  flowEdges.push({
    id: 'edge-reasons-decision',
    source: 'node-reasons',
    target: 'node-decision',
    label: 'Selected Outcome',
    labelStyle: { fill: '#4f46e5', fontSize: 10, fontWeight: 600 },
    style: { stroke: '#6366f1', strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#6366f1' }
  });

  // 5. Column 5: Enforcement Outcome Node
  flowNodes.push({
    id: 'node-outcome',
    position: { x: COL_OUTCOME, y: centerY },
    data: {
      label: (
        <div className="p-4 bg-white border border-gray-300 rounded-lg shadow-sm text-xs space-y-2">
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-700">
            Enforcement Outcome
          </div>
          <div className="font-mono font-bold text-gray-900" data-testid="graph-node-outcome">
            {decision.enforcement_outcome}
          </div>
          <div className="text-[10px] text-gray-500">
            Mode: <span className="font-semibold">{decision.enforcement_mode || 'automatic'}</span>
          </div>
        </div>
      )
    },
    style: { width: 200 }
  });

  // Edge Decision -> Outcome
  flowEdges.push({
    id: 'edge-decision-outcome',
    source: 'node-decision',
    target: 'node-outcome',
    label: 'Enforced',
    labelStyle: { fill: '#64748b', fontSize: 10, fontWeight: 600 },
    style: { stroke: '#94a3b8', strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#94a3b8' }
  });

  return { nodes: flowNodes, edges: flowEdges };
}

export function DecisionGraphPage() {
  const { userId, decisionId } = useParams();

  // Query user decisions
  const { data: decisions = [], isLoading, error } = useQuery({
    queryKey: ['user-decisions', userId],
    queryFn: () => apiRequest(`/admin/users/${userId}/decisions`, { authMode: 'admin' }),
    enabled: !!userId
  });

  const decision = useMemo(() => {
    if (!Array.isArray(decisions)) return null;
    return decisions.find((d) => d.decision_id === decisionId) || null;
  }, [decisions, decisionId]);

  // Extract signals and calculate reconciliation
  const signals = decision?.contributing_signals || [];
  const riskScore = decision?.risk_score !== undefined ? Number(decision.risk_score) : null;

  const weightSum = useMemo(() => {
    return signals.reduce((acc, s) => acc + Number(s.weight || 0), 0);
  }, [signals]);

  const hasScoreMismatch = riskScore !== null && weightSum !== riskScore;

  // Build deterministic 5-column nodes and edges for React Flow
  const { nodes, edges } = useMemo(() => {
    return buildDecisionGraph(decision);
  }, [decision]);

  if (isLoading) {
    return (
      <div className="p-16 flex justify-center items-center" data-testid="graph-loading">
        <Spinner />
      </div>
    );
  }

  if (error || !decision) {
    return (
      <div className="space-y-4">
        <Link to={`/admin/users/${userId}`} className="text-xs font-semibold text-indigo-600 hover:text-indigo-800">
          &larr; Back to User Detail
        </Link>
        <EmptyState
          title="Decision not found"
          description={`Decision ID "${decisionId}" was not found for user "${userId}".`}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="decision-graph-page">
      {/* Breadcrumb & Title */}
      <div>
        <nav className="mb-2">
          <Link
            to={`/admin/users/${userId}`}
            data-testid="back-to-user-detail"
            className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 inline-flex items-center"
          >
            &larr; Back to User Investigation ({userId})
          </Link>
        </nav>
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <div>
            <h2 className="text-xl font-bold text-gray-900" data-testid="decision-graph-title">
              Decision Explanation Graph: <span className="font-mono text-indigo-600">{decisionId}</span>
            </h2>
            <p className="mt-0.5 text-xs text-gray-500">
              Deterministic causal traceability from signal inputs through policy matrix to enforcement outcome.
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <span className="text-xs text-gray-500">Decided:</span>
            <time className="text-xs font-medium text-gray-700">
              {new Date(decision.decided_at).toLocaleString()}
            </time>
          </div>
        </div>
      </div>

      {/* Score Reconciliation Warning */}
      {hasScoreMismatch && (
        <div
          className="bg-amber-50 border-l-4 border-amber-400 p-4 rounded-r-md shadow-sm"
          role="alert"
          data-testid="reconciliation-warning"
        >
          <div className="flex items-start">
            <svg className="h-5 w-5 text-amber-500 mr-3 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <div>
              <h3 className="text-xs font-bold text-amber-800">
                Mathematical Weight-to-Score Divergence Detected
              </h3>
              <p className="mt-1 text-xs text-amber-700">
                Sum of raw contributing signal weights ({weightSum > 0 ? `+${weightSum}` : weightSum}) does not equal final evaluated risk score ({riskScore}). This is expected when baseline floor/ceiling thresholds, category decay weights, or policy normalization rules adjust raw totals.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Interactive Explanation Graph Canvas */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        <div className="px-5 py-3 bg-gray-50 border-b border-gray-200 flex items-center justify-between">
          <div className="text-xs font-semibold text-gray-700">
            Graph Topology: 5 Deterministic Columns (Signals &rarr; Risk &rarr; Rules &rarr; Decision &rarr; Outcome)
          </div>
          <div className="flex items-center space-x-3 text-[11px] text-gray-500">
            <span className="inline-flex items-center">
              <span className="w-2 h-2 rounded-full bg-emerald-500 mr-1.5" /> Mitigating Signal
            </span>
            <span className="inline-flex items-center">
              <span className="w-2 h-2 rounded-full bg-red-500 mr-1.5" /> Aggravating Signal
            </span>
          </div>
        </div>

        <div className="w-full h-[460px] bg-slate-50" data-testid="xyflow-container">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable={true}
          >
            <Background color="#cbd5e1" gap={16} />
            <Controls showInteractive={false} />
          </ReactFlow>
        </div>
      </div>

      {/* Accessible "Why this decision?" Summary Table (WCAG & Screen-Reader accessible) */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        <div className="p-4 bg-gray-50 border-b border-gray-200">
          <h3 className="text-sm font-bold text-gray-900" id="accessible-table-title">
            Accessible Summary: Why this decision?
          </h3>
          <p className="text-xs text-gray-500 mt-0.5">
            Tabular breakdown of evaluated signals, influence direction, and policy reasons for full accessibility compliance.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table
            className="min-w-full divide-y divide-gray-200 text-left text-xs"
            aria-labelledby="accessible-table-title"
            data-testid="why-this-decision-table"
          >
            <thead className="bg-gray-50 text-gray-500 font-semibold uppercase tracking-wider">
              <tr>
                <th scope="col" className="px-6 py-3">Signal / Factor</th>
                <th scope="col" className="px-6 py-3">Category</th>
                <th scope="col" className="px-6 py-3">Impact Direction</th>
                <th scope="col" className="px-6 py-3">Weight</th>
                <th scope="col" className="px-6 py-3">Influence on Decision</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {signals.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-4 text-gray-500 italic text-center">
                    No anomalous signals detected; decision based on base matrix baseline.
                  </td>
                </tr>
              ) : (
                signals.map((s, idx) => {
                  const weight = Number(s.weight || 0);
                  const isMitigating = weight < 0;

                  return (
                    <tr key={idx} className="hover:bg-gray-50">
                      <td className="px-6 py-3 font-mono font-bold text-gray-900">
                        {s.signal}
                      </td>
                      <td className="px-6 py-3 text-gray-600 uppercase text-[11px]">
                        {s.category || 'signal'}
                      </td>
                      <td className="px-6 py-3">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold ${
                            isMitigating ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'
                          }`}
                        >
                          {isMitigating ? 'Mitigating' : 'Aggravating'}
                        </span>
                      </td>
                      <td className="px-6 py-3 font-mono font-bold">
                        <span className={isMitigating ? 'text-emerald-600' : 'text-red-600'}>
                          {weight > 0 ? `+${weight}` : weight}
                        </span>
                      </td>
                      <td className="px-6 py-3 text-gray-600">
                        {isMitigating
                          ? 'Reduced risk score toward lower threshold'
                          : 'Elevated risk score toward escalation threshold'}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Dual Explanations (User-Facing vs Administrator Audit) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6" data-testid="explanations-grid">
        {/* User-facing Explanation */}
        <div className="bg-white rounded-lg p-5 shadow-sm border border-gray-200">
          <div className="flex items-center space-x-2 mb-3">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-500" />
            <h3 className="text-sm font-bold text-gray-900">User-Facing Explanation</h3>
          </div>
          <div className="bg-blue-50 border border-blue-200 rounded p-4 text-xs text-blue-900 leading-relaxed" data-testid="explanation-user-facing">
            {decision.explanation?.user_facing || 'No customer-facing explanation recorded.'}
          </div>
        </div>

        {/* Administrator Audit Explanation */}
        <div className="bg-white rounded-lg p-5 shadow-sm border border-gray-200">
          <div className="flex items-center space-x-2 mb-3">
            <span className="w-2.5 h-2.5 rounded-full bg-slate-800" />
            <h3 className="text-sm font-bold text-gray-900">Administrator Audit Explanation</h3>
          </div>
          <div className="bg-slate-50 border border-slate-200 rounded p-4 text-xs text-slate-900 font-mono leading-relaxed" data-testid="explanation-admin-facing">
            {decision.explanation?.admin_facing || 'No administrative reasoning recorded.'}
          </div>
        </div>
      </div>
    </div>
  );
}
export default DecisionGraphPage;
