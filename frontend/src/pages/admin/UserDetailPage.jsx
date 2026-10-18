import React, { useState, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceArea
} from 'recharts';
import { apiRequest } from '../../services/apiClient.js';
import { TierBadge } from '../../components/common/TierBadge.jsx';
import { Spinner } from '../../components/common/Spinner.jsx';
import { ErrorBanner } from '../../components/common/ErrorBanner.jsx';
import { EmptyState } from '../../components/common/EmptyState.jsx';
import { EventDetailDrawer } from '../../components/admin/EventDetailDrawer.jsx';

/**
 * User Detail & Investigation Page (/admin/users/:id).
 *
 * Provides 4 investigation tabs:
 * 1. Timeline: unified chronological stream merging events, risk evaluations, decisions, and sequence steps
 * 2. Risk: Recharts time series of risk scores with color-coded tier reference bands
 * 3. Decisions: decision records with rule evaluations and links to the explanation graph
 * 4. Sessions: session states, active status, device refs, and containment flags
 */
export function UserDetailPage() {
  const { id } = useParams();
  const [activeTab, setActiveTab] = useState('timeline');
  const [selectedEvent, setSelectedEvent] = useState(null);

  // Queries for all user sub-resources
  const { data: events = [], isLoading: isEventsLoading, error: eventsError } = useQuery({
    queryKey: ['user-events', id],
    queryFn: () => apiRequest(`/admin/users/${id}/events`, { authMode: 'admin' }),
    enabled: !!id
  });

  const { data: riskHistory = [], isLoading: isRiskLoading, error: riskError } = useQuery({
    queryKey: ['user-risk-history', id],
    queryFn: () => apiRequest(`/admin/users/${id}/risk-history`, { authMode: 'admin' }),
    enabled: !!id
  });

  const { data: decisions = [], isLoading: isDecisionsLoading, error: decisionsError } = useQuery({
    queryKey: ['user-decisions', id],
    queryFn: () => apiRequest(`/admin/users/${id}/decisions`, { authMode: 'admin' }),
    enabled: !!id
  });

  const { data: sessions = [], isLoading: isSessionsLoading, error: sessionsError } = useQuery({
    queryKey: ['user-sessions', id],
    queryFn: () => apiRequest(`/admin/users/${id}/sessions`, { authMode: 'admin' }),
    enabled: !!id
  });

  const { data: sequenceData, isLoading: isSequenceLoading } = useQuery({
    queryKey: ['user-sequence', id],
    queryFn: () => apiRequest(`/admin/users/${id}/sequence`, { authMode: 'admin' }),
    enabled: !!id
  });

  const activeSequence = sequenceData?.sequence;

  // Build unified chronological timeline
  const unifiedTimeline = useMemo(() => {
    const list = [];

    // Map sequence events for quick lookup
    const seqEventsMap = new Map();
    if (activeSequence && Array.isArray(activeSequence.events)) {
      activeSequence.events.forEach((se) => {
        seqEventsMap.set(se.event_id, {
          stepOrder: se.step_order,
          totalSteps: activeSequence.event_count || activeSequence.events.length,
          sequenceId: activeSequence.id
        });
      });
    }

    // Map decisions by event_id
    const decisionsByEvent = new Map();
    if (Array.isArray(decisions)) {
      decisions.forEach((d) => {
        if (d.event_id) decisionsByEvent.set(d.event_id, d);
      });
    }

    // Map risk evaluations by event_id
    const riskByEvent = new Map();
    if (Array.isArray(riskHistory)) {
      riskHistory.forEach((r) => {
        if (r.event_id) riskByEvent.set(r.event_id, r);
      });
    }

    // Process all events
    if (Array.isArray(events)) {
      events.forEach((evt) => {
        const d = decisionsByEvent.get(evt.event_id);
        const r = riskByEvent.get(evt.event_id);
        const s = seqEventsMap.get(evt.event_id);

        list.push({
          type: 'event',
          id: evt.event_id,
          timestamp: evt.timestamp,
          eventType: evt.event_type,
          user_id: evt.user_id,
          session_id: evt.session_id,
          coarse_location: evt.coarse_location,
          device_ref: evt.device_ref,
          risk_tier: r ? r.risk_tier : d ? d.risk_tier : null,
          risk_score: r ? r.risk_score : d ? d.risk_score : null,
          contributing_signals: r ? r.contributing_signals : d ? d.contributing_signals : [],
          effective_decision: d ? d.effective_decision : null,
          decision_id: d ? d.decision_id : null,
          reasons: d ? d.reasons : [],
          explanation: d ? d.explanation : r ? r.explanation : {},
          sequenceStep: s || null,
          raw: evt
        });
      });
    }

    // Sort newest first
    return list.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [events, decisions, riskHistory, activeSequence]);

  // Chart data for risk progression
  const riskChartData = useMemo(() => {
    if (!Array.isArray(riskHistory) || riskHistory.length === 0) return [];
    // Sort oldest first for time series
    const sorted = [...riskHistory].sort(
      (a, b) => new Date(a.evaluated_at).getTime() - new Date(b.evaluated_at).getTime()
    );
    return sorted.map((item) => ({
      timestamp: new Date(item.evaluated_at).toLocaleTimeString(),
      score: Number(item.risk_score),
      tier: item.risk_tier,
      event_id: item.event_id
    }));
  }, [riskHistory]);

  const anyError = eventsError || riskError || decisionsError || sessionsError;

  return (
    <div className="space-y-6" data-testid="admin-user-detail-page">
      {/* Header & Breadcrumb */}
      <div>
        <nav className="mb-2">
          <Link
            to="/admin/users"
            data-testid="back-to-users-link"
            className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 inline-flex items-center"
          >
            &larr; Back to User Directory
          </Link>
        </nav>
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <div>
            <h2 className="text-xl font-bold text-gray-900" data-testid="user-detail-title">
              User Investigation: <span className="font-mono text-indigo-600">{id}</span>
            </h2>
            <p className="mt-0.5 text-xs text-gray-500">
              Correlated audit telemetry, multi-signal risk progression, and decision graph.
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-semibold bg-gray-100 text-gray-800">
              {sessions.filter((s) => s.is_active).length} Active Sessions
            </span>
            {activeSequence && (
              <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-bold bg-amber-100 text-amber-800 border border-amber-300" data-testid="active-sequence-badge">
                Active Sequence ({activeSequence.event_count || 2} steps)
              </span>
            )}
          </div>
        </div>
      </div>

      {anyError && (
        <ErrorBanner
          message={anyError.message || 'Failed to fetch user telemetry.'}
          onDismiss={() => {}}
        />
      )}

      {/* Tabs Navigation */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8" aria-label="Investigation Tabs">
          <button
            type="button"
            onClick={() => setActiveTab('timeline')}
            data-testid="tab-timeline"
            className={`py-3 px-1 border-b-2 font-medium text-xs sm:text-sm transition-colors ${
              activeTab === 'timeline'
                ? 'border-indigo-600 text-indigo-600 font-bold'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            Unified Timeline ({unifiedTimeline.length})
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('risk')}
            data-testid="tab-risk"
            className={`py-3 px-1 border-b-2 font-medium text-xs sm:text-sm transition-colors ${
              activeTab === 'risk'
                ? 'border-indigo-600 text-indigo-600 font-bold'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            Risk History ({riskHistory.length})
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('decisions')}
            data-testid="tab-decisions"
            className={`py-3 px-1 border-b-2 font-medium text-xs sm:text-sm transition-colors ${
              activeTab === 'decisions'
                ? 'border-indigo-600 text-indigo-600 font-bold'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            Decisions ({decisions.length})
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('sessions')}
            data-testid="tab-sessions"
            className={`py-3 px-1 border-b-2 font-medium text-xs sm:text-sm transition-colors ${
              activeTab === 'sessions'
                ? 'border-indigo-600 text-indigo-600 font-bold'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            Sessions ({sessions.length})
          </button>
        </nav>
      </div>

      {/* Tab 1: Unified Timeline */}
      {activeTab === 'timeline' && (
        <div className="space-y-4" data-testid="timeline-content">
          {isEventsLoading ? (
            <div className="p-12 flex justify-center"><Spinner /></div>
          ) : unifiedTimeline.length === 0 ? (
            <EmptyState title="No timeline events" description="No activity recorded for this user." />
          ) : (
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
              <ul className="divide-y divide-gray-100" data-testid="timeline-list">
                {unifiedTimeline.map((item, idx) => (
                  <li
                    key={`${item.id}-${idx}`}
                    onClick={() => setSelectedEvent(item)}
                    data-testid="timeline-item"
                    className="p-4 hover:bg-gray-50 cursor-pointer transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-gray-100 text-gray-800">
                          {String(item.eventType)}
                        </span>
                        {item.risk_tier && <TierBadge tier={item.risk_tier} />}
                        {item.effective_decision && (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-bold uppercase bg-indigo-50 text-indigo-700">
                            {String(item.effective_decision)}
                          </span>
                        )}
                        {item.sequenceStep && (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-100 text-amber-800 border border-amber-200">
                            Sequence Step {item.sequenceStep.stepOrder}/{item.sequenceStep.totalSteps}
                          </span>
                        )}
                      </div>

                      <time className="text-xs text-gray-400">
                        {new Date(item.timestamp).toLocaleString()}
                      </time>
                    </div>

                    <div className="mt-2 flex items-center justify-between text-xs text-gray-500">
                      <div className="space-x-4">
                        <span>Event: <code className="font-mono text-gray-700">{item.id}</code></span>
                        {item.session_id && <span>Session: <code className="font-mono text-gray-700">{item.session_id}</code></span>}
                        {item.risk_score !== null && item.risk_score !== undefined && (
                          <span>Score: <strong className="text-gray-900">{item.risk_score}</strong></span>
                        )}
                      </div>

                      {item.decision_id && (
                        <Link
                          to={`/admin/users/${id}/decisions/${item.decision_id}`}
                          onClick={(e) => e.stopPropagation()}
                          data-testid={`timeline-graph-link-${item.decision_id}`}
                          className="text-indigo-600 hover:text-indigo-900 font-semibold"
                        >
                          Graph &rarr;
                        </Link>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Risk History */}
      {activeTab === 'risk' && (
        <div className="space-y-6" data-testid="risk-content">
          <div className="bg-white rounded-lg p-5 shadow-sm border border-gray-200">
            <h3 className="text-sm font-bold text-gray-800 mb-2">Risk Score Progression</h3>
            <p className="text-xs text-gray-500 mb-4">
              Historical risk score assessments plotted against zero-trust policy threshold bands.
            </p>

            {isRiskLoading ? (
              <div className="h-64 flex justify-center items-center"><Spinner /></div>
            ) : riskChartData.length === 0 ? (
              <EmptyState title="No risk evaluations" description="No risk assessments recorded for this user." />
            ) : (
              <div className="h-72" data-testid="user-risk-chart">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={riskChartData} margin={{ top: 20, right: 30, left: -10, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                    <XAxis dataKey="timestamp" tick={{ fontSize: 11, fill: '#64748b' }} />
                    <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: '#64748b' }} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', borderRadius: '0.375rem', fontSize: '12px' }}
                    />
                    {/* Tier Reference Bands */}
                    <ReferenceArea y1={0} y2={29} fill="#10b981" fillOpacity={0.08} />
                    <ReferenceArea y1={30} y2={59} fill="#f59e0b" fillOpacity={0.08} />
                    <ReferenceArea y1={60} y2={79} fill="#f97316" fillOpacity={0.08} />
                    <ReferenceArea y1={80} y2={100} fill="#ef4444" fillOpacity={0.08} />

                    <Line
                      type="monotone"
                      dataKey="score"
                      stroke="#4f46e5"
                      strokeWidth={3}
                      dot={{ r: 5, fill: '#4f46e5' }}
                      activeDot={{ r: 7 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>

          {/* Contributing Signals Detail Cards */}
          <div className="space-y-4">
            <h3 className="text-sm font-bold text-gray-800">Evaluations & Contributing Signals</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {riskHistory.map((item) => (
                <div key={item.id} className="bg-white rounded-lg p-4 border border-gray-200 shadow-sm space-y-3" data-testid="risk-card">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs text-gray-500">{item.id}</span>
                    <TierBadge tier={item.risk_tier} />
                  </div>
                  <div className="flex items-baseline justify-between">
                    <span className="text-2xl font-bold text-gray-900">Score: {item.risk_score}</span>
                    <span className="text-xs text-gray-400">{new Date(item.evaluated_at).toLocaleString()}</span>
                  </div>
                  {item.contributing_signals && item.contributing_signals.length > 0 && (
                    <div>
                      <span className="text-xs font-semibold text-gray-600 block mb-1">Signals:</span>
                      <ul className="text-xs space-y-1 bg-gray-50 rounded p-2 border border-gray-100">
                        {item.contributing_signals.map((s, idx) => (
                          <li key={idx} className="flex justify-between">
                            <span className="font-mono text-gray-700">{s.signal} ({s.category})</span>
                            <span className={Number(s.weight) < 0 ? 'text-emerald-600 font-semibold' : 'text-red-600 font-semibold'}>
                              {Number(s.weight) > 0 ? `+${s.weight}` : s.weight}
                            </span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {item.explanation && (
                    <div className="text-xs text-gray-600 border-t border-gray-100 pt-2">
                      {item.explanation.admin_facing || item.explanation.user_facing}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Decisions */}
      {activeTab === 'decisions' && (
        <div className="space-y-4" data-testid="decisions-content">
          {isDecisionsLoading ? (
            <div className="p-12 flex justify-center"><Spinner /></div>
          ) : decisions.length === 0 ? (
            <EmptyState title="No decisions recorded" description="No policy decisions found for this user." />
          ) : (
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
              <table className="min-w-full divide-y divide-gray-200 text-left text-xs" data-testid="decisions-table">
                <thead className="bg-gray-50 text-gray-500 font-semibold uppercase tracking-wider">
                  <tr>
                    <th scope="col" className="px-6 py-3">Decision ID / Action</th>
                    <th scope="col" className="px-6 py-3">Sensitivity</th>
                    <th scope="col" className="px-6 py-3">Risk Assessment</th>
                    <th scope="col" className="px-6 py-3">Effective Decision</th>
                    <th scope="col" className="px-6 py-3">Enforcement Outcome</th>
                    <th scope="col" className="px-6 py-3">Decided At</th>
                    <th scope="col" className="px-6 py-3 text-right">Explanation Graph</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {decisions.map((d) => (
                    <tr key={d.decision_id} className="hover:bg-gray-50 transition-colors" data-testid="decision-row">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="font-semibold text-gray-900">{d.action_type}</div>
                        <div className="font-mono text-gray-400 text-[11px]">{d.decision_id}</div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800 uppercase">
                          {d.action_sensitivity || 'N/A'}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center space-x-2">
                          <TierBadge tier={d.risk_tier} />
                          <span className="font-mono font-bold text-gray-700">({d.risk_score})</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-bold uppercase bg-indigo-50 text-indigo-700 border border-indigo-200">
                          {d.effective_decision}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="font-mono text-xs text-gray-700">{d.enforcement_outcome}</span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-gray-500">
                        {new Date(d.decided_at).toLocaleString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right">
                        <Link
                          to={`/admin/users/${id}/decisions/${d.decision_id}`}
                          data-testid={`view-graph-${d.decision_id}`}
                          className="inline-flex items-center text-indigo-600 hover:text-indigo-900 font-semibold"
                        >
                          View Graph &rarr;
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab 4: Sessions */}
      {activeTab === 'sessions' && (
        <div className="space-y-4" data-testid="sessions-content">
          {isSessionsLoading ? (
            <div className="p-12 flex justify-center"><Spinner /></div>
          ) : sessions.length === 0 ? (
            <EmptyState title="No active sessions" description="No session records exist for this user." />
          ) : (
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
              <table className="min-w-full divide-y divide-gray-200 text-left text-xs" data-testid="sessions-table">
                <thead className="bg-gray-50 text-gray-500 font-semibold uppercase tracking-wider">
                  <tr>
                    <th scope="col" className="px-6 py-3">Session ID</th>
                    <th scope="col" className="px-6 py-3">Status</th>
                    <th scope="col" className="px-6 py-3">Risk Assessment</th>
                    <th scope="col" className="px-6 py-3">Created</th>
                    <th scope="col" className="px-6 py-3">Expires</th>
                    <th scope="col" className="px-6 py-3">Location / Device</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {sessions.map((s) => (
                    <tr key={s.session_id} className="hover:bg-gray-50 transition-colors" data-testid="session-row">
                      <td className="px-6 py-4 whitespace-nowrap font-mono text-gray-900">
                        {s.session_id}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {s.is_active ? (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-emerald-100 text-emerald-800">
                            Active
                          </span>
                        ) : (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-red-100 text-red-800">
                            Contained / Expired
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center space-x-2">
                          <TierBadge tier={s.risk_tier} />
                          {s.risk_score !== undefined && (
                            <span className="font-mono text-gray-600">({s.risk_score})</span>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-gray-500">
                        {new Date(s.created_at).toLocaleString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-gray-500">
                        {new Date(s.expires_at).toLocaleString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-gray-600">
                        <div>{s.coarse_location ? `${s.coarse_location.country} (${s.coarse_location.region || ''})` : 'N/A'}</div>
                        <div className="font-mono text-[11px] text-gray-400">{s.device_ref || 'N/A'}</div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Slide-over Detail Drawer */}
      <EventDetailDrawer
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />
    </div>
  );
}
export default UserDetailPage;
