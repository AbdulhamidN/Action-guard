import React, { useState, useEffect, useMemo, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  PieChart,
  Pie,
  CartesianGrid
} from 'recharts';
import { apiRequest } from '../../services/apiClient.js';
import { TierBadge } from '../../components/common/TierBadge.jsx';
import { Spinner } from '../../components/common/Spinner.jsx';
import { ErrorBanner } from '../../components/common/ErrorBanner.jsx';
import { EmptyState } from '../../components/common/EmptyState.jsx';
import { EventDetailDrawer } from '../../components/admin/EventDetailDrawer.jsx';

const TIER_COLORS = {
  low: '#10b981',      // emerald-500
  medium: '#f59e0b',   // amber-500
  high: '#f97316',     // orange-500
  critical: '#ef4444'  // red-500
};

const OUTCOME_COLORS = {
  allow: '#10b981',
  monitor: '#3b82f6',
  reverify: '#8b5cf6',
  delay: '#f59e0b',
  block: '#ef4444',
  contained_and_blocked: '#991b1b'
};

/**
 * Overview & Live Console Page (/admin/overview).
 *
 * Provides:
 * - 24h / 7d window toggle with live KPI metric cards
 * - Recharts visualizations for risk assessments and decision outcomes
 * - Live Console with bounded 200-event buffer, pause/resume, and multi-field filtering
 * - Focus-restoring accessible slide-over detail drawer
 *
 * @param {{
 *   events?: Array<{ eventType: string, data: any, receivedAt: string }>
 * }} props
 */
export function OverviewPage({ events = [] }) {
  const [windowRange, setWindowRange] = useState('24h');
  const [isPaused, setIsPaused] = useState(false);
  const [pausedEvents, setPausedEvents] = useState(/** @type {any[]} */ ([]));
  const [tierFilter, setTierFilter] = useState('all');
  const [decisionFilter, setDecisionFilter] = useState('all');
  const [userFilter, setUserFilter] = useState('');
  const [selectedEvent, setSelectedEvent] = useState(null);

  // Snapshot live events when pausing
  const handleTogglePause = () => {
    if (!isPaused) {
      setPausedEvents(events);
      setIsPaused(true);
    } else {
      setIsPaused(false);
    }
  };

  // Active event stream: frozen snapshot if paused, otherwise live stream
  const activeStream = isPaused ? pausedEvents : events;

  // React Query for overview metrics
  const {
    data: overviewData,
    isLoading: isOverviewLoading,
    error: overviewError,
    refetch: refetchOverview
  } = useQuery({
    queryKey: ['overview', windowRange],
    queryFn: () => apiRequest(`/admin/overview?window=${windowRange}`, { authMode: 'admin' })
  });

  // Calculate high + critical alerts count
  const assessmentsByTier = overviewData?.assessments_by_tier || {};
  const highCriticalAlerts = (assessmentsByTier.high || 0) + (assessmentsByTier.critical || 0);

  // Total decisions count
  const decisionsByOutcome = overviewData?.decisions_by_outcome || {};
  const totalDecisions = Object.values(decisionsByOutcome).reduce((acc, curr) => acc + Number(curr || 0), 0);

  // Prepare chart data for risk tiers
  const tierChartData = useMemo(() => {
    return [
      { name: 'Low', key: 'low', count: assessmentsByTier.low || 0, color: TIER_COLORS.low },
      { name: 'Medium', key: 'medium', count: assessmentsByTier.medium || 0, color: TIER_COLORS.medium },
      { name: 'High', key: 'high', count: assessmentsByTier.high || 0, color: TIER_COLORS.high },
      { name: 'Critical', key: 'critical', count: assessmentsByTier.critical || 0, color: TIER_COLORS.critical }
    ];
  }, [assessmentsByTier]);

  // Prepare chart data for decisions
  const decisionChartData = useMemo(() => {
    return Object.entries(decisionsByOutcome).map(([outcome, count]) => ({
      name: outcome.replace(/_/g, ' '),
      key: outcome,
      count: Number(count || 0),
      color: OUTCOME_COLORS[outcome] || '#64748b'
    }));
  }, [decisionsByOutcome]);

  // Filtered live feed items
  const filteredEvents = useMemo(() => {
    return activeStream.filter((item) => {
      const data = item.data || item;
      const tier = (data.risk_tier || (data.assessment && data.assessment.risk_tier) || '').toLowerCase();
      const decision = (data.effective_decision || data.decision || data.recommended_decision || '').toLowerCase();
      const userId = (data.user_id || '').toLowerCase();

      if (tierFilter !== 'all' && tier !== tierFilter.toLowerCase()) {
        return false;
      }
      if (decisionFilter !== 'all' && decision !== decisionFilter.toLowerCase()) {
        return false;
      }
      if (userFilter.trim() && !userId.includes(userFilter.trim().toLowerCase())) {
        return false;
      }
      return true;
    });
  }, [activeStream, tierFilter, decisionFilter, userFilter]);

  return (
    <div className="space-y-8" data-testid="admin-overview-page">
      {/* Header & Window Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-gray-900" data-testid="overview-title">
            Security Telemetry & System Overview
          </h2>
          <p className="mt-0.5 text-xs text-gray-500">
            Real-time cross-account risk evaluation and Policy Enforcement Point metrics.
          </p>
        </div>

        {/* Window Toggle */}
        <div className="inline-flex rounded-md shadow-sm" role="group" aria-label="Overview Time Window">
          <button
            type="button"
            onClick={() => setWindowRange('24h')}
            data-testid="window-toggle-24h"
            className={`px-3 py-1.5 text-xs font-semibold rounded-l-md border transition-colors ${
              windowRange === '24h'
                ? 'bg-indigo-600 text-white border-indigo-600'
                : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
            }`}
          >
            24 Hours
          </button>
          <button
            type="button"
            onClick={() => setWindowRange('7d')}
            data-testid="window-toggle-7d"
            className={`px-3 py-1.5 text-xs font-semibold rounded-r-md border-t border-b border-r transition-colors ${
              windowRange === '7d'
                ? 'bg-indigo-600 text-white border-indigo-600'
                : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
            }`}
          >
            7 Days
          </button>
        </div>
      </div>

      {overviewError && (
        <ErrorBanner
          message={overviewError.message || 'Failed to fetch overview metrics.'}
          onDismiss={() => {}}
        />
      )}

      {/* KPI Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" data-testid="kpi-cards-grid">
        {/* Total Decisions */}
        <div className="bg-white rounded-lg p-5 shadow-sm border border-gray-200">
          <div className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
            Total Evaluations
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-3xl font-extrabold text-gray-900" data-testid="kpi-total-decisions">
              {isOverviewLoading ? '...' : totalDecisions}
            </span>
            <span className="text-xs text-gray-400 font-medium">window: {windowRange}</span>
          </div>
        </div>

        {/* High / Critical Alerts */}
        <div className="bg-white rounded-lg p-5 shadow-sm border border-gray-200">
          <div className="text-xs font-semibold text-red-600 uppercase tracking-wider">
            High / Critical Risk
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-3xl font-extrabold text-red-600" data-testid="kpi-high-critical-alerts">
              {isOverviewLoading ? '...' : highCriticalAlerts}
            </span>
            <span className="text-xs text-gray-400 font-medium">requires review</span>
          </div>
        </div>

        {/* Active Sessions */}
        <div className="bg-white rounded-lg p-5 shadow-sm border border-gray-200">
          <div className="text-xs font-semibold text-indigo-600 uppercase tracking-wider">
            Active Sessions
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-3xl font-extrabold text-indigo-600" data-testid="kpi-active-sessions">
              {isOverviewLoading ? '...' : overviewData?.active_sessions ?? 0}
            </span>
            <span className="text-xs text-gray-400 font-medium">cross-account</span>
          </div>
        </div>

        {/* Contained Sessions */}
        <div className="bg-white rounded-lg p-5 shadow-sm border border-gray-200">
          <div className="text-xs font-semibold text-amber-600 uppercase tracking-wider">
            Contained Sessions
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-3xl font-extrabold text-amber-600" data-testid="kpi-contained-sessions">
              {isOverviewLoading ? '...' : overviewData?.contained_sessions ?? 0}
            </span>
            <span className="text-xs text-gray-400 font-medium">auto-contained</span>
          </div>
        </div>
      </div>

      {/* Visualizations Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6" data-testid="charts-grid">
        {/* Risk Tier Distribution Chart */}
        <div className="bg-white rounded-lg p-5 shadow-sm border border-gray-200">
          <h3 className="text-sm font-bold text-gray-800 mb-4">Risk Assessments by Tier</h3>
          {isOverviewLoading ? (
            <div className="h-64 flex items-center justify-center">
              <Spinner />
            </div>
          ) : (
            <div className="h-64" data-testid="risk-tier-chart">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={tierChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                  <XAxis dataKey="name" tick={{ fontSize: 12, fill: '#64748b' }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 12, fill: '#64748b' }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', borderRadius: '0.375rem', fontSize: '12px' }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {tierChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Decisions by Outcome Chart */}
        <div className="bg-white rounded-lg p-5 shadow-sm border border-gray-200">
          <h3 className="text-sm font-bold text-gray-800 mb-4">Decisions by Outcome</h3>
          {isOverviewLoading ? (
            <div className="h-64 flex items-center justify-center">
              <Spinner />
            </div>
          ) : (
            <div className="h-64" data-testid="decision-outcome-chart">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={decisionChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                  <XAxis dataKey="name" tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 12, fill: '#64748b' }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', borderRadius: '0.375rem', fontSize: '12px' }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {decisionChartData.map((entry, index) => (
                      <Cell key={`cell-outcome-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* Live Console Feed */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden" data-testid="live-console">
        {/* Feed Header & Controls */}
        <div className="p-4 bg-gray-50 border-b border-gray-200 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-center space-x-3">
            <h3 className="text-sm font-bold text-gray-900">Live Activity Console</h3>
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-200 text-gray-700">
              {filteredEvents.length} / {activeStream.length} buffer
            </span>
            {isPaused && (
              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-amber-100 text-amber-800" data-testid="stream-paused-badge">
                PAUSED
              </span>
            )}
          </div>

          {/* Filter Bar & Pause Toggle */}
          <div className="flex flex-wrap items-center gap-2">
            {/* User Search Filter */}
            <input
              type="text"
              value={userFilter}
              onChange={(e) => setUserFilter(e.target.value)}
              placeholder="Filter user ID..."
              data-testid="filter-user"
              className="text-xs px-2.5 py-1.5 border border-gray-300 rounded-md focus:ring-1 focus:ring-indigo-500 focus:outline-none"
            />

            {/* Risk Tier Filter */}
            <select
              value={tierFilter}
              onChange={(e) => setTierFilter(e.target.value)}
              data-testid="filter-tier"
              className="text-xs px-2.5 py-1.5 border border-gray-300 rounded-md bg-white focus:ring-1 focus:ring-indigo-500 focus:outline-none"
            >
              <option value="all">All Tiers</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>

            {/* Decision Filter */}
            <select
              value={decisionFilter}
              onChange={(e) => setDecisionFilter(e.target.value)}
              data-testid="filter-decision"
              className="text-xs px-2.5 py-1.5 border border-gray-300 rounded-md bg-white focus:ring-1 focus:ring-indigo-500 focus:outline-none"
            >
              <option value="all">All Decisions</option>
              <option value="allow">Allow</option>
              <option value="monitor">Monitor</option>
              <option value="reverify">Reverify</option>
              <option value="delay">Delay</option>
              <option value="block">Block</option>
            </select>

            {/* Pause / Resume Button */}
            <button
              type="button"
              onClick={handleTogglePause}
              data-testid="feed-pause-toggle"
              className={`px-3 py-1.5 text-xs font-semibold rounded-md border shadow-sm transition-colors ${
                isPaused
                  ? 'bg-emerald-600 text-white border-emerald-600 hover:bg-emerald-700'
                  : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
              }`}
            >
              {isPaused ? 'Resume Stream' : 'Pause Stream'}
            </button>
          </div>
        </div>

        {/* Feed Items List */}
        {filteredEvents.length === 0 ? (
          <div className="p-8">
            <EmptyState
              title="No events matching criteria"
              description="Awaiting live telemetry or adjust your filter selection."
            />
          </div>
        ) : (
          <ul className="divide-y divide-gray-100 max-h-[500px] overflow-y-auto" data-testid="live-feed-list">
            {filteredEvents.map((item, idx) => {
              const data = item.data || item;
              const key = data.event_id || data.id ? `${data.event_id || data.id}-${idx}` : `live-evt-${idx}`;
              const eventType = data.event_type || data.action_type || item.eventType || 'telemetry';
              const tier = data.risk_tier || (data.assessment && data.assessment.risk_tier);
              const decision = data.effective_decision || data.decision || data.recommended_decision;
              const userId = data.user_id || 'unknown';
              const receivedAt = data.timestamp || data.decided_at || item.receivedAt || new Date().toISOString();

              return (
                <li
                  key={key}
                  onClick={() => setSelectedEvent(item)}
                  data-testid="live-feed-item"
                  className="px-4 py-3 hover:bg-indigo-50/50 cursor-pointer transition-colors flex items-center justify-between"
                  tabIndex={0}
                  role="button"
                  aria-label={`View details for ${eventType} by ${userId}`}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      setSelectedEvent(item);
                    }
                  }}
                >
                  <div className="flex items-center space-x-3 truncate">
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800">
                      {String(eventType)}
                    </span>
                    <span className="text-xs font-mono text-indigo-600 truncate max-w-[150px]" title={String(userId)}>
                      {String(userId)}
                    </span>
                    {tier && <TierBadge tier={tier} />}
                    {decision && (
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wide bg-indigo-50 text-indigo-700">
                        {String(decision)}
                      </span>
                    )}
                  </div>

                  <div className="flex items-center space-x-3 text-xs text-gray-400">
                    <time dateTime={receivedAt}>
                      {new Date(receivedAt).toLocaleTimeString()}
                    </time>
                    <svg className="w-4 h-4 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5l7 7-7 7" />
                    </svg>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {/* Slide-over Detail Drawer */}
      <EventDetailDrawer
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />
    </div>
  );
}
export default OverviewPage;
