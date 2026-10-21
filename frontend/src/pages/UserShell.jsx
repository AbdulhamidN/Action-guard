import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useLiveStream } from '../hooks/useLiveStream.js';
import { Header } from '../components/common/Header.jsx';
import { LiveFeed } from '../components/common/LiveFeed.jsx';
import { ErrorBanner } from '../components/common/ErrorBanner.jsx';
import { apiRequest } from '../services/apiClient.js';
import { clearUserToken } from '../services/authStorage.js';
import { clearAllCancellationTokens } from '../services/cancellationStorage.js';
import { OverviewTab } from '../components/user/OverviewTab.jsx';
import { SessionsTab } from '../components/user/SessionsTab.jsx';
import { DevicesTab } from '../components/user/DevicesTab.jsx';
import { HistoryTab } from '../components/user/HistoryTab.jsx';
import { CoolingOffTab } from '../components/user/CoolingOffTab.jsx';
import { ActionTriggerPanel } from '../components/user/ActionTriggerPanel.jsx';
import { StepUpModal } from '../components/user/StepUpModal.jsx';

/**
 * User application shell (/app/*).
 * Displays connection indicator, logout action, user notice banners, tabbed security portal,
 * live activity feed, and identity re-verification modal.
 */
export function UserShell() {
  const navigate = useNavigate();
  const { status, events, terminationNotice, clearNotice } = useLiveStream('user');

  const [activeTab, setActiveTab] = useState('sessions');
  const [currentUser, setCurrentUser] = useState(null);
  const [currentSessionId, setCurrentSessionId] = useState(null);
  const [currentTier, setCurrentTier] = useState(null);
  const [elevation, setElevation] = useState({ checked: false, elevated: false, remainingSeconds: 0 });
  const [pendingDelayed, setPendingDelayed] = useState(0);

  // Step-Up Modal State
  const [stepUpState, setStepUpState] = useState({
    isOpen: false,
    scope: 'sensitive_action',
    sessionId: null,
    triggeringAction: null
  });

  // Load user profile & identify current session
  const loadUserProfile = useCallback(async () => {
    try {
      const user = await apiRequest('/me', { authMode: 'user' });
      setCurrentUser(user);

      const sessions = await apiRequest('/me/sessions', { authMode: 'user' });
      if (Array.isArray(sessions)) {
        const current = sessions.find((s) => s.is_current);
        const chosen = current || sessions[0];
        if (chosen) {
          setCurrentSessionId(chosen.session_id);
          setCurrentTier(chosen.risk?.risk_tier ?? chosen.risk_tier ?? null);
        }
      }
    } catch (err) {
      console.warn('[UserShell] Failed to load user profile or sessions:', err.message);
    }
  }, []);

  useEffect(() => {
    loadUserProfile();
  }, [loadUserProfile]);

  // Optional, non-blocking indicators: a failure here never affects the shell.
  const loadIndicators = useCallback(async () => {
    try {
      const list = await apiRequest('/cooling-off/actions', { authMode: 'user' });
      const items = Array.isArray(list) ? list : list?.actions || [];
      setPendingDelayed(items.filter((a) => !a.status || a.status === 'pending').length);
    } catch {
      setPendingDelayed(0);
    }
    if (currentSessionId) {
      try {
        const e = await apiRequest(`/sessions/${currentSessionId}/elevate/sensitive_action`, { authMode: 'user' });
        setElevation({ checked: true, elevated: Boolean(e?.elevated), remainingSeconds: e?.remainingSeconds || 0 });
      } catch {
        setElevation({ checked: true, elevated: false, remainingSeconds: 0 });
      }
    }
  }, [currentSessionId]);

  useEffect(() => {
    loadIndicators();
  }, [loadIndicators]);

  const handleLogout = async () => {
    try {
      await apiRequest('/auth/logout', { method: 'POST', authMode: 'user' });
    } catch {
      // Complete client logout regardless of backend network state
    } finally {
      clearUserToken();
      clearAllCancellationTokens();
      navigate('/login');
    }
  };

  const handleOpenStepUp = ({ scope, sessionId, triggeringAction }) => {
    setStepUpState({
      isOpen: true,
      scope: scope || 'sensitive_action',
      sessionId: sessionId || currentSessionId,
      triggeringAction: triggeringAction || null
    });
  };

  const handleCloseStepUp = () => {
    setStepUpState((prev) => ({
      ...prev,
      isOpen: false,
      triggeringAction: null
    }));
  };

  const TABS = [
    ['overview', 'Overview'],
    ['sessions', 'Active Sessions'],
    ['devices', 'Trusted Devices'],
    ['history', 'Security History'],
    ['delayed', 'Delayed Actions (Cooling-Off)'],
    ['playground', 'Policy Playground']
  ];

  const TIER_CHIP = {
    low: 'border-state-ok/50 bg-state-ok/10 text-state-ok',
    medium: 'border-state-warn/50 bg-state-warn/10 text-state-warn',
    high: 'border-state-caution/50 bg-state-caution/10 text-state-caution',
    critical: 'border-state-alert/50 bg-state-alert/10 text-state-alert'
  };
  const tierKey = typeof currentTier === 'string' ? currentTier.toLowerCase() : null;

  return (
    <div className="min-h-screen bg-space-900 text-ink-100 flex flex-col">
      <Header
        title="ActionGuard User Portal"
        roleLabel={currentUser?.email ? `${currentUser.email} — Zero Trust Protected` : 'Zero Trust Protected Session'}
        connectionStatus={status}
        onLogout={handleLogout}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h2 className="text-2xl font-extrabold tracking-tight text-white" data-testid="page-title">
              User Security Portal
            </h2>
            <p className="mt-1 text-sm text-ink-300">
              Continuous session verification, privacy-preserving telemetry, and proactive security management.
            </p>
          </div>

          <button
            type="button"
            onClick={() => handleOpenStepUp({ scope: 'sensitive_action' })}
            className="inline-flex items-center px-4 py-2 rounded-lg text-xs font-semibold text-white bg-gradient-to-r from-neon-indigo to-neon-cyan hover:brightness-110 self-start sm:self-auto"
            data-testid="trigger-step-up-btn"
          >
            <svg className="w-4 h-4 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
            Verify Identity (Step-Up)
          </button>
        </div>

        {/* Security status strip: tier only, never raw signals or numeric scores */}
        <div className="flex flex-wrap gap-3" data-testid="security-status">
          <span className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs font-semibold ${tierKey && TIER_CHIP[tierKey] ? TIER_CHIP[tierKey] : 'border-white/15 text-ink-300'}`} data-testid="session-security-level">
            Session security: {tierKey ? `${tierKey} risk` : 'not yet evaluated'}
          </span>
          {elevation.checked && (
            <span className={`inline-flex items-center px-3 py-1.5 rounded-full border text-xs font-semibold ${elevation.elevated ? 'border-neon-cyan/50 bg-neon-cyan/10 text-neon-cyan' : 'border-white/15 text-ink-300'}`} data-testid="elevation-status">
              {elevation.elevated ? `Re-verified: elevated trust for ${elevation.remainingSeconds}s` : 'Not elevated'}
            </span>
          )}
          {pendingDelayed > 0 && (
            <button
              type="button"
              onClick={() => setActiveTab('delayed')}
              className="inline-flex items-center px-3 py-1.5 rounded-full border border-state-caution/50 bg-state-caution/10 text-state-caution text-xs font-semibold hover:bg-state-caution/20"
              data-testid="pending-delayed-alert"
            >
              {pendingDelayed} delayed action{pendingDelayed === 1 ? '' : 's'} pending
            </button>
          )}
        </div>

        {terminationNotice && (
          <ErrorBanner
            message={terminationNotice}
            onDismiss={clearNotice}
          />
        )}

        {/* Tab Navigation */}
        <div className="border-b border-white/10 overflow-x-auto">
          <nav className="-mb-px flex space-x-8" aria-label="Tabs" data-testid="portal-tabs">
            {TABS.map(([key, label]) => (
              <button
                key={key}
                type="button"
                onClick={() => setActiveTab(key)}
                aria-current={activeTab === key ? 'page' : undefined}
                className={`whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === key
                    ? 'border-neon-cyan text-neon-cyan'
                    : 'border-transparent text-ink-300 hover:text-white hover:border-white/30'
                }`}
                data-testid={`tab-${key}`}
              >
                {label}
              </button>
            ))}
          </nav>
        </div>

        {/* Active Tab Panel (light surface keeps the shared tab components legible) */}
        <div className="rounded-2xl bg-white text-gray-900 p-4 sm:p-6 shadow-[0_0_40px_-12px_rgba(99,102,241,0.35)]">
          {activeTab === 'overview' && <OverviewTab />}

          {activeTab === 'sessions' && (
            <SessionsTab currentSessionId={currentSessionId} onSessionTerminated={loadUserProfile} />
          )}

          {activeTab === 'devices' && (
            <DevicesTab onDeviceChanged={loadUserProfile} />
          )}

          {activeTab === 'history' && <HistoryTab />}

          {activeTab === 'delayed' && <CoolingOffTab />}

          {activeTab === 'playground' && (
            <ActionTriggerPanel
              sessionId={currentSessionId}
              onStepUpRequired={handleOpenStepUp}
              onActionCompleted={() => {
                loadUserProfile();
                loadIndicators();
              }}
            />
          )}
        </div>

        {/* Live Security Feed */}
        <div className="pt-6 border-t border-white/10">
          <div className="mb-4">
            <h3 className="text-md font-semibold text-white">Live Activity Feed</h3>
            <p className="text-xs text-ink-300">Real-time telemetry stream for current authenticated session.</p>
          </div>
          <div className="rounded-2xl bg-white text-gray-900 p-4">
            <LiveFeed events={events} />
          </div>
        </div>
      </main>

      {/* Step-Up Re-Verification Modal */}
      <StepUpModal
        isOpen={stepUpState.isOpen}
        onClose={handleCloseStepUp}
        scope={stepUpState.scope}
        sessionId={stepUpState.sessionId || currentSessionId}
        triggeringAction={stepUpState.triggeringAction}
        onSuccess={() => {
          loadUserProfile();
          loadIndicators();
        }}
      />
    </div>
  );
}
