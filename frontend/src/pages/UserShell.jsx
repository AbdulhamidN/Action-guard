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
        if (current) {
          setCurrentSessionId(current.session_id);
        } else if (sessions.length > 0) {
          setCurrentSessionId(sessions[0].session_id);
        }
      }
    } catch (err) {
      console.warn('[UserShell] Failed to load user profile or sessions:', err.message);
    }
  }, []);

  useEffect(() => {
    loadUserProfile();
  }, [loadUserProfile]);

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

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      <Header
        title="ActionGuard User Portal"
        roleLabel={currentUser?.email ? `${currentUser.email} — Zero Trust Protected` : 'Zero Trust Protected Session'}
        connectionStatus={status}
        onLogout={handleLogout}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h2 className="text-2xl font-bold text-gray-900" data-testid="page-title">
              User Security Portal
            </h2>
            <p className="mt-1 text-sm text-gray-600">
              Continuous session verification, privacy-preserving telemetry, and proactive security management.
            </p>
          </div>

          <button
            type="button"
            onClick={() => handleOpenStepUp({ scope: 'sensitive_action' })}
            className="inline-flex items-center px-4 py-2 border border-indigo-600 rounded-md text-xs font-semibold text-indigo-700 bg-indigo-50 hover:bg-indigo-100 focus:outline-none focus:ring-2 focus:ring-indigo-500 self-start sm:self-auto"
            data-testid="trigger-step-up-btn"
          >
            <svg className="w-4 h-4 mr-1.5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
            Verify Identity (Step-Up)
          </button>
        </div>

        {terminationNotice && (
          <ErrorBanner
            message={terminationNotice}
            onDismiss={clearNotice}
          />
        )}

        {/* Tab Navigation */}
        <div className="border-b border-gray-200">
          <nav className="-mb-px flex space-x-8" aria-label="Tabs" data-testid="portal-tabs">
            <button
              type="button"
              onClick={() => setActiveTab('overview')}
              className={`whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm focus:outline-none ${
                activeTab === 'overview'
                  ? 'border-indigo-600 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
              data-testid="tab-overview"
            >
              Overview
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('sessions')}
              className={`whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm focus:outline-none ${
                activeTab === 'sessions'
                  ? 'border-indigo-600 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
              data-testid="tab-sessions"
            >
              Active Sessions
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('devices')}
              className={`whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm focus:outline-none ${
                activeTab === 'devices'
                  ? 'border-indigo-600 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
              data-testid="tab-devices"
            >
              Trusted Devices
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('history')}
              className={`whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm focus:outline-none ${
                activeTab === 'history'
                  ? 'border-indigo-600 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
              data-testid="tab-history"
            >
              Security History
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('delayed')}
              className={`whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm focus:outline-none ${
                activeTab === 'delayed'
                  ? 'border-indigo-600 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
              data-testid="tab-delayed"
            >
              Delayed Actions (Cooling-Off)
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('playground')}
              className={`whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm focus:outline-none ${
                activeTab === 'playground'
                  ? 'border-indigo-600 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
              data-testid="tab-playground"
            >
              Policy Playground
            </button>
          </nav>
        </div>

        {/* Active Tab Panel */}
        <div className="pt-2">
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
              onActionCompleted={loadUserProfile}
            />
          )}
        </div>

        {/* Live Security Feed */}
        <div className="pt-6 border-t border-gray-200">
          <div className="mb-4">
            <h3 className="text-md font-semibold text-gray-900">Live Activity Feed</h3>
            <p className="text-xs text-gray-500">Real-time telemetry stream for current authenticated session.</p>
          </div>
          <LiveFeed events={events} />
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
        }}
      />
    </div>
  );
}
