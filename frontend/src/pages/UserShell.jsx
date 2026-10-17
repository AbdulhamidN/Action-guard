import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useLiveStream } from '../hooks/useLiveStream.js';
import { Header } from '../components/common/Header.jsx';
import { LiveFeed } from '../components/common/LiveFeed.jsx';
import { ErrorBanner } from '../components/common/ErrorBanner.jsx';
import { apiRequest } from '../services/apiClient.js';
import { clearUserToken } from '../services/authStorage.js';

/**
 * User application shell (/app/*).
 * Displays connection indicator, logout action, user notice banners, and live activity feed.
 */
export function UserShell() {
  const navigate = useNavigate();
  const { status, events, terminationNotice, clearNotice } = useLiveStream('user');

  const handleLogout = async () => {
    try {
      await apiRequest('/auth/logout', { method: 'POST', authMode: 'user' });
    } catch {
      // Complete client logout regardless of backend network state
    } finally {
      clearUserToken();
      navigate('/login');
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      <Header
        title="ActionGuard User Portal"
        roleLabel="Zero Trust Protected Session"
        connectionStatus={status}
        onLogout={handleLogout}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        <div>
          <h2 className="text-2xl font-bold text-gray-900" data-testid="page-title">
            User Shell
          </h2>
          <p className="mt-1 text-sm text-gray-600">
            Continuous verification and live telemetry stream for your active session.
          </p>
        </div>

        {terminationNotice && (
          <ErrorBanner
            message={terminationNotice}
            onDismiss={clearNotice}
          />
        )}

        <div className="grid grid-cols-1 gap-6">
          <LiveFeed events={events} />
        </div>
      </main>
    </div>
  );
}
