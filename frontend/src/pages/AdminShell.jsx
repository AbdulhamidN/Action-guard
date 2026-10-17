import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useLiveStream } from '../hooks/useLiveStream.js';
import { Header } from '../components/common/Header.jsx';
import { LiveFeed } from '../components/common/LiveFeed.jsx';
import { ErrorBanner } from '../components/common/ErrorBanner.jsx';
import { apiRequest } from '../services/apiClient.js';
import { clearAdminToken } from '../services/authStorage.js';

/**
 * Admin operator shell (/admin/*).
 * Streams global system telemetry, displays connection indicator, and handles in-memory session logout.
 */
export function AdminShell() {
  const navigate = useNavigate();
  const { status, events, terminationNotice, clearNotice } = useLiveStream('admin');

  const handleLogout = async () => {
    try {
      await apiRequest('/admin/auth/logout', { method: 'POST', authMode: 'admin' });
    } catch {
      // Clear in-memory token unconditionally
    } finally {
      clearAdminToken();
      navigate('/admin/login');
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 flex flex-col">
      <Header
        title="ActionGuard Admin Operator"
        roleLabel="Global Security Telemetry"
        connectionStatus={status}
        onLogout={handleLogout}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        <div>
          <h2 className="text-2xl font-bold text-white" data-testid="page-title">
            Admin Shell
          </h2>
          <p className="mt-1 text-sm text-slate-400">
            Real-time cross-account telemetry and Policy Enforcement Point oversight.
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
