import React, { Suspense } from 'react';
import { Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { useLiveStream } from '../hooks/useLiveStream.js';
import { Header } from '../components/common/Header.jsx';
import { ErrorBanner } from '../components/common/ErrorBanner.jsx';
import { Spinner } from '../components/common/Spinner.jsx';
import { apiRequest } from '../services/apiClient.js';
import { clearAdminToken } from '../services/authStorage.js';

// Lazy-loaded administrative views for performance and optimal bundle chunking
const OverviewPage = React.lazy(() => import('./admin/OverviewPage.jsx'));
const UserListPage = React.lazy(() => import('./admin/UserListPage.jsx'));
const UserDetailPage = React.lazy(() => import('./admin/UserDetailPage.jsx'));
const DecisionGraphPage = React.lazy(() => import('./admin/DecisionGraphPage.jsx'));
const PolicyPage = React.lazy(() => import('./admin/PolicyPage.jsx'));

const ADMIN_NAV_LINKS = [
  { label: 'Overview', to: '/admin/overview', testId: 'admin-nav-overview' },
  { label: 'Users', to: '/admin/users', testId: 'admin-nav-users' },
  { label: 'Policy', to: '/admin/policy', testId: 'admin-nav-policy' }
];

/**
 * Admin operator shell (/admin/*).
 * Streams global system telemetry, maintains sub-routing, and handles in-memory session logout.
 */
export function AdminShell() {
  const navigate = useNavigate();
  const { status, events, terminationNotice, clearNotice } = useLiveStream('admin');

  const handleLogout = async () => {
    try {
      await apiRequest('/admin/auth/logout', { method: 'POST', authMode: 'admin' });
    } catch {
      // Clear in-memory token unconditionally on logout failure
    } finally {
      clearAdminToken();
      navigate('/admin/login');
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col">
      <Header
        title="ActionGuard Admin Operator"
        roleLabel="Global Security Telemetry"
        connectionStatus={status}
        onLogout={handleLogout}
        navLinks={ADMIN_NAV_LINKS}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        {terminationNotice && (
          <ErrorBanner
            message={terminationNotice}
            onDismiss={clearNotice}
          />
        )}

        <Suspense
          fallback={
            <div className="py-20 flex justify-center items-center" data-testid="route-loading">
              <Spinner />
            </div>
          }
        >
          <Routes>
            <Route index element={<Navigate to="overview" replace />} />
            <Route path="overview" element={<OverviewPage events={events} />} />
            <Route path="users" element={<UserListPage />} />
            <Route path="users/:id" element={<UserDetailPage />} />
            <Route path="users/:userId/decisions/:decisionId" element={<DecisionGraphPage />} />
            <Route path="policy" element={<PolicyPage />} />
            <Route path="*" element={<Navigate to="overview" replace />} />
          </Routes>
        </Suspense>
      </main>
    </div>
  );
}

export default AdminShell;
