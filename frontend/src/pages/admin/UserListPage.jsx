import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { apiRequest } from '../../services/apiClient.js';
import { TierBadge } from '../../components/common/TierBadge.jsx';
import { Spinner } from '../../components/common/Spinner.jsx';
import { ErrorBanner } from '../../components/common/ErrorBanner.jsx';
import { EmptyState } from '../../components/common/EmptyState.jsx';

const PAGE_LIMIT = 10;

/**
 * Admin User Directory Page (/admin/users).
 *
 * Implements:
 * - 300ms debounced prefix/email search
 * - Offset/limit pagination with prev/next controls
 * - Plain-text safe rendering for anti-XSS protection
 * - Account containment / locked_until status flags and risk badges
 */
export function UserListPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [offset, setOffset] = useState(0);

  // 300ms debounce for search input
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(searchTerm);
      setOffset(0); // Reset to first page on search change
    }, 300);

    return () => clearTimeout(timer);
  }, [searchTerm]);

  // Query users list with debounced search and pagination
  const { data, isLoading, error, isPlaceholderData } = useQuery({
    queryKey: ['users', debouncedSearch, offset],
    queryFn: () => {
      const params = new URLSearchParams({
        offset: String(offset),
        limit: String(PAGE_LIMIT)
      });
      if (debouncedSearch.trim()) {
        params.set('search', debouncedSearch.trim());
      }
      return apiRequest(`/admin/users?${params.toString()}`, { authMode: 'admin' });
    },
    placeholderData: (prev) => prev
  });

  const users = data?.users || [];
  const total = Number(data?.total || 0);

  const totalPages = Math.ceil(total / PAGE_LIMIT) || 1;
  const currentPage = Math.floor(offset / PAGE_LIMIT) + 1;

  const handlePrevPage = () => {
    setOffset((prev) => Math.max(0, prev - PAGE_LIMIT));
  };

  const handleNextPage = () => {
    if (offset + PAGE_LIMIT < total) {
      setOffset((prev) => prev + PAGE_LIMIT);
    }
  };

  return (
    <div className="space-y-6" data-testid="admin-user-list-page">
      {/* Page Title & Search Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-gray-900" data-testid="user-list-title">
            User Directory & Session Posture
          </h2>
          <p className="mt-0.5 text-xs text-gray-500">
            Inspect account risk levels, active sessions, and containment lockouts.
          </p>
        </div>

        {/* Debounced Search Input */}
        <div className="w-full sm:w-72">
          <label htmlFor="user-search" className="sr-only">
            Search users
          </label>
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <svg className="h-4 w-4 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </div>
            <input
              id="user-search"
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by email or user ID..."
              data-testid="user-search-input"
              className="block w-full pl-9 pr-3 py-1.5 text-xs border border-gray-300 rounded-md leading-5 bg-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500"
            />
          </div>
        </div>
      </div>

      {error && (
        <ErrorBanner
          message={error.message || 'Failed to retrieve user list.'}
          onDismiss={() => {}}
        />
      )}

      {/* Users Table */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        {isLoading && !data ? (
          <div className="p-12 flex justify-center items-center" data-testid="user-list-loading">
            <Spinner />
          </div>
        ) : users.length === 0 ? (
          <div className="p-8" data-testid="user-list-empty">
            <EmptyState
              title="No users found"
              description={debouncedSearch ? `No users matched "${debouncedSearch}".` : 'No accounts exist in directory.'}
            />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 text-left text-xs" data-testid="users-table">
              <thead className="bg-gray-50 text-gray-500 font-semibold uppercase tracking-wider">
                <tr>
                  <th scope="col" className="px-6 py-3">Account / User ID</th>
                  <th scope="col" className="px-6 py-3">Latest Risk Tier</th>
                  <th scope="col" className="px-6 py-3">Active Sessions</th>
                  <th scope="col" className="px-6 py-3">Status / Lockout</th>
                  <th scope="col" className="px-6 py-3">Created</th>
                  <th scope="col" className="px-6 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200" data-testid="users-table-body">
                {users.map((user) => {
                  const isLocked = user.locked_until && new Date(user.locked_until) > new Date();

                  return (
                    <tr key={user.id} className="hover:bg-gray-50 transition-colors" data-testid="user-row">
                      {/* Account / User ID */}
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="font-medium text-gray-900">{String(user.email || 'No email')}</div>
                        <div className="font-mono text-gray-400 text-[11px] truncate max-w-[200px]" title={user.id}>
                          {String(user.id)}
                        </div>
                      </td>

                      {/* Latest Risk Tier */}
                      <td className="px-6 py-4 whitespace-nowrap">
                        {user.latest_risk_tier ? (
                          <TierBadge tier={user.latest_risk_tier} />
                        ) : (
                          <span className="text-gray-400 italic">No evaluations</span>
                        )}
                      </td>

                      {/* Active Sessions */}
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-gray-100 text-gray-800">
                          {Number(user.active_sessions || 0)} active
                        </span>
                      </td>

                      {/* Status / Lockout */}
                      <td className="px-6 py-4 whitespace-nowrap">
                        {isLocked ? (
                          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-100 text-red-800 border border-red-200">
                            Locked until {new Date(user.locked_until).toLocaleTimeString()}
                          </span>
                        ) : (
                          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-800 border border-emerald-200">
                            Active
                          </span>
                        )}
                      </td>

                      {/* Created */}
                      <td className="px-6 py-4 whitespace-nowrap text-gray-500">
                        {user.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}
                      </td>

                      {/* Action Link */}
                      <td className="px-6 py-4 whitespace-nowrap text-right font-medium">
                        <Link
                          to={`/admin/users/${user.id}`}
                          data-testid={`user-link-${user.id}`}
                          className="text-indigo-600 hover:text-indigo-900 font-semibold"
                        >
                          View Details &rarr;
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Controls */}
        <div className="px-6 py-3 bg-gray-50 border-t border-gray-200 flex items-center justify-between">
          <div className="text-xs text-gray-500">
            Showing <span className="font-semibold">{total === 0 ? 0 : offset + 1}</span> to{' '}
            <span className="font-semibold">{Math.min(offset + PAGE_LIMIT, total)}</span> of{' '}
            <span className="font-semibold">{total}</span> users
          </div>

          <div className="inline-flex space-x-2">
            <button
              type="button"
              onClick={handlePrevPage}
              disabled={offset === 0}
              data-testid="pagination-prev"
              className="px-3 py-1 text-xs font-medium rounded border border-gray-300 bg-white text-gray-700 hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed shadow-sm"
            >
              Previous
            </button>
            <span className="px-2 py-1 text-xs text-gray-600 font-medium self-center">
              Page {currentPage} of {totalPages}
            </span>
            <button
              type="button"
              onClick={handleNextPage}
              disabled={offset + PAGE_LIMIT >= total}
              data-testid="pagination-next"
              className="px-3 py-1 text-xs font-medium rounded border border-gray-300 bg-white text-gray-700 hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed shadow-sm"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
export default UserListPage;
