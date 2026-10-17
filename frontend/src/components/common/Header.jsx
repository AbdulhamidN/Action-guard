import React from 'react';
import { ConnectionIndicator } from './ConnectionIndicator.jsx';

/**
 * Shell header with branding, real-time connection status indicator, and logout button.
 *
 * @param {{
 *   title: string,
 *   connectionStatus: 'connecting' | 'live' | 'offline',
 *   onLogout: () => void,
 *   roleLabel?: string
 * }} props
 */
export function Header({ title, connectionStatus, onLogout, roleLabel }) {
  return (
    <header className="bg-white border-b border-gray-200 px-6 py-4 sticky top-0 z-10 shadow-sm" data-testid="app-header">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="h-8 w-8 bg-indigo-600 rounded-lg flex items-center justify-center text-white font-bold text-lg shadow-sm">
            AG
          </div>
          <div>
            <h1 className="text-lg font-bold text-gray-900 leading-tight">{title}</h1>
            {roleLabel && <p className="text-xs text-gray-500 font-medium">{roleLabel}</p>}
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <ConnectionIndicator status={connectionStatus} />
          <button
            type="button"
            onClick={onLogout}
            data-testid="logout-button"
            className="inline-flex items-center px-3 py-1.5 border border-gray-300 text-xs font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 hover:text-red-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors shadow-sm"
          >
            <svg className="w-4 h-4 mr-1 text-gray-400 group-hover:text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
            </svg>
            Sign Out
          </button>
        </div>
      </div>
    </header>
  );
}
