import React from 'react';

/**
 * @typedef {'connecting' | 'live' | 'offline'} StreamStatus
 */

/**
 * Visual indicator representing the real-time telemetry stream connection status.
 *
 * @param {{ status: StreamStatus }} props
 */
export function ConnectionIndicator({ status }) {
  let dotColor = 'bg-gray-400';
  let label = 'Offline';

  if (status === 'live') {
    dotColor = 'bg-emerald-500 animate-pulse';
    label = 'Live';
  } else if (status === 'connecting') {
    dotColor = 'bg-amber-500 animate-ping';
    label = 'Connecting...';
  }

  return (
    <div
      className="inline-flex items-center space-x-2 text-xs font-medium text-gray-700 bg-white px-2.5 py-1 rounded-full border border-gray-200 shadow-sm"
      data-testid="connection-indicator"
      role="status"
      aria-label={`Connection status: ${label}`}
    >
      <span className={`w-2 h-2 rounded-full ${dotColor}`} aria-hidden="true" />
      <span data-testid="connection-status-text">{label}</span>
    </div>
  );
}
