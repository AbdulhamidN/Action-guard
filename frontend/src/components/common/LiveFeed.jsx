import React from 'react';
import { TierBadge } from './TierBadge.jsx';
import { EmptyState } from './EmptyState.jsx';

/**
 * Minimal live feed showing the most recent 10 events to demonstrate live updates without refresh.
 *
 * @param {{
 *   events: Array<{ eventType: string, data: any, receivedAt: string }>
 * }} props
 */
export function LiveFeed({ events = [] }) {
  const latestTen = events.slice(0, 10);

  if (latestTen.length === 0) {
    return <EmptyState title="No real-time events yet" description="Awaiting telemetry broadcast..." />;
  }

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden" data-testid="live-feed">
      <div className="px-4 py-3 bg-gray-50 border-b border-gray-200 flex justify-between items-center">
        <h3 className="text-sm font-semibold text-gray-700">Live Activity Feed (Last 10 Events)</h3>
        <span className="text-xs text-gray-500">{latestTen.length} shown</span>
      </div>
      <ul className="divide-y divide-gray-100" data-testid="live-feed-list">
        {latestTen.map((item, idx) => {
          const { eventType, data, receivedAt } = item;
          const key = data && data.event_id ? `${data.event_id}-${idx}` : `live-evt-${idx}`;
          const tier = data && (data.risk_tier || (data.assessment && data.assessment.risk_tier));
          const actionOrType = (data && (data.event_type || data.action_type)) || eventType;

          return (
            <li key={key} className="px-4 py-3 hover:bg-gray-50 transition-colors" data-testid="live-feed-item">
              <div className="flex items-center justify-between space-x-2">
                <div className="flex items-center space-x-2 truncate">
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800">
                    {String(eventType)}
                  </span>
                  <span className="text-sm font-medium text-gray-900 truncate">
                    {String(actionOrType)}
                  </span>
                  {tier && <TierBadge tier={tier} />}
                </div>
                <time className="text-xs text-gray-400 whitespace-nowrap">
                  {new Date(receivedAt).toLocaleTimeString()}
                </time>
              </div>

              {data && data.explanation && data.explanation.user_facing && (
                <p className="mt-1 text-xs text-gray-600 line-clamp-1">
                  {String(data.explanation.user_facing)}
                </p>
              )}

              {data && data.decision && (
                <div className="mt-1 text-xs text-indigo-600 font-medium">
                  Decision: <span className="uppercase">{String(data.decision)}</span>
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
