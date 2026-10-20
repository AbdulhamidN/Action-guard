/**
 * @fileoverview Custom React hook for ActionGuard real-time telemetry streaming via Socket.IO.
 * Enforces Zero Trust stream segregation:
 * - 'user' mode sends strictly auth: { token } and receives account-level telemetry.
 * - 'admin' mode sends strictly auth: { adminToken } and receives global telemetry.
 * - Never cross-contaminates credentials between streams.
 * - Manages connection status ('connecting' | 'live' | 'offline').
 * - Maintains a bounded buffer of the last 200 received events.
 * - Invalidates matching React Query caches.
 * - Handles connect_error (unauthorized) and session:terminated by displaying notices and logging out.
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import { io } from 'socket.io-client';
import { useQueryClient } from '@tanstack/react-query';
import {
  getUserToken,
  clearUserToken,
  getAdminToken,
  clearAdminToken
} from '../services/authStorage.js';

const MAX_BUFFER_SIZE = 200;

/** @type {((targetPath: string) => void)|null} */
let liveStreamRedirectHandler = null;

/**
 * Registers an optional custom redirect handler for testing environments.
 *
 * @param {((targetPath: string) => void)|null} handler
 */
export function setLiveStreamRedirectHandler(handler) {
  liveStreamRedirectHandler = handler;
}

/**
 * Safely navigates to the target login route.
 *
 * @param {string} targetPath
 */
function navigateToLogin(targetPath) {
  if (typeof liveStreamRedirectHandler === 'function') {
    liveStreamRedirectHandler(targetPath);
    return;
  }
  try {
    if (typeof window !== 'undefined' && window.location && window.location.pathname !== targetPath) {
      window.location.href = targetPath;
    }
  } catch {
    // jsdom does not implement navigation
  }
}

/**
 * @typedef {'connecting' | 'live' | 'offline'} StreamStatus
 * @typedef {'user' | 'admin'} StreamMode
 *
 * @typedef {Object} LiveEventItem
 * @property {string} eventType - The socket event name ('event:recorded', 'risk:updated', etc.)
 * @property {any} data - The received payload
 * @property {string} receivedAt - Timestamp of arrival
 */

/**
 * Subscribes to ActionGuard live Socket.IO telemetry stream.
 *
 * @param {StreamMode} mode - Stream boundary mode ('user' or 'admin')
 * @returns {{
 *   status: StreamStatus,
 *   events: LiveEventItem[],
 *   terminationNotice: string | null,
 *   clearNotice: () => void
 * }}
 */
export function useLiveStream(mode) {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState(/** @type {StreamStatus} */ ('connecting'));
  const [events, setEvents] = useState(/** @type {LiveEventItem[]} */ ([]));
  const [terminationNotice, setTerminationNotice] = useState(/** @type {string|null} */ (null));
  const socketRef = useRef(null);

  const clearNotice = useCallback(() => {
    setTerminationNotice(null);
  }, []);

  const handleLogout = useCallback((reasonNotice) => {
    if (reasonNotice) {
      setTerminationNotice(reasonNotice);
    }
    if (mode === 'admin') {
      clearAdminToken();
      navigateToLogin('/admin/login');
    } else {
      clearUserToken();
      navigateToLogin('/login');
    }
  }, [mode]);

  useEffect(() => {
    if (mode !== 'user' && mode !== 'admin') {
      setStatus('offline');
      return;
    }

    // Determine initial credential availability
    const initialCred = mode === 'admin' ? getAdminToken() : getUserToken();
    if (!initialCred) {
      setStatus('offline');
      handleLogout();
      return;
    }

    setStatus('connecting');

    // Create socket instance using auth callback to ensure fresh credentials on reconnect
    const socket = io({
      path: '/socket.io',
      transports: ['websocket', 'polling'],
      reconnection: true,
      auth: (cb) => {
        if (mode === 'admin') {
          const adminToken = getAdminToken();
          cb({ adminToken: adminToken || undefined });
        } else {
          const token = getUserToken();
          cb({ token: token || undefined });
        }
      }
    });

    socketRef.current = socket;

    // Helper to push items to bounded 200-event buffer
    const pushEvent = (eventType, data) => {
      const item = {
        eventType,
        data,
        receivedAt: new Date().toISOString()
      };
      setEvents((prev) => {
        const next = [item, ...prev];
        return next.length > MAX_BUFFER_SIZE ? next.slice(0, MAX_BUFFER_SIZE) : next;
      });
    };

    socket.on('connect', () => {
      setStatus('live');
    });

    socket.on('disconnect', () => {
      setStatus('offline');
    });

    socket.on('connect_error', (err) => {
      setStatus('offline');
      const msg = err && err.message ? err.message : '';
      if (
        msg === 'unauthorized' ||
        msg === 'token_expired' ||
        msg === 'invalid_session'
      ) {
        handleLogout('Authentication rejected by real-time server.');
      }
    });

    socket.on('event:recorded', (payload) => {
      pushEvent('event:recorded', payload);
      queryClient.invalidateQueries({ queryKey: ['events'] });
      if (mode === 'admin') {
        queryClient.invalidateQueries({ queryKey: ['overview'] });
        queryClient.invalidateQueries({ queryKey: ['users'] });
      }
    });

    socket.on('risk:updated', (payload) => {
      pushEvent('risk:updated', payload);
      queryClient.invalidateQueries({ queryKey: ['risk'] });
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
      if (mode === 'admin') {
        queryClient.invalidateQueries({ queryKey: ['overview'] });
      }
    });

    socket.on('decision:recorded', (payload) => {
      pushEvent('decision:recorded', payload);
      queryClient.invalidateQueries({ queryKey: ['decisions'] });
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
      if (mode === 'admin') {
        queryClient.invalidateQueries({ queryKey: ['overview'] });
      }
    });

    socket.on('session:terminated', (payload) => {
      const reason = payload && payload.reason ? payload.reason : 'session_invalidated';
      const notice = `Your session was terminated (${reason}).`;
      handleLogout(notice);
    });

    return () => {
      socket.disconnect();
      socketRef.current = null;
    };
  }, [mode, queryClient, handleLogout]);

  return {
    status,
    events,
    terminationNotice,
    clearNotice
  };
}
