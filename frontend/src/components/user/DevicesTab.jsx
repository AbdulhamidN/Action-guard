import React, { useState, useEffect, useCallback } from 'react';
import { apiRequest } from '../../services/apiClient.js';
import { Spinner } from '../common/Spinner.jsx';
import { EmptyState } from '../common/EmptyState.jsx';

/**
 * DevicesTab displays registered user devices and provides lifecycle controls
 * to enroll the current session device or revoke trusted status.
 *
 * Privacy Guarantees:
 * - Never renders raw device fingerprints.
 * - Displays safe, user-facing timestamps and device labels only.
 * - Bound to authenticated server-side session identity.
 *
 * @param {object} [props]
 * @param {() => void} [props.onDeviceChanged]
 */
export function DevicesTab({ onDeviceChanged = null }) {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);
  const [enrolling, setEnrolling] = useState(false);
  const [revokingId, setRevokingId] = useState(null);
  const [deviceLabel, setDeviceLabel] = useState('');

  const fetchDevices = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiRequest('/me/devices', { authMode: 'user' });
      setDevices(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err.message || 'Failed to load registered devices');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDevices();
  }, [fetchDevices]);

  const handleEnrollDevice = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (enrolling) return;

    setEnrolling(true);
    setError(null);
    setSuccessMessage(null);

    try {
      const payload = {};
      if (deviceLabel.trim().length > 0) {
        payload.label = deviceLabel.trim();
      }

      const res = await apiRequest('/me/devices/enroll', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        authMode: 'user'
      });

      setSuccessMessage(res.message || 'Device successfully enrolled as trusted');
      setDeviceLabel('');
      await fetchDevices();
      if (typeof onDeviceChanged === 'function') {
        onDeviceChanged();
      }
    } catch (err) {
      setError(err.message || 'Failed to enroll trusted device');
    } finally {
      setEnrolling(false);
    }
  };

  const handleRevokeDevice = async (deviceId) => {
    if (!deviceId || revokingId) return;

    setRevokingId(deviceId);
    setError(null);
    setSuccessMessage(null);

    try {
      const res = await apiRequest(`/me/devices/${deviceId}`, {
        method: 'DELETE',
        authMode: 'user'
      });

      setSuccessMessage(res.message || 'Device trust successfully revoked');
      await fetchDevices();
      if (typeof onDeviceChanged === 'function') {
        onDeviceChanged();
      }
    } catch (err) {
      setError(err.message || 'Failed to revoke device trust');
    } finally {
      setRevokingId(null);
    }
  };

  const formatDate = (isoString) => {
    if (!isoString) return '—';
    try {
      const d = new Date(isoString);
      return isNaN(d.getTime()) ? String(isoString) : d.toLocaleString();
    } catch {
      return String(isoString);
    }
  };

  const currentDevice = devices.find((d) => d.is_current_device);

  return (
    <div className="space-y-6" data-testid="devices-tab">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h3 className="text-lg font-medium text-gray-900" data-testid="devices-heading">
            Trusted Devices
          </h3>
          <p className="text-sm text-gray-500">
            Manage browser and hardware trust associations to reduce authentication friction.
          </p>
        </div>
        <button
          type="button"
          onClick={fetchDevices}
          disabled={loading || enrolling || Boolean(revokingId)}
          className="inline-flex items-center px-3 py-1.5 border border-gray-300 shadow-sm text-xs font-medium rounded text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-indigo-500 self-start sm:self-auto disabled:opacity-50"
          data-testid="refresh-devices-button"
        >
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {error && (
        <div
          className="rounded-md bg-red-50 p-4 border border-red-200"
          data-testid="devices-error-banner"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <svg className="h-5 w-5 text-red-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span className="text-sm text-red-700 font-medium">{error}</span>
            </div>
            <button
              type="button"
              onClick={() => setError(null)}
              className="text-xs text-red-600 hover:text-red-800 font-semibold focus:outline-none"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {successMessage && (
        <div
          className="rounded-md bg-green-50 p-4 border border-green-200"
          data-testid="devices-success-banner"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <svg className="h-5 w-5 text-green-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
              </svg>
              <span className="text-sm text-green-800 font-medium">{successMessage}</span>
            </div>
            <button
              type="button"
              onClick={() => setSuccessMessage(null)}
              className="text-xs text-green-700 hover:text-green-900 font-semibold focus:outline-none"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Current Device Enrollment Panel */}
      {currentDevice && !currentDevice.is_trust_active && (
        <div
          className="bg-indigo-50 border border-indigo-200 rounded-lg p-5"
          data-testid="enroll-device-panel"
        >
          <div className="sm:flex sm:items-center sm:justify-between">
            <div>
              <h4 className="text-sm font-semibold text-indigo-900">
                Trust this device?
              </h4>
              <p className="mt-1 text-xs text-indigo-700">
                Enrolling your current device establishes a verified trust period of up to 30 days.
              </p>
            </div>
          </div>
          <form onSubmit={handleEnrollDevice} className="mt-4 sm:flex sm:items-center gap-3">
            <div className="w-full sm:max-w-xs">
              <label htmlFor="device-label" className="sr-only">
                Device Label
              </label>
              <input
                type="text"
                id="device-label"
                value={deviceLabel}
                onChange={(e) => setDeviceLabel(e.target.value)}
                placeholder="Device label (e.g. Work MacBook)"
                maxLength={100}
                disabled={enrolling}
                className="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full text-xs border-gray-300 rounded-md py-2 px-3 disabled:opacity-50"
                data-testid="device-label-input"
              />
            </div>
            <button
              type="submit"
              disabled={enrolling}
              className="mt-3 sm:mt-0 inline-flex items-center justify-center px-4 py-2 border border-transparent shadow-sm text-xs font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
              data-testid="trust-device-button"
            >
              {enrolling ? 'Enrolling...' : 'Trust This Device'}
            </button>
          </form>
        </div>
      )}

      {/* Devices List */}
      {loading && devices.length === 0 ? (
        <div className="py-12 flex justify-center">
          <Spinner />
        </div>
      ) : devices.length === 0 ? (
        <EmptyState
          title="No registered devices"
          description="You currently have no devices registered in your security profile."
        />
      ) : (
        <div className="bg-white shadow overflow-hidden sm:rounded-md border border-gray-200">
          <ul className="divide-y divide-gray-200" data-testid="devices-list">
            {devices.map((device) => {
              const isTrusted = Boolean(device.is_trust_active);
              const isRevoked = Boolean(device.revoked_at);
              const isExpired = Boolean(
                !isTrusted && !isRevoked && device.expires_at && new Date(device.expires_at) <= new Date()
              );

              return (
                <li
                  key={device.id}
                  className="p-4 sm:px-6 hover:bg-gray-50 transition duration-150"
                  data-testid={`device-item-${device.id}`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-medium text-gray-900 text-sm" data-testid={`device-label-${device.id}`}>
                          {device.label || 'Unnamed Device'}
                        </span>

                        {device.is_current_device && (
                          <span
                            className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-indigo-100 text-indigo-800"
                            data-testid={`current-device-badge-${device.id}`}
                          >
                            Current Device
                          </span>
                        )}

                        {isTrusted ? (
                          <span
                            className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-green-100 text-green-800"
                            data-testid={`device-status-badge-${device.id}`}
                          >
                            Trusted
                          </span>
                        ) : isRevoked ? (
                          <span
                            className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-red-100 text-red-800"
                            data-testid={`device-status-badge-${device.id}`}
                          >
                            Revoked
                          </span>
                        ) : isExpired ? (
                          <span
                            className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-amber-100 text-amber-800"
                            data-testid={`device-status-badge-${device.id}`}
                          >
                            Expired
                          </span>
                        ) : (
                          <span
                            className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-gray-100 text-gray-700"
                            data-testid={`device-status-badge-${device.id}`}
                          >
                            Untrusted
                          </span>
                        )}
                      </div>

                      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-500">
                        <span>First seen: {formatDate(device.first_seen_at)}</span>
                        <span>Last active: {formatDate(device.last_used_at)}</span>
                        {device.trusted_at && <span>Trusted since: {formatDate(device.trusted_at)}</span>}
                        {device.expires_at && <span>Expires: {formatDate(device.expires_at)}</span>}
                        {device.revoked_at && <span>Revoked: {formatDate(device.revoked_at)}</span>}
                      </div>
                    </div>

                    <div className="flex items-center gap-2 self-start sm:self-center">
                      {(device.is_trust_active || device.is_trusted) && (
                        <button
                          type="button"
                          onClick={() => handleRevokeDevice(device.id)}
                          disabled={revokingId === device.id || enrolling}
                          className="inline-flex items-center px-3 py-1.5 border border-red-300 shadow-sm text-xs font-medium rounded text-red-700 bg-white hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-red-500 disabled:opacity-50"
                          data-testid={`revoke-device-button-${device.id}`}
                        >
                          {revokingId === device.id ? 'Revoking...' : 'Revoke Trust'}
                        </button>
                      )}
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}
