import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { getAdminToken } from '../../services/authStorage.js';

/**
 * Route guard enforcing that an active admin session token exists in memory.
 * If absent (e.g. following a page refresh or expired session), redirects to /admin/login.
 *
 * @param {{ children?: React.ReactNode }} [props]
 */
export function AdminGuard({ children }) {
  const adminToken = getAdminToken();

  if (!adminToken) {
    return <Navigate to="/admin/login" replace />;
  }

  return children ? <>{children}</> : <Outlet />;
}
