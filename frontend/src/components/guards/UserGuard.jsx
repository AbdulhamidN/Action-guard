import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { getUserToken } from '../../services/authStorage.js';

/**
 * Route guard enforcing that an active user session token exists in sessionStorage.
 * If absent, redirects the user to /login.
 *
 * @param {{ children?: React.ReactNode }} [props]
 */
export function UserGuard({ children }) {
  const token = getUserToken();

  if (!token) {
    return <Navigate to="/login" replace />;
  }

  return children ? <>{children}</> : <Outlet />;
}
