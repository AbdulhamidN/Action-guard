import React from 'react';
import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { UserGuard } from '../components/guards/UserGuard.jsx';
import { AdminGuard } from '../components/guards/AdminGuard.jsx';
import * as authStorage from '../services/authStorage.js';

describe('Route Guards', () => {
  beforeEach(() => {
    sessionStorage.clear();
    authStorage.clearAllAuth();
  });

  it('UserGuard blocks unauthenticated user and redirects to /login', () => {
    render(
      <MemoryRouter initialEntries={['/app/dashboard']}>
        <Routes>
          <Route path="/login" element={<div>User Login Destination</div>} />
          <Route
            path="/app/*"
            element={
              <UserGuard>
                <div>Protected User Shell Content</div>
              </UserGuard>
            }
          />
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByText('User Login Destination')).toBeInTheDocument();
    expect(screen.queryByText('Protected User Shell Content')).not.toBeInTheDocument();
  });

  it('UserGuard allows access when user token is present in sessionStorage', () => {
    authStorage.setUserToken('valid-user-jwt');

    render(
      <MemoryRouter initialEntries={['/app/dashboard']}>
        <Routes>
          <Route path="/login" element={<div>User Login Destination</div>} />
          <Route
            path="/app/*"
            element={
              <UserGuard>
                <div>Protected User Shell Content</div>
              </UserGuard>
            }
          />
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByText('Protected User Shell Content')).toBeInTheDocument();
    expect(screen.queryByText('User Login Destination')).not.toBeInTheDocument();
  });

  it('AdminGuard blocks operator when in-memory token is absent and redirects to /admin/login', () => {
    render(
      <MemoryRouter initialEntries={['/admin/overview']}>
        <Routes>
          <Route path="/admin/login" element={<div>Admin Login Destination</div>} />
          <Route
            path="/admin/*"
            element={
              <AdminGuard>
                <div>Protected Admin Shell Content</div>
              </AdminGuard>
            }
          />
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByText('Admin Login Destination')).toBeInTheDocument();
    expect(screen.queryByText('Protected Admin Shell Content')).not.toBeInTheDocument();
  });

  it('AdminGuard allows access when in-memory admin token is present', () => {
    authStorage.setAdminToken('agadm_valid_session_token');

    render(
      <MemoryRouter initialEntries={['/admin/overview']}>
        <Routes>
          <Route path="/admin/login" element={<div>Admin Login Destination</div>} />
          <Route
            path="/admin/*"
            element={
              <AdminGuard>
                <div>Protected Admin Shell Content</div>
              </AdminGuard>
            }
          />
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByText('Protected Admin Shell Content')).toBeInTheDocument();
    expect(screen.queryByText('Admin Login Destination')).not.toBeInTheDocument();
  });
});
