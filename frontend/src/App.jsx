import React from 'react';
import { Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { LandingPage } from './pages/LandingPage.jsx';
import { UserLoginPage } from './pages/UserLoginPage.jsx';
import { UserSignupPage } from './pages/UserSignupPage.jsx';
import { AdminLoginPage } from './pages/AdminLoginPage.jsx';
import { UserShell } from './pages/UserShell.jsx';
import { AdminShell } from './pages/AdminShell.jsx';
import { NotFoundPage } from './pages/NotFoundPage.jsx';
import { UserGuard } from './components/guards/UserGuard.jsx';
import { AdminGuard } from './components/guards/AdminGuard.jsx';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 5000
    }
  }
});

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/login" element={<UserLoginPage />} />
        <Route path="/signup" element={<UserSignupPage />} />
        <Route path="/admin/login" element={<AdminLoginPage />} />

        {/* Protected User Shell */}
        <Route
          path="/app/*"
          element={
            <UserGuard>
              <UserShell />
            </UserGuard>
          }
        />

        {/* Protected Admin Shell */}
        <Route
          path="/admin/*"
          element={
            <AdminGuard>
              <AdminShell />
            </AdminGuard>
          }
        />

        {/* 404 Catch-All */}
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </QueryClientProvider>
  );
}

export default App;
