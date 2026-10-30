import React from 'react';
import { describe, it, expect, beforeAll } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { PublicNavbar } from '../components/public/PublicNavbar.jsx';
import { PublicFooter } from '../components/public/PublicFooter.jsx';
import { PlatformPage } from '../pages/public/PlatformPage.jsx';
import { SolutionsPage } from '../pages/public/SolutionsPage.jsx';
import { DocsPage } from '../pages/public/DocsPage.jsx';
import { AboutPage } from '../pages/public/AboutPage.jsx';

describe('ActionGuard Public Website & Navigation', () => {
  beforeAll(() => {
    // Mock scrollTo for JSDOM environment
    window.scrollTo = () => {};
  });

  it('renders PublicNavbar with branding, nav links, and Sign In dropdown', () => {
    render(
      <MemoryRouter>
        <PublicNavbar />
      </MemoryRouter>
    );

    // Brand and primary navigation
    expect(screen.getByText('ActionGuard')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /^home$/i })).toHaveAttribute('href', '/');
    expect(screen.getByRole('link', { name: /^about$/i })).toHaveAttribute('href', '/about');

    // Sign In dropdown & admin login link
    expect(screen.getByTestId('nav-admin')).toHaveAttribute('href', '/admin/login');
  });

  it('renders PublicFooter with verified project links and open source info', () => {
    render(
      <MemoryRouter>
        <PublicFooter />
      </MemoryRouter>
    );

    expect(screen.getByTestId('public-footer')).toBeInTheDocument();
    expect(screen.getByText(/Apache-2.0 License/i)).toBeInTheDocument();
    expect(screen.getByText(/INSA Summer Camp 2026/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /github repository/i })).toHaveAttribute('href', 'https://github.com/AbdulhamidN/Action-guard');
  });

  it('renders Platform page with Overview, How It Works, Capabilities, and Architecture', () => {
    render(
      <MemoryRouter>
        <PlatformPage />
      </MemoryRouter>
    );

    expect(screen.getByText(/A Decoupled Zero Trust Engine for Continuous Action Security/i)).toBeInTheDocument();
    expect(screen.getByText(/Why Login-Time Authentication Is No Longer Enough/i)).toBeInTheDocument();
    expect(screen.getByText(/The 6-Stage Security Decision & Enforcement Flow/i)).toBeInTheDocument();
    expect(screen.getByText(/Modular Signals, Scoring, and Containment Tools/i)).toBeInTheDocument();
    expect(screen.getByText(/PDP & PEP Separation Across Modular Components/i)).toBeInTheDocument();
  });

  it('renders Solutions page with ATO, Session Security, and Adaptive Authorization', () => {
    render(
      <MemoryRouter>
        <SolutionsPage />
      </MemoryRouter>
    );

    expect(screen.getByText(/Proactive Defense Against Account Takeover & Session Hijacking/i)).toBeInTheDocument();
    expect(screen.getByText(/Account Takeover \(ATO\) Protection/i)).toBeInTheDocument();
    expect(screen.getByText(/Session Hijacking & Cookie Theft Defense/i)).toBeInTheDocument();
    expect(screen.getByText(/Adaptive, Risk-Proportional Authorization/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Allow/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Block & Contain/i)).toBeInTheDocument();
  });

  it('renders Docs page with Installation Guide, Environment Variables, and API Contract', () => {
    render(
      <MemoryRouter>
        <DocsPage />
      </MemoryRouter>
    );

    expect(screen.getByText(/ActionGuard Developer Documentation/i)).toBeInTheDocument();
    expect(screen.getByText(/Installation & Deployment/i)).toBeInTheDocument();
    expect(screen.getByText(/Configuration Reference \(\.env\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Core Endpoints & Request Contracts/i)).toBeInTheDocument();

    // Verifies authentic routes
    expect(screen.getByText('/api/v1/auth/signup')).toBeInTheDocument();
    expect(screen.getByText('/api/v1/auth/login')).toBeInTheDocument();
    expect(screen.getByText('/api/v1/account/recovery-email')).toBeInTheDocument();
  });

  it('renders About page with verified INSA Summer Camp 2026 origin and mission', () => {
    render(
      <MemoryRouter>
        <AboutPage />
      </MemoryRouter>
    );

    expect(screen.getByText(/Building Open-Source Zero Trust for Continuous Session Defense/i)).toBeInTheDocument();
    expect(screen.getByText(/INSA Summer Camp 2026 \(Group 2\)/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Jimma, Ethiopia/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Never Trust, Always Verify/i)).toBeInTheDocument();
  });
});