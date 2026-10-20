import React from 'react';
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { LandingPage } from '../pages/LandingPage.jsx';

describe('Landing page', () => {
  const renderPage = () =>
    render(
      <MemoryRouter>
        <LandingPage />
      </MemoryRouter>
    );

  it('renders the headline and all five response tiers', () => {
    renderPage();
    expect(screen.getByTestId('landing-title')).toBeInTheDocument();
    const tiers = screen.getByTestId('tier-list');
    ['allow', 'monitor', 'reverify', 'delay', 'block'].forEach((t) => {
      expect(tiers).toHaveTextContent(t);
    });
  });

  it('links to signup, login and admin login', () => {
    renderPage();
    expect(screen.getByTestId('cta-signup')).toHaveAttribute('href', '/signup');
    expect(screen.getByTestId('cta-login')).toHaveAttribute('href', '/login');
    expect(screen.getByTestId('nav-admin')).toHaveAttribute('href', '/admin/login');
  });
});
