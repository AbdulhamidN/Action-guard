import React from 'react';
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { TierBadge } from '../components/common/TierBadge.jsx';

describe('TierBadge Accessibility & Structure', () => {
  it('renders low tier with explicit text and an icon (never color alone)', () => {
    const { container } = render(<TierBadge tier="low" />);

    const badge = screen.getByRole('status', { name: /Risk tier: Low/i });
    expect(badge).toBeInTheDocument();
    expect(screen.getByText('Low')).toBeInTheDocument();

    const svgIcon = container.querySelector('svg');
    expect(svgIcon).toBeInTheDocument();
  });

  it('renders medium tier with explicit text and an icon', () => {
    const { container } = render(<TierBadge tier="medium" />);

    const badge = screen.getByRole('status', { name: /Risk tier: Medium/i });
    expect(badge).toBeInTheDocument();
    expect(screen.getByText('Medium')).toBeInTheDocument();

    const svgIcon = container.querySelector('svg');
    expect(svgIcon).toBeInTheDocument();
  });

  it('renders high tier with explicit text and an icon', () => {
    const { container } = render(<TierBadge tier="high" />);

    const badge = screen.getByRole('status', { name: /Risk tier: High/i });
    expect(badge).toBeInTheDocument();
    expect(screen.getByText('High')).toBeInTheDocument();

    const svgIcon = container.querySelector('svg');
    expect(svgIcon).toBeInTheDocument();
  });

  it('renders critical tier with explicit text and an icon', () => {
    const { container } = render(<TierBadge tier="critical" />);

    const badge = screen.getByRole('status', { name: /Risk tier: Critical/i });
    expect(badge).toBeInTheDocument();
    expect(screen.getByText('Critical')).toBeInTheDocument();

    const svgIcon = container.querySelector('svg');
    expect(svgIcon).toBeInTheDocument();
  });
});
