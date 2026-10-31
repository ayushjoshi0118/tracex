import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import { StatusBadge } from '../components/StatusBadge';
import { MetricCard } from '../components/MetricCard';
import { Navbar } from '../components/Navbar';
import { ShieldAlert } from 'lucide-react';

describe('TRACEX UI Component Tests', () => {
  it('renders StatusBadge with correct classification text', () => {
    const { getByText } = render(<StatusBadge status="verified" />);
    expect(getByText(/VERIFIED/i)).toBeDefined();
  });

  it('renders MetricCard with label and value', () => {
    const { getByText } = render(
      <MetricCard
        label="Test Metric"
        value="42"
        subValue="Subtext explanation"
        icon={ShieldAlert}
      />
    );
    expect(getByText(/Test Metric/i)).toBeDefined();
    expect(getByText('42')).toBeDefined();
    expect(getByText(/Subtext explanation/i)).toBeDefined();
  });

  it('renders Navbar with brand and official tagline', () => {
    const { getByText } = render(
      <Navbar currentTab="dashboard" setCurrentTab={() => {}} />
    );
    expect(getByText('TRACEX')).toBeDefined();
    expect(getByText(/Investigate\. Analyze\. Correlate\. Discover\./i)).toBeDefined();
  });
});
