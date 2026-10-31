import { test, expect } from '@playwright/test';

test.describe('TRACEX Platform Smoke Suite', () => {
  test('loads SOC overview and verifies branding and navigation', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveTitle(/TRACEX|Vite/);
    await expect(page.getByText('TRACEX')).toBeVisible();
    await expect(page.getByText('Investigate. Analyze. Correlate. Discover.')).toBeVisible();
    await expect(page.getByText('File Forensics')).toBeVisible();
    await expect(page.getByText('Threat Intel')).toBeVisible();
    await expect(page.getByText('Evidence Locker')).toBeVisible();
  });
});
