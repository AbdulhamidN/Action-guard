const { createRequire } = require('module');
const frontendRequire = createRequire(require('path').resolve(__dirname, '../frontend/package.json'));
const { test, expect } = frontendRequire('@playwright/test');
const http = require('http');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const app = require('../src/app');
const { initSocketServer, closeSocketServer } = require('../src/realtime/socketServer');
const { User, Session, SecurityEvent, RiskAssessment, PolicyDecision } = require('../src/database/models');
const { createSession } = require('../src/services/sessionService');

test.describe('User Security Portal E2E (Module 12c-2)', () => {
  let server;
  let port;
  let baseUrl;
  let testUser;
  let testPassword = 'TestPassword123!';
  const origServeFrontend = process.env.SERVE_FRONTEND;
  const origDemoMode = process.env.ACTIONGUARD_DEMO_MODE;
  const origJwtSecret = process.env.JWT_SECRET;

  test.beforeAll(async () => {
    process.env.SERVE_FRONTEND = 'true';
    process.env.ACTIONGUARD_DEMO_MODE = 'true';
    process.env.JWT_SECRET = 'test_jwt_secret_must_be_at_least_32_characters_long_12345';

    // Seed test user with hashed password
    const passwordHash = await bcrypt.hash(testPassword, 10);
    testUser = await User.create({
      id: `usr_e2e_uportal_${Date.now()}`,
      email: `user-portal-e2e-${Date.now()}@actionguard.test`,
      password_hash: passwordHash
    });

    server = http.createServer(app);
    await new Promise((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        initSocketServer(server, { corsOrigins: [baseUrl, `http://localhost:${port}`] });
        resolve();
      });
    });
  });

  test.afterAll(async () => {
    try {
      await closeSocketServer();
    } catch {
      // ignore
    }
    if (server && server.listening) {
      await new Promise((resolve) => server.close(resolve));
    }
    if (testUser) {
      try {
        await SecurityEvent.destroy({ where: { user_id: testUser.id }, force: true });
        await RiskAssessment.destroy({ where: { user_id: testUser.id }, force: true });
        await PolicyDecision.destroy({ where: { user_id: testUser.id }, force: true });
        await Session.destroy({ where: { user_id: testUser.id }, force: true });
        await User.destroy({ where: { id: testUser.id }, force: true });
      } catch {
        // ignore cleanup error
      }
    }
    if (origServeFrontend) {
      process.env.SERVE_FRONTEND = origServeFrontend;
    } else {
      delete process.env.SERVE_FRONTEND;
    }
    if (origDemoMode) {
      process.env.ACTIONGUARD_DEMO_MODE = origDemoMode;
    } else {
      delete process.env.ACTIONGUARD_DEMO_MODE;
    }
    if (origJwtSecret) {
      process.env.JWT_SECRET = origJwtSecret;
    } else {
      delete process.env.JWT_SECRET;
    }
  });

  test('user logs in, inspects active sessions, terminates secondary session, elevates via step-up OTP, and logs out', async ({ page }) => {
    // 1. Navigate to user login page
    await page.goto(`${baseUrl}/login`);
    await expect(page.locator('#user-email')).toBeVisible();
    await expect(page.locator('#user-password')).toBeVisible();

    // 2. Submit credentials
    await page.locator('#user-email').fill(testUser.email);
    await page.locator('#user-password').fill(testPassword);
    await page.getByRole('button', { name: 'Sign In' }).click();

    // 3. Confirm redirected to User Portal
    await expect(page).toHaveURL(`${baseUrl}/app`);
    await expect(page.getByTestId('page-title')).toHaveText('User Security Portal');
    await expect(page.getByTestId('portal-tabs')).toBeVisible();

    // 4. Verify Active Sessions tab is default
    await expect(page.getByTestId('current-session-badge')).toHaveText('Current Session');
    await expect(page.getByTestId('current-session-note')).toHaveText('Active (Use Sign Out)');

    // 5. Seed a secondary session for this user to test remote session termination
    const secondarySession = await createSession(testUser.id, testUser.email, 3600);
    await page.getByTestId('refresh-sessions-button').click();

    const terminateBtn = page.getByTestId(`terminate-session-${secondarySession.sessionId}`);
    await expect(terminateBtn).toBeVisible({ timeout: 10000 });

    // Terminate the secondary session
    await terminateBtn.click();
    await expect(page.getByTestId('sessions-success')).toHaveText(/successfully terminated/);
    await expect(terminateBtn).not.toBeVisible();

    // 6. Test Step-Up Identity Re-Verification Modal
    await page.getByTestId('trigger-step-up-btn').click();
    const modal = page.getByTestId('step-up-modal');
    await expect(modal).toBeVisible();
    await expect(page.getByTestId('step-up-title')).toHaveText('Identity Re-Verification Required');
    await expect(page.getByTestId('step-up-input')).toBeVisible();

    // Click demo button to fetch OTP
    await page.getByTestId('step-up-demo-button').click();

    // Verify 6-digit code was fetched and populated
    await expect(page.getByTestId('step-up-input')).toHaveValue(/^\d{6}$/);

    // Submit verification
    await page.getByTestId('step-up-submit-button').click();

    // Modal should close upon successful elevation
    await expect(modal).not.toBeVisible();

    // 7. Policy Playground Demonstration
    await page.getByTestId('tab-playground').click();
    await expect(page.getByTestId('action-panel-title')).toBeVisible();

    // Execute standard action (Update Phone) -> expect Allow
    await page.getByTestId('btn-update-phone').click();
    await expect(page.getByTestId('action-success-alert')).toBeVisible();
    await expect(page.getByTestId('action-success-alert')).toContainText('Action Allowed & Completed');

    // 8. Delayed Actions (Cooling-Off) tab inspection
    await page.getByTestId('tab-delayed').click();
    await expect(page.getByTestId('cooling-off-heading')).toBeVisible();

    // 9. Logout
    await page.getByRole('button', { name: 'Sign Out' }).click();
    await expect(page).toHaveURL(`${baseUrl}/login`);

    // Verify tokens were cleared from sessionStorage and localStorage remains empty
    const sessionToken = await page.evaluate(() => sessionStorage.getItem('ag_user_token'));
    const localStorageCount = await page.evaluate(() => localStorage.length);
    expect(sessionToken).toBeNull();
    expect(localStorageCount).toBe(0);
  });
});
