const { createRequire } = require('module');
const frontendRequire = createRequire(require('path').resolve(__dirname, '../frontend/package.json'));
const { test, expect } = frontendRequire('@playwright/test');
const http = require('http');
const app = require('../src/app');
const { initSocketServer, closeSocketServer } = require('../src/realtime/socketServer');
const { User, SecurityEvent, RiskAssessment, PolicyDecision } = require('../src/database/models');

const TEST_ADMIN_KEY = 'admin_secret_key_with_at_least_32_characters_12345';
const TEST_SERVICE_KEY = 'service_key_for_events_integration_test_32chars';

test.describe('Admin Console E2E & Real-Time Live Feed', () => {
  let server;
  let port;
  let baseUrl;
  let testUserId;
  const originalAdminKey = process.env.ACTIONGUARD_ADMIN_API_KEY;
  const originalApiKey = process.env.API_KEY;
  const originalServeFrontend = process.env.SERVE_FRONTEND;

  test.beforeAll(async () => {
    process.env.ACTIONGUARD_ADMIN_API_KEY = TEST_ADMIN_KEY;
    process.env.API_KEY = TEST_SERVICE_KEY;
    process.env.SERVE_FRONTEND = 'true';

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
    if (testUserId) {
      try {
        await SecurityEvent.destroy({ where: { user_id: testUserId }, force: true });
        await RiskAssessment.destroy({ where: { user_id: testUserId }, force: true });
        await PolicyDecision.destroy({ where: { user_id: testUserId }, force: true });
        await User.destroy({ where: { id: testUserId }, force: true });
      } catch {
        // ignore cleanup error
      }
    }
    if (originalAdminKey) {
      process.env.ACTIONGUARD_ADMIN_API_KEY = originalAdminKey;
    } else {
      delete process.env.ACTIONGUARD_ADMIN_API_KEY;
    }
    if (originalApiKey) {
      process.env.API_KEY = originalApiKey;
    } else {
      delete process.env.API_KEY;
    }
    if (originalServeFrontend) {
      process.env.SERVE_FRONTEND = originalServeFrontend;
    } else {
      delete process.env.SERVE_FRONTEND;
    }
  });

  test('operator logs in, receives real-time event via WebSocket without page reload, and inspects drawer', async ({ page, request }) => {
    // 1. Navigate to admin operator login
    await page.goto(`${baseUrl}/admin/login`);
    await expect(page.getByTestId('admin-key-input')).toBeVisible();

    // 2. Submit valid admin key
    await page.getByTestId('admin-key-input').fill(TEST_ADMIN_KEY);
    await page.getByTestId('admin-submit-button').click();

    // 3. Confirm redirected to Admin Shell / Overview
    await expect(page).toHaveURL(`${baseUrl}/admin/overview`);
    await expect(page.getByTestId('overview-title')).toBeVisible();
    await expect(page.getByTestId('live-console')).toBeVisible();

    // 4. Capture current page reload state marker to prove no full page reload occurs
    await page.evaluate(() => {
      window.__AG_E2E_NO_RELOAD_MARKER__ = 'SESSION_RETAINED_NO_RELOAD';
    });

    // 5. Create test user in database to satisfy foreign key validation for event ingestion
    testUserId = `usr_e2e_stream_${Date.now()}`;
    await User.create({
      id: testUserId,
      email: `${testUserId}@actionguard.test`,
      password_hash: '$2b$10$devdummyhashforseedonlynotforproduction0000000000000000'
    });

    // 6. Submit valid security event via documented POST /api/v1/events endpoint using service-level API key
    const nowIso = new Date().toISOString();
    const eventResponse = await request.post(`${baseUrl}/api/v1/events`, {
      headers: {
        'Authorization': `Bearer ${TEST_SERVICE_KEY}`,
        'Content-Type': 'application/json'
      },
      data: {
        user_id: testUserId,
        event_type: 'password_change',
        timestamp: nowIso,
        context: {
          ip_address: '198.51.100.42',
          device_fingerprint: 'fp_valid_device_e2e_test',
          user_agent: 'ActionGuardE2ETest/1.0'
        },
        metadata: {
          action_sensitivity: 'critical'
        }
      }
    });

    expect(eventResponse.status()).toBe(201);
    const eventResult = await eventResponse.json();
    const uniqueEventId = eventResult.event_id;
    expect(uniqueEventId).toBeDefined();

    // 7. Verify event dynamically appears in live activity feed without page reload
    const liveItem = page.getByRole('button', {
      name: `View details for password_change by ${testUserId}`
    });
    await expect(liveItem).toBeVisible({ timeout: 10000 });

    // Assert that the page was NOT reloaded during event arrival
    const marker = await page.evaluate(() => window.__AG_E2E_NO_RELOAD_MARKER__);
    expect(marker).toBe('SESSION_RETAINED_NO_RELOAD');

    // 8. Click event row to open accessible EventDetailDrawer
    await liveItem.click();
    const drawer = page.getByTestId('event-detail-drawer');
    await expect(drawer).toBeVisible();
    await expect(page.getByTestId('drawer-title')).toHaveText('Event Details');
    await expect(drawer.getByText(uniqueEventId)).toBeVisible();
    await expect(drawer.getByText('password_change')).toBeVisible();
    await expect(drawer.getByText(testUserId)).toBeVisible();

    // 9. Press Escape to close drawer and confirm closure
    await page.keyboard.press('Escape');
    await expect(drawer).not.toBeVisible();
  });
});
