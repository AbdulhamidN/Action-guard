const { createRequire } = require('module');
const frontendRequire = createRequire(require('path').resolve(__dirname, 'frontend/package.json'));
const { defineConfig, devices } = frontendRequire('@playwright/test');

module.exports = defineConfig({
  testDir: './e2e',
  testMatch: '**/*.e2e.js',
  timeout: 30000,
  expect: { timeout: 10000 },
  workers: 1,
  use: {
    headless: true,
    viewport: { width: 1280, height: 720 },
    ignoreHTTPSErrors: true
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] }
    }
  ]
});
