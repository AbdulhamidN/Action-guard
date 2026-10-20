import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

describe('Production Build Artifact Verification', () => {
  it('strictly compiles out the ag_fp_override fingerprint bypass from production bundle', () => {
    const distDir = path.resolve(__dirname, '../../dist/assets');

    expect(fs.existsSync(distDir), 'frontend/dist/assets must exist (built prior to test execution)').toBe(true);

    const assetFiles = fs.readdirSync(distDir);
    const jsFiles = assetFiles.filter((file) => file.endsWith('.js'));

    expect(jsFiles.length).toBeGreaterThan(0);

    for (const jsFile of jsFiles) {
      const content = fs.readFileSync(path.join(distDir, jsFile), 'utf-8');
      expect(content).not.toContain('ag_fp_override');
    }
  });
});
