import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

/**
 * Recursively retrieves all application source files (.js, .jsx) excluding test files.
 *
 * @param {string} dir
 * @returns {string[]}
 */
function getAppSourceFiles(dir) {
  let results = [];
  const list = fs.readdirSync(dir);
  for (const file of list) {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      if (file !== 'tests' && file !== '__tests__' && file !== 'node_modules') {
        results = results.concat(getAppSourceFiles(fullPath));
      }
    } else if (
      (file.endsWith('.js') || file.endsWith('.jsx')) &&
      !file.endsWith('.test.js') &&
      !file.endsWith('.test.jsx') &&
      file !== 'setupTests.js'
    ) {
      results.push(fullPath);
    }
  }
  return results;
}

describe('Security Hygiene & Anti-XSS Source Audit', () => {
  it('confirms that no dangerouslySetInnerHTML exists anywhere in frontend/src', () => {
    const srcDir = path.resolve(__dirname, '..');
    const sourceFiles = getAppSourceFiles(srcDir);

    expect(sourceFiles.length).toBeGreaterThan(0);

    const forbiddenToken = ['dangerously', 'SetInnerHTML'].join('');

    for (const file of sourceFiles) {
      const code = fs.readFileSync(file, 'utf-8');
      expect(code, `dangerouslySetInnerHTML found in ${file}`).not.toContain(forbiddenToken);
    }
  });
});
