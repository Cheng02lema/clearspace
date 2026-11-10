'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs/promises');
const os = require('node:os');
const { createContext, getTargets } = require('../legacy/src/core/targets');
const { publicPrivacyActions, browsersRunning, parseFirefoxProfilesIni } = require('../legacy/src/core/privacy-actions');
const { getEffectiveTargetCatalog } = require('../legacy/src/core/target-catalog');

test('macOS honors an absolute custom Claude directory without exposing a full reset', () => {
  const context = createContext({ platform: 'darwin', homeDir: '/Users/example', env: { CLAUDE_CONFIG_DIR: '/Users/example/custom-claude' } });
  const targets = getTargets(context);
  assert.equal(context.claudeConfigDir, '/Users/example/custom-claude');
  assert.equal(targets.find(t => t.id === 'code.credentials-file').resources[0].path, '/Users/example/custom-claude/.credentials.json');
  assert.equal(targets.some(t => t.id === 'code.full-reset'), false);
});

test('macOS blocks a relative custom Claude directory', () => {
  const context = createContext({ platform: 'darwin', homeDir: '/Users/example', env: { CLAUDE_CONFIG_DIR: 'relative' } });
  assert.ok(context.claudeConfigError);
  assert.ok(getTargets(context).filter(t => t.group === 'code').every(t => t.blockedReason));
});

test('macOS action list excludes Windows-only DNS, AdGuard and language management', () => {
  const actions = publicPrivacyActions({ platform: 'darwin' });
  const ids = new Set(actions.map(a => a.id));
  for (const id of ['protect-dns', 'restore-dns', 'install-adguard', 'remove-managed-adguard', 'block-location-sync-language', 'restore-browser-location-language']) {
    assert.equal(ids.has(id), false, id);
  }
  assert.ok(ids.has('block-location'));
  assert.match(actions.find(a => a.id === 'claude-environment').description, /shell/);
});

test('macOS detects running browsers using a mocked process list', async () => {
  const context = createContext({ platform: 'darwin', homeDir: '/Users/example', env: {} });
  const result = await browsersRunning(context, async () => ({ code: 0, stdout: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n/Applications/Firefox.app/Contents/MacOS/firefox\n' }));
  assert.deepEqual(result, ['Google Chrome', 'Firefox']);
});

test('Firefox relative profiles resolve relative to profiles.ini on macOS', () => {
  const ini = '[Profile0]\nIsRelative=1\nPath=Profiles/abc.default-release\n';
  assert.deepEqual(parseFirefoxProfilesIni(ini, '/Users/example/Library/Application Support/Firefox', path.posix),
    ['/Users/example/Library/Application Support/Firefox/Profiles/abc.default-release']);
});

test('invalid macOS configuration blocks dynamically discovered Code data', { skip: process.platform !== 'darwin' }, async () => {
  const parent = await fs.realpath(os.homedir());
  const root = await fs.mkdtemp(path.join(parent, '.clearspace-test-'));
  try {
    const config = path.join(root, '.claude');
    await fs.mkdir(config);
    await fs.writeFile(path.join(config, 'settings.json'), '{}');
    const context = createContext({ platform: 'darwin', homeDir: root, env: { CLAUDE_CONFIG_DIR: 'relative' } });
    const { targets } = await getEffectiveTargetCatalog(context, {
      discovery: { globalSearch: true, discoveryRoots: [{ path: root, scope: 'all', maxDepth: 3 }], timeoutMs: 10000 },
    });
    const code = targets.filter(item => item.group === 'code');
    assert.ok(code.length > 0);
    assert.ok(code.every(item => item.blockedReason && !item.defaultSelected));
  } finally {
    assert.equal(path.dirname(root), parent);
    assert.ok(path.basename(root).startsWith('.clearspace-test-'));
    assert.equal((await fs.lstat(root)).isSymbolicLink(), false);
    await fs.rm(root, { recursive: true, force: true });
  }
});
