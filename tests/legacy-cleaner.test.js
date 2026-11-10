'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createContext } = require('../legacy/src/core/targets');
const { cleanTargets } = require('../legacy/src/core/cleaner');

async function removeFixture(root, prefix) {
  assert.equal(path.resolve(path.dirname(root)).toLowerCase(), path.resolve(os.tmpdir()).toLowerCase());
  assert.ok(path.basename(root).startsWith(prefix));
  assert.equal((await fs.lstat(root)).isSymbolicLink(), false);
  await fs.rm(root, { recursive: true, force: true });
}

test('cleanup is confined to selected files in a temporary fixture', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'clearspace-test-'));
  try {
    const home = path.join(root, 'home');
    const targetDir = path.join(home, 'data');
    const quarantine = path.join(root, 'quarantine');
    await fs.mkdir(targetDir, { recursive: true });
    const victim = path.join(targetDir, 'selected.txt');
    const neighbor = path.join(targetDir, 'untouched.txt');
    await fs.writeFile(victim, 'selected test data');
    await fs.writeFile(neighbor, 'keep test data');
    const context = createContext({ homeDir: home, documentsDir: path.join(home, 'Documents'),
      userDataDir: path.join(home, 'userdata'), env: { LOCALAPPDATA: path.join(home, 'AppData', 'Local'), APPDATA: path.join(home, 'AppData', 'Roaming') } });
    const target = { id: 'fixture.file', title: 'fixture', resources: [{ type: 'path', label: 'fixture', path: victim }], exclusiveWith: [], backup: false };
    const result = await cleanTargets([target.id], context, { targets: [target], backupRoot: quarantine, createBackups: false, retainOperationRecord: false });
    assert.equal(result.results[0].status, 'cleaned');
    await assert.rejects(fs.stat(victim), { code: 'ENOENT' });
    assert.equal(await fs.readFile(neighbor, 'utf8'), 'keep test data');
  } finally {
    await removeFixture(root, 'clearspace-test-');
  }
});

test('cleanup refuses a junction and preserves its contents', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'clearspace-test-link-'));
  try {
    const home = path.join(root, 'home');
    const outside = path.join(root, 'outside');
    await fs.mkdir(home, { recursive: true });
    await fs.mkdir(outside, { recursive: true });
    await fs.writeFile(path.join(outside, 'keep.txt'), 'keep');
    const link = path.join(home, 'linked');
    await fs.symlink(outside, link, process.platform === 'win32' ? 'junction' : 'dir');
    const context = createContext({ homeDir: home, documentsDir: path.join(home, 'Documents'),
      userDataDir: path.join(home, 'userdata'), env: { LOCALAPPDATA: path.join(home, 'AppData', 'Local'), APPDATA: path.join(home, 'AppData', 'Roaming') } });
    const target = { id: 'fixture.link', title: 'fixture link', resources: [{ type: 'path', label: 'link', path: link }], exclusiveWith: [], backup: false };
    const result = await cleanTargets([target.id], context, { targets: [target], backupRoot: path.join(root, 'quarantine'), createBackups: false, retainOperationRecord: false });
    assert.equal(result.results[0].status, 'failed');
    assert.equal(await fs.readFile(path.join(outside, 'keep.txt'), 'utf8'), 'keep');
  } finally {
    await removeFixture(root, 'clearspace-test-link-');
  }
});
