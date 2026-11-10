'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { browsersRunning } = require('../legacy/src/core/privacy-actions');
const { createContext } = require('../legacy/src/core/targets');

const context = createContext({ platform: 'win32', homeDir: 'C:\\Users\\Test', env: { SystemRoot: 'C:\\Windows' } });
test('uses verified fallback when tasklist is unavailable', async () => {
  const called = [];
  const runner = async (file) => {
    called.push(path.win32.basename(file).toLowerCase());
    return called.length === 1 ? { code: 1, stdout: '' } : { code: 0, stdout: 'chrome.exe\r\nCLEARSPACE_PROCESS_CHECK_OK\r\n' };
  };
  assert.deepEqual(await browsersRunning(context, runner), ['chrome.exe']);
  assert.deepEqual(called, ['tasklist.exe', 'powershell.exe']);
});

test('fails closed if process inventory is incomplete', async () => {
  let calls = 0;
  const runner = async () => ++calls === 1 ? { code: 1, stdout: '' } : { code: 0, stdout: '' };
  await assert.rejects(browsersRunning(context, runner));
});
