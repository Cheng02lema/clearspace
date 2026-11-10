const { spawn } = require('node:child_process');
const readline = require('node:readline');

function createPythonConfirmationService({ python, script }) {
  let child = null;
  let nextId = 0;
  const pending = new Map();
  function failAll(error) {
    for (const item of pending.values()) { clearTimeout(item.timer); item.reject(error); }
    pending.clear();
  }
  function start() {
    if (child) return;
    const process = spawn(python, ['-u', script], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], env: { ...globalThis.process.env, PYTHONIOENCODING: 'utf-8', PYTHONUTF8: '1' } });
    child = process;
    readline.createInterface({ input: process.stdout }).on('line', (line) => {
      let response;
      try { response = JSON.parse(line); } catch { failAll(new Error('Python 后端返回了无效数据。')); process.kill(); return; }
      const item = pending.get(response.id);
      if (!item) return;
      pending.delete(response.id);
      clearTimeout(item.timer);
      if (response.error) item.reject(new Error(response.error)); else item.resolve(response.result);
    });
    process.stderr.on('data', () => {});
    process.stdin.on('error', () => {});
    process.on('error', (error) => { failAll(new Error(`无法启动 Python 后端：${error.message}`)); });
    process.on('exit', () => { if (child === process) child = null; failAll(new Error('Python 后端已退出，请重新操作。')); });
  }
  function request(action, payload = {}) {
    start();
    return new Promise((resolve, reject) => {
      const id = ++nextId;
      const timer = setTimeout(() => { pending.delete(id); reject(new Error('Python 后端响应超时。')); }, action === 'path_size' ? 120000 : 10000);
      pending.set(id, { resolve, reject, timer });
      child.stdin.write(`${JSON.stringify({ id, action, ...payload })}\n`, (error) => {
        if (error && pending.has(id)) { clearTimeout(timer); pending.delete(id); reject(error); }
      });
    });
  }
  return {
    ping: () => request('ping'),
    pathSize: (path) => request('path_size', { path }),
    issue: (kind, values) => request('issue', { kind, values }),
    consume: (token, kind, values) => request('consume', { token, kind, values }),
    close: () => { if (child) child.kill(); },
  };
}
module.exports = { createPythonConfirmationService };

