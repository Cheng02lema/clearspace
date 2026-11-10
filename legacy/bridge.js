'use strict';

// Compatibility adapter around the original, security-sensitive core.
// The Python client talks to this process over private stdin/stdout only.
const path = require('node:path');
const readline = require('node:readline');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { createContext } = require('./src/core/targets');
const { scanTargets } = require('./src/core/scanner');
const { getEffectiveTargetCatalog } = require('./src/core/target-catalog');
const { enumerateGlobalDiscoveryRoots } = require('./src/core/discovery');
const { cleanTargets, validateSelection } = require('./src/core/cleaner');
const privacy = require('./src/core/privacy-actions');
const recovery = require('./src/core/network-recovery');
const { openAdGuardSetupPages } = require('./src/core/adguard-browser-setup');
const { buildAdGuardImportUrl } = require('./src/core/adguard-setup');

const base = path.resolve(__dirname, '..');
const home = process.env.USERPROFILE || process.env.HOME;
const context = createContext({
  homeDir: home,
  documentsDir: process.env.CLEARSPACE_DOCUMENTS || path.join(home, 'Documents'),
  userDataDir: process.env.CLEARSPACE_USER_DATA || path.join(process.env.APPDATA || path.join(home, 'Library', 'Application Support'), '澄界'),
  appVersion: '2.3.7-python-preview',
});
context.workspaceRoot = base;
context.dnscryptRoot = path.join(__dirname, 'assets', 'dnscrypt-proxy', 'windows-x64');
const pending = new Map();
const ttl = 300000;

function issue(kind, values, details) {
  const now = Date.now();
  for (const [key, item] of pending) if (item.expires <= now) pending.delete(key);
  const token = crypto.randomBytes(24).toString('hex');
  pending.set(token, { kind, values: JSON.stringify(values), details, expires: now + ttl });
  return token;
}
function consume(token, kind, values) {
  const item = pending.get(token);
  pending.delete(token);
  if (!item || item.kind !== kind || item.expires <= Date.now() || item.values !== JSON.stringify(values)) {
    throw new Error('确认已过期或操作内容发生变化，请重新检查。');
  }
  return item.details;
}
function idsArg(ids, max = 500) {
  if (!Array.isArray(ids) || !ids.length || ids.length > max || ids.some(x => typeof x !== 'string' || !x || x.length > 80) || new Set(ids).size !== ids.length) throw new Error('选择的项目无效。');
  return [...ids].sort();
}
async function discovery() {
  return { globalSearch: true, discoveryRoots: await enumerateGlobalDiscoveryRoots(context, { maxDepth: 10 }), maxDepth: 10, maxEntries: 250000, maxCandidateEntries: 4096, timeoutMs: 60000 };
}
async function getCatalog() {
  const options = await discovery();
  const catalog = await getEffectiveTargetCatalog(context, { discovery: options });
  const scan = await scanTargets(context, { targets: catalog.targets, discovery: options });
  return { catalog, scan };
}
function scanSignature(scan, ids) {
  const selected = ids.map(id => {
    const item = scan.find(x => x.id === id);
    if (!item || !item.exists || item.blockedReason) throw new Error('所选项目不可用或扫描结果已变化，请重新扫描。');
    return { id, resources: item.resources.filter(r => r.exists).map(r => ({path: r.displayPath, kind: r.kind})).sort((a,b) => a.path.localeCompare(b.path)) };
  });
  return selected;
}
async function resolveClean(ids) {
  const { catalog, scan } = await getCatalog();
  const selected = validateSelection(ids, new Map(catalog.targets.map(t => [t.id, t])));
  const signature = scanSignature(scan, ids);
  if (selected.some(t => t.requiresBrowserClosed)) {
    const running = await privacy.browsersRunning(context);
    if (running.length) throw new Error(`请先完全退出浏览器：${running.join('、')}`);
  }
  return { catalog, scan, signature };
}
function privacySelection(ids) {
  const actions = privacy.publicPrivacyActions(context);
  const selected = ids.map(id => actions.find(a => a.id === id));
  if (selected.some(a => !a)) throw new Error('包含不支持的设置。');
  for (const action of selected) if ((action.exclusiveWith || []).some(id => ids.includes(id))) throw new Error(`“${action.title}”与另一项冲突，请只选一项。`);
  return selected;
}
// Python's urllib observes the Windows user proxy settings, unlike plain Node fetch.
function systemFetch(url) {
  const allowed = new Set(['https://ipwho.is/', 'https://ipapi.co/json/', 'https://www.cloudflare.com/cdn-cgi/trace']);
  if (!allowed.has(url)) return Promise.reject(new Error('不受支持的网络地址'));
  return new Promise((resolve, reject) => {
    const child = spawn(process.env.CLEARSPACE_PYTHON, [path.join(base, 'clearspace', 'fetch.py'), url], { windowsHide: true });
    let out = '', err = '';
    const timer = setTimeout(() => child.kill(), 9000);
    child.stdout.on('data', x => { out += x; if (out.length > 100000) child.kill(); });
    child.stderr.on('data', x => { err += x; });
    child.on('error', e => { clearTimeout(timer); reject(e); });
    child.on('close', code => { clearTimeout(timer); if (code !== 0) return reject(new Error(err.trim() || '查询失败')); resolve({ ok: true, headers: { get: () => null }, text: async () => out }); });
  });
}
async function dispatch(command, payload = {}) {
  switch (command) {
    case 'ping': return { ready: true };
    case 'scan': return (await getCatalog()).scan;
    case 'actions': return privacy.publicPrivacyActions(context);
    case 'prepare-clean': {
      const ids = idsArg(payload.ids); const { scan, signature } = await resolveClean(ids);
      const chosen = ids.map(id => scan.find(t => t.id === id));
      return { token: issue('clean', signature), title: '确认永久清理', detail: '所列项目将被永久删除，不创建恢复备份。请先完全退出 Claude 和相关 IDE。', items: chosen.flatMap(t => [t.title, ...t.resources.filter(r => r.exists).map(r => '    ' + r.displayPath)]) };
    }
    case 'clean': {
      const ids = idsArg(payload.ids); const { catalog, signature } = await resolveClean(ids);
      consume(payload.token, 'clean', signature);
      if (payload.acknowledged !== true) throw new Error('请先确认已了解影响。');
      return cleanTargets(ids, context, { backupRoot: path.join(context.userDataDir, 'CleanupQuarantine'), createBackups: false, retainOperationRecord: false, targets: catalog.targets });
    }
    case 'prepare-privacy': {
      const ids = idsArg(payload.ids, 16); const selected = privacySelection(ids);
      return { token: issue('privacy', ids), title: '确认更改设置', items: selected.map(a => a.title), detail: '这些操作可能影响登录状态、浏览器通话、定位、DNS 网络连接或系统时间。请先保存工作；涉及浏览器的操作需要完全退出浏览器。' };
    }
    case 'privacy': {
      const ids = idsArg(payload.ids, 16); privacySelection(ids); consume(payload.token, 'privacy', ids);
      if (payload.acknowledged !== true) throw new Error('请先确认已了解影响。');
      const result = await privacy.executePrivacyActions(ids, context, { fetchImpl: systemFetch });
      const adguard = result.results.find(x => x.status === 'completed' && x.configurationUrl);
      if (adguard) {
        const pages = await openAdGuardSetupPages(context, { configurationUrl: adguard.configurationUrl });
        adguard.message += ' ' + pages.map(p => `${p.browser}：${p.status}${p.message ? '（' + p.message + '）' : ''}`).join('；') + '。官方配置导入仍需用户确认。';
        if (pages.some(p => !['installed-enabled','not-installed'].includes(p.status)) || !pages.some(p => p.status === 'installed-enabled')) { adguard.status = 'failed'; result.status = 'completed-with-errors'; }
      }
      return result;
    }
    case 'adguard-retry': return openAdGuardSetupPages(context, { configurationUrl: buildAdGuardImportUrl(), timeoutMs: 20000 });
    case 'adguard-url': return buildAdGuardImportUrl();
    case 'prepare-close': {
      const running = (await privacy.browsersRunning(context)).sort();
      if (!running.length) return { empty: true, message: '没有检测到正在运行的受支持浏览器。' };
      return { token: issue('close', running), title: '确认关闭浏览器', items: running, detail: '会结束浏览器及其后台进程，未保存的表单、下载和网页任务可能丢失。' };
    }
    case 'close': {
      const running = (await privacy.browsersRunning(context)).sort(); consume(payload.token, 'close', running);
      if (payload.acknowledged !== true) throw new Error('请先确认已保存工作。');
      return privacy.closeSupportedBrowsers(context);
    }
    case 'inspect-recovery': return recovery.inspectNetworkRecovery(context);
    case 'prepare-recovery': {
      const inspection = await recovery.inspectNetworkRecovery(context);
      const plan = recovery.prepareRecoveryPlan(inspection, payload.repairProxy === true);
      if (plan.empty) return { empty: true, message: '未发现可自动恢复的项目。' };
      return { token: issue('recovery', plan.values, plan), title: '确认恢复网络', items: plan.items, detail: '仅处理检测到的本软件 DNS 残留和所选的失效本机代理开关；保留代理地址与节点配置。' };
    }
    case 'recover': {
      const inspection = await recovery.inspectNetworkRecovery(context);
      const plan = recovery.prepareRecoveryPlan(inspection, payload.repairProxy === true);
      consume(payload.token, 'recovery', plan.values);
      if (payload.acknowledged !== true) throw new Error('请先确认已了解影响。');
      return recovery.executeNetworkRecovery(context, plan);
    }
    default: throw new Error('不支持的操作。');
  }
}
let sequence = Promise.resolve();
readline.createInterface({ input: process.stdin, crlfDelay: Infinity }).on('line', line => {
  sequence = sequence.then(async () => {
    let request;
    try { request = JSON.parse(line); const result = await dispatch(request.command, request.payload); process.stdout.write(JSON.stringify({ id: request.id, result }) + '\n'); }
    catch (error) { process.stdout.write(JSON.stringify({ id: request?.id, error: error.message || String(error) }) + '\n'); }
  });
});
