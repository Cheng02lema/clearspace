const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const {
  DNSCRYPT_EXE_SHA256,
  FIREWALL_RULES,
  backupPath,
  emergencyRestoreWindowsDns,
} = require('./leak-protection');

const INTERNET_SETTINGS_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
const OWNED_INSTALL_PARTS = ['KelaudeStudio', 'DnsCryptProxy', 'dnscrypt-proxy.exe'];

function runCommand(file, args, options = {}) {
  return new Promise((resolve, reject) => {
    const { timeoutMs = 10_000, ...spawnOptions } = options;
    const child = spawn(file, args, {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      ...spawnOptions,
    });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) child.kill();
    }, timeoutMs);
    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');
    child.stdout?.on('data', (chunk) => { stdout += chunk; });
    child.stderr?.on('data', (chunk) => { stderr += chunk; });
    child.once('error', (error) => {
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    child.once('close', (code) => {
      settled = true;
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

async function isRegularFile(candidate) {
  try {
    const stat = await fs.lstat(candidate);
    return stat.isFile() && !stat.isSymbolicLink();
  } catch {
    return false;
  }
}

function windowsTool(context, name) {
  const root = context.env.SystemRoot || context.env.WINDIR || 'C:\\Windows';
  return context.pathApi.join(root, 'System32', name);
}

function parseRegistryValue(output, name) {
  const escaped = String(name).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = String(output || '').match(new RegExp(`^\\s*${escaped}\\s+REG_[A-Z0-9_]+\\s+(.*?)\\s*$`, 'im'));
  return match ? match[1] : null;
}

async function readInternetSetting(commandRunner, reg, name) {
  const result = await commandRunner(reg, ['query', INTERNET_SETTINGS_KEY, '/v', name]);
  if (result.code !== 0) return { present: false, value: null };
  const value = parseRegistryValue(result.stdout, name);
  return { present: value !== null, value };
}

function splitHostPort(raw) {
  let value = String(raw || '').trim().replace(/^[a-z]+:\/\//i, '');
  const slash = value.indexOf('/');
  if (slash >= 0) value = value.slice(0, slash);
  if (value.startsWith('[')) {
    const close = value.indexOf(']');
    const port = Number(value.slice(close + 2));
    if (close < 1 || value[close + 1] !== ':' || !Number.isInteger(port) || port < 1 || port > 65535) return null;
    return { host: value.slice(1, close), port };
  }
  const colon = value.lastIndexOf(':');
  if (colon < 1) return null;
  const port = Number(value.slice(colon + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host: value.slice(0, colon).trim(), port };
}

function isLoopbackHost(host) {
  const normalized = String(host || '').trim().toLowerCase();
  if (normalized === 'localhost' || normalized === '::1') return true;
  return net.isIP(normalized) === 4 && normalized.startsWith('127.');
}

function parseProxyServer(raw) {
  const source = String(raw || '').trim();
  if (!source) return { valid: false, safeForAutomaticDisable: false, reason: '未配置代理地址', endpoints: [] };
  if (source.length > 4096) return { valid: false, safeForAutomaticDisable: false, reason: '代理地址内容过长，已保持不变', endpoints: [] };
  const parts = source.split(';').map((item) => item.trim()).filter(Boolean);
  const endpoints = [];
  let hasProtocolMap = false;
  let unsupported = false;
  for (const part of parts) {
    const separator = part.indexOf('=');
    const protocol = separator > 0 ? part.slice(0, separator).trim().toLowerCase() : 'direct';
    const address = separator > 0 ? part.slice(separator + 1).trim() : part;
    if (separator > 0) hasProtocolMap = true;
    if (!['direct', 'http', 'https'].includes(protocol)) unsupported = true;
    const endpoint = splitHostPort(address);
    if (!endpoint) return { valid: false, safeForAutomaticDisable: false, reason: '代理地址格式无法安全识别', endpoints: [] };
    endpoints.push({ protocol, ...endpoint, loopback: isLoopbackHost(endpoint.host) });
  }
  const allLoopback = endpoints.length > 0 && endpoints.every((endpoint) => endpoint.loopback);
  const safe = !unsupported && allLoopback && (!hasProtocolMap || endpoints.every((endpoint) => ['http', 'https'].includes(endpoint.protocol)));
  return {
    valid: true,
    safeForAutomaticDisable: safe,
    reason: safe ? '' : unsupported ? '包含 SOCKS 或其他代理类型，将保留并交由代理软件恢复' : '包含非本机代理地址，将保持不变',
    endpoints,
  };
}

function probeTcpEndpoint(endpoint, timeoutMs = 700) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: endpoint.host, port: endpoint.port });
    let settled = false;
    const finish = (reachable) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(reachable);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

async function fileMatchesHash(candidate, expectedHash) {
  try {
    const stat = await fs.lstat(candidate);
    if (!stat.isFile() || stat.isSymbolicLink()) return false;
    const digest = crypto.createHash('sha256').update(await fs.readFile(candidate)).digest('hex');
    return digest === expectedHash;
  } catch {
    return false;
  }
}

async function inspectNetworkRecovery(context, options = {}) {
  if (context.platform !== 'win32') {
    return {
      platform: context.platform,
      available: false,
      hasRecoverableIssue: false,
      summary: '此无需卡密急救用于恢复 Windows 版助手创建的 DNS 网络改动。',
      dns: { needsRecovery: false },
      proxy: { staleLoopback: false, canRepairAutomatically: false },
    };
  }

  const commandRunner = options.commandRunner || runCommand;
  const netsh = windowsTool(context, 'netsh.exe');
  const sc = windowsTool(context, 'sc.exe');
  const reg = windowsTool(context, 'reg.exe');
  const programData = context.env.ProgramData || 'C:\\ProgramData';
  const ownedExe = context.pathApi.join(programData, ...OWNED_INSTALL_PARTS);
  const [dnsOutput, serviceOutput, ...firewallOutputs] = await Promise.all([
    commandRunner(netsh, ['interface', 'ipv4', 'show', 'dnsservers']).catch(() => ({ code: 1, stdout: '', stderr: '' })),
    commandRunner(sc, ['qc', 'dnscrypt-proxy']).catch(() => ({ code: 1, stdout: '', stderr: '' })),
    ...FIREWALL_RULES.map((name) => commandRunner(netsh, ['advfirewall', 'firewall', 'show', 'rule', `name=${name}`, 'verbose'])
      .catch(() => ({ code: 1, stdout: '', stderr: '' }))),
  ]);
  const [proxyEnable, proxyServer, autoConfigUrl] = await Promise.all([
    readInternetSetting(commandRunner, reg, 'ProxyEnable').catch(() => ({ present: false, value: null })),
    readInternetSetting(commandRunner, reg, 'ProxyServer').catch(() => ({ present: false, value: null })),
    readInternetSetting(commandRunner, reg, 'AutoConfigURL').catch(() => ({ present: false, value: null })),
  ]);

  const backupFound = await isRegularFile(backupPath(context));
  const loopbackLocked = /(^|[^0-9])127\.0\.0\.1([^0-9]|$)/m.test(dnsOutput.stdout || '');
  const servicePathMatches = serviceOutput.code === 0
    && String(serviceOutput.stdout || '').toLowerCase().includes(ownedExe.toLowerCase());
  const ownedFirewallRules = firewallOutputs.filter((result, index) => result.code === 0
    && String(result.stdout || '').includes(FIREWALL_RULES[index])).length;
  const ownedBinary = await fileMatchesHash(ownedExe, DNSCRYPT_EXE_SHA256);
  const ownedService = servicePathMatches && ownedBinary;
  const ownershipEvidence = backupFound || ownedService || ownedFirewallRules > 0 || ownedBinary;
  const dnsNeedsRecovery = ownedFirewallRules > 0 || ownedService || (loopbackLocked && ownershipEvidence);

  const enabledValue = String(proxyEnable.value || '').trim().toLowerCase();
  const proxyEnabled = proxyEnable.present && (enabledValue === '0x1' || enabledValue === '1');
  const pacUrl = autoConfigUrl.present ? String(autoConfigUrl.value || '').trim() : '';
  const parsedProxy = parseProxyServer(proxyServer.value);
  let endpointReachability = [];
  if (proxyEnabled && !pacUrl && parsedProxy.safeForAutomaticDisable) {
    const unique = [...new Map(parsedProxy.endpoints.map((endpoint) => [`${endpoint.host.toLowerCase()}:${endpoint.port}`, endpoint])).values()];
    endpointReachability = await Promise.all(unique.map(async (endpoint) => ({
      host: endpoint.host,
      port: endpoint.port,
      reachable: await (options.probeEndpoint || probeTcpEndpoint)(endpoint),
    })));
  }
  const staleLoopback = proxyEnabled
    && !pacUrl
    && parsedProxy.safeForAutomaticDisable
    && endpointReachability.length > 0
    && endpointReachability.every((endpoint) => !endpoint.reachable);

  const proxy = {
    enabled: proxyEnabled,
    server: proxyServer.present ? String(proxyServer.value || '') : '',
    pacConfigured: Boolean(pacUrl),
    kind: parsedProxy.valid ? (parsedProxy.safeForAutomaticDisable ? 'local-http' : 'preserved-other') : 'unrecognized',
    staleLoopback,
    canRepairAutomatically: staleLoopback,
    reason: pacUrl ? '检测到 PAC 自动配置，将保持不变' : parsedProxy.reason,
    endpoints: endpointReachability,
  };
  const hasRecoverableIssue = dnsNeedsRecovery || staleLoopback;
  return {
    platform: context.platform,
    available: true,
    hasRecoverableIssue,
    summary: hasRecoverableIssue
      ? '检测到可安全撤销的本助手 DNS 改动或已经失效的本机浏览器代理。'
      : '未检测到本助手造成的可恢复网络锁定；代理软件和节点配置均未修改。',
    dns: {
      backupFound,
      loopbackLocked,
      ownedFirewallRules,
      ownedService,
      ownedBinary,
      ownershipEvidence,
      needsRecovery: dnsNeedsRecovery,
    },
    proxy,
  };
}

function prepareRecoveryPlan(inspection, repairStaleProxy) {
  const restoreDns = Boolean(inspection?.dns?.needsRecovery);
  const repairProxy = Boolean(repairStaleProxy && inspection?.proxy?.canRepairAutomatically);
  const values = [
    `dns:${restoreDns ? 1 : 0}:${inspection?.dns?.loopbackLocked ? 1 : 0}:${Number(inspection?.dns?.ownedFirewallRules || 0)}:${inspection?.dns?.ownedService ? 1 : 0}`,
    `proxy:${repairProxy ? 1 : 0}:${repairProxy ? String(inspection?.proxy?.server || '') : ''}`,
  ];
  const items = [];
  if (restoreDns) items.push('移除本助手的 DNS 防火墙规则，并将可信清单中仍锁定为 127.0.0.1 的网卡恢复为自动 DNS');
  if (repairProxy) items.push('临时关闭已经失效的本机 HTTP/HTTPS 系统代理开关（保留代理地址、节点、订阅与软件配置）');
  return { restoreDns, repairProxy, values, items, empty: items.length === 0 };
}

async function writeProxySnapshot(context, values) {
  const directory = context.pathApi.join(context.userDataDir, 'network-recovery');
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const target = context.pathApi.join(directory, `proxy-state-${Date.now()}-${crypto.randomUUID()}.json`);
  const temporary = `${target}.${process.pid}.tmp`;
  const payload = { schema: 1, capturedAt: new Date().toISOString(), ...values };
  await fs.writeFile(temporary, JSON.stringify(payload, null, 2), { encoding: 'utf8', mode: 0o600 });
  await fs.rename(temporary, target);
  return target;
}

async function disableStaleLoopbackProxy(context, inspection, options = {}) {
  if (!inspection?.proxy?.canRepairAutomatically) {
    return { changed: 0, message: '当前代理不是可安全自动关闭的失效本机 HTTP/HTTPS 代理，已保持不变。' };
  }
  const commandRunner = options.commandRunner || runCommand;
  const reg = windowsTool(context, 'reg.exe');
  const currentEnable = await readInternetSetting(commandRunner, reg, 'ProxyEnable');
  const currentServer = await readInternetSetting(commandRunner, reg, 'ProxyServer');
  const currentPac = await readInternetSetting(commandRunner, reg, 'AutoConfigURL');
  if (!currentEnable.present || !['0x1', '1'].includes(String(currentEnable.value || '').trim().toLowerCase())
    || String(currentServer.value || '') !== inspection.proxy.server
    || Boolean(String(currentPac.value || '').trim())) {
    throw new Error('代理状态在确认后发生了变化，为避免误改已停止自动恢复，请重新检测。');
  }
  const currentParsed = parseProxyServer(currentServer.value);
  if (!currentParsed.safeForAutomaticDisable) {
    throw new Error('代理类型在确认后发生了变化，已保持原设置。');
  }
  const uniqueEndpoints = [...new Map(currentParsed.endpoints
    .map((endpoint) => [`${endpoint.host.toLowerCase()}:${endpoint.port}`, endpoint])).values()];
  const probe = options.probeEndpoint || probeTcpEndpoint;
  const reachability = await Promise.all(uniqueEndpoints.map((endpoint) => probe(endpoint)));
  if (reachability.some(Boolean)) {
    return { changed: 0, message: '本机代理端口已经恢复响应，已保留当前代理开关和全部配置。' };
  }
  const snapshotPath = await writeProxySnapshot(context, {
    ProxyEnable: currentEnable,
    ProxyServer: currentServer,
    AutoConfigURL: currentPac,
  });
  const changed = await commandRunner(reg, ['add', INTERNET_SETTINGS_KEY, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '0', '/f']);
  if (changed.code !== 0) throw new Error(changed.stderr || '无法关闭失效的本机系统代理开关。');
  const verified = await readInternetSetting(commandRunner, reg, 'ProxyEnable');
  if (!verified.present || !['0x0', '0'].includes(String(verified.value || '').trim().toLowerCase())) {
    throw new Error('系统未报告代理开关已关闭，代理地址和节点配置未删除。');
  }
  return {
    changed: 1,
    snapshotPath,
    message: '已临时关闭失效的本机浏览器代理开关；代理地址、软件、节点和订阅均保留。重新打开代理工具后可再次启用系统代理。',
  };
}

async function executeNetworkRecovery(context, confirmedPlan = {}, options = {}) {
  const inspection = await inspectNetworkRecovery(context, options);
  const currentPlan = prepareRecoveryPlan(inspection, confirmedPlan.repairProxy === true);
  const plan = {
    restoreDns: confirmedPlan.restoreDns === true && currentPlan.restoreDns,
    repairProxy: confirmedPlan.repairProxy === true && currentPlan.repairProxy,
  };
  plan.empty = !plan.restoreDns && !plan.repairProxy;
  if (plan.empty) return { changed: 0, inspection, results: [], message: '重新检测后未发现可安全自动恢复的项目，未修改网络配置。' };
  const results = [];
  if (plan.restoreDns) results.push({ id: 'dns', ...(await emergencyRestoreWindowsDns(context, { commandRunner: options.commandRunner || runCommand })) });
  if (plan.repairProxy) results.push({ id: 'proxy', ...(await disableStaleLoopbackProxy(context, inspection, options)) });
  const changed = results.reduce((sum, item) => sum + Number(item.changed || 0), 0);
  return {
    changed,
    results,
    message: `${results.map((item) => item.message).join(' ')} 请完全退出并重新打开浏览器；无需卸载 Clash、v2rayN 或其他代理工具。`,
  };
}

module.exports = {
  INTERNET_SETTINGS_KEY,
  disableStaleLoopbackProxy,
  executeNetworkRecovery,
  inspectNetworkRecovery,
  isLoopbackHost,
  parseProxyServer,
  parseRegistryValue,
  prepareRecoveryPlan,
  probeTcpEndpoint,
  runCommand,
};
