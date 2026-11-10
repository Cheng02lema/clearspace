const fs = require('node:fs/promises');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { createContext } = require('./targets');
const { assertSafePathComponents } = require('./path-safety');
const {
  ianaToWindowsId,
  isValidIanaTimezone,
  lookupExitLocation,
  maskIp,
} = require('./timezone-sync');
const { installAdGuardPolicies, removeAdGuardPolicies } = require('./adguard-setup');
const {
  enableWindowsDnsLeakProtection,
  restoreWindowsDns,
} = require('./leak-protection');
const {
  applyChromiumLanguageProfiles,
  applyWindowsLocationLanguage,
  localeForCountry,
  preferredLanguages,
  restoreChromiumLanguageProfiles,
  restoreWindowsLocationLanguage,
} = require('./browser-location-language');

const CLAUDE_ENV_NAMES = Object.freeze([
  'ANTHROPIC_API_KEY',
  'ANTHROPIC_AUTH_TOKEN',
  'CLAUDE_CODE_OAUTH_TOKEN',
  'CLAUDE_CODE_OAUTH_REFRESH_TOKEN',
  'ANTHROPIC_BASE_URL',
  'ANTHROPIC_MODEL',
  'ANTHROPIC_DEFAULT_HAIKU_MODEL',
  'ANTHROPIC_DEFAULT_SONNET_MODEL',
  'ANTHROPIC_DEFAULT_OPUS_MODEL',
  'CLAUDE_CONFIG_DIR',
  'CLAUDE_CODE_USE_BEDROCK',
  'CLAUDE_CODE_USE_VERTEX',
  'CLAUDE_CODE_USE_FOUNDRY',
  'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC',
]);

const CHINA_TIMEZONE = 'Asia/Shanghai';

const PRIVACY_ACTIONS = Object.freeze([
  {
    id: 'claude-environment',
    title: '清除 Claude 用户环境变量',
    description: '移除当前用户范围内的 Anthropic / Claude 专用变量；不删除通用代理、AWS 或 Google Cloud 变量。',
    risk: 'high',
    requiresBrowserClosed: false,
  },
  {
    id: 'mail-cookie',
    title: '清除 mail.com Cookie',
    description: '浏览器完全退出后，仅从 Chrome、Edge 与 Firefox 当前用户配置中删除 mail.com 域 Cookie。',
    risk: 'medium',
    requiresBrowserClosed: true,
  },
  {
    id: 'block-location',
    title: '关闭浏览器定位',
    description: '将 Chrome、Edge 与 Firefox 的默认定位权限设为阻止；浏览器重启后生效。',
    risk: 'medium',
    requiresBrowserClosed: true,
    excludeFromSelectAll: true,
    exclusiveWith: ['block-location-sync-language', 'restore-browser-location-language'],
  },
  {
    id: 'block-location-sync-language',
    title: '关闭浏览器定位并同步代理地区语言',
    description: '读取当前公网出口国家/地区，关闭 Chrome、Edge 与 Firefox 定位，并将浏览器界面及网站首选语言同步为该地区常用语言；需要管理员授权和重启浏览器。',
    risk: 'high',
    requiresBrowserClosed: true,
    exclusiveWith: ['block-location', 'restore-browser-location-language'],
  },
  {
    id: 'restore-browser-location-language',
    title: '恢复浏览器定位与语言',
    description: '仅恢复本助手在“同步代理地区语言”前保存且此后未被其他程序改写的 Chrome、Edge 策略，并移除本助手的 Firefox 定位与语言标记。',
    risk: 'medium',
    requiresBrowserClosed: true,
    excludeFromSelectAll: true,
    exclusiveWith: ['block-location', 'block-location-sync-language'],
  },
  {
    id: 'disable-system-location',
    title: '关闭系统定位',
    description: '关闭 Windows 或 macOS 的系统位置服务；需要管理员授权，可能影响地图、天气和查找设备等功能。',
    risk: 'high',
    requiresBrowserClosed: false,
  },
  {
    id: 'restrict-webrtc',
    title: '限制 WebRTC IP 暴露',
    description: '限制 Chrome / Edge 的非代理 UDP，并在 Firefox 中关闭 WebRTC；可能影响网页通话与会议。',
    risk: 'high',
    requiresBrowserClosed: true,
  },
  {
    id: 'protect-dns',
    title: '强制 DNS 防泄漏',
    description: 'Windows 10/11：使用多个 DoH 上游，仅接管已连接的物理网卡，不绑定 Clash、v2rayN 等本机代理端口；只阻断物理网卡的明文 53 端口，启用前后都会验证，失败自动恢复。',
    risk: 'high',
    requiresBrowserClosed: true,
    exclusiveWith: ['restore-dns'],
  },
  {
    id: 'restore-dns',
    title: '关闭 DNS 防泄漏并恢复网络',
    description: '移除本助手创建的 DNS 防火墙规则，并恢复启用前保存的网卡 DNS 与浏览器加密 DNS 配置。',
    risk: 'medium',
    requiresBrowserClosed: true,
    excludeFromSelectAll: true,
    exclusiveWith: ['protect-dns'],
  },
  {
    id: 'sync-proxy-timezone',
    title: '同步代理节点地区时区区域',
    description: '通过 HTTPS 查询当前公网出口 IP 的国家/地区与 IANA 时区，同步系统时区及“国家或地区”；不会强制更改系统显示语言。支持系统或 VPN 代理，浏览器专用代理可能无法被本应用读取。查询失败时不会更改。',
    risk: 'high',
    requiresBrowserClosed: false,
    exclusiveWith: ['restore-china-timezone'],
  },
  {
    id: 'restore-china-timezone',
    title: '恢复中国北京时间与区域',
    description: '将系统时区恢复为 Asia/Shanghai（Windows：China Standard Time），并将系统“国家或地区”恢复为中国。',
    risk: 'medium',
    requiresBrowserClosed: false,
    excludeFromSelectAll: true,
    exclusiveWith: ['sync-proxy-timezone'],
  },
  {
    id: 'install-adguard',
    title: '安装并启用 AdGuard（替换 uBlock）',
    description: '在 Edge 与 Chrome 后台安装官方 AdGuard，移除旧 uBlock 策略；检测扩展安装完成后打开官方配置导入页，并预先打开“跟踪保护”设置页供核对。官方导入仍需确认一次。',
    risk: 'high',
    requiresBrowserClosed: true,
  },
  {
    id: 'remove-managed-adguard',
    title: '解除 AdGuard“由组织管理”',
    description: '仅移除本助手使用的 AdGuard 强制安装策略；不会删除其他组织策略。重启浏览器后生效。',
    risk: 'medium',
    requiresBrowserClosed: true,
    excludeFromSelectAll: true,
  },
]);

function publicPrivacyActions(rawContext = {}) {
  const platform = rawContext.platform || process.platform;
  const hiddenOnMac = new Set([
    'block-location-sync-language',
    'restore-browser-location-language',
    'protect-dns',
    'restore-dns',
    'install-adguard',
    'remove-managed-adguard',
  ]);
  return PRIVACY_ACTIONS
    .filter((action) => platform !== 'darwin' || !hiddenOnMac.has(action.id))
    .map((action) => ({
      ...action,
      ...(platform === 'darwin' && action.id === 'claude-environment' ? {
        description: '移除 launchctl 中的 Claude 专用变量，并删除用户 shell 配置文件中匹配的整行；可能需要重新配置终端或 Claude，且不创建备份。',
      } : {}),
    }));
}

function runCommand(file, args, options = {}) {
  return new Promise((resolve, reject) => {
    const { timeoutMs = 30_000, ...spawnOptions } = options;
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

async function existingDirectories(root, matcher) {
  let entries;
  try {
    entries = await fs.readdir(root, { withFileTypes: true });
  } catch (error) {
    if (error && error.code === 'ENOENT') return [];
    throw error;
  }
  return entries
    .filter((entry) => entry.isDirectory() && matcher(entry.name))
    .map((entry) => path.join(root, entry.name));
}

async function pathIsRegularFile(candidate) {
  try {
    const stat = await fs.lstat(candidate);
    return stat.isFile() && !stat.isSymbolicLink();
  } catch (error) {
    if (error && error.code === 'ENOENT') return false;
    throw error;
  }
}

function safeProfileLeaf(name, p) {
  return typeof name === 'string' && name.length > 0 && name.length <= 160
    && name !== '.' && name !== '..' && p.basename(name) === name
    && !name.includes('/') && !name.includes('\\');
}

async function chromiumProfileDirectories(root, p = path) {
  const names = new Set();
  for (const directory of await existingDirectories(root, (name) => name === 'Default' || name === 'Guest Profile' || /^Profile \d+$/.test(name))) {
    names.add(p.basename(directory));
  }
  try {
    const state = JSON.parse(await fs.readFile(p.join(root, 'Local State'), 'utf8'));
    for (const name of Object.keys(state?.profile?.info_cache || {})) {
      if (safeProfileLeaf(name, p)) names.add(name);
    }
  } catch (error) {
    if (!error || (error.code !== 'ENOENT' && !(error instanceof SyntaxError))) throw error;
  }
  const directories = [];
  for (const name of names) {
    if (!safeProfileLeaf(name, p)) continue;
    const directory = p.join(root, name);
    if (await pathIsRegularFile(p.join(directory, 'Preferences'))) directories.push(directory);
  }
  return directories;
}

function parseFirefoxProfilesIni(text, firefoxDirectory, p) {
  const sections = [];
  let current = null;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    const header = line.match(/^\[([^\]]+)\]$/);
    if (header) {
      current = /^Profile\d+$/i.test(header[1]) ? {} : null;
      if (current) sections.push(current);
      continue;
    }
    if (!current || !line || line.startsWith(';') || line.startsWith('#')) continue;
    const separator = line.indexOf('=');
    if (separator > 0) current[line.slice(0, separator)] = line.slice(separator + 1);
  }
  return sections
    .filter((section) => section.Path)
    .map((section) => section.IsRelative === '0' ? p.resolve(section.Path) : p.resolve(firefoxDirectory, section.Path));
}

async function getBrowserProfiles(rawContext = {}) {
  const context = rawContext.pathApi ? rawContext : createContext(rawContext);
  const p = context.pathApi;
  const profiles = [];
  const chromiumRoots = context.platform === 'win32'
    ? [
      { browser: 'Chrome', root: p.join(context.localAppData, 'Google', 'Chrome', 'User Data') },
      { browser: 'Edge', root: p.join(context.localAppData, 'Microsoft', 'Edge', 'User Data') },
    ]
    : [
      { browser: 'Chrome', root: p.join(context.homeDir, 'Library', 'Application Support', 'Google', 'Chrome') },
      { browser: 'Edge', root: p.join(context.homeDir, 'Library', 'Application Support', 'Microsoft Edge') },
  ];

  for (const item of chromiumRoots) {
    if (context.platform === 'win32' && /^\\\\/.test(item.root)) continue;
    try { assertWithin(item.root, context.homeDir, context); } catch { continue; }
    await assertSafePathComponents(item.root, context);
    const directories = await chromiumProfileDirectories(item.root, p);
    for (const directory of directories) {
      const cacheRoot = context.platform === 'darwin'
        ? p.join(context.homeDir, 'Library', 'Caches', item.browser === 'Chrome' ? 'Google/Chrome' : 'Microsoft Edge')
        : directory;
      profiles.push({
        browser: item.browser,
        engine: 'chromium',
        root: item.root,
        directory,
        cacheDirectory: context.platform === 'darwin' ? p.join(cacheRoot, p.basename(directory)) : directory,
      });
    }
  }

  const firefoxRoot = context.platform === 'win32'
    ? p.join(context.roamingAppData, 'Mozilla', 'Firefox', 'Profiles')
    : p.join(context.homeDir, 'Library', 'Application Support', 'Firefox', 'Profiles');
  const firefoxCandidates = new Set();
  if (context.platform === 'win32' && /^\\\\/.test(firefoxRoot)) return profiles;
  try { assertWithin(firefoxRoot, context.homeDir, context); } catch { return profiles; }
  await assertSafePathComponents(firefoxRoot, context);
  try {
    for (const directory of parseFirefoxProfilesIni(
      await fs.readFile(p.join(p.dirname(firefoxRoot), 'profiles.ini'), 'utf8'),
      p.dirname(firefoxRoot),
      p,
    )) firefoxCandidates.add(p.normalize(directory));
  } catch (error) {
    if (!error || error.code !== 'ENOENT') throw error;
  }
  // Firefox's newer selectable-profile service can keep additional profiles in
  // Profile Groups. Enumerating every signed directory under Profiles avoids
  // relying on profiles.ini as a complete index without modifying group DBs.
  for (const directory of await existingDirectories(firefoxRoot, () => true)) firefoxCandidates.add(p.normalize(directory));
  const firefoxCacheRoot = context.platform === 'win32'
    ? p.join(context.localAppData, 'Mozilla', 'Firefox', 'Profiles')
    : p.join(context.homeDir, 'Library', 'Caches', 'Firefox', 'Profiles');
  const normalizedHome = context.platform === 'win32' ? p.resolve(context.homeDir).toLowerCase() : p.resolve(context.homeDir);
  for (const directory of firefoxCandidates) {
    const normalizedDirectory = context.platform === 'win32' ? p.resolve(directory).toLowerCase() : p.resolve(directory);
    const relativeToHome = p.relative(normalizedHome, normalizedDirectory);
    if (!relativeToHome || relativeToHome.startsWith('..') || p.isAbsolute(relativeToHome)) continue;
    if (!await pathIsRegularFile(p.join(directory, 'prefs.js'))) continue;
    const profileStat = await fs.lstat(directory);
    if (!profileStat.isDirectory() || profileStat.isSymbolicLink()) continue;
    profiles.push({
      browser: 'Firefox',
      engine: 'firefox',
      root: firefoxRoot,
      directory,
      cacheDirectory: p.join(firefoxCacheRoot, p.basename(directory)),
    });
  }
  const seen = new Set();
  return profiles.filter((profile) => {
    const key = context.platform === 'win32' ? p.normalize(profile.directory).toLowerCase() : p.normalize(profile.directory);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

async function browsersRunning(context, commandRunner = runCommand) {
  if (context.platform === 'win32') {
    const systemRoot = context.env.SystemRoot || context.env.WINDIR || 'C:\\Windows';
    const result = await commandRunner(path.win32.join(systemRoot, 'System32', 'tasklist.exe'), ['/FO', 'CSV', '/NH']);
    if (result.code === 0) {
      const output = result.stdout.toLowerCase();
      return ['chrome.exe', 'msedge.exe', 'firefox.exe'].filter((name) => output.includes(`"${name}"`));
    }
    // Some managed Windows environments deny tasklist while permitting the
    // native process inventory. Require a completion marker; an incomplete or
    // failed inventory must never be interpreted as all browsers being closed.
    const powershell = path.win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    const script = "$ErrorActionPreference='Stop'; $all=@(Get-Process -ErrorAction Stop | ForEach-Object { $_.ProcessName.ToLowerInvariant() }); foreach($n in @('chrome','msedge','firefox')) { if($all -contains $n){ Write-Output ($n+'.exe') } }; Write-Output 'CLEARSPACE_PROCESS_CHECK_OK'";
    const fallback = await commandRunner(powershell, ['-NoProfile', '-NonInteractive', '-Command', script]);
    const lines = String(fallback.stdout || '').trim().toLowerCase().split(/\r?\n/).map(line => line.trim());
    if (fallback.code !== 0 || !lines.includes('clearspace_process_check_ok')) throw new Error('无法确认浏览器是否已退出，安全策略已停止操作。');
    return ['chrome.exe', 'msedge.exe', 'firefox.exe'].filter((name) => lines.includes(name));
  }
  const result = await commandRunner('/bin/ps', ['-axo', 'comm=']);
  if (result.code !== 0) throw new Error('无法确认浏览器是否已退出，安全策略已停止操作。');
  const output = result.stdout.toLowerCase();
  return [
    { name: 'Google Chrome', token: 'google chrome' },
    { name: 'Microsoft Edge', token: 'microsoft edge' },
    { name: 'Firefox', token: '/firefox' },
  ].filter((item) => output.includes(item.token)).map((item) => item.name);
}

function waitMilliseconds(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function closeSupportedBrowsers(rawContext = {}, options = {}) {
  const context = rawContext.pathApi ? rawContext : createContext(rawContext);
  const commandRunner = options.commandRunner || runCommand;
  const wait = options.wait || waitMilliseconds;
  const before = await browsersRunning(context, commandRunner);
  if (!before.length) return { status: 'not-running', detected: [], closed: [], remaining: [] };

  if (context.platform === 'win32') {
    const systemRoot = context.env.SystemRoot || context.env.WINDIR || 'C:\\Windows';
    const taskkill = path.win32.join(systemRoot, 'System32', 'taskkill.exe');
    for (const imageName of before) {
      // The native confirmation is handled in the main process. /T also closes
      // browser helpers; /F is needed for Chromium's --no-startup-window mode.
      await commandRunner(taskkill, ['/IM', imageName, '/T', '/F']);
    }
  } else {
    const appNames = before.filter((name) => ['Google Chrome', 'Microsoft Edge', 'Firefox'].includes(name));
    for (const appName of appNames) {
      await commandRunner('/usr/bin/osascript', ['-e', `tell application "${appName}" to quit`]);
    }
    await wait(650);
    const afterQuit = await browsersRunning(context, commandRunner);
    const uid = Number.isInteger(options.uid) ? options.uid : (typeof process.getuid === 'function' ? process.getuid() : null);
    if (uid !== null) {
      const patterns = {
        'Google Chrome': 'Google Chrome\\.app/Contents/MacOS/Google Chrome(?:$| )',
        'Microsoft Edge': 'Microsoft Edge\\.app/Contents/MacOS/Microsoft Edge(?:$| )',
        Firefox: 'Firefox\\.app/Contents/MacOS/firefox(?:$| )',
      };
      for (const appName of afterQuit) {
        const pattern = patterns[appName];
        if (pattern) await commandRunner('/usr/bin/pkill', ['-TERM', '-U', String(uid), '-f', pattern]);
      }
    }
  }

  await wait(750);
  const remaining = await browsersRunning(context, commandRunner);
  const closed = before.filter((name) => !remaining.includes(name));
  return {
    status: remaining.length ? 'partial' : 'closed',
    detected: before,
    closed,
    remaining,
  };
}

function assertWithin(candidate, root, context) {
  const p = context.pathApi;
  const resolvedRoot = p.resolve(root);
  const resolved = p.resolve(candidate);
  const relative = p.relative(resolvedRoot, resolved);
  if (!relative || relative.startsWith('..') || p.isAbsolute(relative)) throw new Error('浏览器路径越界，已拒绝操作。');
  return resolved;
}

async function removeGeneratedPath(candidate, root, context) {
  const safePath = assertWithin(candidate, root, context);
  try {
    await assertSafePathComponents(safePath, context);
    await fs.rm(safePath, { recursive: true, force: false, maxRetries: 3, retryDelay: 200 });
    return true;
  } catch (error) {
    if (error && error.code === 'ENOENT') return false;
    throw error;
  }
}

function browserCleanupEntries(profile, context) {
  const p = context.pathApi;
  const entries = [];
  const add = (root, relative, label) => {
    entries.push({
      path: p.join(root, ...relative.split('/')),
      root,
      label: `${profile.browser} ${p.basename(profile.directory)} · ${label}`,
    });
  };
  if (profile.engine === 'chromium') {
    for (const relative of [
      'Network/Cookies', 'Network/Cookies-journal', 'Network/Cookies-wal', 'Network/Cookies-shm',
      'Cookies', 'Cookies-journal', 'Cookies-wal', 'Cookies-shm',
    ]) add(profile.directory, relative, 'Cookie');
    for (const relative of ['Local Storage', 'Session Storage', 'IndexedDB', 'Service Worker/CacheStorage']) {
      add(profile.directory, relative, '网站存储');
    }
    for (const relative of ['Cache', 'Code Cache', 'GPUCache', 'DawnCache']) {
      add(profile.cacheDirectory, relative, '缓存');
    }
  } else {
    for (const relative of ['cookies.sqlite', 'cookies.sqlite-wal', 'cookies.sqlite-shm']) {
      add(profile.directory, relative, 'Cookie');
    }
    for (const relative of ['storage/default', 'storage/temporary']) add(profile.directory, relative, '网站存储');
    for (const relative of ['cache2', 'startupCache', 'OfflineCache']) add(profile.cacheDirectory, relative, '缓存');
  }
  return entries;
}

async function getBrowserCleanupTarget(rawContext = {}) {
  const context = rawContext.pathApi ? rawContext : createContext(rawContext);
  const profiles = await getBrowserProfiles(context);
  const resources = [];
  const seen = new Set();
  for (const profile of profiles) {
    for (const entry of browserCleanupEntries(profile, context)) {
      assertWithin(entry.path, entry.root, context);
      const key = context.platform === 'win32' ? entry.path.toLowerCase() : entry.path;
      if (seen.has(key)) continue;
      try {
        await fs.lstat(entry.path);
        await assertSafePathComponents(entry.path, context);
        resources.push({ type: 'path', path: entry.path, label: entry.label });
        seen.add(key);
      } catch (error) {
        if (error && error.code === 'ENOENT') continue;
        throw error;
      }
    }
  }
  if (!resources.length) return null;
  return {
    id: 'browser.data',
    group: 'browser',
    title: '清除浏览器缓存与全部 Cookie',
    description: '永久清除 Chrome、Edge 与 Firefox 的全部 Cookie、缓存及网站本地存储（含 Local/Session Storage、IndexedDB 与 Cache Storage）。网站会退出登录，Claude 网页设备 Cookie 之后可能重新生成；不会删除 Anthropic 服务端记录。',
    risk: 'high',
    defaultSelected: false,
    backup: false,
    requiresBrowserClosed: true,
    resources,
    exclusiveWith: [],
    source: 'Claude 网页版教程',
  };
}

async function clearAllBrowserData(context) {
  const profiles = await getBrowserProfiles(context);
  let removed = 0;
  for (const profile of profiles) {
    for (const entry of browserCleanupEntries(profile, context)) {
      if (await removeGeneratedPath(entry.path, entry.root, context)) removed += 1;
    }
  }
  return { changed: removed, message: `已清除 ${profiles.length} 个浏览器配置中的 ${removed} 个 Cookie、缓存与网站存储项目。` };
}

function deleteDomainCookies(databasePath, table, column) {
  const allowed = new Map([
    ['cookies', 'host_key'],
    ['moz_cookies', 'host'],
  ]);
  if (allowed.get(table) !== column) throw new Error('Cookie 数据库规则无效。');
  const { DatabaseSync } = require('node:sqlite');
  const database = new DatabaseSync(databasePath, {
    readOnly: false,
    enableForeignKeyConstraints: false,
    allowExtension: false,
    timeout: 1500,
  });
  let transactionStarted = false;
  try {
    database.exec('PRAGMA busy_timeout = 1500; PRAGMA trusted_schema = OFF; PRAGMA recursive_triggers = OFF; PRAGMA secure_delete = ON');
    const found = database.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name=?").get(table);
    const columns = found ? database.prepare(`PRAGMA table_info("${table}")`).all() : [];
    if (!found || !columns.some((item) => item.name === column)) {
      const error = new Error('Cookie 数据库结构无法识别，已安全跳过。');
      error.code = 'COOKIE_SCHEMA_UNSUPPORTED';
      throw error;
    }
    const predicate = `lower("${column}") = ? OR lower("${column}") LIKE ?`;
    database.exec('BEGIN IMMEDIATE');
    transactionStarted = true;
    try {
      const result = database.prepare(`DELETE FROM "${table}" WHERE ${predicate}`).run('mail.com', '%.mail.com');
      const remaining = database.prepare(`SELECT count(*) AS total FROM "${table}" WHERE ${predicate}`).get('mail.com', '%.mail.com');
      if (Number(remaining?.total || 0) !== 0) throw new Error('mail.com Cookie 删除后校验失败。');
      database.exec('COMMIT');
      transactionStarted = false;
      database.exec('PRAGMA wal_checkpoint(TRUNCATE)');
      return Number(result.changes || 0);
    } catch (error) {
      if (transactionStarted) {
        database.exec('ROLLBACK');
        transactionStarted = false;
      }
      throw error;
    }
  } finally {
    if (transactionStarted) {
      try { database.exec('ROLLBACK'); } catch {}
    }
    database.close();
  }
}

async function clearMailCookies(context) {
  const profiles = await getBrowserProfiles(context);
  let changes = 0;
  let databases = 0;
  let skipped = 0;
  for (const profile of profiles) {
    const candidates = profile.engine === 'chromium'
      ? [context.pathApi.join(profile.directory, 'Network', 'Cookies'), context.pathApi.join(profile.directory, 'Cookies')]
      : [context.pathApi.join(profile.directory, 'cookies.sqlite')];
    for (const candidate of candidates) {
      try {
        assertWithin(candidate, profile.directory, context);
        await assertSafePathComponents(candidate, context);
        const stat = await fs.lstat(candidate);
        if (!stat.isFile() || stat.isSymbolicLink()) continue;
        changes += deleteDomainCookies(candidate, profile.engine === 'chromium' ? 'cookies' : 'moz_cookies', profile.engine === 'chromium' ? 'host_key' : 'host');
        databases += 1;
      } catch (error) {
        if (error && error.code === 'ENOENT') continue;
        if (error && error.code === 'COOKIE_SCHEMA_UNSUPPORTED') {
          skipped += 1;
          continue;
        }
        throw error;
      }
    }
  }
  return {
    changed: changes,
    message: `已检查 ${databases} 个 Cookie 数据库，删除 ${changes} 条 mail.com Cookie${skipped ? `；${skipped} 个未知结构数据库已跳过` : ''}。`,
  };
}

function replaceManagedFirefoxBlock(text, lines) {
  const begin = '// BEGIN 克劳德工作室清理助手';
  const end = '// END 克劳德工作室清理助手';
  const pattern = new RegExp(`${begin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[\\s\\S]*?${end.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\r?\\n?`, 'g');
  const cleaned = text.replace(pattern, '').replace(/\s+$/, '');
  if (!lines.length) return `${cleaned}${cleaned ? '\n' : ''}`;
  return `${cleaned}${cleaned ? '\n\n' : ''}${begin}\n${lines.join('\n')}\n${end}\n`;
}

function managedFirefoxLines(text) {
  const match = text.match(/\/\/ BEGIN 克劳德工作室清理助手\r?\n([\s\S]*?)\/\/ END 克劳德工作室清理助手/);
  if (!match) return [];
  return match[1].split(/\r?\n/).map((line) => line.trim()).filter((line) => /^user_pref\("[A-Za-z0-9._-]+", (?:true|false|\d+|"[A-Za-z0-9,._-]*")\);$/.test(line));
}

function firefoxLanguageLines(locale) {
  const languages = preferredLanguages(locale);
  return [
    `user_pref("intl.accept_languages", "${languages.join(',')}");`,
    `user_pref("intl.locale.requested", "${locale}");`,
  ];
}

async function writeFirefoxPreferences(context, mode, locale) {
  const profiles = (await getBrowserProfiles(context)).filter((profile) => profile.engine === 'firefox');
  const lines = [];
  if (mode === 'location' || mode === 'location-language') lines.push('user_pref("permissions.default.geo", 2);');
  if (mode === 'location-language') lines.push(...firefoxLanguageLines(locale));
  if (mode === 'webrtc') lines.push('user_pref("media.peerconnection.enabled", false);');
  if (mode === 'dns') lines.push(
    'user_pref("network.trr.mode", 5);',
    'user_pref("network.dns.disablePrefetch", true);',
    'user_pref("network.dns.disablePrefetchFromHTTPS", true);',
  );
  let changed = 0;
  for (const profile of profiles) {
    const filePath = context.pathApi.join(profile.directory, 'user.js');
    await assertSafePathComponents(filePath, context);
    let current = '';
    try {
      const stat = await fs.lstat(filePath);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('Firefox user.js 不是普通文件，已跳过。');
      current = await fs.readFile(filePath, 'utf8');
    } catch (error) {
      if (!error || error.code !== 'ENOENT') throw error;
    }
    let existingLines = managedFirefoxLines(current);
    if (mode === 'location-language') {
      existingLines = existingLines.filter((line) => !/"intl\.(?:accept_languages|locale\.requested)"/.test(line));
    }
    const next = replaceManagedFirefoxBlock(current, [...new Set([...existingLines, ...lines])]);
    if (next === current) continue;
    const temporary = `${filePath}.cleantrace-${process.pid}.tmp`;
    await assertSafePathComponents(temporary, context);
    await fs.writeFile(temporary, next, { encoding: 'utf8', mode: 0o600 });
    await fs.rename(temporary, filePath);
    changed += 1;
  }
  return changed;
}

async function removeFirefoxDnsPreferences(context) {
  const profiles = (await getBrowserProfiles(context)).filter((profile) => profile.engine === 'firefox');
  let changed = 0;
  for (const profile of profiles) {
    const filePath = context.pathApi.join(profile.directory, 'user.js');
    await assertSafePathComponents(filePath, context);
    let current;
    try { current = await fs.readFile(filePath, 'utf8'); }
    catch (error) { if (error && error.code === 'ENOENT') continue; throw error; }
    const managed = managedFirefoxLines(current);
    if (!managed.some((line) => line.includes('network.trr.mode'))) continue;
    const remaining = managed.filter((line) => !/"network\.(?:trr\.mode|dns\.disablePrefetch(?:FromHTTPS)?)"/.test(line));
    const next = replaceManagedFirefoxBlock(current, remaining);
    const temporary = `${filePath}.cleantrace-${process.pid}.tmp`;
    await fs.writeFile(temporary, next, { encoding: 'utf8', mode: 0o600 });
    await fs.rename(temporary, filePath);
    changed += 1;
  }
  return changed;
}

async function removeFirefoxLocationLanguagePreferences(context) {
  const profiles = (await getBrowserProfiles(context)).filter((profile) => profile.engine === 'firefox');
  let changed = 0;
  for (const profile of profiles) {
    const filePath = context.pathApi.join(profile.directory, 'user.js');
    await assertSafePathComponents(filePath, context);
    let current;
    try { current = await fs.readFile(filePath, 'utf8'); }
    catch (error) { if (error && error.code === 'ENOENT') continue; throw error; }
    const managed = managedFirefoxLines(current);
    const remaining = managed.filter((line) => !/"(?:permissions\.default\.geo|intl\.(?:accept_languages|locale\.requested))"/.test(line));
    if (remaining.length === managed.length) continue;
    const next = replaceManagedFirefoxBlock(current, remaining);
    const temporary = `${filePath}.cleantrace-${process.pid}.tmp`;
    await assertSafePathComponents(temporary, context);
    await fs.writeFile(temporary, next, { encoding: 'utf8', mode: 0o600 });
    await fs.rename(temporary, filePath);
    changed += 1;
  }
  return changed;
}

function plainObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function ensureObject(parent, key) {
  if (!plainObject(parent[key])) parent[key] = {};
  return parent[key];
}

function applyChromiumPreference(preferences, mode) {
  if (!plainObject(preferences)) throw new Error('浏览器 Preferences 不是有效对象。');
  if (mode === 'location') {
    const profile = ensureObject(preferences, 'profile');
    const defaults = ensureObject(profile, 'default_content_setting_values');
    defaults.geolocation = 2;
  } else if (mode === 'webrtc') {
    const webrtc = ensureObject(preferences, 'webrtc');
    webrtc.ip_handling_policy = 'disable_non_proxied_udp';
  } else {
    throw new Error('浏览器防封设置模式无效。');
  }
  return preferences;
}

async function writeChromiumProfilePreferences(context, mode) {
  const profiles = (await getBrowserProfiles(context)).filter((profile) => profile.engine === 'chromium');
  let changed = 0;
  for (const profile of profiles) {
    const filePath = context.pathApi.join(profile.directory, 'Preferences');
    assertWithin(filePath, profile.directory, context);
    await assertSafePathComponents(filePath, context);
    const stat = await fs.lstat(filePath);
    if (!stat.isFile() || stat.isSymbolicLink()) continue;
    const current = await fs.readFile(filePath, 'utf8');
    let preferences;
    try {
      preferences = JSON.parse(current);
    } catch {
      throw new Error(`${profile.browser} 的 Preferences 无法解析，已停止修改。`);
    }
    const next = `${JSON.stringify(applyChromiumPreference(preferences, mode))}\n`;
    if (next === current || next.trimEnd() === current.trimEnd()) continue;
    const temporary = `${filePath}.cleantrace-${process.pid}-${Date.now()}.tmp`;
    await assertSafePathComponents(temporary, context);
    const handle = await fs.open(temporary, 'wx', stat.mode & 0o777);
    try {
      await handle.writeFile(next, 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      const currentStat = await fs.lstat(filePath);
      if (currentStat.dev !== stat.dev || currentStat.ino !== stat.ino
        || currentStat.size !== stat.size || currentStat.mtimeMs !== stat.mtimeMs) {
        throw new Error(`${profile.browser} 的 Preferences 在操作期间发生变化，已停止修改。`);
      }
      await fs.rename(temporary, filePath);
      changed += 1;
    } catch (error) {
      await fs.rm(temporary, { force: true }).catch(() => {});
      throw error;
    }
  }
  return changed;
}

function quotePowerShellLiteral(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

function buildWindowsBrowserPolicyScript(mode, diagnosticPath) {
  const settings = mode === 'location'
    ? [
      ['Google Chrome', 'HKLM:\\Software\\Policies\\Google\\Chrome', 'DefaultGeolocationSetting', 'DWord', 2],
      ['Microsoft Edge', 'HKLM:\\Software\\Policies\\Microsoft\\Edge', 'DefaultGeolocationSetting', 'DWord', 2],
    ]
    : mode === 'webrtc'
      ? [
        ['Google Chrome', 'HKLM:\\Software\\Policies\\Google\\Chrome', 'WebRtcIPHandling', 'String', 'disable_non_proxied_udp'],
        ['Microsoft Edge', 'HKLM:\\Software\\Policies\\Microsoft\\Edge', 'WebRtcLocalhostIpHandling', 'String', 'disable_non_proxied_udp'],
      ]
      : null;
  if (!settings) throw new Error('浏览器防封设置模式无效。');

  const script = [
    "$ErrorActionPreference = 'Stop'",
    '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8',
    `$diagnosticPath = ${quotePowerShellLiteral(diagnosticPath)}`,
    "$stage = '初始化'",
    'function Write-PolicyDiagnostic([bool]$ok, [string]$stageName, [string]$message, [int]$exitCode) {',
    '  [ordered]@{ Ok=$ok; Stage=$stageName; Message=$message; ExitCode=$exitCode } | ConvertTo-Json -Compress | Set-Content -LiteralPath $diagnosticPath -Encoding UTF8 -Force',
    '}',
    'try {',
  ];
  for (const [browser, key, name, type, value] of settings) {
    const escapedBrowser = browser.replace(/'/g, "''");
    const escapedKey = key.replace(/'/g, "''");
    const escapedName = name.replace(/'/g, "''");
    const stageBase = `${escapedBrowser}/${escapedName}`;
    script.push(`  $stage = '${stageBase}/创建策略路径'`);
    script.push(`  New-Item -Path '${escapedKey}' -Force | Out-Null`);
    script.push(`  $stage = '${stageBase}/写入策略'`);
    script.push(type === 'DWord'
      ? `  New-ItemProperty -Path '${escapedKey}' -Name '${escapedName}' -PropertyType DWord -Value ${Number(value)} -Force | Out-Null`
      : `  New-ItemProperty -Path '${escapedKey}' -Name '${escapedName}' -PropertyType String -Value '${String(value).replace(/'/g, "''")}' -Force | Out-Null`);
    script.push(`  $stage = '${stageBase}/回读验证'`);
    script.push(type === 'DWord'
      ? `  if ([int](Get-ItemPropertyValue -Path '${escapedKey}' -Name '${escapedName}' -ErrorAction Stop) -ne ${Number(value)}) { throw '回读值与预期不一致' }`
      : `  if ([string](Get-ItemPropertyValue -Path '${escapedKey}' -Name '${escapedName}' -ErrorAction Stop) -ne '${String(value).replace(/'/g, "''")}') { throw '回读值与预期不一致' }`);
  }
  script.push(
    "  Write-PolicyDiagnostic $true '完成' '策略写入与回读验证成功' 0",
    "  Write-Output 'BROWSER_POLICY_OK'",
    '} catch {',
    '  $nativeMessage = $_.Exception.Message',
    '  try { Write-PolicyDiagnostic $false $stage $nativeMessage 41 } catch {}',
    '  exit 41',
    '}',
  );
  return { script: script.join('; '), settings };
}

function parsePolicyDiagnostic(stdout) {
  const lines = String(stdout || '').replace(/^\uFEFF/, '').trim().split(/\r?\n/).reverse();
  for (const rawLine of lines) {
    const line = rawLine.replace(/^\uFEFF/, '').trim();
    if (!line.startsWith('{')) continue;
    try {
      const parsed = JSON.parse(line);
      if (typeof parsed.Ok === 'boolean') return parsed;
    } catch {}
  }
  return null;
}

async function runElevatedBrowserPolicyScript(context, mode, commandRunner) {
  const systemRoot = context.env.SystemRoot || context.env.WINDIR || 'C:\\Windows';
  const powershell = path.win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const diagnosticDir = context.env.TEMP || context.env.TMP || context.localAppData;
  const diagnosticPath = path.win32.join(diagnosticDir, 'KelaudeStudioCleaner', `browser-policy-${process.pid}-${Date.now()}.json`);
  const { script, settings } = buildWindowsBrowserPolicyScript(mode, diagnosticPath);
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  const escapedPowerShell = quotePowerShellLiteral(powershell);
  const escapedDiagnostic = quotePowerShellLiteral(diagnosticPath);
  const elevate = [
    "$ErrorActionPreference = 'Stop'",
    '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8',
    `$diagnosticPath = ${escapedDiagnostic}`,
    '$diagnosticDirectory = Split-Path -Parent $diagnosticPath',
    'New-Item -Path $diagnosticDirectory -ItemType Directory -Force | Out-Null',
    'Remove-Item -LiteralPath $diagnosticPath -Force -ErrorAction SilentlyContinue',
    'try {',
    `  $p = Start-Process -FilePath ${escapedPowerShell} -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand','${encoded}') -Verb RunAs -Wait -PassThru`,
    '  if (Test-Path -LiteralPath $diagnosticPath) { Get-Content -LiteralPath $diagnosticPath -Raw -Encoding UTF8 }',
    '  exit ([int]$p.ExitCode)',
    '} catch {',
    "  Write-Error ('ELEVATION_START_FAILED: ' + $_.Exception.Message)",
    '  exit 1223',
    '} finally {',
    '  Remove-Item -LiteralPath $diagnosticPath -Force -ErrorAction SilentlyContinue',
    '}',
  ].join('; ');
  const result = await commandRunner(powershell, ['-NoProfile', '-NonInteractive', '-Command', elevate]);
  const diagnostic = parsePolicyDiagnostic(result.stdout);
  if (result.code !== 0 || !diagnostic?.Ok) {
    const label = mode === 'webrtc' ? 'WebRTC 防泄漏' : '浏览器定位';
    const exitCode = diagnostic?.ExitCode ?? result.code ?? '未知';
    const stage = diagnostic?.Stage || '启动管理员授权';
    const detail = diagnostic?.Message || String(result.stderr || result.stdout || '请在 Windows 授权窗口选择“是”。').trim();
    throw new Error(`${label}策略失败（阶段：${stage}；退出码：${exitCode}）：${detail}`);
  }
  return settings.length;
}

async function writeBrowserPolicy(context, mode, commandRunner = runCommand) {
  let chromium = 0;
  if (context.platform === 'win32') {
    chromium = await runElevatedBrowserPolicyScript(context, mode, commandRunner);
  } else {
    // Unmanaged macOS apps cannot silently install supported enterprise
    // profiles. With the browser closed, edit each current user's Preferences
    // file instead and report this honestly as a local best-effort setting.
    chromium = await writeChromiumProfilePreferences(context, mode);
  }
  const firefox = await writeFirefoxPreferences(context, mode);
  const detail = mode === 'location'
    ? '默认定位权限已设为阻止'
    : 'Chrome / Edge 已限制非代理 UDP，Firefox 已关闭 WebRTC（可能影响网页通话）';
  return { changed: chromium + firefox, message: `${detail}；已处理 ${chromium} 个 Chromium 设置与 ${firefox} 个 Firefox 配置，请重启浏览器。` };
}

async function clearClaudeEnvironment(context, commandRunner = runCommand) {
  let changed = 0;
  if (context.platform === 'win32') {
    const systemRoot = context.env.SystemRoot || context.env.WINDIR || 'C:\\Windows';
    const reg = path.win32.join(systemRoot, 'System32', 'reg.exe');
    for (const name of CLAUDE_ENV_NAMES) {
      const query = await commandRunner(reg, ['query', 'HKCU\\Environment', '/v', name]);
      if (query.code === 0) {
        const removed = await commandRunner(reg, ['delete', 'HKCU\\Environment', '/v', name, '/f']);
        if (removed.code !== 0) throw new Error(removed.stderr || `无法删除用户环境变量 ${name}`);
        changed += 1;
      }
      if (Object.prototype.hasOwnProperty.call(process.env, name)) delete process.env[name];
    }
  } else {
    for (const name of CLAUDE_ENV_NAMES) {
      const current = await commandRunner('/bin/launchctl', ['getenv', name]);
      if (current.code === 0 && current.stdout.trim()) {
        const result = await commandRunner('/bin/launchctl', ['unsetenv', name]);
        if (result.code !== 0) throw new Error(`无法移除 launchctl 环境变量 ${name}`);
        changed += 1;
      }
      if (Object.prototype.hasOwnProperty.call(process.env, name)) delete process.env[name];
    }
    const files = ['.zshrc', '.zprofile', '.bash_profile', '.bashrc', '.profile'];
    for (const leaf of files) {
      const filePath = context.pathApi.join(context.homeDir, leaf);
      let text;
      try {
        await assertSafePathComponents(filePath, context);
        const stat = await fs.lstat(filePath);
        if (!stat.isFile() || stat.isSymbolicLink()) continue;
        text = await fs.readFile(filePath, 'utf8');
      } catch (error) { if (error && error.code === 'ENOENT') continue; throw error; }
      const names = CLAUDE_ENV_NAMES.join('|');
      const pattern = new RegExp(`^\\s*(?:(?:export\\s+)?(?:${names})\\s*=|launchctl\\s+setenv\\s+(?:${names})\\b).*$`, 'gm');
      const next = text.replace(pattern, '').replace(/\n{3,}/g, '\n\n');
      if (next !== text) {
        const temporary = `${filePath}.cleantrace-${process.pid}.tmp`;
        await fs.writeFile(temporary, next, { encoding: 'utf8', mode: 0o600 });
        await fs.rename(temporary, filePath);
        changed += 1;
      }
    }
  }
  return { changed, message: `已移除 ${changed} 个当前用户范围的 Claude 环境配置。系统级变量未自动修改；请重启终端、IDE 与 Claude。` };
}

async function flushDns(context, commandRunner = runCommand) {
  if (context.platform === 'win32') {
    const systemRoot = context.env.SystemRoot || context.env.WINDIR || 'C:\\Windows';
    const ipconfig = path.win32.join(systemRoot, 'System32', 'ipconfig.exe');
    const direct = await commandRunner(ipconfig, ['/flushdns']);
    if (direct.code === 0) return { changed: 1, message: 'Windows DNS 缓存已刷新。' };
    const powershell = path.win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    const elevated = await commandRunner(powershell, ['-NoProfile', '-NonInteractive', '-Command', `$p = Start-Process -FilePath '${ipconfig.replace(/'/g, "''")}' -ArgumentList '/flushdns' -Verb RunAs -Wait -PassThru; exit $p.ExitCode`]);
    if (elevated.code !== 0) throw new Error(elevated.stderr || 'DNS 刷新未获得管理员授权。');
    return { changed: 1, message: 'Windows DNS 缓存已通过管理员授权刷新。' };
  }
  const script = 'do shell script "/usr/bin/dscacheutil -flushcache; /usr/bin/killall -HUP mDNSResponder" with administrator privileges';
  const result = await commandRunner('/usr/bin/osascript', ['-e', script]);
  if (result.code !== 0) throw new Error(result.stderr || 'DNS 刷新未获得管理员授权。');
  return { changed: 1, message: 'macOS DNS 缓存已刷新。' };
}

async function protectDnsLeaks(context, options = {}) {
  const commandRunner = options.commandRunner || runCommand;
  await enableWindowsDnsLeakProtection(context, {
    commandRunner,
    fetchImpl: options.fetchImpl,
    sourceDir: options.dnscryptRoot || context.dnscryptRoot,
  });
  try {
    const firefox = await writeFirefoxPreferences(context, 'dns');
    return {
      changed: 1 + firefox,
      message: `Windows 兼容优先的加密 DNS 已通过本地解析、系统解析与 HTTPS 验证；只接管物理网卡且不依赖代理软件本机端口。已处理 ${firefox} 个 Firefox 配置，请重启浏览器。`,
    };
  } catch (error) {
    try { await restoreWindowsDns(context, { commandRunner }); }
    catch (restoreError) { throw new Error(`Firefox DNS 防护写入失败，系统自动恢复也失败：${error.message}；${restoreError.message}`); }
    throw new Error(`Firefox DNS 防护写入失败，已恢复系统网络配置：${error.message}`);
  }
}

async function restoreDnsProtection(context, options = {}) {
  const result = await restoreWindowsDns(context, { commandRunner: options.commandRunner || runCommand });
  const firefox = await removeFirefoxDnsPreferences(context);
  return { ...result, changed: result.changed + firefox, message: `${result.message} 已移除 ${firefox} 个 Firefox 强制 DNS 配置。` };
}

function parseJsonCommandOutput(output, label) {
  const text = String(output || '').replace(/^\uFEFF/, '').trim();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${label}返回了无法识别的结果。`);
  }
}

async function readSystemRegion(context, commandRunner = runCommand) {
  if (context.platform === 'win32') {
    const systemRoot = context.env.SystemRoot || context.env.WINDIR || 'C:\\Windows';
    const powershell = path.win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    const script = [
      "$ErrorActionPreference='Stop'",
      '$region=Get-WinHomeLocation',
      "[pscustomobject]@{GeoId=[int]$region.GeoId;Name=[string]$region.HomeLocation}|ConvertTo-Json -Compress",
    ].join(';');
    const result = await commandRunner(powershell, ['-NoProfile', '-NonInteractive', '-Command', script]);
    if (result.code !== 0) throw new Error(result.stderr || '无法读取 Windows 当前国家或地区。');
    const parsed = parseJsonCommandOutput(result.stdout, 'Windows 区域读取');
    if (!Number.isInteger(Number(parsed.GeoId))) throw new Error('Windows 当前区域 GeoId 无效。');
    return { platform: 'win32', geoId: Number(parsed.GeoId), name: String(parsed.Name || '') };
  }
  const result = await commandRunner('/usr/bin/defaults', ['read', '-g', 'AppleLocale']);
  if (result.code !== 0 || !String(result.stdout || '').trim()) throw new Error(result.stderr || '无法读取 macOS 当前区域。');
  return { platform: 'darwin', locale: String(result.stdout).trim() };
}

async function restoreSystemRegion(context, previous, commandRunner = runCommand) {
  if (!previous) return;
  if (context.platform === 'win32') {
    const systemRoot = context.env.SystemRoot || context.env.WINDIR || 'C:\\Windows';
    const powershell = path.win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    const script = `$ErrorActionPreference='Stop';Set-WinHomeLocation -GeoId ${Number(previous.geoId)};$actual=Get-WinHomeLocation;if([int]$actual.GeoId-ne${Number(previous.geoId)}){throw 'region rollback verification failed'}`;
    const result = await commandRunner(powershell, ['-NoProfile', '-NonInteractive', '-Command', script]);
    if (result.code !== 0) throw new Error(result.stderr || 'Windows 区域自动回滚失败。');
    return;
  }
  const result = await commandRunner('/usr/bin/defaults', ['write', '-g', 'AppleLocale', '-string', previous.locale]);
  if (result.code !== 0) throw new Error(result.stderr || 'macOS 区域自动回滚失败。');
  await commandRunner('/usr/bin/killall', ['cfprefsd']);
}

async function changeSystemRegion(context, countryCode, commandRunner = runCommand) {
  const iso = String(countryCode || '').toUpperCase();
  if (!/^[A-Z]{2}$/.test(iso)) throw new Error('公网出口未返回有效的国家/地区代码，系统区域未更改。');
  if (context.platform === 'win32') {
    const systemRoot = context.env.SystemRoot || context.env.WINDIR || 'C:\\Windows';
    const powershell = path.win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    const script = [
      "$ErrorActionPreference='Stop'",
      `$iso=${quotePowerShellLiteral(iso)}`,
      '$matches=@([System.Globalization.CultureInfo]::GetCultures([System.Globalization.CultureTypes]::SpecificCultures)|ForEach-Object{try{New-Object System.Globalization.RegionInfo -ArgumentList $_.Name}catch{}}|Where-Object{$_.TwoLetterISORegionName-eq$iso}|Sort-Object GeoId -Unique)',
      "if($matches.Count-lt1){throw 'country code has no Windows GeoId'}",
      '$target=$matches[0]',
      'Set-WinHomeLocation -GeoId $target.GeoId',
      '$actual=Get-WinHomeLocation',
      "if([int]$actual.GeoId-ne[int]$target.GeoId){throw 'region verification failed'}",
      '[pscustomobject]@{GeoId=[int]$actual.GeoId;CountryCode=$iso;Name=[string]$actual.HomeLocation}|ConvertTo-Json -Compress',
    ].join(';');
    const result = await commandRunner(powershell, ['-NoProfile', '-NonInteractive', '-Command', script]);
    if (result.code !== 0) throw new Error(result.stderr || `Windows 无法将国家或地区更改为 ${iso}。`);
    const parsed = parseJsonCommandOutput(result.stdout, 'Windows 区域更改');
    if (Number(parsed.GeoId) <= 0) throw new Error('Windows 区域更改后校验失败。');
    return { changed: 1, countryCode: iso, geoId: Number(parsed.GeoId), locale: localeForCountry(iso) };
  }
  const locale = localeForCountry(iso).replace('-', '_');
  const result = await commandRunner('/usr/bin/defaults', ['write', '-g', 'AppleLocale', '-string', locale]);
  if (result.code !== 0) throw new Error(result.stderr || `macOS 无法将区域更改为 ${iso}。`);
  const verified = await commandRunner('/usr/bin/defaults', ['read', '-g', 'AppleLocale']);
  if (verified.code !== 0 || String(verified.stdout || '').trim() !== locale) throw new Error('macOS 区域更改后校验失败。');
  await commandRunner('/usr/bin/killall', ['cfprefsd']);
  return { changed: 1, countryCode: iso, locale };
}

async function changeTimezone(context, timezone, commandRunner = runCommand) {
  if (!isValidIanaTimezone(timezone)) throw new Error('未获得有效的 IANA 系统时区，系统时区未更改。');
  if (context.platform === 'win32') {
    const windowsId = ianaToWindowsId(timezone);
    if (!windowsId) throw new Error(`Windows 不支持或无法映射时区 ${timezone}，系统时区未更改。`);
    const systemRoot = context.env.SystemRoot || context.env.WINDIR || 'C:\\Windows';
    const tzutil = path.win32.join(systemRoot, 'System32', 'tzutil.exe');
    const direct = await commandRunner(tzutil, ['/s', windowsId]);
    if (direct.code !== 0) {
      const powershell = path.win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
      const elevated = await commandRunner(powershell, ['-NoProfile', '-NonInteractive', '-Command', `$p = Start-Process -FilePath '${tzutil.replace(/'/g, "''")}' -ArgumentList @('/s','${windowsId.replace(/'/g, "''")}') -Verb RunAs -Wait -PassThru; exit $p.ExitCode`]);
      if (elevated.code !== 0) throw new Error(elevated.stderr || '时区更改未获得管理员授权。');
    }
    const verified = await commandRunner(tzutil, ['/g']);
    if (verified.code !== 0 || verified.stdout.trim().toLowerCase() !== windowsId.toLowerCase()) {
      throw new Error('系统未报告预期时区，已标记为失败。');
    }
  } else {
    const script = `do shell script "/usr/sbin/systemsetup -settimezone ${timezone}; /usr/sbin/systemsetup -gettimezone" with administrator privileges`;
    const result = await commandRunner('/usr/bin/osascript', ['-e', script]);
    if (result.code !== 0 || !result.stdout.includes(timezone)) throw new Error(result.stderr || '时区更改未获得管理员授权或未能验证。');
  }
  return { changed: 1, message: `系统时区已更改为 ${timezone}。`, timezone };
}

async function syncProxyTimezone(context, options = {}) {
  const location = await lookupExitLocation(options.fetchImpl, options.locationOptions);
  const commandRunner = options.commandRunner || runCommand;
  const previousRegion = await readSystemRegion(context, commandRunner);
  const region = await changeSystemRegion(context, location.countryCode, commandRunner);
  let changed;
  try {
    changed = await changeTimezone(context, location.timezone, commandRunner);
  } catch (error) {
    try {
      await restoreSystemRegion(context, previousRegion, commandRunner);
    } catch (rollbackError) {
      throw new Error(`时区同步失败，且系统区域自动回滚失败：${error.message}；${rollbackError.message}`);
    }
    throw new Error(`时区同步失败，系统区域已自动恢复：${error.message}`);
  }
  const place = [location.countryCode, location.city].filter(Boolean).join(' · ');
  return {
    ...changed,
    changed: changed.changed + region.changed,
    countryCode: region.countryCode,
    locale: region.locale,
    message: `已按当前公网出口 ${maskIp(location.ip)}${place ? `（${place}）` : ''} 将系统时区同步为 ${location.timezone}，并将系统“国家或地区”同步为 ${location.countryCode}。系统显示语言未更改；重新打开 Windows 设置或重新登录后可看到完整区域刷新。`,
    detectedRegion: place,
    provider: location.provider,
  };
}

async function restoreChinaTimezoneRegion(context, options = {}) {
  const commandRunner = options.commandRunner || runCommand;
  const previousRegion = await readSystemRegion(context, commandRunner);
  const region = await changeSystemRegion(context, 'CN', commandRunner);
  let timezone;
  try {
    timezone = await changeTimezone(context, CHINA_TIMEZONE, commandRunner);
  } catch (error) {
    try { await restoreSystemRegion(context, previousRegion, commandRunner); }
    catch (rollbackError) { throw new Error(`中国时区恢复失败，且区域自动回滚失败：${error.message}；${rollbackError.message}`); }
    throw new Error(`中国时区恢复失败，系统区域已自动回滚：${error.message}`);
  }
  return {
    changed: timezone.changed + region.changed,
    timezone: CHINA_TIMEZONE,
    countryCode: 'CN',
    message: '系统时区已恢复为 Asia/Shanghai，系统“国家或地区”已恢复为中国。',
  };
}

async function syncBrowserLocationLanguage(context, options = {}) {
  if (context.platform !== 'win32') {
    throw new Error('关闭定位并同步代理地区语言当前仅支持 Windows 10/11。');
  }
  const location = await lookupExitLocation(options.fetchImpl, options.locationOptions);
  const locale = localeForCountry(location.countryCode);
  const chromiumPolicies = await applyWindowsLocationLanguage(context, locale, options.commandRunner || runCommand);
  const profiles = await getBrowserProfiles(context);
  let chromiumProfiles;
  try {
    chromiumProfiles = await applyChromiumLanguageProfiles(context, profiles, locale);
  } catch (error) {
    throw new Error(`Chrome / Edge 策略已设置，但浏览器 Profile 语言写入失败：${error.message}。可执行“恢复浏览器定位与语言”撤销本次设置。`);
  }
  let firefox;
  try {
    firefox = await writeFirefoxPreferences(context, 'location-language', locale);
  } catch (error) {
    throw new Error(`Chrome / Edge 已设置，但 Firefox 配置失败：${error.message}。可执行“恢复浏览器定位与语言”撤销本次策略。`);
  }
  const place = [location.countryCode, location.city].filter(Boolean).join(' · ');
  return {
    changed: chromiumPolicies + chromiumProfiles.changed + firefox,
    locale,
    expectedIntlLocale: locale,
    intlRuntimeVerified: false,
    languages: chromiumProfiles.languages,
    chromiumProfiles: chromiumProfiles.profiles,
    detectedRegion: place,
    provider: location.provider,
    message: `已按当前公网出口 ${maskIp(location.ip)}${place ? `（${place}）` : ''} 关闭浏览器定位；Chrome、Edge 与 Firefox 的首选语言已同步为 ${chromiumProfiles.languages}。Chrome / Edge 的界面语言策略、${chromiumProfiles.browserRoots} 个 Local State 应用区域值和 ${chromiumProfiles.profiles} 个 Profile 已完成磁盘回读验证；Edge 已禁止向网站额外共享 Windows 区域格式。浏览器完全退出后重新启动时，navigator.language 与默认 Intl locale 预计为 ${locale}；本助手未在网页渲染进程中冒充运行时验证。Intl timeZone 由“同步代理节点地区时区”单独负责。`,
  };
}

async function restoreBrowserLocationLanguage(context, options = {}) {
  if (context.platform !== 'win32') {
    throw new Error('浏览器定位与语言自动恢复当前仅支持 Windows 10/11。');
  }
  const errors = [];
  let changed = 0;
  try {
    await restoreWindowsLocationLanguage(context, options.commandRunner || runCommand);
    changed += 1;
  } catch (error) {
    errors.push(error.message);
  }
  try {
    const profiles = await getBrowserProfiles(context);
    const restoredProfiles = await restoreChromiumLanguageProfiles(context, profiles);
    changed += restoredProfiles.changed;
  } catch (error) {
    errors.push(`Chrome / Edge Profile 语言恢复失败：${error.message}`);
  }
  try {
    changed += await removeFirefoxLocationLanguagePreferences(context);
  } catch (error) {
    errors.push(`Firefox 恢复失败：${error.message}`);
  }
  if (errors.length) throw new Error(errors.join('；'));
  return {
    changed,
    message: '已恢复本助手保存的 Chrome / Edge 定位、界面/Intl 区域策略、Local State 应用区域和 Profile 首选语言，并移除 Firefox 中由本助手管理的定位与语言标记；其他程序后续改写的值已安全跳过。请重启浏览器。',
  };
}

async function disableSystemLocation(context, commandRunner = runCommand) {
  if (context.platform === 'win32') {
    const systemRoot = context.env.SystemRoot || context.env.WINDIR || 'C:\\Windows';
    const reg = path.win32.join(systemRoot, 'System32', 'reg.exe');
    const powershell = path.win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    const sc = path.win32.join(systemRoot, 'System32', 'sc.exe');

    const currentUser = await commandRunner(reg, [
      'add',
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location',
      '/v', 'Value', '/t', 'REG_SZ', '/d', 'Deny', '/f',
    ]);
    if (currentUser.code !== 0) throw new Error(currentUser.stderr || '无法关闭当前用户的系统定位权限。');

    const adminScript = [
      `$reg = '${reg.replace(/'/g, "''")}'`,
      `$sc = '${sc.replace(/'/g, "''")}'`,
      `& $reg add 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors' /v DisableLocation /t REG_DWORD /d 1 /f`,
      'if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }',
      `& $reg add 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors' /v DisableWindowsLocationProvider /t REG_DWORD /d 1 /f`,
      'if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }',
      `& $sc stop lfsvc | Out-Null`,
      `& $sc config lfsvc start= disabled | Out-Null`,
      'exit $LASTEXITCODE',
    ].join('; ');
    const encoded = Buffer.from(adminScript, 'utf16le').toString('base64');
    const elevate = `$p = Start-Process -FilePath '${powershell.replace(/'/g, "''")}' -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand','${encoded}') -Verb RunAs -Wait -PassThru; exit $p.ExitCode`;
    const elevated = await commandRunner(powershell, ['-NoProfile', '-NonInteractive', '-Command', elevate]);
    if (elevated.code !== 0) throw new Error(elevated.stderr || '关闭 Windows 系统定位未获得管理员授权。');

    const userVerified = await commandRunner(reg, [
      'query',
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location',
      '/v', 'Value',
    ]);
    const policyVerified = await commandRunner(reg, [
      'query', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors', '/v', 'DisableLocation',
    ]);
    if (userVerified.code !== 0 || !/\bDeny\b/i.test(userVerified.stdout)
      || policyVerified.code !== 0 || !/0x1\b/i.test(policyVerified.stdout)) {
      throw new Error('Windows 未报告预期的定位关闭状态，已标记为失败。');
    }
    return { changed: 1, message: 'Windows 系统定位策略与位置服务已关闭；重启系统后完全生效。' };
  }

  const script = 'do shell script "/usr/bin/defaults write /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled -bool false; /usr/bin/killall locationd >/dev/null 2>&1 || true; /usr/bin/defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled" with administrator privileges';
  const result = await commandRunner('/usr/bin/osascript', ['-e', script]);
  if (result.code !== 0 || !/(^|\s)0(\s|$)/.test(result.stdout)) {
    throw new Error(result.stderr || '关闭 macOS 系统定位未获得管理员授权或未能验证。');
  }
  return { changed: 1, message: 'macOS 系统定位服务已关闭；部分应用可能需要重新启动。' };
}

async function executePrivacyActions(ids, rawContext = {}, options = {}) {
  const context = rawContext.pathApi ? rawContext : createContext(rawContext);
  if (!Array.isArray(ids) || !ids.length || ids.length > PRIVACY_ACTIONS.length
    || ids.some((id) => typeof id !== 'string' || !PRIVACY_ACTIONS.some((action) => action.id === id))) {
    throw new Error('防封设置请求无效。');
  }
  const unique = [...new Set(ids)];
  for (const id of unique) {
    const action = PRIVACY_ACTIONS.find((candidate) => candidate.id === id);
    const conflict = (action.exclusiveWith || []).find((candidate) => unique.includes(candidate));
    if (conflict) throw new Error(`“${action.title}”不能与“${PRIVACY_ACTIONS.find((candidate) => candidate.id === conflict).title}”同时执行。`);
  }
  const needsBrowserClosed = unique.some((id) => PRIVACY_ACTIONS.find((action) => action.id === id).requiresBrowserClosed);
  if (needsBrowserClosed) {
    const running = await browsersRunning(context, options.commandRunner);
    if (running.length) throw new Error(`请先完全退出浏览器后重试：${running.join('、')}`);
  }

  const results = [];
  for (const id of unique) {
    try {
      let result;
      if (id === 'claude-environment') result = await clearClaudeEnvironment(context, options.commandRunner);
      else if (id === 'mail-cookie') result = await clearMailCookies(context);
      else if (id === 'block-location') result = await writeBrowserPolicy(context, 'location', options.commandRunner);
      else if (id === 'block-location-sync-language') result = await syncBrowserLocationLanguage(context, options);
      else if (id === 'restore-browser-location-language') result = await restoreBrowserLocationLanguage(context, options);
      else if (id === 'disable-system-location') result = await disableSystemLocation(context, options.commandRunner);
      else if (id === 'restrict-webrtc') result = await writeBrowserPolicy(context, 'webrtc', options.commandRunner);
      else if (id === 'protect-dns') result = await protectDnsLeaks(context, options);
      else if (id === 'restore-dns') result = await restoreDnsProtection(context, options);
      else if (id === 'sync-proxy-timezone') result = await syncProxyTimezone(context, options);
      else if (id === 'restore-china-timezone') result = await restoreChinaTimezoneRegion(context, options);
      else if (id === 'install-adguard') {
        result = await installAdGuardPolicies(context, options.commandRunner || runCommand);
        result.message += ' WebRTC 防泄漏是独立选项，不影响 AdGuard 安装结果。';
      }
      else if (id === 'remove-managed-adguard') result = await removeAdGuardPolicies(context, options.commandRunner || runCommand);
      results.push({ id, status: 'completed', ...result });
    } catch (error) {
      results.push({ id, status: 'failed', changed: 0, message: error.message || '操作失败。' });
    }
  }
  return { status: results.some((result) => result.status === 'failed') ? 'completed-with-errors' : 'completed', results };
}

module.exports = {
  CLAUDE_ENV_NAMES,
  CHINA_TIMEZONE,
  applyChromiumPreference,
  browsersRunning,
  closeSupportedBrowsers,
  clearAllBrowserData,
  clearClaudeEnvironment,
  clearMailCookies,
  changeTimezone,
  changeSystemRegion,
  disableSystemLocation,
  deleteDomainCookies,
  executePrivacyActions,
  getBrowserCleanupTarget,
  getBrowserProfiles,
  parseFirefoxProfilesIni,
  publicPrivacyActions,
  replaceManagedFirefoxBlock,
  protectDnsLeaks,
  restoreDnsProtection,
  restoreChinaTimezoneRegion,
  readSystemRegion,
  restoreBrowserLocationLanguage,
  syncBrowserLocationLanguage,
  syncProxyTimezone,
  writeBrowserPolicy,
  writeChromiumProfilePreferences,
};
