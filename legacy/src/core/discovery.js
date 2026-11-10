const crypto = require('node:crypto');
const fs = require('node:fs/promises');

const { inspectPathComponents } = require('./path-safety');
const { createContext } = require('./targets');

const DEFAULT_LIMITS = Object.freeze({
  maxDepth: 3,
  maxEntries: 8_000,
  maxCandidateEntries: 512,
  timeoutMs: 3_000,
});

const DESKTOP_DIRECTORY_NAMES = new Set([
  'claude',
  'claude-3p',
  'com.anthropic.claude',
  'com.anthropic.claudefordesktop',
]);

const DESKTOP_PROFILE_FEATURES = new Map([
  ['Preferences', { type: 'file', score: 2 }],
  ['Local State', { type: 'file', score: 2 }],
  ['ant-did', { type: 'file', score: 2 }],
  ['Session Storage', { type: 'directory', score: 1 }],
  ['Local Storage', { type: 'directory', score: 1 }],
  ['IndexedDB', { type: 'directory', score: 1 }],
  ['Network', { type: 'directory', score: 1 }],
  ['Cache', { type: 'directory', score: 0.5 }],
  ['Code Cache', { type: 'directory', score: 0.5 }],
  ['GPUCache', { type: 'directory', score: 0.5 }],
  ['Cache_Data', { type: 'directory', score: 0.5 }],
]);

const CODE_FILE_FEATURES = new Set([
  '.credentials.json',
  'settings.json',
  'history.jsonl',
  'stats-cache.json',
]);

const CODE_DIRECTORY_FEATURES = new Set([
  'commands',
  'debug',
  'plans',
  'plugins',
  'projects',
  'session-env',
  'shell-snapshots',
  'todos',
]);

const GLOBAL_CONFIG_KEYS = new Set([
  'autoUpdates',
  'cachedChangelog',
  'hasCompletedOnboarding',
  'installMethod',
  'mcpServers',
  'numStartups',
  'oauthAccount',
  'projects',
  'tipsHistory',
  'userID',
]);

const PROJECT_ROOT_MARKERS = Object.freeze([
  '.git', '.hg', '.svn',
  'package.json', 'pyproject.toml', 'Cargo.toml', 'go.mod', 'pom.xml',
  'composer.json', 'Gemfile', '*.sln',
]);

function normalizeContext(rawContext = {}) {
  const base = rawContext.pathApi ? rawContext : createContext(rawContext);
  return {
    ...base,
    discoveryRoots: rawContext.discoveryRoots ?? base.discoveryRoots,
    workspaceRoot: rawContext.workspaceRoot ?? base.workspaceRoot ?? process.cwd(),
  };
}

function comparable(candidate, context) {
  const normalized = context.pathApi.normalize(context.pathApi.resolve(candidate));
  return context.platform === 'win32' ? normalized.toLowerCase() : normalized;
}

function samePath(left, right, context) {
  return comparable(left, context) === comparable(right, context);
}

function isPathWithin(base, candidate, context) {
  const p = context.pathApi;
  const relative = p.relative(p.resolve(base), p.resolve(candidate));
  if (relative === '') return true;
  return relative !== '..' && !relative.startsWith(`..${p.sep}`) && !p.isAbsolute(relative);
}

function isWindowsNetworkPath(candidate, context) {
  if (context.platform !== 'win32') return false;
  const normalized = context.pathApi.normalize(candidate);
  return normalized.startsWith('\\\\') || normalized.startsWith('\\\\?\\UNC\\');
}

function clampInteger(value, fallback, minimum, maximum) {
  if (!Number.isInteger(value)) return fallback;
  return Math.min(maximum, Math.max(minimum, value));
}

function rootDescriptor(candidate, scope, maxDepth, context) {
  if (typeof candidate === 'string') {
    return {
      path: context.pathApi.resolve(candidate),
      scope,
      maxDepth,
    };
  }

  if (!candidate || typeof candidate.path !== 'string') return null;
  const supportedScopes = new Set(['all', 'app-data', 'cache', 'code-config', 'home']);
  return {
    path: context.pathApi.resolve(candidate.path),
    scope: supportedScopes.has(candidate.scope) ? candidate.scope : scope,
    maxDepth: clampInteger(candidate.maxDepth, maxDepth, 0, 16),
  };
}

function resolveDiscoveryRoots(rawContext = {}, options = {}) {
  const context = normalizeContext(rawContext);
  const p = context.pathApi;
  const configured = options.discoveryRoots ?? context.discoveryRoots;
  let roots;

  if (Array.isArray(configured)) {
    roots = configured
      .map((candidate) => rootDescriptor(candidate, 'all', options.maxDepth ?? DEFAULT_LIMITS.maxDepth, context))
      .filter(Boolean);
  } else if (context.platform === 'win32') {
    roots = [
      rootDescriptor(context.homeDir, 'home', 0, context),
      rootDescriptor(context.localAppData, 'app-data', options.maxDepth ?? DEFAULT_LIMITS.maxDepth, context),
      rootDescriptor(context.roamingAppData, 'app-data', options.maxDepth ?? DEFAULT_LIMITS.maxDepth, context),
      rootDescriptor(context.claudeConfigDir, 'code-config', 0, context),
    ];
  } else {
    roots = [
      rootDescriptor(context.homeDir, 'home', 0, context),
      rootDescriptor(p.join(context.homeDir, 'Library', 'Application Support'), 'app-data', options.maxDepth ?? DEFAULT_LIMITS.maxDepth, context),
      rootDescriptor(p.join(context.homeDir, 'Library', 'Caches'), 'cache', options.maxDepth ?? DEFAULT_LIMITS.maxDepth, context),
      rootDescriptor(context.claudeConfigDir, 'code-config', 0, context),
    ];
  }

  const unique = new Map();
  for (const root of roots.filter(Boolean)) {
    const key = comparable(root.path, context);
    const existing = unique.get(key);
    if (!existing || existing.scope === 'home') unique.set(key, root);
  }
  return [...unique.values()];
}

async function enumerateGlobalDiscoveryRoots(rawContext = {}, options = {}) {
  const context = normalizeContext(rawContext);
  const p = context.pathApi;
  let candidates = Array.isArray(options.volumeRoots) ? options.volumeRoots : null;

  if (!candidates && context.platform === 'win32') {
    candidates = Array.from({ length: 26 }, (_, index) => `${String.fromCharCode(65 + index)}:\\`);
  } else if (!candidates) {
    candidates = ['/Users'];
    try {
      const volumes = await fs.readdir('/Volumes', { withFileTypes: true });
      for (const volume of volumes) {
        if (volume.isDirectory() && !volume.isSymbolicLink()) candidates.push(p.join('/Volumes', volume.name));
      }
    } catch {
      // /Volumes may not exist or may be unreadable; /Users remains available.
    }
  }

  const roots = [];
  for (const candidate of candidates) {
    if (typeof candidate !== 'string' || !p.isAbsolute(candidate) || isWindowsNetworkPath(candidate, context)) continue;
    const resolved = p.resolve(candidate);
    try {
      const stat = await fs.lstat(resolved);
      if (!stat.isDirectory() || stat.isSymbolicLink()) continue;
      const real = await fs.realpath(resolved);
      if (!samePath(real, resolved, context)) continue;
      roots.push({ path: resolved, scope: 'all', maxDepth: clampInteger(options.maxDepth, 10, 1, 16) });
    } catch {
      // Missing, offline, permission-protected and empty drive letters are ignored.
    }
  }
  return roots;
}

function protectedSystemRoots(context, options = {}) {
  const p = context.pathApi;
  if (context.platform === 'win32') {
    const volumeRoot = p.parse(context.homeDir).root;
    return [
      context.env.SystemRoot,
      context.env.WINDIR,
      context.env.ProgramFiles,
      context.env['ProgramFiles(x86)'],
      context.env.ProgramData,
      p.join(volumeRoot, 'Windows'),
      p.join(volumeRoot, 'Program Files'),
      p.join(volumeRoot, 'Program Files (x86)'),
      p.join(volumeRoot, 'ProgramData'),
    ].filter((item) => typeof item === 'string' && p.isAbsolute(item));
  }
  const roots = ['/System', '/Library', '/Applications', '/usr', '/bin', '/sbin', '/private'];
  if (!options.globalSearch) roots.push('/Volumes');
  return roots;
}

function rejectRootReason(candidate, context, options = {}) {
  const p = context.pathApi;
  if (typeof candidate !== 'string' || !p.isAbsolute(candidate)) return '根目录不是绝对路径';
  if (isWindowsNetworkPath(candidate, context)) return '不扫描 UNC 或网络共享';
  if (!options.globalSearch && samePath(candidate, p.parse(p.resolve(candidate)).root, context)) return '不扫描系统卷根目录';

  if (context.platform === 'win32' && !options.globalSearch) {
    const candidateVolume = p.parse(p.resolve(candidate)).root;
    const homeVolume = p.parse(p.resolve(context.homeDir)).root;
    if (candidateVolume.toLowerCase() !== homeVolume.toLowerCase()) return '不跨越当前用户主目录所在卷';
  }

  for (const systemRoot of protectedSystemRoots(context, options)) {
    if (isPathWithin(systemRoot, candidate, context)) return '不扫描系统或程序目录';
  }

  if (!options.globalSearch) {
    const currentUserAnchors = [context.homeDir, context.localAppData, context.roamingAppData]
      .filter((item) => typeof item === 'string' && p.isAbsolute(item));
    if (!currentUserAnchors.some((anchor) => isPathWithin(anchor, candidate, context))) {
      return '不扫描当前用户目录范围之外的位置';
    }
  }

  if (context.workspaceRoot && isPathWithin(context.workspaceRoot, candidate, context)) {
    return '不扫描应用自身工作区';
  }
  return null;
}

function abortError() {
  const error = new Error('Claude 数据发现已取消。');
  error.name = 'AbortError';
  error.code = 'ABORT_ERR';
  return error;
}

function checkBudget(state) {
  if (state.signal?.aborted) throw abortError();
  if (Date.now() >= state.deadline) {
    state.timedOut = true;
    state.partial = true;
    return false;
  }
  if (state.entriesVisited >= state.maxEntries) {
    state.maxEntriesReached = true;
    state.partial = true;
    return false;
  }
  return true;
}

async function validateDiscoveryRoot(root, context, options = {}) {
  const rejected = rejectRootReason(root.path, context, options);
  if (rejected) return { safe: false, reason: rejected };

  try {
    const safety = await inspectPathComponents(root.path, context);
    if (!safety.safe) return { safe: false, reason: '根目录包含符号链接、Junction 或重解析点' };
    const stat = await fs.lstat(root.path);
    if (stat.isSymbolicLink()) return { safe: false, reason: '根目录是符号链接或重解析点' };
    if (!stat.isDirectory()) return { safe: false, reason: '发现根不是目录' };
    const real = await fs.realpath(root.path);
    if (!samePath(real, root.path, context)) return { safe: false, reason: '发现根重定向到了其他位置' };
    return { safe: true, reason: null };
  } catch (error) {
    if (error?.code === 'ENOENT') return { safe: false, reason: '目录不存在' };
    return { safe: false, reason: '目录不可读取' };
  }
}

function isWorkspacePath(candidate, context) {
  return Boolean(context.workspaceRoot && isPathWithin(context.workspaceRoot, candidate, context));
}

async function inspectCandidateDirectory(candidate, context, state) {
  if (!checkBudget(state) || isWorkspacePath(candidate, context)) return null;
  const rejected = rejectRootReason(candidate, context, state.options);
  if (rejected) return null;

  try {
    const safety = await inspectPathComponents(candidate, context);
    if (!safety.safe) {
      state.linkedPathsSkipped += 1;
      return null;
    }
    const stat = await fs.lstat(candidate);
    if (!stat.isDirectory() || stat.isSymbolicLink()) return null;
    const real = await fs.realpath(candidate);
    if (!samePath(real, candidate, context)) {
      state.linkedPathsSkipped += 1;
      return null;
    }

    const entries = await fs.readdir(candidate, { withFileTypes: true });
    if (entries.length > state.maxCandidateEntries) return null;
    const inspected = new Map();
    for (const entry of entries) {
      if (!checkBudget(state)) return null;
      state.entriesVisited += 1;
      const child = context.pathApi.join(candidate, entry.name);
      if (entry.isSymbolicLink()) {
        state.linkedPathsSkipped += 1;
        return null;
      }
      const childStat = await fs.lstat(child);
      if (childStat.isSymbolicLink()) {
        state.linkedPathsSkipped += 1;
        return null;
      }
      if (childStat.isDirectory()) {
        const childReal = await fs.realpath(child);
        if (!samePath(childReal, child, context)) {
          state.linkedPathsSkipped += 1;
          return null;
        }
      }
      inspected.set(entry.name, childStat.isDirectory() ? 'directory' : childStat.isFile() ? 'file' : 'other');
    }
    return inspected;
  } catch {
    return null;
  }
}

async function readJsonObject(filePath, context, maximumBytes = 2 * 1024 * 1024) {
  try {
    const safety = await inspectPathComponents(filePath, context);
    if (!safety.safe) return null;
    const stat = await fs.lstat(filePath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maximumBytes) return null;
    const parsed = JSON.parse(await fs.readFile(filePath, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    return parsed;
  } catch {
    return null;
  }
}

async function isProjectLocalClaudeDirectory(candidate, context) {
  const parent = context.pathApi.dirname(candidate);
  try {
    const entries = await fs.readdir(parent, { withFileTypes: true });
    return entries.some((entry) => {
      const name = context.platform === 'win32' ? entry.name.toLowerCase() : entry.name;
      return PROJECT_ROOT_MARKERS.some((marker) => (
        marker === '*.sln' ? name.toLowerCase().endsWith('.sln') : name === (context.platform === 'win32' ? marker.toLowerCase() : marker)
      ));
    });
  } catch { return false; }
}

function stableDiscoveryId(kind, candidate, context) {
  const digest = crypto
    .createHash('sha256')
    .update(`${kind}\0${comparable(candidate, context)}`, 'utf8')
    .digest('hex')
    .slice(0, 20);
  return `discovered.${kind}.${digest}`;
}

function targetBase({ id, group, category, title, description, risk, backup, path: targetPath, strategy, signature }) {
  return {
    id,
    group,
    category,
    title,
    label: title,
    description,
    risk,
    defaultSelected: false,
    backup,
    path: targetPath,
    strategy,
    exists: true,
    resources: [{ type: 'path', path: targetPath, label: title }],
    exclusiveWith: [],
    source: '当前用户安全发现',
    blockedReason: null,
    discovered: true,
    signature,
  };
}

function relativeDepth(base, candidate, context) {
  const relative = context.pathApi.relative(context.pathApi.resolve(base), context.pathApi.resolve(candidate));
  if (relative === '') return 0;
  return relative.split(/[\\/]+/).filter(Boolean).length;
}

function isInDiscoveryScope(candidate, scopes, context, options = {}) {
  return resolveDiscoveryRoots(context, options).some((root) => (
    scopes.includes(root.scope)
      && isPathWithin(root.path, candidate, context)
      && relativeDepth(root.path, candidate, context) <= root.maxDepth
  ));
}

function isCodeDirectoryLocation(candidate, context, options = {}) {
  const p = context.pathApi;
  if (context.claudeConfigDir && samePath(candidate, context.claudeConfigDir, context)) return true;
  if (p.basename(candidate).toLowerCase() !== '.claude') return false;
  return resolveDiscoveryRoots(context, options).some((root) => {
    if (root.scope !== 'home' && root.scope !== 'all') return false;
    if (options.globalSearch) {
      return isPathWithin(root.path, candidate, context)
        && relativeDepth(root.path, candidate, context) <= root.maxDepth;
    }
    return samePath(p.dirname(candidate), root.path, context);
  });
}

function reconstructedTarget(kind, targetPath, context) {
  const p = context.pathApi;
  const signature = { type: 'reconstructed-discovery-reference' };
  if (kind === 'desktop-reset' || kind === 'desktop-cache') {
    const cacheOnly = kind === 'desktop-cache';
    const fullId = stableDiscoveryId(kind, targetPath, context);
    const target = targetBase({
      id: fullId,
      group: 'desktop',
      category: cacheOnly ? 'claude-desktop-cache' : 'claude-desktop',
      title: cacheOnly ? '发现的 Claude 桌面端缓存' : '发现的 Claude 桌面端数据',
      description: '根据已验证的安全发现记录重建的清理目标引用。',
      risk: cacheOnly ? 'medium' : 'high',
      backup: false,
      path: targetPath,
      strategy: 'remove-directory',
      signature,
    });
    if (!cacheOnly) target.exclusiveWith = [stableDiscoveryId('desktop-device-id', p.join(targetPath, 'ant-did'), context)];
    return target;
  }

  if (kind === 'desktop-device-id') {
    const target = targetBase({
      id: stableDiscoveryId(kind, targetPath, context),
      group: 'desktop',
      category: 'claude-desktop-device-id',
      title: '发现的 Claude 桌面端设备标识',
      description: '根据已验证的安全发现记录重建的 ant-did 清理目标引用。',
      risk: 'low',
      backup: true,
      path: targetPath,
      strategy: 'remove-file',
      signature,
    });
    target.exclusiveWith = [stableDiscoveryId('desktop-reset', p.dirname(targetPath), context)];
    return target;
  }

  if (kind === 'code-reset') {
    const target = targetBase({
      id: stableDiscoveryId(kind, targetPath, context),
      group: 'code',
      category: 'claude-code',
      title: '发现的 Claude Code 本地数据',
      description: '根据已验证的安全发现记录重建的 Claude Code 目录引用。',
      risk: 'high',
      backup: false,
      path: targetPath,
      strategy: 'remove-directory',
      signature,
    });
    target.exclusiveWith = [
      stableDiscoveryId('code-credentials', p.join(targetPath, '.credentials.json'), context),
      stableDiscoveryId('code-settings', p.join(targetPath, 'settings.json'), context),
    ];
    return target;
  }

  const codeFileDefinitions = {
    'code-credentials': {
      category: 'claude-code-credentials',
      title: '发现的 Claude Code 登录凭据',
      description: '根据已验证的安全发现记录重建的凭据文件引用。',
      risk: 'medium',
      backup: false,
    },
    'code-settings': {
      category: 'claude-code-settings',
      title: '发现的 Claude Code 用户设置',
      description: '根据已验证的安全发现记录重建的设置文件引用。',
      risk: 'high',
      backup: true,
    },
    'code-global-config': {
      category: 'claude-code-global-config',
      title: '发现的 Claude Code 全局状态文件',
      description: '根据已验证的安全发现记录重建的全局状态文件引用。',
      risk: 'high',
      backup: false,
    },
  };
  const definition = codeFileDefinitions[kind];
  if (!definition) return null;
  const target = targetBase({
    id: stableDiscoveryId(kind, targetPath, context),
    group: 'code',
    ...definition,
    path: targetPath,
    strategy: 'remove-file',
    signature,
  });
  if (kind !== 'code-global-config') {
    target.exclusiveWith = [stableDiscoveryId('code-reset', p.dirname(targetPath), context)];
  }
  return target;
}

function reconstructDiscoveredTarget(targetId, originalPath, rawContext = {}, options = {}) {
  const context = normalizeContext(rawContext);
  const p = context.pathApi;
  if (typeof targetId !== 'string' || typeof originalPath !== 'string' || !p.isAbsolute(originalPath)) return null;
  const match = /^discovered\.([a-z-]+)\.[a-f0-9]{20}$/.exec(targetId);
  if (!match) return null;
  const kind = match[1];
  const resolved = p.resolve(originalPath);
  if (stableDiscoveryId(kind, resolved, context) !== targetId) return null;
  if (rejectRootReason(resolved, context, options)) return null;

  const basename = p.basename(resolved).toLowerCase();
  let validLocation = false;
  if (kind === 'desktop-reset') {
    validLocation = DESKTOP_DIRECTORY_NAMES.has(basename)
      && isInDiscoveryScope(resolved, ['app-data', 'all'], context, options);
  } else if (kind === 'desktop-cache') {
    validLocation = DESKTOP_DIRECTORY_NAMES.has(basename)
      && isInDiscoveryScope(resolved, ['cache', 'all'], context, options);
  } else if (kind === 'desktop-device-id') {
    const parent = p.dirname(resolved);
    validLocation = basename === 'ant-did'
      && DESKTOP_DIRECTORY_NAMES.has(p.basename(parent).toLowerCase())
      && isInDiscoveryScope(parent, ['app-data', 'all'], context, options);
  } else if (kind === 'code-reset') {
    validLocation = isCodeDirectoryLocation(resolved, context, options);
  } else if (kind === 'code-credentials' || kind === 'code-settings') {
    const expectedLeaf = kind === 'code-credentials' ? '.credentials.json' : 'settings.json';
    validLocation = basename === expectedLeaf.toLowerCase()
      && isCodeDirectoryLocation(p.dirname(resolved), context, options);
  } else if (kind === 'code-global-config') {
    validLocation = basename === '.claude.json'
      && resolveDiscoveryRoots(context, options).some((root) => (
        (root.scope === 'home' || root.scope === 'all')
          && (options.globalSearch
            ? isPathWithin(root.path, resolved, context) && relativeDepth(root.path, resolved, context) <= root.maxDepth
            : samePath(p.dirname(resolved), root.path, context))
      ));
  }
  if (!validLocation) return null;

  const target = reconstructedTarget(kind, resolved, context);
  return target ? { ...target, exists: false } : null;
}

async function detectDesktopDirectory(candidate, scope, context, state) {
  const basename = context.pathApi.basename(candidate).toLowerCase();
  if (!DESKTOP_DIRECTORY_NAMES.has(basename)) return [];
  const entries = await inspectCandidateDirectory(candidate, context, state);
  if (!entries) return [];

  const features = [];
  let profileScore = 0;
  let nonCacheFeatureCount = 0;
  for (const [name, expected] of DESKTOP_PROFILE_FEATURES) {
    if (entries.get(name) !== expected.type) continue;
    features.push(name);
    profileScore += expected.score;
    if (!['Cache', 'Code Cache', 'GPUCache', 'Cache_Data'].includes(name)) nonCacheFeatureCount += 1;
  }

  const cacheFeatureCount = features.filter((name) => ['Cache', 'Code Cache', 'GPUCache', 'Cache_Data'].includes(name)).length;
  const isCacheOnly = nonCacheFeatureCount === 0 && (scope === 'cache' || state.globalSearch) && cacheFeatureCount >= 2;
  const isProfile = nonCacheFeatureCount >= 2 && profileScore >= 3;
  if (!isProfile && !isCacheOnly) return [];

  const signature = {
    type: isCacheOnly ? 'claude-desktop-cache' : 'claude-desktop-profile',
    features: features.sort(),
    score: profileScore,
  };
  const fullKind = isCacheOnly ? 'desktop-cache' : 'desktop-reset';
  const fullId = stableDiscoveryId(fullKind, candidate, context);
  const full = targetBase({
    id: fullId,
    group: 'desktop',
    category: isCacheOnly ? 'claude-desktop-cache' : 'claude-desktop',
    title: isCacheOnly ? '发现的 Claude 桌面端缓存' : '发现的 Claude 桌面端数据',
    description: isCacheOnly
      ? '结构校验通过的当前用户 Claude 桌面端缓存目录。'
      : '结构校验通过的当前用户 Claude 桌面端应用数据目录。完整清理不可恢复。',
    risk: isCacheOnly ? 'medium' : 'high',
    backup: false,
    path: candidate,
    strategy: 'remove-directory',
    signature,
  });

  if (entries.get('ant-did') !== 'file') return [full];
  const devicePath = context.pathApi.join(candidate, 'ant-did');
  const deviceId = stableDiscoveryId('desktop-device-id', devicePath, context);
  const device = targetBase({
    id: deviceId,
    group: 'desktop',
    category: 'claude-desktop-device-id',
    title: '发现的 Claude 桌面端设备标识',
    description: '仅清理结构校验通过目录中的 ant-did 文件，可创建备份。',
    risk: 'low',
    backup: true,
    path: devicePath,
    strategy: 'remove-file',
    signature: { type: 'claude-desktop-device-id', parentFeatures: signature.features },
  });
  full.exclusiveWith = [deviceId];
  device.exclusiveWith = [fullId];
  return [full, device];
}

async function detectCodeDirectory(candidate, root, context, state) {
  const p = context.pathApi;
  const basename = p.basename(candidate).toLowerCase();
  const configuredPath = context.claudeConfigDir && samePath(candidate, context.claudeConfigDir, context);
  const directHomeConfig = basename === '.claude' && samePath(p.dirname(candidate), context.homeDir, context);
  const directOverrideConfig = root.scope === 'all' && basename === '.claude'
    && (state.globalSearch ? isPathWithin(root.path, candidate, context) : samePath(p.dirname(candidate), root.path, context));
  if (!configuredPath && !directHomeConfig && !directOverrideConfig) return [];
  if (!configuredPath && !directHomeConfig && await isProjectLocalClaudeDirectory(candidate, context)) return [];

  const entries = await inspectCandidateDirectory(candidate, context, state);
  if (!entries) return [];
  const features = [];
  let strongFiles = 0;
  let knownDirectories = 0;

  for (const name of CODE_FILE_FEATURES) {
    if (entries.get(name) !== 'file') continue;
    if (name.endsWith('.json')) {
      const parsed = await readJsonObject(p.join(candidate, name), context);
      if (!parsed) continue;
    }
    features.push(name);
    strongFiles += 1;
  }
  for (const name of CODE_DIRECTORY_FEATURES) {
    if (entries.get(name) !== 'directory') continue;
    features.push(name);
    knownDirectories += 1;
  }
  if (strongFiles < 1 && knownDirectories < 2) return [];

  const signature = { type: 'claude-code-config', features: features.sort() };
  const fullId = stableDiscoveryId('code-reset', candidate, context);
  const full = targetBase({
    id: fullId,
    group: 'code',
    category: 'claude-code',
    title: '发现的 Claude Code 本地数据',
    description: '结构校验通过的当前用户 Claude Code 配置与状态目录。完整清理不可恢复。',
    risk: 'high',
    backup: false,
    path: candidate,
    strategy: 'remove-directory',
    signature,
  });

  const children = [];
  if (features.includes('.credentials.json')) {
    const credentialsPath = p.join(candidate, '.credentials.json');
    children.push(targetBase({
      id: stableDiscoveryId('code-credentials', credentialsPath, context),
      group: 'code',
      category: 'claude-code-credentials',
      title: '发现的 Claude Code 登录凭据',
      description: '清理后 Claude Code 需要重新登录；敏感凭据不创建持久备份。',
      risk: 'medium',
      backup: false,
      path: credentialsPath,
      strategy: 'remove-file',
      signature: { type: 'claude-code-credentials', parentFeatures: signature.features },
    }));
  }
  if (features.includes('settings.json')) {
    const settingsPath = p.join(candidate, 'settings.json');
    children.push(targetBase({
      id: stableDiscoveryId('code-settings', settingsPath, context),
      group: 'code',
      category: 'claude-code-settings',
      title: '发现的 Claude Code 用户设置',
      description: '结构校验通过的 settings.json，可创建备份后清理。',
      risk: 'high',
      backup: true,
      path: settingsPath,
      strategy: 'remove-file',
      signature: { type: 'claude-code-settings', parentFeatures: signature.features },
    }));
  }

  full.exclusiveWith = children.map((target) => target.id);
  for (const child of children) child.exclusiveWith = [fullId];
  return [full, ...children];
}

async function detectGlobalConfig(filePath, root, context, state) {
  const p = context.pathApi;
  const directHomeConfig = samePath(p.dirname(filePath), context.homeDir, context);
  const directOverrideConfig = root.scope === 'all'
    && (state.globalSearch ? isPathWithin(root.path, filePath, context) : samePath(p.dirname(filePath), root.path, context));
  if (!directHomeConfig && !directOverrideConfig) return [];
  if (!checkBudget(state) || isWorkspacePath(filePath, context)) return [];
  state.entriesVisited += 1;
  const parsed = await readJsonObject(filePath, context);
  if (!parsed) return [];
  const keys = Object.keys(parsed).filter((key) => GLOBAL_CONFIG_KEYS.has(key)).sort();
  if (keys.length === 0) return [];

  return [targetBase({
    id: stableDiscoveryId('code-global-config', filePath, context),
    group: 'code',
    category: 'claude-code-global-config',
    title: '发现的 Claude Code 全局状态文件',
    description: '结构校验通过的 .claude.json，可能包含 OAuth、MCP 与项目状态；不保留敏感备份。',
    risk: 'high',
    backup: false,
    path: filePath,
    strategy: 'remove-file',
    signature: { type: 'claude-code-global-config', keys },
  })];
}

async function addTargets(targets, additions) {
  for (const target of additions) targets.set(target.id, target);
}

async function scanHomeOrOverride(root, context, state, targets) {
  if (!checkBudget(state)) return;
  const p = context.pathApi;
  await addTargets(targets, await detectCodeDirectory(p.join(root.path, '.claude'), root, context, state));
  if (!checkBudget(state)) return;
  await addTargets(targets, await detectGlobalConfig(p.join(root.path, '.claude.json'), root, context, state));
}

function candidatePriority(entry) {
  const lower = entry.name.toLowerCase();
  if (DESKTOP_DIRECTORY_NAMES.has(lower) || lower === '.claude') return 0;
  if (lower === 'users' || lower === 'appdata' || lower === 'library' || lower === 'application support') return 1;
  if (lower.includes('anthropic')) return 2;
  return 3;
}

async function scanAppDataTree(root, context, state, targets) {
  const p = context.pathApi;
  const queue = [{ path: root.path, depth: 0 }];
  while (queue.length > 0 && checkBudget(state)) {
    const current = queue.shift();
    if (isWorkspacePath(current.path, context)) continue;
    let entries;
    try {
      entries = await fs.readdir(current.path, { withFileTypes: true });
    } catch {
      state.unreadableDirectories += 1;
      continue;
    }
    entries.sort((left, right) => candidatePriority(left) - candidatePriority(right) || left.name.localeCompare(right.name));

    for (const entry of entries) {
      if (!checkBudget(state)) return;
      state.entriesVisited += 1;
      const child = p.join(current.path, entry.name);
      const childDepth = current.depth + 1;
      if (isWorkspacePath(child, context)) continue;
      if (entry.isSymbolicLink()) {
        state.linkedPathsSkipped += 1;
        continue;
      }
      if (!entry.isDirectory()) {
        if (state.globalSearch && entry.isFile() && entry.name.toLowerCase() === '.claude.json') {
          await addTargets(targets, await detectGlobalConfig(child, root, context, state));
        }
        continue;
      }
      if (childDepth > root.maxDepth) continue;
      if (rejectRootReason(child, context, state.options)) continue;

      const lower = entry.name.toLowerCase();
      if (DESKTOP_DIRECTORY_NAMES.has(lower)) {
        await addTargets(targets, await detectDesktopDirectory(child, root.scope, context, state));
        continue;
      }
      if (root.scope === 'all' && lower === '.claude' && (state.globalSearch || current.depth === 0)) {
        await addTargets(targets, await detectCodeDirectory(child, root, context, state));
        continue;
      }
      if (childDepth < root.maxDepth) queue.push({ path: child, depth: childDepth });
    }
  }
}

async function scanDiscoveryRoot(root, context, state) {
  const validation = await validateDiscoveryRoot(root, context, state.options);
  if (!validation.safe) return { targets: new Map(), skipped: { path: root.path, reason: validation.reason }, state };
  state.rootsScanned += 1;
  const targets = new Map();
  if (root.scope === 'home' || root.scope === 'all') {
    await scanHomeOrOverride(root, context, state, targets);
  }
  // An explicitly configured Claude directory may have an arbitrary name or
  // be outside the home directory. In that case it is itself a discovery root,
  // rather than a child that scanAppDataTree can encounter.
  if (checkBudget(state) && root.scope === 'all' && context.claudeConfigDir
      && samePath(root.path, context.claudeConfigDir, context)) {
    await addTargets(targets, await detectCodeDirectory(root.path, root, context, state));
  }
  if (checkBudget(state)) {
    if (root.scope === 'code-config') {
      await addTargets(targets, await detectCodeDirectory(root.path, root, context, state));
    } else if (root.scope === 'app-data' || root.scope === 'cache' || root.scope === 'all') {
      await scanAppDataTree(root, context, state, targets);
    }
  }
  return { targets, skipped: null, state };
}

function freshRootState(base, deadline) {
  return {
    ...base,
    deadline,
    entriesVisited: 0,
    linkedPathsSkipped: 0,
    unreadableDirectories: 0,
    rootsScanned: 0,
    partial: false,
    timedOut: false,
    maxEntriesReached: false,
  };
}

function mergeRootState(aggregate, rootState) {
  aggregate.entriesVisited += rootState.entriesVisited;
  aggregate.linkedPathsSkipped += rootState.linkedPathsSkipped;
  aggregate.unreadableDirectories += rootState.unreadableDirectories;
  aggregate.rootsScanned += rootState.rootsScanned;
  aggregate.partial ||= rootState.partial;
  aggregate.timedOut ||= rootState.timedOut;
  aggregate.maxEntriesReached ||= rootState.maxEntriesReached;
}

async function discoverClaudeData(rawContext = {}, options = {}) {
  const startedAt = Date.now();
  const context = normalizeContext(rawContext);
  const state = {
    signal: options.signal,
    deadline: startedAt + clampInteger(options.timeoutMs, DEFAULT_LIMITS.timeoutMs, 1, 60_000),
    maxEntries: clampInteger(options.maxEntries, DEFAULT_LIMITS.maxEntries, 1, 1_000_000),
    maxCandidateEntries: clampInteger(options.maxCandidateEntries, DEFAULT_LIMITS.maxCandidateEntries, 8, 4_096),
    entriesVisited: 0,
    linkedPathsSkipped: 0,
    unreadableDirectories: 0,
    rootsScanned: 0,
    partial: false,
    timedOut: false,
    maxEntriesReached: false,
    globalSearch: options.globalSearch === true,
    options,
  };
  if (state.signal?.aborted) throw abortError();

  const roots = resolveDiscoveryRoots(context, options);
  const skippedRoots = [];
  const targets = new Map();
  if (state.globalSearch) {
    const rootResults = await Promise.all(roots.map((root) => (
      scanDiscoveryRoot(root, context, freshRootState(state, state.deadline))
    )));
    for (const result of rootResults) {
      mergeRootState(state, result.state);
      if (result.skipped) skippedRoots.push(result.skipped);
      await addTargets(targets, result.targets.values());
    }
  } else {
    for (const root of roots) {
      if (!checkBudget(state)) break;
      const result = await scanDiscoveryRoot(root, context, state);
      if (result.skipped) skippedRoots.push(result.skipped);
      await addTargets(targets, result.targets.values());
    }
  }

  const sortedTargets = [...targets.values()].sort((left, right) => (
    left.group.localeCompare(right.group)
      || comparable(left.path, context).localeCompare(comparable(right.path, context))
      || left.strategy.localeCompare(right.strategy)
  ));
  return {
    targets: sortedTargets,
    meta: {
      rootsScanned: state.rootsScanned,
      skippedRoots,
      entriesVisited: state.entriesVisited,
      linkedPathsSkipped: state.linkedPathsSkipped,
      unreadableDirectories: state.unreadableDirectories,
      timedOut: state.timedOut,
      maxEntriesReached: state.maxEntriesReached,
      partial: state.partial,
      durationMs: Date.now() - startedAt,
    },
  };
}

async function discoverClaudeTargets(rawContext = {}, options = {}) {
  return (await discoverClaudeData(rawContext, options)).targets;
}

module.exports = {
  DEFAULT_LIMITS,
  discoverClaudeData,
  discoverClaudeTargets,
  enumerateGlobalDiscoveryRoots,
  isPathWithin,
  reconstructDiscoveredTarget,
  resolveDiscoveryRoots,
  stableDiscoveryId,
  validateDiscoveryRoot,
};
