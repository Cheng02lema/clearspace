const os = require('node:os');
const path = require('node:path');

function createContext(overrides = {}) {
  const platform = overrides.platform || process.platform;
  const env = overrides.env || process.env;
  const pathApi = platform === 'win32' ? path.win32 : path.posix;
  const homeCandidate = overrides.homeDir || os.homedir();
  const homeDir = pathApi.isAbsolute(homeCandidate) ? pathApi.resolve(homeCandidate) : pathApi.resolve(os.homedir());

  const absoluteOrFallback = (candidate, fallback) => (
    typeof candidate === 'string' && candidate.length > 0 && pathApi.isAbsolute(candidate)
      ? pathApi.resolve(candidate)
      : pathApi.resolve(fallback)
  );

  const localAppData = platform === 'win32'
    ? absoluteOrFallback(env.LOCALAPPDATA, pathApi.join(homeDir, 'AppData', 'Local'))
    : pathApi.join(homeDir, 'Library', 'Application Support');
  const roamingAppData = platform === 'win32'
    ? absoluteOrFallback(env.APPDATA, pathApi.join(homeDir, 'AppData', 'Roaming'))
    : localAppData;

  const hasCustomClaudeDir = platform === 'win32' && typeof env.CLAUDE_CONFIG_DIR === 'string' && env.CLAUDE_CONFIG_DIR.length > 0;
  const invalidClaudeConfigDir = hasCustomClaudeDir && !pathApi.isAbsolute(env.CLAUDE_CONFIG_DIR);
  const configuredClaudeDir = hasCustomClaudeDir && !invalidClaudeConfigDir
    ? pathApi.resolve(env.CLAUDE_CONFIG_DIR)
    : pathApi.join(homeDir, '.claude');

  const documentsCandidate = overrides.documentsDir || pathApi.join(homeDir, 'Documents');
  const userDataCandidate = overrides.userDataDir || pathApi.join(localAppData, 'KelaudeStudioCleaner');

  return {
    platform,
    env,
    pathApi,
    homeDir,
    localAppData,
    roamingAppData,
    claudeConfigDir: configuredClaudeDir,
    claudeConfigError: invalidClaudeConfigDir
      ? 'CLAUDE_CONFIG_DIR 不是绝对路径，安全策略已禁止自动清理 Claude Code 数据。'
      : null,
    documentsDir: absoluteOrFallback(documentsCandidate, pathApi.join(homeDir, 'Documents')),
    userDataDir: absoluteOrFallback(userDataCandidate, pathApi.join(localAppData, 'KelaudeStudioCleaner')),
    appVersion: overrides.appVersion || '0.0.0-test',
  };
}

function pathResource(targetPath, label) {
  return { type: 'path', path: targetPath, label };
}

function getTargets(rawContext = {}) {
  const context = rawContext.pathApi ? rawContext : createContext(rawContext);
  const p = context.pathApi;
  const isWindows = context.platform === 'win32';
  const desktopRoot = isWindows
    ? p.join(context.localAppData, 'Claude-3p')
    : p.join(context.homeDir, 'Library', 'Application Support', 'Claude-3p');
  const legacyDesktopRoot = isWindows ? p.join(context.roamingAppData, 'Claude-3p') : null;
  const codeDir = context.claudeConfigDir;
  const defaultCodeDir = p.join(context.homeDir, '.claude');
  const customCodeDir = p.normalize(codeDir) !== p.normalize(defaultCodeDir);
  const globalConfig = p.join(context.homeDir, '.claude.json');
  const isUnc = (candidate) => isWindows && /^\\\\/.test(candidate);
  const sameWindowsVolume = (candidate) => !isWindows
    || p.parse(candidate).root.toLowerCase() === p.parse(context.homeDir).root.toLowerCase();

  const targets = [
    {
      id: 'desktop.device-id',
      group: 'desktop',
      title: 'Claude 桌面端设备标识',
      description: '删除 Claude-3p 中的 ant-did。本地应用下次启动时可能重新生成。',
      risk: 'low',
      defaultSelected: true,
      backup: true,
      resources: [pathResource(p.join(desktopRoot, 'ant-did'), 'ant-did')],
      exclusiveWith: ['desktop.full-reset'],
      source: 'Claude 桌面端教程',
    },
    {
      id: 'desktop.full-reset',
      group: 'desktop',
      title: isWindows ? 'Claude 桌面端完整重置（Local）' : 'Claude 桌面端完整重置',
      description: '删除整个 Claude-3p 应用数据目录，包含会话、记忆、配置、插件、缓存与本地凭据数据。不会删除用户产出目录。',
      risk: 'high',
      defaultSelected: false,
      backup: false,
      resources: [pathResource(desktopRoot, 'Claude-3p 数据目录')],
      exclusiveWith: ['desktop.device-id'],
      source: 'Claude 桌面端教程',
    },
    {
      id: 'code.credentials-file',
      group: 'code',
      title: 'Claude Code 登录凭据文件',
      description: isWindows
        ? '删除 .credentials.json，之后使用 Claude Code 时需要重新登录。'
        : '清理可能存在的兼容凭据文件；macOS 通常将凭据保存在钥匙串。',
      risk: 'medium',
      defaultSelected: true,
      backup: false,
      resources: [pathResource(p.join(codeDir, '.credentials.json'), '.credentials.json')],
      exclusiveWith: ['code.full-reset'],
      source: 'Claude Code 教程',
    },
    {
      id: 'code.settings',
      group: 'code',
      title: 'Claude Code 用户设置',
      description: '删除用户级 settings.json；MCP、权限与界面偏好可能需要重新配置。',
      risk: 'high',
      defaultSelected: false,
      backup: true,
      resources: [pathResource(p.join(codeDir, 'settings.json'), 'settings.json')],
      exclusiveWith: ['code.full-reset'],
      source: 'Claude Code 教程',
    },
    {
      id: 'code.global-config',
      group: 'code',
      title: 'Claude Code 全局状态文件',
      description: '删除 ~/.claude.json，可能移除 OAuth 会话、MCP 配置、项目状态与缓存。',
      risk: 'high',
      defaultSelected: false,
      backup: false,
      resources: [pathResource(globalConfig, '.claude.json')],
      exclusiveWith: ['code.full-reset'],
      source: 'Claude Code 教程',
    },
  ];

  if (isWindows && p.normalize(legacyDesktopRoot) !== p.normalize(desktopRoot)) {
    targets.splice(1, 0, {
      id: 'desktop.device-id-legacy',
      group: 'desktop',
      title: 'Claude 桌面端设备标识（旧 Roaming 路径）',
      description: '早期版本可能保留在 %APPDATA%。此项单独显示且默认不选。',
      risk: isUnc(legacyDesktopRoot) ? 'high' : 'low',
      defaultSelected: false,
      backup: true,
      blockedReason: isUnc(legacyDesktopRoot) ? '旧 Roaming 路径位于网络共享，安全策略已禁止自动清理。' : null,
      resources: [pathResource(p.join(legacyDesktopRoot, 'ant-did'), '旧路径 ant-did')],
      exclusiveWith: ['desktop.full-reset-legacy'],
      source: 'Claude 桌面端教程',
    });
    targets.splice(3, 0, {
      id: 'desktop.full-reset-legacy',
      group: 'desktop',
      title: 'Claude 桌面端完整重置（旧 Roaming）',
      description: '删除旧 %APPDATA% 下整个 Claude-3p。若路径已重定向到网络共享则禁止执行。',
      risk: 'high',
      defaultSelected: false,
      backup: false,
      blockedReason: isUnc(legacyDesktopRoot) ? '旧 Roaming 路径位于网络共享，安全策略已禁止自动清理。' : null,
      resources: [pathResource(legacyDesktopRoot, '旧 Claude-3p 数据目录')],
      exclusiveWith: ['desktop.device-id-legacy'],
      source: 'Claude 桌面端教程',
    });
  }

  if (!customCodeDir) {
    targets.push({
      id: 'code.full-reset',
      group: 'code',
      title: 'Claude Code 完整本地重置',
      description: '删除 ~/.claude 和 ~/.claude.json；项目目录内的 .claude 设置不会被删除。',
      risk: 'high',
      defaultSelected: false,
      backup: false,
      resources: [
        pathResource(codeDir, 'Claude Code 配置目录'),
        pathResource(globalConfig, '.claude.json'),
      ],
      exclusiveWith: ['code.credentials-file', 'code.settings', 'code.global-config'],
      source: 'Claude Code 教程',
    });
  }

  for (const target of targets) {
    if (target.group === 'code' && context.claudeConfigError) {
      target.blockedReason = context.claudeConfigError;
    }
    if (target.resources.some((resource) => resource.type === 'path' && isUnc(resource.path))) {
      target.blockedReason = target.blockedReason || '目标位于 UNC 网络共享，安全策略已禁止自动清理。';
      target.defaultSelected = false;
      target.risk = 'high';
    }
    if (target.resources.some((resource) => resource.type === 'path' && !sameWindowsVolume(resource.path))) {
      target.blockedReason = target.blockedReason || '目标与用户主目录不在同一卷，安全策略已禁止自动清理。';
      target.defaultSelected = false;
      target.risk = 'high';
    }
  }

  return targets;
}

function publicTarget(target) {
  return {
    id: target.id,
    group: target.group,
    title: target.title,
    description: target.description,
    risk: target.risk,
    defaultSelected: target.defaultSelected,
    backup: target.backup,
    exclusiveWith: target.exclusiveWith,
    source: target.source,
    requiresBrowserClosed: Boolean(target.requiresBrowserClosed),
    blockedReason: target.blockedReason || null,
    discovered: Boolean(target.discovered),
    category: target.category || null,
  };
}

module.exports = {
  createContext,
  getTargets,
  publicTarget,
};
