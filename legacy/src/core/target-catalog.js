const { discoverClaudeData, reconstructDiscoveredTarget } = require('./discovery');
const { getBrowserCleanupTarget } = require('./privacy-actions');
const { createContext, getTargets } = require('./targets');

function resourceKey(candidate, context) {
  const normalized = context.pathApi.normalize(context.pathApi.resolve(candidate));
  return context.platform === 'win32' ? normalized.toLowerCase() : normalized;
}

function mergeTargets(fixedTargets, discoveredTargets, context) {
  const fixedPaths = new Set(fixedTargets.flatMap((target) => (
    target.resources
      .filter((resource) => resource.type === 'path')
      .map((resource) => resourceKey(resource.path, context))
  )));
  const additions = discoveredTargets.filter((target) => {
    const paths = target.resources
      .filter((resource) => resource.type === 'path')
      .map((resource) => resourceKey(resource.path, context));
    return paths.length > 0 && paths.some((candidate) => !fixedPaths.has(candidate));
  });
  const combined = [...fixedTargets, ...additions];
  const validIds = new Set(combined.map((target) => target.id));
  return combined.map((target) => ({
    ...target,
    exclusiveWith: (target.exclusiveWith || []).filter((id) => validIds.has(id)),
  }));
}

async function getEffectiveTargetCatalog(rawContext = {}, options = {}) {
  const context = rawContext.pathApi ? rawContext : createContext(rawContext);
  const fixedTargets = options.discovery?.globalSearch ? [] : getTargets(context);
  const discovery = await discoverClaudeData(context, options.discovery || {});
  const browserTarget = await getBrowserCleanupTarget(context);
  const defaultCodeDir = context.pathApi.join(context.homeDir, '.claude');
  const customCodeDir = resourceKey(context.claudeConfigDir, context) !== resourceKey(defaultCodeDir, context);
  const targets = mergeTargets(fixedTargets, discovery.targets, context).map((target) => {
    if (context.claudeConfigError && target.group === 'code') {
      return { ...target, blockedReason: context.claudeConfigError, defaultSelected: false };
    }
    // A custom configuration directory could contain unrelated data. Its
    // recognized individual files may be offered, but never the entire root.
    if (customCodeDir && target.category === 'claude-code' && target.resources.some((resource) => (
      resource.type === 'path' && resourceKey(resource.path, context) === resourceKey(context.claudeConfigDir, context)
    ))) {
      return { ...target, blockedReason: '自定义 Claude 配置目录可能包含其他数据，禁止完整清理该目录。', defaultSelected: false };
    }
    return target;
  });
  return {
    targets: [
      ...targets,
      ...(browserTarget ? [browserTarget] : []),
    ],
    discovery: discovery.meta,
  };
}

async function getEffectiveTargets(rawContext = {}, options = {}) {
  return (await getEffectiveTargetCatalog(rawContext, options)).targets;
}

function ensureManifestTarget(entry, targetMap, context, options = {}) {
  let target = targetMap.get(entry?.targetId);
  if (!target && typeof entry?.targetId === 'string' && entry.targetId.startsWith('discovered.')) {
    target = reconstructDiscoveredTarget(entry.targetId, entry.originalPath, context, options.discovery || {});
    if (target) targetMap.set(target.id, target);
  }
  return target || null;
}

module.exports = {
  ensureManifestTarget,
  getEffectiveTargetCatalog,
  getEffectiveTargets,
  mergeTargets,
  resourceKey,
};
