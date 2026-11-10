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
  return {
    targets: [
      ...mergeTargets(fixedTargets, discovery.targets, context),
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
