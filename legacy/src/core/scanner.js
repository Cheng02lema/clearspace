const fs = require('node:fs/promises');
const { createContext, publicTarget } = require('./targets');
const { getEffectiveTargets } = require('./target-catalog');
const { inspectPathComponents } = require('./path-safety');

async function pathSize(targetPath, state = { nodes: 0, partial: false, maxNodes: 4_000, deadline: Date.now() + 900 }) {
  if (state.nodes >= state.maxNodes || Date.now() >= state.deadline) {
    state.partial = true;
    return { bytes: 0, partial: true };
  }
  const stat = await fs.lstat(targetPath);
  state.nodes += 1;

  if (state.nodes >= state.maxNodes || Date.now() >= state.deadline) {
    state.partial = true;
    return { bytes: 0, partial: true };
  }
  if (stat.isSymbolicLink()) return { bytes: stat.size, partial: state.partial };
  if (!stat.isDirectory()) return { bytes: stat.size, partial: state.partial };

  let bytes = 0;
  let entries;
  try {
    entries = await fs.readdir(targetPath, { withFileTypes: true });
  } catch {
    state.partial = true;
    return { bytes: 0, partial: true };
  }

  for (const entry of entries) {
    if (state.nodes >= state.maxNodes || Date.now() >= state.deadline) {
      state.partial = true;
      break;
    }
    try {
      const result = await pathSize(require('node:path').join(targetPath, entry.name), state);
      bytes += result.bytes;
    } catch {
      state.partial = true;
    }
  }
  return { bytes, partial: state.partial };
}

async function scanPathResource(resource, context, estimateSize = pathSize) {
  try {
    const safety = await inspectPathComponents(resource.path, context);
    if (!safety.safe) {
      let exists = false;
      try {
        await fs.lstat(resource.path);
        exists = true;
      } catch (error) {
        if (!error || error.code !== 'ENOENT') throw error;
      }
      return {
        type: 'path',
        label: resource.label,
        displayPath: resource.path,
        exists,
        bytes: 0,
        partialSize: true,
        kind: 'linked',
        unsafeLink: true,
        error: safety.reason,
      };
    }
    const stat = await fs.lstat(resource.path);
    const size = await estimateSize(resource.path);
    return {
      type: 'path',
      label: resource.label,
      displayPath: resource.path,
      exists: true,
      bytes: size.bytes,
      partialSize: size.partial,
      kind: stat.isSymbolicLink() ? 'link' : stat.isDirectory() ? 'directory' : 'file',
    };
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return {
        type: 'path',
        label: resource.label,
        displayPath: resource.path,
        exists: false,
        bytes: 0,
        partialSize: false,
        kind: 'missing',
      };
    }
    return {
      type: 'path',
      label: resource.label,
      displayPath: resource.path,
      exists: false,
      bytes: 0,
      partialSize: true,
      kind: 'unreadable',
      error: '没有权限读取该路径。',
    };
  }
}

async function scanTargets(rawContext = {}, options = {}) {
  const context = rawContext.pathApi ? rawContext : createContext(rawContext);
  const targets = Array.isArray(options.targets) ? options.targets : await getEffectiveTargets(context, options);

  return Promise.all(targets.map(async (target) => {
    if (target.blockedReason) {
      return {
        ...publicTarget(target),
        exists: false,
        bytes: 0,
        partialSize: true,
        resources: target.resources.map((resource) => ({
          type: 'path',
          label: resource.label,
          displayPath: resource.path,
          exists: false,
          bytes: 0,
          partialSize: true,
          kind: 'blocked',
          error: target.blockedReason,
        })),
      };
    }
    const resources = await Promise.all(target.resources.map((resource) => scanPathResource(resource, context, options.estimateSize)));
    const unsafeLink = resources.some((resource) => resource.unsafeLink);
    return {
      ...publicTarget(target),
      blockedReason: target.blockedReason || (unsafeLink ? '目标路径包含符号链接、Junction 或重解析点，安全策略已禁止自动清理。' : null),
      exists: resources.some((resource) => resource.exists),
      bytes: resources.reduce((sum, resource) => sum + resource.bytes, 0),
      partialSize: resources.some((resource) => resource.partialSize),
      resources,
    };
  }));
}

module.exports = {
  pathSize,
  scanTargets,
};
