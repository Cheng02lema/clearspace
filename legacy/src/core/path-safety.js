const fs = require('node:fs/promises');

function comparable(candidate, context) {
  const normalized = context.pathApi.normalize(context.pathApi.resolve(candidate));
  return context.platform === 'win32' ? normalized.toLowerCase() : normalized;
}

async function inspectPathComponents(candidate, context) {
  const p = context.pathApi;
  const resolved = p.resolve(candidate);
  const root = p.parse(resolved).root;
  let current = resolved;
  let nearestExisting = null;

  while (true) {
    try {
      const stat = await fs.lstat(current);
      if (!nearestExisting) nearestExisting = current;
      if (stat.isSymbolicLink()) {
        return { safe: false, linkedPath: current, reason: '目标路径包含符号链接或 Junction。' };
      }
    } catch (error) {
      if (!error || error.code !== 'ENOENT') throw error;
    }

    if (comparable(current, context) === comparable(root, context)) break;
    const parent = p.dirname(current);
    if (parent === current) break;
    current = parent;
  }

  if (nearestExisting) {
    const real = await fs.realpath(nearestExisting);
    if (comparable(real, context) !== comparable(nearestExisting, context)) {
      return { safe: false, linkedPath: nearestExisting, reason: '目标路径经重解析点指向了其他位置。' };
    }
  }

  return { safe: true, linkedPath: null, reason: null };
}

async function assertSafePathComponents(candidate, context) {
  const result = await inspectPathComponents(candidate, context);
  if (!result.safe) throw new Error(`安全保护已阻止操作：${result.reason}`);
  return true;
}

module.exports = {
  assertSafePathComponents,
  inspectPathComponents,
};
