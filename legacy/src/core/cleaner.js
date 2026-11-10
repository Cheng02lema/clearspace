const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const { createContext, getTargets } = require('./targets');
const { assertSafePathComponents } = require('./path-safety');
const { ensureManifestTarget, getEffectiveTargets } = require('./target-catalog');

const OPERATION_ID = /^\d{8}T\d{6}Z-[0-9a-f]{8}$/;
const HASH = /^[0-9a-f]{64}$/;
const MAX_MANIFEST_BYTES = 1024 * 1024;

function operationName(now = new Date()) {
  const stamp = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
  return `${stamp}-${crypto.randomUUID().slice(0, 8)}`;
}

function safeLeaf(value) {
  return String(value).replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 80) || 'item';
}

function cleanError(error) {
  const code = error && error.code ? ` (${error.code})` : '';
  if (error && error.code === 'EBUSY') return `文件正被占用，请完全退出相关应用后重试${code}`;
  if (error && (error.code === 'EACCES' || error.code === 'EPERM')) return `没有权限执行该操作${code}`;
  if (error && error.code === 'ENOSPC') return `备份磁盘空间不足${code}`;
  if (error && error.code === 'EXDEV') return `目标与私有备份目录不在同一磁盘；为避免非原子删除，已跳过${code}`;
  return `${error && error.message ? error.message : '未知错误'}${code}`;
}

function validateSelection(ids, targets) {
  if (!Array.isArray(ids) || ids.length === 0) throw new Error('没有选择任何清理项。');
  if (ids.length > 500 || ids.some((id) => typeof id !== 'string' || id.length === 0 || id.length > 80)) {
    throw new Error('清理项格式或数量异常。');
  }

  const unique = [...new Set(ids)];
  const selected = unique.map((id) => {
    if (!targets.has(id)) throw new Error('包含未知清理项。');
    return targets.get(id);
  });
  const selectedIds = new Set(unique);

  for (const target of selected) {
    if (target.blockedReason) throw new Error(target.blockedReason);
    for (const conflict of target.exclusiveWith || []) {
      if (selectedIds.has(conflict)) throw new Error(`“${target.title}”与另一清理项重复，请只选择其一。`);
    }
  }
  return selected;
}

function assertSafeRemovalPath(candidate, context, target) {
  const p = context.pathApi;
  if (typeof candidate !== 'string' || !p.isAbsolute(candidate)) throw new Error('安全保护已阻止非绝对路径。');
  const resolved = p.resolve(candidate);
  const root = p.parse(resolved).root;
  if (context.platform === 'win32' && /^\\\\/.test(resolved)) {
    throw new Error('安全保护已阻止对 UNC 网络共享执行清理。');
  }
  const forbidden = new Set([
    p.normalize(root),
    p.normalize(context.homeDir),
    p.normalize(context.localAppData),
    p.normalize(context.roamingAppData),
    p.normalize(context.documentsDir),
  ].map((value) => context.platform === 'win32' ? value.toLowerCase() : value));
  const comparable = context.platform === 'win32' ? p.normalize(resolved).toLowerCase() : p.normalize(resolved);

  if (forbidden.has(comparable)) throw new Error('安全保护已阻止对系统根目录或用户主目录的删除。');

  const allowed = target.resources
    .filter((resource) => resource.type === 'path')
    .map((resource) => {
      const normalized = p.normalize(p.resolve(resource.path));
      return context.platform === 'win32' ? normalized.toLowerCase() : normalized;
    });
  if (!allowed.includes(comparable)) throw new Error('安全保护已阻止未在规则中的路径。');

  const depth = p.relative(root, resolved).split(/[\\/]+/).filter(Boolean).length;
  if (depth < 2) throw new Error('安全保护已阻止过于宽泛的路径。');
  return resolved;
}

function fileKind(stat) {
  if (stat.isDirectory()) return 'directory';
  if (stat.isFile()) return 'file';
  return 'other';
}

function sameObjectIdentity(first, second) {
  return Number(first.dev) === Number(second.dev)
    && Number(first.ino) === Number(second.ino)
    && fileKind(first) === fileKind(second);
}

function sameStableIdentity(first, second) {
  return sameObjectIdentity(first, second)
    && Number(first.size) === Number(second.size)
    && Number(first.birthtimeMs) === Number(second.birthtimeMs)
    && Number(first.mtimeMs) === Number(second.mtimeMs);
}

function serializeIdentity(stat) {
  return {
    dev: String(stat.dev),
    ino: String(stat.ino),
    kind: fileKind(stat),
    size: Number(stat.size),
    birthtimeMs: Number(stat.birthtimeMs),
    mtimeMs: Number(stat.mtimeMs),
    mode: Number(stat.mode),
  };
}

function validStoredIdentity(identity) {
  return identity && typeof identity === 'object'
    && /^\d+$/.test(identity.dev)
    && /^\d+$/.test(identity.ino)
    && (identity.kind === 'file' || identity.kind === 'directory')
    && Number.isFinite(identity.size)
    && Number.isFinite(identity.birthtimeMs)
    && Number.isFinite(identity.mtimeMs)
    && Number.isInteger(identity.mode);
}

function sameStoredObject(identity, stat) {
  return validStoredIdentity(identity)
    && identity.dev === String(stat.dev)
    && identity.ino === String(stat.ino)
    && identity.kind === fileKind(stat);
}

function sameStoredStable(identity, stat) {
  return sameStoredObject(identity, stat)
    && identity.size === Number(stat.size)
    && identity.birthtimeMs === Number(stat.birthtimeMs)
    && identity.mtimeMs === Number(stat.mtimeMs);
}

async function resourceExists(resourcePath) {
  try {
    await fs.lstat(resourcePath);
    return true;
  } catch (error) {
    if (error && error.code === 'ENOENT') return false;
    throw error;
  }
}

async function assertContainerUnchanged(containerPath, expectedStat, context) {
  await assertSafePathComponents(containerPath, context);
  const currentStat = await fs.lstat(containerPath);
  if (!sameObjectIdentity(expectedStat, currentStat)) {
    throw new Error('受保护目录在操作期间发生变化，已取消操作。');
  }
}

async function atomicWriteJson(filePath, value) {
  const temporary = `${filePath}.${crypto.randomUUID()}.tmp`;
  let handle;
  try {
    handle = await fs.open(temporary, 'wx', 0o600);
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporary, filePath);
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await fs.unlink(temporary).catch(() => {});
    throw error;
  }
}

function validateOperationId(operationId) {
  if (typeof operationId !== 'string' || !OPERATION_ID.test(operationId)) throw new Error('备份编号无效。');
}

function operationDirectory(operationId, context, backupRoot) {
  validateOperationId(operationId);
  const p = context.pathApi;
  const resolvedRoot = p.resolve(backupRoot);
  const resolvedOperation = p.resolve(resolvedRoot, operationId);
  const relative = p.relative(resolvedRoot, resolvedOperation);
  if (!relative || relative.startsWith('..') || p.isAbsolute(relative)) throw new Error('备份路径越界。');
  return resolvedOperation;
}

function resolveOperationRelative(operationDir, relativePath, context) {
  const p = context.pathApi;
  if (typeof relativePath !== 'string' || !relativePath || relativePath.length > 4096 || p.isAbsolute(relativePath)) {
    throw new Error('备份条目路径无效。');
  }
  const resolvedOperation = p.resolve(operationDir);
  const resolved = p.resolve(resolvedOperation, relativePath);
  const relative = p.relative(resolvedOperation, resolved);
  if (!relative || relative.startsWith('..') || p.isAbsolute(relative)) throw new Error('备份条目路径越界。');
  return resolved;
}

async function createOperationGuards(operationDir, backupRoot, context) {
  const resolvedRoot = context.pathApi.resolve(backupRoot);
  await assertSafePathComponents(resolvedRoot, context);
  await assertSafePathComponents(operationDir, context);
  return {
    backupRoot: resolvedRoot,
    backupRootStat: await fs.lstat(resolvedRoot),
    operationDir,
    operationDirStat: await fs.lstat(operationDir),
  };
}

async function assertOperationGuards(guards, context) {
  await assertContainerUnchanged(guards.backupRoot, guards.backupRootStat, context);
  await assertContainerUnchanged(guards.operationDir, guards.operationDirStat, context);
}

async function writeManifest(manifestPath, manifest, guards, context) {
  await assertOperationGuards(guards, context);
  await atomicWriteJson(manifestPath, manifest);
  await assertOperationGuards(guards, context);
}

async function hashHandle(handle) {
  const hash = crypto.createHash('sha256');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  let position = 0;
  while (true) {
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
    if (!bytesRead) break;
    hash.update(buffer.subarray(0, bytesRead));
    position += bytesRead;
  }
  return { sha256: hash.digest('hex'), bytes: position };
}

async function fingerprintBackupFile(filePath, storedIdentity, parentPath, parentStat, guards, context) {
  await assertOperationGuards(guards, context);
  await assertContainerUnchanged(parentPath, parentStat, context);
  await assertSafePathComponents(filePath, context);
  const pathStat = await fs.lstat(filePath);
  if (!pathStat.isFile() || pathStat.isSymbolicLink() || !sameStoredStable(storedIdentity, pathStat)) {
    throw new Error('私有备份文件身份校验失败。');
  }

  const handle = await fs.open(filePath, 'r');
  try {
    const before = await handle.stat();
    if (!sameStoredStable(storedIdentity, before)) throw new Error('私有备份文件身份校验失败。');
    const digest = await hashHandle(handle);
    const after = await handle.stat();
    if (!sameStableIdentity(before, after) || digest.bytes !== Number(after.size)) {
      throw new Error('私有备份文件在校验期间发生变化。');
    }
    await assertContainerUnchanged(parentPath, parentStat, context);
    await assertOperationGuards(guards, context);
    const finalPathStat = await fs.lstat(filePath);
    if (!sameStableIdentity(after, finalPathStat)) throw new Error('私有备份路径在校验期间发生变化。');
    return digest;
  } finally {
    await handle.close();
  }
}

async function removeTreeNoFollow(targetPath, storedRootIdentity, context, isRoot = true) {
  await assertSafePathComponents(targetPath, context);
  const stat = await fs.lstat(targetPath);
  if (isRoot && !sameStoredObject(storedRootIdentity, stat)) throw new Error('隔离目标身份发生变化，拒绝删除。');
  if (stat.isSymbolicLink()) {
    await fs.unlink(targetPath);
    return;
  }
  if (stat.isFile()) {
    await fs.unlink(targetPath);
    return;
  }
  if (!stat.isDirectory()) throw new Error('隔离目标包含不支持的文件类型，拒绝删除。');
  const finalStat = await fs.lstat(targetPath);
  if (!sameObjectIdentity(stat, finalStat)) throw new Error('隔离目录在删除前发生变化。');
  // Node's platform implementation removes directory links as links rather than
  // recursively traversing their targets. The root was first atomically moved
  // into CleanTrace's private operation directory and its identity was fixed.
  await fs.rm(targetPath, { recursive: true, force: false, maxRetries: 3, retryDelay: 250 });
  if (await resourceExists(targetPath)) throw new Error('隔离目录未能完整移除。');
}

function relativePathFor(target, resource, resourceIndex, context, persistentBackup = target.backup) {
  const bucket = persistentBackup ? 'items' : 'transient';
  return context.pathApi.join(bucket, safeLeaf(target.id), `${resourceIndex}-${safeLeaf(context.pathApi.basename(resource.path))}`);
}

function sameConfiguredPath(first, second, context) {
  const p = context.pathApi;
  const a = p.normalize(p.resolve(first));
  const b = p.normalize(p.resolve(second));
  return context.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function validateManifestEntry(entry, targetMap, context) {
  if (!entry || typeof entry !== 'object' || entry.resourceType !== 'path') throw new Error('备份条目格式无效。');
  const target = ensureManifestTarget(entry, targetMap, context);
  if (!target || !Number.isInteger(entry.resourceIndex) || entry.resourceIndex < 0 || entry.resourceIndex >= target.resources.length) {
    throw new Error('备份条目指向未知清理项。');
  }
  const resource = target.resources[entry.resourceIndex];
  if (typeof entry.originalPath !== 'string' || !sameConfiguredPath(entry.originalPath, resource.path, context)) {
    throw new Error('备份条目的原始路径与当前规则不一致。');
  }
  if (!validStoredIdentity(entry.sourceIdentity) || entry.kind !== entry.sourceIdentity.kind) {
    throw new Error('备份条目缺少有效的文件身份。');
  }
  const persistentBackup = entry.backupRelativePath !== null;
  const expectedRelative = relativePathFor(target, resource, entry.resourceIndex, context, persistentBackup);
  if (persistentBackup) {
    if (!target.backup || entry.backupRelativePath !== expectedRelative || entry.quarantineRelativePath !== null) {
      throw new Error('可恢复备份路径与当前规则不一致。');
    }
  } else if (entry.quarantineRelativePath !== null && entry.quarantineRelativePath !== expectedRelative) {
    throw new Error('隔离路径与当前规则不一致。');
  }
  if (entry.restorable && (!persistentBackup || !target.backup || entry.kind !== 'file' || !HASH.test(entry.backupSha256 || '')
    || !Number.isInteger(entry.backupSize) || entry.backupSize < 0)) {
    throw new Error('可恢复备份缺少完整性校验信息。');
  }
  return { target, resource };
}

function validateManifestShape(manifest) {
  const states = new Set(['prepared', 'isolated', 'deleting', 'completed', 'deletion-error', 'rolled-back', 'conflict', 'missing', 'reconcile-error', 'restore-conflict']);
  if (!manifest || manifest.schemaVersion !== 2 || !OPERATION_ID.test(manifest.operationId || '')
    || !Array.isArray(manifest.entries) || manifest.entries.length > 2_000
    || typeof manifest.platform !== 'string' || typeof manifest.createdAt !== 'string') {
    throw new Error('备份清单格式无效。');
  }
  for (const entry of manifest.entries) {
    if (!entry || typeof entry !== 'object'
      || typeof entry.targetId !== 'string' || entry.targetId.length > 80
      || typeof entry.targetTitle !== 'string' || entry.targetTitle.length > 200
      || typeof entry.originalPath !== 'string' || entry.originalPath.length > 32768
      || !states.has(entry.state)
      || (entry.kind !== 'file' && entry.kind !== 'directory')
      || (entry.backupRelativePath !== null && (typeof entry.backupRelativePath !== 'string' || entry.backupRelativePath.length > 4096))
      || (entry.quarantineRelativePath !== null && (typeof entry.quarantineRelativePath !== 'string' || entry.quarantineRelativePath.length > 4096))
      || (entry.error !== null && (typeof entry.error !== 'string' || entry.error.length > 2000))
      || typeof entry.removed !== 'boolean' || typeof entry.restorable !== 'boolean' || typeof entry.restored !== 'boolean'
      || (entry.backupRelativePath && entry.quarantineRelativePath)
      || (entry.restorable && (!entry.removed || !entry.backupRelativePath))
      || (entry.restored && (!entry.removed || !entry.restorable))) {
      throw new Error('备份条目格式无效。');
    }
  }
}

async function readManifest(manifestPath, context) {
  await assertSafePathComponents(manifestPath, context);
  const handle = await fs.open(manifestPath, 'r');
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size > MAX_MANIFEST_BYTES) throw new Error('备份清单不是有效的普通文件。');
    const raw = await handle.readFile('utf8');
    const after = await handle.stat();
    if (!sameStableIdentity(before, after)) throw new Error('备份清单在读取期间发生变化。');
    const manifest = JSON.parse(raw);
    validateManifestShape(manifest);
    return manifest;
  } finally {
    await handle.close();
  }
}

async function cleanTargets(ids, rawContext = {}, options = {}) {
  const context = rawContext.pathApi ? rawContext : createContext(rawContext);
  const targets = Array.isArray(options.targets) ? options.targets : await getEffectiveTargets(context, options);
  const targetMap = new Map(targets.map((target) => [target.id, target]));
  const selected = validateSelection(ids, targetMap);
  const createBackups = options.createBackups !== false;
  const backupRoot = options.backupRoot || context.pathApi.join(context.documentsDir, 'CleanTrace Backups');
  const operationId = operationName(options.now);
  const operationDir = operationDirectory(operationId, context, backupRoot);
  const manifestPath = context.pathApi.join(operationDir, 'manifest.json');
  const manifest = {
    schemaVersion: 2,
    operationId,
    appVersion: context.appVersion,
    platform: context.platform,
    createdAt: (options.now || new Date()).toISOString(),
    createBackups,
    completedAt: null,
    status: 'running',
    entries: [],
  };

  await assertSafePathComponents(backupRoot, context);
  await fs.mkdir(operationDir, { recursive: true, mode: 0o700 });
  await assertSafePathComponents(operationDir, context);
  if (context.platform !== 'win32') await fs.chmod(operationDir, 0o700);
  const guards = await createOperationGuards(operationDir, backupRoot, context);
  await writeManifest(manifestPath, manifest, guards, context);

  const results = [];
  for (const target of selected) {
    const targetResult = { id: target.id, title: target.title, status: 'skipped', resources: [] };
    let succeeded = 0;
    let failed = 0;

    for (let resourceIndex = 0; resourceIndex < target.resources.length; resourceIndex += 1) {
      const resource = target.resources[resourceIndex];
      const persistentBackup = target.backup && createBackups;
      let entry = null;
      let isolatedPath = null;
      let isolatedParent = null;
      let isolatedParentStat = null;
      try {
        const source = assertSafeRemovalPath(resource.path, context, target);
        if (!await resourceExists(source)) {
          targetResult.resources.push({ label: resource.label, status: 'missing' });
          continue;
        }
        await assertSafePathComponents(source, context);
        const sourceStat = await fs.lstat(source);
        if (sourceStat.isSymbolicLink()) throw new Error('检测到符号链接；为避免跨目录操作，已跳过该项。');
        const kind = fileKind(sourceStat);
        if (kind === 'other' || (persistentBackup && kind !== 'file')) throw new Error('目标不是支持的普通文件或目录，已跳过。');

        const sourceParent = context.pathApi.dirname(source);
        await assertSafePathComponents(sourceParent, context);
        const sourceParentStat = await fs.lstat(sourceParent);
        const relativePath = relativePathFor(target, resource, resourceIndex, context, persistentBackup);
        isolatedPath = resolveOperationRelative(operationDir, relativePath, context);
        isolatedParent = context.pathApi.dirname(isolatedPath);
        entry = {
          targetId: target.id,
          targetTitle: target.title,
          resourceIndex,
          resourceType: 'path',
          originalPath: source,
          backupRelativePath: persistentBackup ? relativePath : null,
          quarantineRelativePath: persistentBackup ? null : relativePath,
          kind,
          sourceIdentity: serializeIdentity(sourceStat),
          backupSha256: null,
          backupSize: null,
          state: 'prepared',
          removed: false,
          restorable: false,
          restored: false,
          error: null,
        };
        manifest.entries.push(entry);
        await writeManifest(manifestPath, manifest, guards, context);

        await assertOperationGuards(guards, context);
        await assertSafePathComponents(isolatedParent, context);
        await fs.mkdir(isolatedParent, { recursive: true, mode: 0o700 });
        await assertSafePathComponents(isolatedParent, context);
        isolatedParentStat = await fs.lstat(isolatedParent);
        if (await resourceExists(isolatedPath)) throw new Error('私有隔离路径已存在，已取消清理。');
        await assertContainerUnchanged(sourceParent, sourceParentStat, context);
        await assertContainerUnchanged(isolatedParent, isolatedParentStat, context);
        await assertOperationGuards(guards, context);
        const finalSourceStat = await fs.lstat(source);
        if (!sameStableIdentity(sourceStat, finalSourceStat)) throw new Error('目标在确认后发生变化，已取消清理。');

        await fs.rename(source, isolatedPath);
        await assertContainerUnchanged(sourceParent, sourceParentStat, context);
        await assertContainerUnchanged(isolatedParent, isolatedParentStat, context);
        await assertOperationGuards(guards, context);
        await assertSafePathComponents(isolatedPath, context);
        const isolatedStat = await fs.lstat(isolatedPath);
        if (!sameStoredStable(entry.sourceIdentity, isolatedStat)) throw new Error('原子隔离后的目标身份不一致。');
        entry.state = persistentBackup ? 'isolated' : 'deleting';
        entry.removed = true;
        await writeManifest(manifestPath, manifest, guards, context);

        if (persistentBackup) {
          const digest = await fingerprintBackupFile(isolatedPath, entry.sourceIdentity, isolatedParent, isolatedParentStat, guards, context);
          entry.backupSha256 = digest.sha256;
          entry.backupSize = digest.bytes;
          entry.restorable = true;
        } else {
          await assertContainerUnchanged(isolatedParent, isolatedParentStat, context);
          await assertOperationGuards(guards, context);
          await removeTreeNoFollow(isolatedPath, entry.sourceIdentity, context);
          await assertContainerUnchanged(isolatedParent, isolatedParentStat, context);
          await assertOperationGuards(guards, context);
          entry.quarantineRelativePath = null;
        }

        entry.state = 'completed';
        entry.error = null;
        await writeManifest(manifestPath, manifest, guards, context);
        succeeded += 1;
        targetResult.resources.push({ label: resource.label, status: 'cleaned' });
      } catch (error) {
        if (entry) {
          const isolatedExists = isolatedPath ? await resourceExists(isolatedPath).catch(() => false) : false;
          const originalExists = await resourceExists(entry.originalPath).catch(() => false);
          if (isolatedExists && !originalExists) {
            entry.removed = true;
            entry.state = persistentBackup ? 'isolated' : 'deletion-error';
          } else if (!isolatedExists && !originalExists && !persistentBackup) {
            entry.removed = true;
            entry.quarantineRelativePath = null;
            entry.state = 'completed';
          } else if (!isolatedExists && originalExists) {
            entry.removed = false;
            entry.restorable = false;
            entry.state = 'rolled-back';
          } else {
            entry.state = 'conflict';
          }
          entry.error = cleanError(error);
          await writeManifest(manifestPath, manifest, guards, context);
        }
        failed += 1;
        targetResult.resources.push({ label: resource.label, status: 'failed', error: cleanError(error) });
      }
    }

    targetResult.status = failed > 0 ? (succeeded > 0 ? 'partial' : 'failed') : (succeeded > 0 ? 'cleaned' : 'skipped');
    results.push(targetResult);
  }

  manifest.completedAt = new Date().toISOString();
  manifest.status = results.some((result) => result.status === 'failed' || result.status === 'partial')
    ? 'completed-with-errors'
    : 'completed';
  await writeManifest(manifestPath, manifest, guards, context);

  const restorableCount = manifest.entries.filter((entry) => entry.removed && entry.restorable && !entry.restored).length;
  const irreversibleCount = manifest.entries.filter((entry) => entry.removed && !entry.restorable).length;
  let operationRecordRetained = true;
  if (options.retainOperationRecord === false && restorableCount === 0
    && manifest.entries.every((entry) => entry.backupRelativePath === null && entry.quarantineRelativePath === null)) {
    await assertOperationGuards(guards, context);
    await fs.rm(operationDir, { recursive: true, force: false });
    operationRecordRetained = false;
    await fs.rmdir(backupRoot).catch(() => {});
  }
  return {
    operationId: operationRecordRetained ? operationId : null,
    backupPath: operationRecordRetained ? operationDir : null,
    operationRecordRetained,
    status: manifest.status,
    restorableCount,
    irreversibleCount,
    results,
  };
}

async function reconcileManifest(operationDir, manifest, context, guards, targetMap) {
  if (manifest.platform !== context.platform) return false;
  let changed = false;
  for (const entry of manifest.entries) {
    if (entry.restored || entry.state === 'completed' || entry.state === 'rolled-back') continue;
    const { target } = validateManifestEntry(entry, targetMap, context);
    try {
      const original = assertSafeRemovalPath(entry.originalPath, context, target);
      await assertSafePathComponents(original, context);
      const originalExists = await resourceExists(original);
      const relativePath = entry.backupRelativePath || entry.quarantineRelativePath;
      if (!relativePath) {
        if (entry.removed && !entry.restorable) {
          entry.state = 'completed';
          changed = true;
        }
        continue;
      }
      const isolated = resolveOperationRelative(operationDir, relativePath, context);
      await assertSafePathComponents(isolated, context);
      const isolatedExists = await resourceExists(isolated);

      if (entry.backupRelativePath) {
        if (isolatedExists) {
          const isolatedParent = context.pathApi.dirname(isolated);
          await assertSafePathComponents(isolatedParent, context);
          const isolatedParentStat = await fs.lstat(isolatedParent);
          const digest = await fingerprintBackupFile(isolated, entry.sourceIdentity, isolatedParent, isolatedParentStat, guards, context);
          entry.backupSha256 = digest.sha256;
          entry.backupSize = digest.bytes;
          entry.removed = true;
          entry.restorable = true;
          entry.state = 'completed';
          entry.error = originalExists ? '原位置已有新数据；恢复时将保守跳过，不会覆盖。' : null;
        } else if (originalExists) {
          entry.removed = false;
          entry.restorable = false;
          entry.state = 'rolled-back';
        } else {
          entry.removed = false;
          entry.restorable = false;
          entry.state = 'missing';
          entry.error = '原位置和私有备份均不存在。';
        }
        changed = true;
        continue;
      }

      if (isolatedExists) {
        const isolatedStat = await fs.lstat(isolated);
        if (!sameStoredObject(entry.sourceIdentity, isolatedStat)) throw new Error('临时隔离目标身份发生变化。');
        const isolatedParent = context.pathApi.dirname(isolated);
        await assertSafePathComponents(isolatedParent, context);
        const isolatedParentStat = await fs.lstat(isolatedParent);
        await assertContainerUnchanged(isolatedParent, isolatedParentStat, context);
        await assertOperationGuards(guards, context);
        await removeTreeNoFollow(isolated, entry.sourceIdentity, context);
        await assertContainerUnchanged(isolatedParent, isolatedParentStat, context);
        entry.removed = true;
        entry.restorable = false;
        entry.quarantineRelativePath = null;
        entry.state = 'completed';
        entry.error = originalExists ? '清理中断后已移除私有隔离副本；原位置的新数据未改动。' : null;
      } else if (originalExists) {
        entry.removed = false;
        entry.restorable = false;
        entry.state = 'rolled-back';
      } else {
        entry.removed = true;
        entry.restorable = false;
        entry.quarantineRelativePath = null;
        entry.state = 'completed';
      }
      changed = true;
    } catch (error) {
      entry.state = 'reconcile-error';
      entry.error = cleanError(error);
      changed = true;
    }
  }

  if (changed) {
    manifest.status = manifest.entries.some((entry) => entry.state === 'reconcile-error' || entry.state === 'conflict' || entry.state === 'missing')
      ? 'completed-with-errors'
      : 'completed';
    await writeManifest(context.pathApi.join(operationDir, 'manifest.json'), manifest, guards, context);
  }
  return changed;
}

async function listBackups(rawContext = {}, options = {}) {
  const context = rawContext.pathApi ? rawContext : createContext(rawContext);
  const backupRoot = context.pathApi.resolve(options.backupRoot || context.pathApi.join(context.documentsDir, 'CleanTrace Backups'));
  try {
    await assertSafePathComponents(backupRoot, context);
    const rootStat = await fs.lstat(backupRoot);
    if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) return [];
  } catch (error) {
    if (error && error.code === 'ENOENT') return [];
    throw error;
  }

  const directories = await fs.readdir(backupRoot, { withFileTypes: true });
  const targetMap = new Map(getTargets(context).map((target) => [target.id, target]));
  const backups = [];
  for (const directory of directories) {
    if (!directory.isDirectory() || !OPERATION_ID.test(directory.name)) continue;
    try {
      const operationDir = operationDirectory(directory.name, context, backupRoot);
      await assertSafePathComponents(operationDir, context);
      const guards = await createOperationGuards(operationDir, backupRoot, context);
      const manifestPath = context.pathApi.join(operationDir, 'manifest.json');
      const manifest = await readManifest(manifestPath, context);
      if (manifest.operationId !== directory.name || manifest.platform !== context.platform) continue;
      for (const entry of manifest.entries) validateManifestEntry(entry, targetMap, context);
      await reconcileManifest(operationDir, manifest, context, guards, targetMap);
      const activeEntries = manifest.entries.filter((entry) => entry.removed);
      backups.push({
        operationId: manifest.operationId,
        platform: manifest.platform,
        createdAt: manifest.createdAt,
        status: manifest.status,
        itemCount: activeEntries.length,
        restorableCount: activeEntries.filter((entry) => entry.restorable && !entry.restored).length,
        restoredCount: manifest.entries.filter((entry) => entry.restored).length,
        titles: [...new Set(activeEntries.map((entry) => targetMap.get(entry.targetId)?.title || entry.targetTitle))],
      });
    } catch {
      // Ignore malformed, tampered, unrelated, or incomplete directories.
    }
  }
  return backups.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
}

async function writeAll(handle, buffer, position) {
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesWritten } = await handle.write(buffer, offset, buffer.length - offset, position + offset);
    if (!bytesWritten) throw new Error('恢复暂存文件写入失败。');
    offset += bytesWritten;
  }
}

async function copyAndHash(sourceHandle, destinationHandle) {
  const hash = crypto.createHash('sha256');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  let position = 0;
  while (true) {
    const { bytesRead } = await sourceHandle.read(buffer, 0, buffer.length, position);
    if (!bytesRead) break;
    const chunk = buffer.subarray(0, bytesRead);
    hash.update(chunk);
    await writeAll(destinationHandle, chunk, position);
    position += bytesRead;
  }
  await destinationHandle.sync();
  return { sha256: hash.digest('hex'), bytes: position };
}

async function safeUnlinkExact(filePath, expectedStat, parentPath, parentStat, context) {
  try {
    await assertContainerUnchanged(parentPath, parentStat, context);
    await assertSafePathComponents(filePath, context);
    const current = await fs.lstat(filePath);
    if (!current.isFile() || current.isSymbolicLink() || !sameObjectIdentity(expectedStat, current)) return false;
    await fs.unlink(filePath);
    await assertContainerUnchanged(parentPath, parentStat, context);
    return true;
  } catch (error) {
    if (error && error.code === 'ENOENT') return true;
    return false;
  }
}

async function restoreBackup(operationId, rawContext = {}, options = {}) {
  const context = rawContext.pathApi ? rawContext : createContext(rawContext);
  const backupRoot = context.pathApi.resolve(options.backupRoot || context.pathApi.join(context.documentsDir, 'CleanTrace Backups'));
  const operationDir = operationDirectory(operationId, context, backupRoot);
  await assertSafePathComponents(backupRoot, context);
  await assertSafePathComponents(operationDir, context);
  const guards = await createOperationGuards(operationDir, backupRoot, context);
  const manifestPath = context.pathApi.join(operationDir, 'manifest.json');
  const manifest = await readManifest(manifestPath, context);
  if (manifest.platform !== context.platform) throw new Error('此备份来自另一操作系统，不能在当前系统恢复。');
  if (manifest.operationId !== operationId) throw new Error('备份编号与清单不一致。');

  const targetMap = new Map(getTargets(context).map((target) => [target.id, target]));
  for (const entry of manifest.entries) validateManifestEntry(entry, targetMap, context);
  await reconcileManifest(operationDir, manifest, context, guards, targetMap);

  const results = [];
  for (const entry of manifest.entries) {
    if (!entry.removed || !entry.restorable || entry.restored || entry.resourceType !== 'path') continue;
    const { target } = validateManifestEntry(entry, targetMap, context);
    let destination = null;
    let destinationParent = null;
    let destinationParentStat = null;
    let destinationCreatedStat = null;
    let stagingPath = null;
    let stagingStat = null;
    let sourceHandle = null;
    let stagingHandle = null;
    try {
      destination = assertSafeRemovalPath(entry.originalPath, context, target);
      await assertSafePathComponents(destination, context);
      if (await resourceExists(destination)) {
        results.push({ title: target.title, status: 'conflict', error: '原位置已有新数据，未覆盖。' });
        continue;
      }

      const source = resolveOperationRelative(operationDir, entry.backupRelativePath, context);
      const sourceParent = context.pathApi.dirname(source);
      await assertSafePathComponents(sourceParent, context);
      const sourceParentStat = await fs.lstat(sourceParent);
      await assertSafePathComponents(source, context);
      const sourcePathStat = await fs.lstat(source);
      if (!sourcePathStat.isFile() || sourcePathStat.isSymbolicLink() || !sameStoredStable(entry.sourceIdentity, sourcePathStat)) {
        throw new Error('私有备份文件身份校验失败。');
      }
      sourceHandle = await fs.open(source, 'r');
      const sourceHandleStat = await sourceHandle.stat();
      if (!sameStoredStable(entry.sourceIdentity, sourceHandleStat)) throw new Error('私有备份文件身份校验失败。');
      await assertContainerUnchanged(sourceParent, sourceParentStat, context);
      await assertOperationGuards(guards, context);

      destinationParent = context.pathApi.dirname(destination);
      await assertSafePathComponents(destinationParent, context);
      await fs.mkdir(destinationParent, { recursive: true, mode: 0o700 });
      await assertSafePathComponents(destinationParent, context);
      destinationParentStat = await fs.lstat(destinationParent);
      if (await resourceExists(destination)) {
        await sourceHandle.close();
        sourceHandle = null;
        results.push({ title: target.title, status: 'conflict', error: '原位置已有新数据，未覆盖。' });
        continue;
      }

      stagingPath = context.pathApi.join(destinationParent, `.cleantrace-restore-${crypto.randomUUID()}`);
      await assertSafePathComponents(stagingPath, context);
      stagingHandle = await fs.open(stagingPath, 'wx', 0o600);
      stagingStat = await stagingHandle.stat();
      await assertContainerUnchanged(destinationParent, destinationParentStat, context);
      const digest = await copyAndHash(sourceHandle, stagingHandle);
      const finalSourceStat = await sourceHandle.stat();
      const finalStagingStat = await stagingHandle.stat();
      await sourceHandle.close();
      sourceHandle = null;
      await stagingHandle.close();
      stagingHandle = null;
      stagingStat = finalStagingStat;
      if (!sameStableIdentity(sourceHandleStat, finalSourceStat)
        || digest.sha256 !== entry.backupSha256 || digest.bytes !== entry.backupSize
        || digest.bytes !== Number(finalStagingStat.size)) {
        throw new Error('备份内容完整性校验失败。');
      }
      await assertContainerUnchanged(sourceParent, sourceParentStat, context);
      await assertContainerUnchanged(destinationParent, destinationParentStat, context);
      await assertOperationGuards(guards, context);
      if (await resourceExists(destination)) throw new Error('恢复位置出现新数据，未覆盖。');

      await fs.link(stagingPath, destination);
      destinationCreatedStat = stagingStat;
      await assertContainerUnchanged(destinationParent, destinationParentStat, context);
      await assertSafePathComponents(destination, context);
      const destinationStat = await fs.lstat(destination);
      if (!sameObjectIdentity(stagingStat, destinationStat)) throw new Error('恢复文件身份校验失败。');

      entry.restored = true;
      entry.restoredAt = new Date().toISOString();
      await writeManifest(manifestPath, manifest, guards, context);
      const stagingRemoved = await safeUnlinkExact(stagingPath, stagingStat, destinationParent, destinationParentStat, context);
      if (!stagingRemoved) throw new Error('恢复成功，但暂存文件无法安全移除；请检查备份记录。');
      stagingPath = null;
      results.push({ title: target.title, status: 'restored' });
    } catch (error) {
      if (sourceHandle) await sourceHandle.close().catch(() => {});
      if (stagingHandle) await stagingHandle.close().catch(() => {});
      let cleanupConflict = false;
      if (destinationCreatedStat && destination && destinationParent && destinationParentStat) {
        cleanupConflict = !await safeUnlinkExact(destination, destinationCreatedStat, destinationParent, destinationParentStat, context);
      }
      if (stagingStat && stagingPath && destinationParent && destinationParentStat) {
        cleanupConflict = !await safeUnlinkExact(stagingPath, stagingStat, destinationParent, destinationParentStat, context) || cleanupConflict;
      }
      entry.restored = false;
      delete entry.restoredAt;
      if (cleanupConflict) entry.state = 'restore-conflict';
      await writeManifest(manifestPath, manifest, guards, context).catch(() => {});
      results.push({
        title: target.title,
        status: 'failed',
        error: `${cleanError(error)}${cleanupConflict ? '；检测到并发变更，未删除无法确认身份的文件' : ''}`,
      });
    }
  }

  await writeManifest(manifestPath, manifest, guards, context);
  return { operationId, results };
}

async function deleteBackup(operationId, rawContext = {}, options = {}) {
  const context = rawContext.pathApi ? rawContext : createContext(rawContext);
  const backupRoot = context.pathApi.resolve(options.backupRoot || context.pathApi.join(context.documentsDir, 'CleanTrace Backups'));
  const operationDir = operationDirectory(operationId, context, backupRoot);
  await assertSafePathComponents(backupRoot, context);
  await assertSafePathComponents(operationDir, context);
  const guards = await createOperationGuards(operationDir, backupRoot, context);
  const manifest = await readManifest(context.pathApi.join(operationDir, 'manifest.json'), context);
  if (manifest.operationId !== operationId || manifest.platform !== context.platform) {
    throw new Error('备份编号或操作系统与清单不一致。');
  }

  const quarantine = context.pathApi.join(backupRoot, `.delete-${operationId}-${crypto.randomUUID()}`);
  await assertSafePathComponents(quarantine, context);
  if (await resourceExists(quarantine)) throw new Error('备份删除隔离路径已存在。');
  await assertOperationGuards(guards, context);
  await fs.rename(operationDir, quarantine);
  await assertSafePathComponents(quarantine, context);
  const quarantinedStat = await fs.lstat(quarantine);
  if (!sameObjectIdentity(guards.operationDirStat, quarantinedStat)) {
    throw new Error('备份隔离后的目录身份不一致，已停止删除。');
  }
  await fs.rm(quarantine, { recursive: true, force: false, maxRetries: 3, retryDelay: 250 });
  if (await resourceExists(quarantine)) throw new Error('备份目录未能完整删除。');
  return { operationId, deleted: true };
}

function getBackupManifestPath(operationId, rawContext = {}, options = {}) {
  const context = rawContext.pathApi ? rawContext : createContext(rawContext);
  const backupRoot = options.backupRoot || context.pathApi.join(context.documentsDir, 'CleanTrace Backups');
  return context.pathApi.join(operationDirectory(operationId, context, backupRoot), 'manifest.json');
}

module.exports = {
  assertSafeRemovalPath,
  cleanTargets,
  deleteBackup,
  getBackupManifestPath,
  listBackups,
  restoreBackup,
  validateSelection,
};
