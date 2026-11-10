const fs = require('node:fs/promises');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { EDGE_ADGUARD_ID, CHROME_ADGUARD_ID, buildAdGuardImportUrl } = require('./adguard-setup');

const PROFILE_PATTERN = /^(?:Default|Profile \d+)$/;
const DEFAULT_INSTALL_TIMEOUT_MS = 120000;

function browserTargets(context) {
  const localAppData = context.localAppData || context.env.LOCALAPPDATA || '';
  const programFiles = context.env.ProgramFiles || 'C:\\Program Files';
  const programFilesX86 = context.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
  return [
    {
      id: 'edge',
      name: 'Microsoft Edge',
      extensionId: EDGE_ADGUARD_ID,
      userDataRoot: path.win32.join(localAppData, 'Microsoft', 'Edge', 'User Data'),
      executables: [
        path.win32.join(programFilesX86, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
        path.win32.join(programFiles, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
        path.win32.join(localAppData, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      ],
      optionsUrl: `extension://${EDGE_ADGUARD_ID}/pages/options.html#/stealth`,
      policyUrl: 'edge://policy/',
      storeUrl: `https://microsoftedge.microsoft.com/addons/detail/adguard-adblocker/${EDGE_ADGUARD_ID}`,
    },
    {
      id: 'chrome',
      name: 'Google Chrome',
      extensionId: CHROME_ADGUARD_ID,
      userDataRoot: path.win32.join(localAppData, 'Google', 'Chrome', 'User Data'),
      executables: [
        path.win32.join(programFiles, 'Google', 'Chrome', 'Application', 'chrome.exe'),
        path.win32.join(programFilesX86, 'Google', 'Chrome', 'Application', 'chrome.exe'),
        path.win32.join(localAppData, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      ],
      optionsUrl: `chrome-extension://${CHROME_ADGUARD_ID}/pages/options.html#/stealth`,
      policyUrl: 'chrome://policy/',
      storeUrl: `https://chromewebstore.google.com/detail/adguard-adblocker/${CHROME_ADGUARD_ID}`,
    },
  ];
}

async function isRegularFile(candidate) {
  try {
    const stat = await fs.lstat(candidate);
    return stat.isFile() && !stat.isSymbolicLink();
  } catch (error) {
    if (error && error.code === 'ENOENT') return false;
    throw error;
  }
}

async function directoryExists(candidate) {
  try {
    const stat = await fs.lstat(candidate);
    return stat.isDirectory() && !stat.isSymbolicLink();
  } catch (error) {
    if (error && ['ENOENT', 'EACCES', 'EBUSY'].includes(error.code)) return false;
    throw error;
  }
}

async function findBrowserExecutable(target) {
  for (const candidate of target.executables) {
    if (await isRegularFile(candidate)) return candidate;
  }
  return null;
}

async function readLastUsedProfile(userDataRoot) {
  try {
    const localStatePath = path.win32.join(userDataRoot, 'Local State');
    const stat = await fs.lstat(localStatePath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4 * 1024 * 1024) return 'Default';
    const localState = JSON.parse(await fs.readFile(localStatePath, 'utf8'));
    const lastUsed = localState?.profile?.last_used;
    return PROFILE_PATTERN.test(lastUsed) ? lastUsed : 'Default';
  } catch (error) {
    if (error && ['ENOENT', 'EACCES', 'SyntaxError'].includes(error.code || error.name)) return 'Default';
    return 'Default';
  }
}

function isSafeProfilePath(userDataRoot, profile) {
  if (!PROFILE_PATTERN.test(profile)) return false;
  const candidate = path.win32.join(userDataRoot, profile);
  const relative = path.win32.relative(userDataRoot, candidate);
  return relative === profile && !path.win32.isAbsolute(relative) && !relative.startsWith('..');
}

async function enumerateChromiumProfiles(userDataRoot) {
  if (!await directoryExists(userDataRoot)) return [];
  const lastUsed = await readLastUsedProfile(userDataRoot);
  const candidates = new Set([lastUsed]);

  // Local State is a useful hint, but it is not authoritative: an already-running
  // browser can create or switch profiles without immediately updating last_used.
  try {
    const localStatePath = path.win32.join(userDataRoot, 'Local State');
    const stat = await fs.lstat(localStatePath);
    if (stat.isFile() && !stat.isSymbolicLink() && stat.size <= 4 * 1024 * 1024) {
      const localState = JSON.parse(await fs.readFile(localStatePath, 'utf8'));
      for (const profile of Object.keys(localState?.profile?.info_cache || {})) {
        if (PROFILE_PATTERN.test(profile)) candidates.add(profile);
      }
    }
  } catch (error) {
    if (!error || !['ENOENT', 'EACCES', 'EBUSY', 'SyntaxError'].includes(error.code || error.name)) throw error;
  }

  // Always scan the directory as well. This is deliberately repeated by the wait
  // loop so a profile created after the store page opens is detected in this run.
  try {
    const entries = await fs.readdir(userDataRoot, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory() && !entry.isSymbolicLink() && PROFILE_PATTERN.test(entry.name)) {
        candidates.add(entry.name);
      }
    }
  } catch (error) {
    if (!error || !['ENOENT', 'EACCES', 'EBUSY'].includes(error.code)) throw error;
  }

  const profiles = [];
  for (const profile of candidates) {
    if (!isSafeProfilePath(userDataRoot, profile)) continue;
    const directory = path.win32.join(userDataRoot, profile);
    if (await directoryExists(directory)) profiles.push(profile);
  }
  return profiles.sort((left, right) => {
    if (left === lastUsed) return -1;
    if (right === lastUsed) return 1;
    if (left === 'Default') return -1;
    if (right === 'Default') return 1;
    return left.localeCompare(right, undefined, { numeric: true });
  });
}

function launch(executable, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      detached: true,
      stdio: 'ignore',
      windowsHide: false,
      shell: false,
    });
    let settled = false;
    child.once('error', (error) => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    });
    child.once('spawn', () => {
      if (!settled) {
        settled = true;
        child.unref();
        resolve();
      }
    });
  });
}

async function findValidExtensionManifest(extensionRoot) {
  try {
    const versions = await fs.readdir(extensionRoot, { withFileTypes: true });
    for (const version of versions) {
      if (!version.isDirectory() || version.isSymbolicLink()) continue;
      const manifestPath = path.win32.join(extensionRoot, version.name, 'manifest.json');
      if (!await isRegularFile(manifestPath)) continue;
      try {
        const stat = await fs.lstat(manifestPath);
        if (stat.size < 2 || stat.size > 2 * 1024 * 1024) continue;
        const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
        if (manifest && typeof manifest === 'object' && typeof manifest.version === 'string'
          && Number.isInteger(manifest.manifest_version)) {
          return { manifestPath, version: manifest.version };
        }
      } catch (error) {
        if (!error || !['ENOENT', 'EACCES', 'SyntaxError'].includes(error.code || error.name)) throw error;
      }
    }
    return null;
  } catch (error) {
    if (error && error.code === 'ENOENT') return null;
    throw error;
  }
}

async function readJsonObject(candidate) {
  try {
    const stat = await fs.lstat(candidate);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 32 * 1024 * 1024) return null;
    const value = JSON.parse(await fs.readFile(candidate, 'utf8'));
    return value && typeof value === 'object' ? value : null;
  } catch (error) {
    if (error && ['ENOENT', 'EACCES', 'EBUSY', 'SyntaxError'].includes(error.code || error.name)) return null;
    throw error;
  }
}

function extensionSettingState(document, extensionId) {
  const setting = document?.extensions?.settings?.[extensionId];
  if (!setting || typeof setting !== 'object') return null;
  const hasState = Object.prototype.hasOwnProperty.call(setting, 'state');
  const numericState = hasState ? Number(setting.state) : null;
  const disableReasons = setting.disable_reasons;
  const hasDisableReasons = Array.isArray(disableReasons)
    ? disableReasons.length > 0
    : disableReasons && typeof disableReasons === 'object'
      ? Object.keys(disableReasons).length > 0
      : Number(disableReasons || 0) !== 0;
  const blocklistState = setting.blocklist_state ?? setting.blacklist_state;
  const isBlocklisted = Number(blocklistState || 0) !== 0;
  const explicitlyDisabled = hasState && (!Number.isFinite(numericState) || numericState !== 1);

  // Current Chromium/Edge builds may omit `state` for an enabled Web Store
  // extension.  The protected settings entry plus an on-disk manifest and no
  // disable/blocklist reason is the enabled representation in that case.  Do
  // not extend this compatibility rule to an explicit non-enabled state.
  return {
    enabled: !explicitlyDisabled && !hasDisableReasons && !isBlocklisted,
    state: hasState ? setting.state : null,
    disableReasons: disableReasons ?? null,
    blocklistState: blocklistState ?? null,
  };
}

async function inspectExtensionState(userDataRoot, profile, extensionId) {
  const profileRoot = path.win32.join(userDataRoot, profile);
  const extensionRoot = path.win32.join(profileRoot, 'Extensions', extensionId);
  const manifest = await findValidExtensionManifest(extensionRoot);
  if (!manifest) return { status: 'not-installed' };

  const preferenceFiles = ['Secure Preferences', 'Preferences'];
  for (const preferenceFile of preferenceFiles) {
    const document = await readJsonObject(path.win32.join(profileRoot, preferenceFile));
    const state = extensionSettingState(document, extensionId);
    if (!state) continue;
    if (state.enabled) return { status: 'installed-enabled', version: manifest.version, manifestPath: manifest.manifestPath };
    return {
      status: 'installed-disabled',
      version: manifest.version,
      state: state.state,
      disableReasons: state.disableReasons,
      blocklistState: state.blocklistState,
    };
  }
  return { status: 'installed-state-pending', version: manifest.version };
}

async function inspectExtensionAcrossProfiles(target) {
  const profiles = await enumerateChromiumProfiles(target.userDataRoot);
  let pending = null;
  let disabled = null;
  for (const profile of profiles) {
    const state = await inspectExtensionState(target.userDataRoot, profile, target.extensionId);
    const result = { ...state, profile, profilesScanned: profiles.length };
    if (state.status === 'installed-enabled') return result;
    if (state.status === 'installed-state-pending' && !pending) pending = result;
    if (state.status === 'installed-disabled' && !disabled) disabled = result;
  }
  return pending || disabled || { status: 'not-installed', profilesScanned: profiles.length };
}

async function extensionIsReady(extensionRoot) {
  return Boolean(await findValidExtensionManifest(extensionRoot));
}

async function waitForExtensionState(target, profile, timeoutMs = DEFAULT_INSTALL_TIMEOUT_MS) {
  const deadline = Date.now() + timeoutMs;
  let state = await inspectExtensionState(target.userDataRoot, profile, target.extensionId);
  while (Date.now() < deadline) {
    if (state.status === 'installed-enabled') return state;
    await new Promise((resolve) => setTimeout(resolve, 500));
    state = await inspectExtensionState(target.userDataRoot, profile, target.extensionId);
  }
  return state;
}

async function waitForExtensionAcrossProfiles(
  target,
  timeoutMs = DEFAULT_INSTALL_TIMEOUT_MS,
  pollIntervalMs = 500,
) {
  const deadline = Date.now() + timeoutMs;
  let state = await inspectExtensionAcrossProfiles(target);
  while (state.status !== 'installed-enabled' && Date.now() < deadline) {
    const remaining = deadline - Date.now();
    await new Promise((resolve) => setTimeout(resolve, Math.max(1, Math.min(pollIntervalMs, remaining))));
    // Re-enumerate on every pass. Both extension state and the selected profile may
    // be persisted after the store has already changed to "Remove".
    state = await inspectExtensionAcrossProfiles(target);
  }
  return state;
}

async function waitForExtension(extensionRoot, timeoutMs = DEFAULT_INSTALL_TIMEOUT_MS) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await extensionIsReady(extensionRoot)) return true;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  return extensionIsReady(extensionRoot);
}

function validateConfigurationUrl(configurationUrl) {
  const parsed = new URL(configurationUrl || buildAdGuardImportUrl());
  if (parsed.protocol !== 'https:' || parsed.hostname !== 'reports.adguard.info'
    || parsed.pathname !== '/zh_cn/settings/import.html') {
    throw new Error('已拒绝打开非官方 AdGuard 配置地址。');
  }
  return parsed.toString();
}

function validateStoreUrl(target) {
  const parsed = new URL(target.storeUrl);
  const expectedHost = target.id === 'edge'
    ? 'microsoftedge.microsoft.com'
    : 'chromewebstore.google.com';
  const expectedPath = target.id === 'edge'
    ? `/addons/detail/adguard-adblocker/${EDGE_ADGUARD_ID}`
    : `/detail/adguard-adblocker/${CHROME_ADGUARD_ID}`;
  if (parsed.protocol !== 'https:' || parsed.hostname !== expectedHost || parsed.pathname !== expectedPath
    || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error(`${target.name} 官方扩展商店地址校验失败。`);
  }
  return parsed.toString();
}

async function openAdGuardSetupPages(context, options = {}) {
  if (context.platform !== 'win32') throw new Error('此自动打开流程当前仅支持 Windows。');
  const configurationUrl = validateConfigurationUrl(options.configurationUrl);
  const launchBrowser = options.launchBrowser || launch;
  const timeoutMs = options.timeoutMs ?? DEFAULT_INSTALL_TIMEOUT_MS;
  const pollIntervalMs = options.pollIntervalMs ?? 500;
  const results = [];

  await Promise.all(browserTargets(context).map(async (target) => {
    const storeUrl = validateStoreUrl(target);
    const executable = await findBrowserExecutable(target);
    if (!executable) {
      results.push({ browser: target.name, status: 'not-installed' });
      return;
    }
    const launchProfile = await readLastUsedProfile(target.userDataRoot);
    let state = await inspectExtensionAcrossProfiles(target);
    if (state.status !== 'installed-enabled') {
      try {
        // Chromium reloads machine policies when a new browser process starts. Keep the
        // official store page first/foreground so a browser that requires an explicit
        // Add/Get confirmation gives the user the supported installation path. The
        // built-in policy page remains available behind it for auditable diagnostics.
        await Promise.resolve(launchBrowser(executable, [
          `--profile-directory=${launchProfile}`,
          '--no-first-run',
          '--no-default-browser-check',
          '--disable-background-mode',
          storeUrl,
          target.policyUrl,
        ]));
      } catch (error) {
        results.push({ browser: target.name, profile: launchProfile, status: 'launch-failed', message: error.message });
        return;
      }
      state = await waitForExtensionAcrossProfiles(target, timeoutMs, pollIntervalMs);
    }
    const profile = state.profile || launchProfile;
    if (state.status === 'installed-disabled') {
      results.push({ browser: target.name, profile, status: 'extension-disabled', version: state.version });
      return;
    }
    if (state.status !== 'installed-enabled') {
      results.push({
        browser: target.name,
        profile,
        status: 'extension-timeout',
        detail: state.status,
      });
      return;
    }
    // Open the options page first and the official import flow second, leaving the
    // confirmation page in the foreground while the exact tracking page is ready behind it.
    try {
      await Promise.resolve(launchBrowser(executable, [
        `--profile-directory=${profile}`,
        target.optionsUrl,
        configurationUrl,
      ]));
      results.push({ browser: target.name, profile, status: 'installed-enabled', version: state.version, setupPagesOpened: true });
    } catch (error) {
      results.push({ browser: target.name, profile, status: 'installed-enabled', version: state.version, setupPagesOpened: false, message: error.message });
    }
  }));

  return results.sort((a, b) => a.browser.localeCompare(b.browser));
}

module.exports = {
  PROFILE_PATTERN,
  DEFAULT_INSTALL_TIMEOUT_MS,
  browserTargets,
  enumerateChromiumProfiles,
  extensionIsReady,
  inspectExtensionAcrossProfiles,
  inspectExtensionState,
  openAdGuardSetupPages,
  readLastUsedProfile,
  validateConfigurationUrl,
  validateStoreUrl,
  waitForExtension,
  waitForExtensionAcrossProfiles,
  waitForExtensionState,
};
