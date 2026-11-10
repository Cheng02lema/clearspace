const fs = require('node:fs/promises');
const path = require('node:path');
const { assertSafePathComponents } = require('./path-safety');

const STATE_KEY = 'HKLM:\\Software\\KelaudeStudio\\Cleaner';
const STATE_VALUE = 'BrowserLocationLanguageState';
const PROFILE_STATE_FILE = 'browser-location-language-profiles.json';
const PROFILE_STATE_SCHEMA = 1;

let profileMutationQueue = Promise.resolve();

// Primary browser locale by ISO 3166-1 alpha-2 country. This intentionally
// chooses one broadly used locale per exit country; it does not claim to infer
// a user's personal language in multilingual countries.
const COUNTRY_LOCALES = Object.freeze({
  AE: 'ar-AE', AF: 'fa-AF', AL: 'sq-AL', AM: 'hy-AM', AO: 'pt-AO', AR: 'es-AR', AT: 'de-AT', AU: 'en-AU', AZ: 'az-AZ',
  BA: 'bs-BA', BD: 'bn-BD', BE: 'nl-BE', BG: 'bg-BG', BH: 'ar-BH', BO: 'es-BO', BR: 'pt-BR', BY: 'be-BY',
  CA: 'en-CA', CH: 'de-CH', CL: 'es-CL', CN: 'zh-CN', CO: 'es-CO', CR: 'es-CR', CU: 'es-CU', CY: 'el-CY', CZ: 'cs-CZ',
  DE: 'de-DE', DK: 'da-DK', DO: 'es-DO', DZ: 'ar-DZ', EC: 'es-EC', EE: 'et-EE', EG: 'ar-EG', ES: 'es-ES', ET: 'am-ET',
  FI: 'fi-FI', FR: 'fr-FR', GB: 'en-GB', GE: 'ka-GE', GH: 'en-GH', GR: 'el-GR', GT: 'es-GT', HK: 'zh-HK', HN: 'es-HN', HR: 'hr-HR', HU: 'hu-HU',
  ID: 'id-ID', IE: 'en-IE', IL: 'he-IL', IN: 'hi-IN', IQ: 'ar-IQ', IR: 'fa-IR', IS: 'is-IS', IT: 'it-IT', JM: 'en-JM', JO: 'ar-JO', JP: 'ja-JP',
  KE: 'en-KE', KG: 'ky-KG', KH: 'km-KH', KR: 'ko-KR', KW: 'ar-KW', KZ: 'kk-KZ', LA: 'lo-LA', LB: 'ar-LB', LK: 'si-LK', LT: 'lt-LT', LU: 'fr-LU', LV: 'lv-LV',
  MA: 'ar-MA', MD: 'ro-MD', ME: 'sr-ME', MK: 'mk-MK', MM: 'my-MM', MN: 'mn-MN', MO: 'zh-MO', MT: 'mt-MT', MX: 'es-MX', MY: 'ms-MY',
  NG: 'en-NG', NI: 'es-NI', NL: 'nl-NL', NO: 'nb-NO', NP: 'ne-NP', NZ: 'en-NZ', OM: 'ar-OM', PA: 'es-PA', PE: 'es-PE', PH: 'en-PH', PK: 'ur-PK', PL: 'pl-PL', PR: 'es-PR', PT: 'pt-PT', PY: 'es-PY',
  QA: 'ar-QA', RO: 'ro-RO', RS: 'sr-RS', RU: 'ru-RU', SA: 'ar-SA', SE: 'sv-SE', SG: 'en-SG', SI: 'sl-SI', SK: 'sk-SK', SV: 'es-SV', SY: 'ar-SY',
  TH: 'th-TH', TN: 'ar-TN', TR: 'tr-TR', TW: 'zh-TW', UA: 'uk-UA', US: 'en-US', UY: 'es-UY', UZ: 'uz-UZ', VE: 'es-VE', VN: 'vi-VN', ZA: 'en-ZA',
});

function localeForCountry(countryCode) {
  const code = typeof countryCode === 'string' ? countryCode.trim().toUpperCase() : '';
  return COUNTRY_LOCALES[code] || 'en-US';
}

function validateLocale(locale) {
  if (typeof locale !== 'string' || !/^[a-z]{2,3}(?:-[A-Z]{2})?$/.test(locale)) {
    throw new Error('代理地区无法映射为安全的浏览器语言。');
  }
  return locale;
}

function preferredLanguages(locale) {
  const safe = validateLocale(locale);
  const base = safe.split('-')[0];
  return base === safe ? [safe] : [safe, base];
}

function quotePowerShell(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

function windowsSettings(locale) {
  const safe = validateLocale(locale);
  const languages = preferredLanguages(safe);
  return [
    { Browser: 'Google Chrome', Path: 'HKLM:\\Software\\Policies\\Google\\Chrome', Name: 'DefaultGeolocationSetting', Type: 'DWord', Value: 2 },
    { Browser: 'Google Chrome', Path: 'HKLM:\\Software\\Policies\\Google\\Chrome', Name: 'ApplicationLocaleValue', Type: 'String', Value: safe },
    ...languages.map((language, index) => ({ Browser: 'Google Chrome', Path: 'HKLM:\\Software\\Policies\\Google\\Chrome\\ForcedLanguages', Name: String(index + 1), Type: 'String', Value: language })),
    { Browser: 'Microsoft Edge', Path: 'HKLM:\\Software\\Policies\\Microsoft\\Edge', Name: 'DefaultGeolocationSetting', Type: 'DWord', Value: 2 },
    { Browser: 'Microsoft Edge', Path: 'HKLM:\\Software\\Policies\\Microsoft\\Edge', Name: 'ApplicationLocaleValue', Type: 'String', Value: safe },
    { Browser: 'Microsoft Edge', Path: 'HKLM:\\Software\\Policies\\Microsoft\\Edge', Name: 'DefinePreferredLanguages', Type: 'String', Value: languages.join(',') },
    // Edge can otherwise expose the Windows regional format through the
    // default JavaScript Intl locale. "Never" makes it derive the region from
    // the browser display locale instead (Edge 108+).
    { Browser: 'Microsoft Edge', Path: 'HKLM:\\Software\\Policies\\Microsoft\\Edge', Name: 'DefaultShareAdditionalOSRegionSetting', Type: 'DWord', Value: 2 },
  ];
}

function encodedJson(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
}

function comparable(candidate, context) {
  const normalized = context.pathApi.normalize(context.pathApi.resolve(candidate));
  return context.platform === 'win32' ? normalized.toLowerCase() : normalized;
}

function isWithin(candidate, root, context) {
  const relative = context.pathApi.relative(
    comparable(root, context),
    comparable(candidate, context),
  );
  return relative === '' || (!relative.startsWith('..') && !context.pathApi.isAbsolute(relative));
}

function safeProfileName(value, context) {
  return typeof value === 'string' && value.length > 0 && value.length <= 160
    && value !== '.' && value !== '..'
    && context.pathApi.basename(value) === value
    && !value.includes('/') && !value.includes('\\');
}

function chromiumRoot(context, browser) {
  if (browser === 'Chrome') return context.pathApi.join(context.localAppData, 'Google', 'Chrome', 'User Data');
  if (browser === 'Edge') return context.pathApi.join(context.localAppData, 'Microsoft', 'Edge', 'User Data');
  return null;
}

function validateChromiumProfile(profile, context) {
  if (!profile || profile.engine !== 'chromium') throw new Error('浏览器语言配置只允许处理已验证的 Chromium 配置。');
  const root = chromiumRoot(context, profile.browser);
  if (!root || comparable(profile.root, context) !== comparable(root, context)) {
    throw new Error('浏览器语言配置的用户数据目录不在允许范围内。');
  }
  const name = context.pathApi.basename(profile.directory);
  const expected = context.pathApi.join(root, name);
  if (!safeProfileName(name, context) || comparable(profile.directory, context) !== comparable(expected, context)
    || !isWithin(profile.directory, root, context)) {
    throw new Error('浏览器语言配置包含无效的 Profile 路径。');
  }
  return {
    browser: profile.browser,
    profile: name,
    filePath: context.pathApi.join(expected, 'Preferences'),
  };
}

function languageStatePath(context) {
  return context.pathApi.join(context.userDataDir, PROFILE_STATE_FILE);
}

function profileKey(browser, profile) {
  return `${browser}:${profile}`;
}

function snapshotField(object, name) {
  return Object.prototype.hasOwnProperty.call(object, name)
    ? { Existed: true, Value: object[name] }
    : { Existed: false, Value: null };
}

function validateLanguageState(value) {
  if (!value || value.Schema !== PROFILE_STATE_SCHEMA || !Array.isArray(value.Records) || value.Records.length > 500) {
    throw new Error('浏览器语言恢复状态无法识别。');
  }
  // Schema 1 was originally released without LocalStateRecords. Treating a
  // missing collection as empty keeps those recovery files usable.
  if (!Object.prototype.hasOwnProperty.call(value, 'LocalStateRecords')) value.LocalStateRecords = [];
  if (!Array.isArray(value.LocalStateRecords) || value.LocalStateRecords.length > 2) {
    throw new Error('浏览器语言恢复状态包含无效 Local State 记录。');
  }
  for (const record of value.Records) {
    if (!record || !['Chrome', 'Edge'].includes(record.Browser)
      || typeof record.Profile !== 'string' || record.Profile.length > 160
      || !record.Original || !record.Owned) {
      throw new Error('浏览器语言恢复状态包含无效记录。');
    }
    for (const field of ['AcceptLanguages', 'SelectedLanguages']) {
      const original = record.Original[field];
      const owned = record.Owned[field];
      if (!original || typeof original.Existed !== 'boolean' || !Array.isArray(owned)
        || owned.length > 50 || owned.some((item) => typeof item !== 'string' || item.length > 256)) {
        throw new Error('浏览器语言恢复状态包含无效语言值。');
      }
    }
  }
  const seenBrowsers = new Set();
  for (const record of value.LocalStateRecords) {
    if (!record || !['Chrome', 'Edge'].includes(record.Browser) || seenBrowsers.has(record.Browser)
      || !record.Original || typeof record.Original.IntlExisted !== 'boolean'
      || !record.Original.AppLocale || typeof record.Original.AppLocale.Existed !== 'boolean'
      || (record.Original.AppLocale.Existed
        && (typeof record.Original.AppLocale.Value !== 'string' || record.Original.AppLocale.Value.length > 64))
      || !record.Owned || !Array.isArray(record.Owned.AppLocale)
      || record.Owned.AppLocale.length > 50
      || record.Owned.AppLocale.some((item) => typeof item !== 'string' || item.length > 64)) {
      throw new Error('浏览器语言恢复状态包含无效 Local State 语言值。');
    }
    seenBrowsers.add(record.Browser);
  }
  return value;
}

async function readLanguageState(context) {
  const filePath = languageStatePath(context);
  await assertSafePathComponents(filePath, context);
  try {
    const stat = await fs.lstat(filePath);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('浏览器语言恢复状态不是普通文件。');
    return validateLanguageState(JSON.parse((await fs.readFile(filePath, 'utf8')).replace(/^\uFEFF/, '')));
  } catch (error) {
    if (error && error.code === 'ENOENT') return { Schema: PROFILE_STATE_SCHEMA, Records: [], LocalStateRecords: [] };
    if (error instanceof SyntaxError) throw new Error('浏览器语言恢复状态不是有效 JSON。');
    throw error;
  }
}

async function writeAtomicFile(filePath, contents, context, mode = 0o600) {
  const directory = context.pathApi.dirname(filePath);
  if (!isWithin(filePath, directory, context)) throw new Error('原子写入路径无效。');
  await assertSafePathComponents(directory, context);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  await assertSafePathComponents(directory, context);
  const temporary = context.pathApi.join(
    directory,
    `.${context.pathApi.basename(filePath)}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`,
  );
  await assertSafePathComponents(temporary, context);
  const handle = await fs.open(temporary, 'wx', mode);
  try {
    await handle.writeFile(contents, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await assertSafePathComponents(filePath, context);
    await fs.rename(temporary, filePath);
  } catch (error) {
    await fs.rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

async function saveLanguageState(context, state) {
  validateLanguageState(state);
  await writeAtomicFile(languageStatePath(context), `${JSON.stringify(state)}\n`, context);
}

async function readPreferences(filePath, profileDirectory, context) {
  if (!isWithin(filePath, profileDirectory, context)) throw new Error('Preferences 路径超出浏览器 Profile。');
  await assertSafePathComponents(filePath, context);
  const stat = await fs.lstat(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('Preferences 不是普通文件。');
  const text = await fs.readFile(filePath, 'utf8');
  let value;
  try { value = JSON.parse(text.replace(/^\uFEFF/, '')); }
  catch { throw new Error('浏览器 Preferences 无法解析，已停止修改。'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('浏览器 Preferences 不是有效对象。');
  if (Object.prototype.hasOwnProperty.call(value, 'intl')
    && (!value.intl || typeof value.intl !== 'object' || Array.isArray(value.intl))) {
    throw new Error('浏览器 Preferences 的 intl 节点格式异常，已停止修改。');
  }
  return { stat, value, text };
}

function sameStat(left, right) {
  return left.dev === right.dev && left.ino === right.ino
    && left.size === right.size && left.mtimeMs === right.mtimeMs;
}

async function replacePreferences(filePath, profileDirectory, context, read, nextValue, verify) {
  const next = `${JSON.stringify(nextValue)}\n`;
  if (next.trimEnd() === read.text.trimEnd()) {
    verify(nextValue);
    return false;
  }
  const temporary = `${filePath}.kelaude-language-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}.tmp`;
  if (!isWithin(temporary, profileDirectory, context)) throw new Error('Preferences 临时文件路径无效。');
  await assertSafePathComponents(temporary, context);
  const handle = await fs.open(temporary, 'wx', read.stat.mode & 0o777);
  try {
    await handle.writeFile(next, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await assertSafePathComponents(filePath, context);
    const currentStat = await fs.lstat(filePath);
    if (!currentStat.isFile() || currentStat.isSymbolicLink() || !sameStat(currentStat, read.stat)) {
      throw new Error('浏览器 Preferences 在操作期间发生变化，已停止修改。');
    }
    await fs.rename(temporary, filePath);
    await assertSafePathComponents(filePath, context);
    const verifiedStat = await fs.lstat(filePath);
    if (!verifiedStat.isFile() || verifiedStat.isSymbolicLink()) throw new Error('浏览器 Preferences 写入后类型异常。');
    const verified = JSON.parse((await fs.readFile(filePath, 'utf8')).replace(/^\uFEFF/, ''));
    verify(verified);
    return true;
  } catch (error) {
    await fs.rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

function runProfileMutation(task) {
  const result = profileMutationQueue.then(task, task);
  profileMutationQueue = result.catch(() => {});
  return result;
}

async function applyChromiumLanguageProfiles(context, profiles, locale) {
  return runProfileMutation(async () => {
    const languages = preferredLanguages(locale).join(',');
    const candidates = profiles.filter((profile) => profile.engine === 'chromium')
      .map((profile) => validateChromiumProfile(profile, context));
    const state = await readLanguageState(context);
    const records = new Map(state.Records.map((record) => [profileKey(record.Browser, record.Profile), record]));
    const localStateRecords = new Map(state.LocalStateRecords.map((record) => [record.Browser, record]));
    const localStates = [];
    for (const browser of [...new Set(candidates.map((candidate) => candidate.browser))]) {
      const root = chromiumRoot(context, browser);
      const filePath = context.pathApi.join(root, 'Local State');
      const read = await readPreferences(filePath, root, context);
      const intl = read.value.intl || {};
      let record = localStateRecords.get(browser);
      if (!record) {
        record = {
          Browser: browser,
          Original: {
            IntlExisted: Object.prototype.hasOwnProperty.call(read.value, 'intl'),
            AppLocale: snapshotField(intl, 'app_locale'),
          },
          Owned: { AppLocale: [] },
        };
        state.LocalStateRecords.push(record);
        localStateRecords.set(browser, record);
      }
      if (!record.Owned.AppLocale.includes(locale)) record.Owned.AppLocale.push(locale);
      localStates.push({ browser, root, filePath, read });
    }
    const reads = [];
    for (const candidate of candidates) {
      const read = await readPreferences(candidate.filePath, context.pathApi.dirname(candidate.filePath), context);
      const intl = read.value.intl || {};
      const key = profileKey(candidate.browser, candidate.profile);
      let record = records.get(key);
      if (!record) {
        record = {
          Browser: candidate.browser,
          Profile: candidate.profile,
          Original: {
            IntlExisted: Object.prototype.hasOwnProperty.call(read.value, 'intl'),
            AcceptLanguages: snapshotField(intl, 'accept_languages'),
            SelectedLanguages: snapshotField(intl, 'selected_languages'),
          },
          Owned: { AcceptLanguages: [], SelectedLanguages: [] },
        };
        state.Records.push(record);
        records.set(key, record);
      }
      for (const field of ['AcceptLanguages', 'SelectedLanguages']) {
        if (!record.Owned[field].includes(languages)) record.Owned[field].push(languages);
      }
      reads.push({ candidate, read });
    }
    // Save originals and the intended owned values before changing any browser file.
    await saveLanguageState(context, state);
    let changed = 0;
    for (const { browser, root, filePath, read } of localStates) {
      const intl = read.value.intl || (read.value.intl = {});
      intl.app_locale = locale;
      changed += Number(await replacePreferences(
        filePath,
        root,
        context,
        read,
        read.value,
        (verified) => {
          if (verified?.intl?.app_locale !== locale) {
            throw new Error(`${browser} Local State 的应用区域设置回读验证失败。`);
          }
        },
      ));
    }
    for (const { candidate, read } of reads) {
      const intl = read.value.intl || (read.value.intl = {});
      intl.accept_languages = languages;
      intl.selected_languages = languages;
      changed += Number(await replacePreferences(
        candidate.filePath,
        context.pathApi.dirname(candidate.filePath),
        context,
        read,
        read.value,
        (verified) => {
          const actual = verified?.intl;
          if (typeof actual?.accept_languages !== 'string' || actual.accept_languages.split(',')[0] !== locale
            || typeof actual?.selected_languages !== 'string' || actual.selected_languages.split(',')[0] !== locale) {
            throw new Error(`${candidate.browser} ${candidate.profile} 的语言首选项回读验证失败。`);
          }
        },
      ));
    }
    return { changed, profiles: candidates.length, browserRoots: localStates.length, locale, languages };
  });
}

function restoreField(intl, record, preferenceName, stateName) {
  const current = intl[preferenceName];
  if (!record.Owned[stateName].includes(current)) return false;
  const original = record.Original[stateName];
  if (original.Existed) intl[preferenceName] = original.Value;
  else delete intl[preferenceName];
  return true;
}

async function restoreChromiumLanguageProfiles(context, profiles) {
  return runProfileMutation(async () => {
    const filePath = languageStatePath(context);
    const state = await readLanguageState(context);
    const currentProfiles = new Map();
    for (const profile of profiles.filter((item) => item.engine === 'chromium')) {
      const candidate = validateChromiumProfile(profile, context);
      currentProfiles.set(profileKey(candidate.browser, candidate.profile), candidate);
    }
    let changed = 0;
    let skipped = 0;
    for (const record of state.LocalStateRecords) {
      const root = chromiumRoot(context, record.Browser);
      const localStatePath = context.pathApi.join(root, 'Local State');
      try {
        const read = await readPreferences(localStatePath, root, context);
        if (!read.value.intl || typeof read.value.intl !== 'object' || Array.isArray(read.value.intl)
          || !record.Owned.AppLocale.includes(read.value.intl.app_locale)) {
          skipped += 1;
          continue;
        }
        const original = record.Original.AppLocale;
        if (original.Existed) read.value.intl.app_locale = original.Value;
        else delete read.value.intl.app_locale;
        if (!record.Original.IntlExisted && Object.keys(read.value.intl).length === 0) delete read.value.intl;
        changed += Number(await replacePreferences(
          localStatePath,
          root,
          context,
          read,
          read.value,
          (verified) => {
            const actual = verified?.intl;
            if (original.Existed) {
              if (!actual || actual.app_locale !== original.Value) throw new Error(`${record.Browser} Local State 区域设置恢复验证失败。`);
            } else if (actual && Object.prototype.hasOwnProperty.call(actual, 'app_locale')) {
              throw new Error(`${record.Browser} Local State 区域设置恢复删除验证失败。`);
            }
          },
        ));
      } catch (error) {
        if (error?.code === 'ENOENT') { skipped += 1; continue; }
        throw error;
      }
    }
    for (const record of state.Records) {
      const candidate = currentProfiles.get(profileKey(record.Browser, record.Profile));
      if (!candidate) { skipped += 1; continue; }
      const read = await readPreferences(candidate.filePath, context.pathApi.dirname(candidate.filePath), context);
      if (!read.value.intl || typeof read.value.intl !== 'object' || Array.isArray(read.value.intl)) {
        skipped += 1;
        continue;
      }
      const restoredAccept = restoreField(read.value.intl, record, 'accept_languages', 'AcceptLanguages');
      const restoredSelected = restoreField(read.value.intl, record, 'selected_languages', 'SelectedLanguages');
      if (!restoredAccept && !restoredSelected) { skipped += 1; continue; }
      if (!record.Original.IntlExisted && Object.keys(read.value.intl).length === 0) delete read.value.intl;
      changed += Number(await replacePreferences(
        candidate.filePath,
        context.pathApi.dirname(candidate.filePath),
        context,
        read,
        read.value,
        (verified) => {
          for (const [name, stateName, restored] of [
            ['accept_languages', 'AcceptLanguages', restoredAccept],
            ['selected_languages', 'SelectedLanguages', restoredSelected],
          ]) {
            if (!restored) continue;
            const original = record.Original[stateName];
            const actualIntl = verified?.intl;
            if (original.Existed) {
              if (!actualIntl || actualIntl[name] !== original.Value) throw new Error(`${candidate.browser} 语言恢复回读验证失败。`);
            } else if (actualIntl && Object.prototype.hasOwnProperty.call(actualIntl, name)) {
              throw new Error(`${candidate.browser} 语言恢复删除验证失败。`);
            }
          }
        },
      ));
      if (restoredAccept !== restoredSelected) skipped += 1;
    }
    await assertSafePathComponents(filePath, context);
    await fs.rm(filePath, { force: true });
    return { changed, skipped };
  });
}

function commonScriptPreamble(stateKeyPath, diagnosticPath) {
  return [
    "$ErrorActionPreference = 'Stop'",
    '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8',
    `$stateKeyPath = ${quotePowerShell(stateKeyPath)}`,
    `$stateValueName = ${quotePowerShell(STATE_VALUE)}`,
    `$diagnosticPath = ${quotePowerShell(diagnosticPath)}`,
    "$stage = '初始化'",
    'function Save-State($value) {',
    '  New-Item -Path $stateKeyPath -Force | Out-Null',
    '  $json = $value | ConvertTo-Json -Depth 12 -Compress',
    '  New-ItemProperty -Path $stateKeyPath -Name $stateValueName -PropertyType String -Value $json -Force | Out-Null',
    '}',
    'function Test-SavedState {',
    '  if (-not (Test-Path -LiteralPath $stateKeyPath)) { return $false }',
    '  try { [void](Get-ItemPropertyValue -LiteralPath $stateKeyPath -Name $stateValueName -ErrorAction Stop); return $true } catch { return $false }',
    '}',
    'function Load-State {',
    '  return ([string](Get-ItemPropertyValue -LiteralPath $stateKeyPath -Name $stateValueName -ErrorAction Stop) | ConvertFrom-Json)',
    '}',
    'function Remove-SavedState {',
    '  Remove-ItemProperty -LiteralPath $stateKeyPath -Name $stateValueName -Force -ErrorAction SilentlyContinue',
    '}',
    'function Write-Diagnostic([bool]$ok, [string]$stageName, [string]$message, [int]$exitCode) {',
    '  $directory = Split-Path -Parent $diagnosticPath',
    '  New-Item -Path $directory -ItemType Directory -Force | Out-Null',
    '  [ordered]@{ Ok=$ok; Stage=$stageName; Message=$message; ExitCode=$exitCode } | ConvertTo-Json -Compress | Set-Content -LiteralPath $diagnosticPath -Encoding UTF8 -Force',
    '}',
    'function Read-RegistrySnapshot([string]$keyPath, [string]$name) {',
    '  $keyExisted = Test-Path -LiteralPath $keyPath',
    '  if (-not $keyExisted) { return [ordered]@{ KeyExisted=$false; HadValue=$false; Kind=$null; Value=$null } }',
    '  try {',
    '    $item = Get-Item -LiteralPath $keyPath -ErrorAction Stop',
    '    $value = Get-ItemPropertyValue -LiteralPath $keyPath -Name $name -ErrorAction Stop',
    '    return [ordered]@{ KeyExisted=$true; HadValue=$true; Kind=[string]$item.GetValueKind($name); Value=$value }',
    '  } catch [System.Management.Automation.PSArgumentException] {',
    '    return [ordered]@{ KeyExisted=$true; HadValue=$false; Kind=$null; Value=$null }',
    '  } catch [System.Management.Automation.ItemNotFoundException] {',
    '    return [ordered]@{ KeyExisted=$true; HadValue=$false; Kind=$null; Value=$null }',
    '  }',
    '}',
  ];
}

function buildWindowsApplyScript(stateKeyPath, diagnosticPath, locale) {
  const settings = windowsSettings(locale);
  const lines = [
    ...commonScriptPreamble(stateKeyPath, diagnosticPath),
    `$settings = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('${encodedJson(settings)}')) | ConvertFrom-Json`,
    'try {',
    "  $stage = '读取恢复状态'",
    '  if (Test-SavedState) {',
    '    $state = Load-State',
    "    if ([int]$state.Schema -ne 1) { throw '恢复状态版本无法识别' }",
    '  } else {',
    '    $state = [pscustomobject]@{ Schema=1; Records=[System.Collections.ArrayList]@() }',
    '  }',
    '  $recordList = New-Object System.Collections.ArrayList',
    '  foreach ($existingRecord in @($state.Records)) { [void]$recordList.Add($existingRecord) }',
    '  $state.Records = $recordList',
    '  foreach ($setting in $settings) {',
    "    $stage = [string]$setting.Browser + '/' + [string]$setting.Name + '/保存原始值'",
    '    $record = @($state.Records | Where-Object { $_.Path -eq $setting.Path -and $_.Name -eq $setting.Name }) | Select-Object -First 1',
    '    if ($null -eq $record) {',
    '      $original = Read-RegistrySnapshot ([string]$setting.Path) ([string]$setting.Name)',
    '      $record = [pscustomobject]@{ Path=[string]$setting.Path; Name=[string]$setting.Name; Original=$original; OwnedValues=[System.Collections.ArrayList]@() }',
    '      [void]$state.Records.Add($record)',
    '    }',
    '    $ownedList = New-Object System.Collections.ArrayList',
    '    foreach ($existingOwned in @($record.OwnedValues)) { [void]$ownedList.Add($existingOwned) }',
    '    $record.OwnedValues = $ownedList',
    '    $alreadyOwned = @($record.OwnedValues | Where-Object { $_.Type -eq $setting.Type -and [string]$_.Value -eq [string]$setting.Value }).Count -gt 0',
    '    if (-not $alreadyOwned) { [void]$record.OwnedValues.Add([pscustomobject]@{ Type=[string]$setting.Type; Value=$setting.Value }) }',
    '    Save-State $state',
    "    $stage = [string]$setting.Browser + '/' + [string]$setting.Name + '/写入策略'",
    '    New-Item -Path ([string]$setting.Path) -Force | Out-Null',
    "    if ($setting.Type -eq 'DWord') {",
    '      New-ItemProperty -Path ([string]$setting.Path) -Name ([string]$setting.Name) -PropertyType DWord -Value ([int]$setting.Value) -Force | Out-Null',
    '      $actual = [int](Get-ItemPropertyValue -LiteralPath ([string]$setting.Path) -Name ([string]$setting.Name) -ErrorAction Stop)',
    "      if ($actual -ne [int]$setting.Value) { throw '回读值与预期不一致' }",
    '    } else {',
    '      New-ItemProperty -Path ([string]$setting.Path) -Name ([string]$setting.Name) -PropertyType String -Value ([string]$setting.Value) -Force | Out-Null',
    '      $actual = [string](Get-ItemPropertyValue -LiteralPath ([string]$setting.Path) -Name ([string]$setting.Name) -ErrorAction Stop)',
    "      if ($actual -ne [string]$setting.Value) { throw '回读值与预期不一致' }",
    '    }',
    '  }',
    "  Write-Diagnostic $true '完成' '定位与语言策略写入并验证成功' 0",
    "  Write-Output 'BROWSER_LOCATION_LANGUAGE_OK'",
    '} catch {',
    '  try { Write-Diagnostic $false $stage $_.Exception.Message 42 } catch {}',
    '  exit 42',
    '}',
  ];
  return { script: lines.join('\n'), settings };
}

function buildWindowsRestoreScript(stateKeyPath, diagnosticPath) {
  const lines = [
    ...commonScriptPreamble(stateKeyPath, diagnosticPath),
    'function Set-OriginalValue($record) {',
    '  $original = $record.Original',
    '  if (-not [bool]$original.HadValue) {',
    '    Remove-ItemProperty -LiteralPath ([string]$record.Path) -Name ([string]$record.Name) -Force -ErrorAction SilentlyContinue',
    '    return',
    '  }',
    "  switch ([string]$original.Kind) {",
    "    'DWord' { New-ItemProperty -Path ([string]$record.Path) -Name ([string]$record.Name) -PropertyType DWord -Value ([int]$original.Value) -Force | Out-Null }",
    "    'QWord' { New-ItemProperty -Path ([string]$record.Path) -Name ([string]$record.Name) -PropertyType QWord -Value ([long]$original.Value) -Force | Out-Null }",
    "    'ExpandString' { New-ItemProperty -Path ([string]$record.Path) -Name ([string]$record.Name) -PropertyType ExpandString -Value ([string]$original.Value) -Force | Out-Null }",
    "    'MultiString' { New-ItemProperty -Path ([string]$record.Path) -Name ([string]$record.Name) -PropertyType MultiString -Value ([string[]]$original.Value) -Force | Out-Null }",
    "    'Binary' { New-ItemProperty -Path ([string]$record.Path) -Name ([string]$record.Name) -PropertyType Binary -Value ([byte[]]$original.Value) -Force | Out-Null }",
    "    'String' { New-ItemProperty -Path ([string]$record.Path) -Name ([string]$record.Name) -PropertyType String -Value ([string]$original.Value) -Force | Out-Null }",
    "    default { throw ('无法安全恢复注册表类型：' + [string]$original.Kind) }",
    '  }',
    '}',
    'try {',
    "  $stage = '读取恢复状态'",
    "  if (-not (Test-SavedState)) { throw '未找到本助手保存的浏览器定位与语言状态' }",
    '  $state = Load-State',
    "  if ([int]$state.Schema -ne 1) { throw '恢复状态版本无法识别' }",
    '  $restored = 0; $skipped = 0',
    '  foreach ($record in @($state.Records)) {',
    "    $stage = [string]$record.Path + '/' + [string]$record.Name + '/确认所有权'",
    '    if (-not (Test-Path -LiteralPath ([string]$record.Path))) { continue }',
    '    try { $current = Get-ItemPropertyValue -LiteralPath ([string]$record.Path) -Name ([string]$record.Name) -ErrorAction Stop } catch { continue }',
    '    $owned = @($record.OwnedValues | Where-Object {',
    "      if ($_.Type -eq 'DWord') { [int]$current -eq [int]$_.Value } else { [string]$current -ceq [string]$_.Value }",
    '    }).Count -gt 0',
    '    if (-not $owned) { $skipped += 1; continue }',
    "    $stage = [string]$record.Path + '/' + [string]$record.Name + '/恢复原始值'",
    '    Set-OriginalValue $record',
    '    $restored += 1',
    '  }',
    '  foreach ($record in @($state.Records | Where-Object { -not [bool]$_.Original.KeyExisted } | Sort-Object Path -Unique)) {',
    '    if (-not (Test-Path -LiteralPath ([string]$record.Path))) { continue }',
    '    $item = Get-Item -LiteralPath ([string]$record.Path)',
    '    $hasValues = @($item.GetValueNames()).Count -gt 0',
    '    $hasChildren = @(Get-ChildItem -LiteralPath ([string]$record.Path) -ErrorAction SilentlyContinue).Count -gt 0',
    '    if (-not $hasValues -and -not $hasChildren) { Remove-Item -LiteralPath ([string]$record.Path) -Force }',
    '  }',
    '  Remove-SavedState',
    "  Write-Diagnostic $true '完成' ('已恢复 ' + $restored + ' 项；跳过 ' + $skipped + ' 项后续已变更的设置') 0",
    "  Write-Output ('BROWSER_LOCATION_LANGUAGE_RESTORED:' + $restored + ':' + $skipped)",
    '} catch {',
    '  try { Write-Diagnostic $false $stage $_.Exception.Message 43 } catch {}',
    '  exit 43',
    '}',
  ];
  return lines.join('\n');
}

function parseDiagnostic(stdout) {
  const lines = String(stdout || '').replace(/^\uFEFF/, '').trim().split(/\r?\n/).reverse();
  for (const raw of lines) {
    const line = raw.replace(/^\uFEFF/, '').trim();
    if (!line.startsWith('{')) continue;
    try {
      const value = JSON.parse(line);
      if (typeof value.Ok === 'boolean') return value;
    } catch {}
  }
  return null;
}

async function runElevated(context, script, diagnosticPath, commandRunner, label) {
  const systemRoot = context.env.SystemRoot || context.env.WINDIR || 'C:\\Windows';
  const powershell = path.win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  const wrapper = [
    "$ErrorActionPreference = 'Stop'",
    '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8',
    `$diagnosticPath = ${quotePowerShell(diagnosticPath)}`,
    '$diagnosticDirectory = Split-Path -Parent $diagnosticPath',
    'New-Item -Path $diagnosticDirectory -ItemType Directory -Force | Out-Null',
    'Remove-Item -LiteralPath $diagnosticPath -Force -ErrorAction SilentlyContinue',
    'try {',
    `  $p = Start-Process -FilePath ${quotePowerShell(powershell)} -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand','${encoded}') -Verb RunAs -Wait -PassThru`,
    '  if (Test-Path -LiteralPath $diagnosticPath) { Get-Content -LiteralPath $diagnosticPath -Raw -Encoding UTF8 }',
    '  exit ([int]$p.ExitCode)',
    '} catch {',
    "  Write-Error ('ELEVATION_START_FAILED: ' + $_.Exception.Message)",
    '  exit 1223',
    '} finally {',
    '  Remove-Item -LiteralPath $diagnosticPath -Force -ErrorAction SilentlyContinue',
    '}',
  ].join('; ');
  const result = await commandRunner(powershell, ['-NoProfile', '-NonInteractive', '-Command', wrapper]);
  const diagnostic = parseDiagnostic(result.stdout);
  if (result.code !== 0 || !diagnostic?.Ok) {
    const stage = diagnostic?.Stage || '启动管理员授权';
    const code = diagnostic?.ExitCode ?? result.code ?? '未知';
    const detail = diagnostic?.Message || String(result.stderr || result.stdout || '请在 Windows 授权窗口选择“是”。').trim();
    throw new Error(`${label}失败（阶段：${stage}；退出码：${code}）：${detail}`);
  }
  return diagnostic;
}

function statePath() {
  return STATE_KEY;
}

function diagnosticPath(context, operation) {
  const directory = context.env.TEMP || context.env.TMP || context.localAppData;
  return path.win32.join(directory, 'KelaudeStudioCleaner', `browser-language-${operation}-${process.pid}-${Date.now()}.json`);
}

async function applyWindowsLocationLanguage(context, locale, commandRunner) {
  const diagnostic = diagnosticPath(context, 'apply');
  const built = buildWindowsApplyScript(statePath(context), diagnostic, locale);
  await runElevated(context, built.script, diagnostic, commandRunner, '浏览器定位与语言策略');
  return built.settings.length;
}

async function restoreWindowsLocationLanguage(context, commandRunner) {
  const diagnostic = diagnosticPath(context, 'restore');
  await runElevated(context, buildWindowsRestoreScript(statePath(context), diagnostic), diagnostic, commandRunner, '恢复浏览器定位与语言');
  return true;
}

module.exports = {
  COUNTRY_LOCALES,
  PROFILE_STATE_FILE,
  STATE_KEY,
  STATE_VALUE,
  applyChromiumLanguageProfiles,
  applyWindowsLocationLanguage,
  buildWindowsApplyScript,
  buildWindowsRestoreScript,
  localeForCountry,
  preferredLanguages,
  restoreChromiumLanguageProfiles,
  restoreWindowsLocationLanguage,
  languageStatePath,
  statePath,
  validateLocale,
  windowsSettings,
};
