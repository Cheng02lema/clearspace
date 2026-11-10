const path = require('node:path');

const EDGE_ADGUARD_ID = 'pdffkfellgipmhklpdmokmckkkfcopbh';
const CHROME_ADGUARD_ID = 'bgnkhhnnamicmpeenaelnjfhikgbkllg';
const LEGACY_UBLOCK_IDS = Object.freeze([
  'odfafepnkmbhccpbejgmiehpchacaeak',
  'ddkjiahejlhfcafbddmgiahcphecmpfh',
  'cjpalhdlnbpafiamejdnhcphjbkeiagm',
]);

const POLICY_TARGETS = Object.freeze([
  {
    name: 'Microsoft Edge',
    key: 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist',
    queryKey: 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist',
    extensionId: EDGE_ADGUARD_ID,
    updateUrl: 'https://edge.microsoft.com/extensionwebstorebase/v1/crx',
  },
  {
    name: 'Google Chrome',
    key: 'HKLM:\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist',
    queryKey: 'HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist',
    extensionId: CHROME_ADGUARD_ID,
    updateUrl: 'https://clients2.google.com/service/update2/crx',
  },
]);

function buildAdGuardImportUrl() {
  const url = new URL('https://reports.adguard.info/zh_cn/settings/import.html');
  const parameters = {
    scheme_version: '4',
    // The reports page creates an adguard: link from window.location.search.
    // Keep the comma list encoded through that second URL layer.
    regular_filters: encodeURIComponent('2,3,17,224'),
    'stealth.enabled': '1',
    'stealth.hide_search_queries': '1',
    'stealth.send_dnt': '1',
    'stealth.strip_url': '1',
    'stealth.block_trackers': '1',
    'stealth.x_client': '1',
    'browsing_security.enabled': '0',
  };
  for (const [name, value] of Object.entries(parameters)) url.searchParams.set(name, value);
  return url.toString();
}

function quotePowerShell(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

function policyMutationScript(mode, diagnosticPath = null) {
  if (!['install', 'remove'].includes(mode)) throw new Error('AdGuard 策略操作模式无效。');
  const targetDefinitions = POLICY_TARGETS
    .map((target) => `@{ Key=${quotePowerShell(target.key)}; Id=${quotePowerShell(target.extensionId)}; Value=${quotePowerShell(`${target.extensionId};${target.updateUrl}`)} }`)
    .join(',');
  const oldIds = LEGACY_UBLOCK_IDS.map(quotePowerShell).join(',');
  return [
    "$ErrorActionPreference='Stop'",
    `$diagnosticPath=${diagnosticPath ? quotePowerShell(diagnosticPath) : '$null'}`,
    "$stage='初始化'",
    'function Write-AdGuardDiagnostic([bool]$ok,[string]$stageName,[string]$message,[int]$exitCode) { if ($null -ne $diagnosticPath) { [ordered]@{ Ok=$ok; Stage=$stageName; Message=$message; ExitCode=$exitCode } | ConvertTo-Json -Compress | Set-Content -LiteralPath $diagnosticPath -Encoding UTF8 -Force } }',
    `$targets=@(${targetDefinitions})`,
    `$oldIds=@(${oldIds})`,
    'try {',
    'foreach ($target in $targets) {',
    "  $stage=('更新扩展策略/' + $target.Id)",
    "  if (-not (Test-Path -LiteralPath $target.Key)) { if ('install' -eq '" + mode + "') { New-Item -Path $target.Key -Force | Out-Null } else { continue } }",
    '  $item=Get-ItemProperty -LiteralPath $target.Key',
    '  foreach ($property in $item.PSObject.Properties) {',
    "    if ($property.Name -like 'PS*') { continue }",
    '    $value=[string]$property.Value',
    mode === 'install'
      ? '    if (($oldIds | Where-Object { $value -like "$_;*" }).Count -gt 0 -or $value -like "$($target.Id);*") { Remove-ItemProperty -LiteralPath $target.Key -Name $property.Name -Force }'
      : '    if ($value -like "$($target.Id);*") { Remove-ItemProperty -LiteralPath $target.Key -Name $property.Name -Force }',
    '  }',
    ...(mode === 'install' ? [
      '  $used=@((Get-ItemProperty -LiteralPath $target.Key).PSObject.Properties.Name)',
      '  $slot=1000; while ($used -contains [string]$slot) { $slot++ }',
      '  New-ItemProperty -LiteralPath $target.Key -Name ([string]$slot) -PropertyType String -Value $target.Value -Force | Out-Null',
    ] : []),
    '}',
    'foreach ($target in $targets) {',
    "  $stage=('回读验证扩展策略/' + $target.Id)",
    '  $values=@()',
    '  if (Test-Path -LiteralPath $target.Key) { $values=@((Get-ItemProperty -LiteralPath $target.Key).PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object { [string]$_.Value }) }',
    ...(mode === 'install' ? [
      "  if (@($values | Where-Object { $_ -eq $target.Value }).Count -ne 1) { throw '未找到唯一的 AdGuard 强制安装值' }",
      "  foreach ($oldId in $oldIds) { if (@($values | Where-Object { $_ -like ($oldId + ';*') }).Count -gt 0) { throw ('旧 uBlock 策略仍存在：' + $oldId) } }",
    ] : [
      "  if (@($values | Where-Object { $_ -like ($target.Id + ';*') }).Count -gt 0) { throw 'AdGuard 策略移除后仍可回读' }",
    ]),
    '}',
    "Write-AdGuardDiagnostic $true '完成' 'AdGuard 策略写入与回读验证成功' 0",
    "Write-Output 'ADGUARD_POLICY_OK'",
    '} catch {',
    '  $nativeMessage=$_.Exception.Message',
    '  try { Write-AdGuardDiagnostic $false $stage $nativeMessage 51 } catch {}',
    '  exit 51',
    '}',
  ].join('\r\n');
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

async function runElevatedPolicyScript(context, commandRunner, mode) {
  if (context.platform !== 'win32') {
    throw new Error('macOS 无法由普通应用静默强制安装浏览器扩展；需要浏览器确认或由企业 MDM 下发。');
  }
  const systemRoot = context.env.SystemRoot || context.env.WINDIR || 'C:\\Windows';
  const powershell = path.win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const diagnosticDir = context.env.TEMP || context.env.TMP || context.localAppData;
  const diagnosticPath = path.win32.join(diagnosticDir, 'KelaudeStudioCleaner', `adguard-policy-${process.pid}-${Date.now()}.json`);
  const script = policyMutationScript(mode, diagnosticPath);
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  const elevate = [
    "$ErrorActionPreference='Stop'",
    '[Console]::OutputEncoding=[System.Text.Encoding]::UTF8',
    `$diagnosticPath=${quotePowerShell(diagnosticPath)}`,
    '$diagnosticDirectory=Split-Path -Parent $diagnosticPath',
    'New-Item -Path $diagnosticDirectory -ItemType Directory -Force | Out-Null',
    'Remove-Item -LiteralPath $diagnosticPath -Force -ErrorAction SilentlyContinue',
    'try {',
    `  $p=Start-Process -FilePath ${quotePowerShell(powershell)} -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand','${encoded}') -Verb RunAs -Wait -PassThru`,
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
    const exitCode = diagnostic?.ExitCode ?? result.code ?? '未知';
    const stage = diagnostic?.Stage || '启动管理员授权';
    const detail = diagnostic?.Message || String(result.stderr || result.stdout || '请在 Windows 授权窗口选择“是”。').trim();
    throw new Error(`AdGuard 浏览器策略失败（阶段：${stage}；退出码：${exitCode}）：${detail}`);
  }
  return { powershell, script };
}

async function installAdGuardPolicies(context, commandRunner) {
  await runElevatedPolicyScript(context, commandRunner, 'install');
  const verified = POLICY_TARGETS.map((target) => target.name);
  return {
    changed: verified.length,
    message: `已为 ${verified.join('、')} 写入官方 AdGuard 强制安装策略并移除旧 uBlock 策略；正在逐个启动已安装的浏览器，等待扩展真正落盘并验证启用状态。`,
    configurationUrl: buildAdGuardImportUrl(),
    requiresConfigurationConfirmation: true,
  };
}

async function removeAdGuardPolicies(context, commandRunner) {
  await runElevatedPolicyScript(context, commandRunner, 'remove');
  return {
    changed: POLICY_TARGETS.length,
    message: '已移除本助手写入的 AdGuard 强制安装策略；重启浏览器后将不再显示为由该策略管理。',
  };
}

module.exports = {
  CHROME_ADGUARD_ID,
  EDGE_ADGUARD_ID,
  LEGACY_UBLOCK_IDS,
  POLICY_TARGETS,
  buildAdGuardImportUrl,
  installAdGuardPolicies,
  policyMutationScript,
  removeAdGuardPolicies,
};
