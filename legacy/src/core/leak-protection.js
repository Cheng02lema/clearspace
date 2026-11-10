const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const zlib = require('node:zlib');

const DNS_BACKUP_NAME = 'dns-leak-protection-state.json';
const DNS_DIAGNOSTIC_DIR = 'dns-diagnostics';
const DNS_PROBE_URL = 'https://www.cloudflare.com/cdn-cgi/trace';
const DNSCRYPT_VERSION = '2.1.16';
const DNSCRYPT_EXE_SHA256 = '23d1895bcfa8573605e811056d12b2bf5f13b0633758fbeda3ded79c5a6ea19d';
const DNSCRYPT_RESOLVERS_SHA256 = '19ad2ba0b05768e4e91f8dc44308bd898776dc46eb489763788682e07680bfd1';
const DNSCRYPT_RESOLVERS_SIGNATURE_SHA256 = '19dd7f3b6db57ead23c51cd0c8a7ef46c993ca61623113db30e8f33574480a3b';
const FIREWALL_RULES = Object.freeze([
  'KelaudeStudio-DnsLeakGuard-UDP',
  'KelaudeStudio-DnsLeakGuard-TCP',
]);

function quotePowerShell(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

function backupPath(context) {
  return context.pathApi.join(context.userDataDir, DNS_BACKUP_NAME);
}

async function fileSha256(filePath) {
  return crypto.createHash('sha256').update(await fs.readFile(filePath)).digest('hex');
}

async function verifyDnscryptAssets(sourceDir) {
  if (typeof sourceDir !== 'string' || !path.isAbsolute(sourceDir)) throw new Error('找不到 Windows 加密 DNS 服务组件。');
  const expected = [
    ['dnscrypt-proxy.exe', DNSCRYPT_EXE_SHA256],
    ['public-resolvers.md', DNSCRYPT_RESOLVERS_SHA256],
    ['public-resolvers.md.minisig', DNSCRYPT_RESOLVERS_SIGNATURE_SHA256],
  ];
  for (const [name, digest] of expected) {
    const candidate = path.join(sourceDir, name);
    const stat = await fs.lstat(candidate);
    if (!stat.isFile() || stat.isSymbolicLink() || await fileSha256(candidate) !== digest) {
      throw new Error(`加密 DNS 服务组件校验失败：${name}`);
    }
  }
  for (const name of ['dnscrypt-proxy.toml', 'LICENSE']) {
    const stat = await fs.lstat(path.join(sourceDir, name));
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`加密 DNS 服务组件缺失：${name}`);
  }
  return true;
}

function operationPrelude(operation, action) {
  return [
    `$operationId = ${quotePowerShell(operation.operationId)}`,
    `$resultPath = ${quotePowerShell(operation.resultPath)}`,
    `$action = ${quotePowerShell(action)}`,
    "$stage = 'initialize'",
    "$stageLabel = '初始化'",
    '$mutationStarted = $false',
    "$mutationStage = 'none'",
    '$adapterDnsModified = @()',
    '$script:LastNativeExitCode = 0',
    'function Write-OperationResult([bool]$success,[string]$message,[int]$exitCode,[int64]$hresult) {',
    "  $payload = [ordered]@{ Schema = 1; OperationId = $operationId; Action = $action; Success = $success; Stage = $stage; StageLabel = $stageLabel; Message = $message; HResult = $hresult; ExitCode = $exitCode; MutationStarted = $mutationStarted; MutationStage = $mutationStage; AdapterDnsModified = @($adapterDnsModified); DnscryptVersion = '2.1.16'; TimestampUtc = [DateTime]::UtcNow.ToString('o') }",
    '  $json = $payload | ConvertTo-Json -Depth 6 -Compress',
    "  $tempResult = $resultPath + '.' + $PID + '.tmp'",
    '  [IO.File]::WriteAllText($tempResult,$json,(New-Object Text.UTF8Encoding($false)))',
    '  Move-Item -LiteralPath $tempResult -Destination $resultPath -Force',
    '}',
  ];
}

function operationEpilogue(successMessage) {
  return [
    `$stage = 'complete'; $stageLabel = '完成'`,
    `Write-OperationResult $true ${quotePowerShell(successMessage)} 0 0`,
    'exit 0',
    '} catch {',
    '  $failure = $_.Exception',
    '  $exitCode = if ($script:LastNativeExitCode -ne 0) { [int]$script:LastNativeExitCode } else { 1 }',
    '  $hresult = if ($null -ne $failure) { [int64]$failure.HResult } else { 0 }',
    "  $message = if ($null -ne $failure -and -not [string]::IsNullOrWhiteSpace($failure.Message)) { $failure.Message } else { '未知错误' }",
    '  try { Write-OperationResult $false $message $exitCode $hresult } catch { }',
    '  exit 1',
    '}',
  ];
}

function buildWindowsEnableScript(statePath, sourceDir = 'C:\\KelaudeDnsAssets', operation = {}) {
  const resolvedOperation = {
    operationId: operation.operationId || 'standalone-enable',
    resultPath: operation.resultPath || `${statePath}.enable-result.json`,
  };
  return [
    "$ErrorActionPreference = 'Stop'",
    "$ProgressPreference = 'SilentlyContinue'",
    '[Console]::OutputEncoding = [Text.Encoding]::UTF8',
    `$statePath = ${quotePowerShell(statePath)}`,
    `$sourceDir = ${quotePowerShell(sourceDir)}`,
    "$installDir = Join-Path $env:ProgramData 'KelaudeStudio\\DnsCryptProxy'",
    "$serviceName = 'dnscrypt-proxy'",
    ...operationPrelude(resolvedOperation, 'enable'),
    'try {',
    "  $stage = 'prepare-diagnostics'; $stageLabel = '准备诊断记录'",
    '  New-Item -ItemType Directory -Path (Split-Path -Parent $resultPath) -Force | Out-Null',
    "  function Read-RegValue([string]$regPath,[string]$name) { $item = Get-ItemProperty -LiteralPath $regPath -ErrorAction SilentlyContinue; $property = if ($null -ne $item) { $item.PSObject.Properties[$name] } else { $null }; return [ordered]@{ Present = ($null -ne $property); Value = if ($null -ne $property) { [string]$property.Value } else { $null } } }",
    "  function Invoke-Dnscrypt([string[]]$arguments,[string]$failureMessage) {",
    "    $stdoutPath = Join-Path $env:TEMP ('kelaude-dnscrypt-' + [Guid]::NewGuid().ToString('N') + '.stdout.log')",
    "    $stderrPath = Join-Path $env:TEMP ('kelaude-dnscrypt-' + [Guid]::NewGuid().ToString('N') + '.stderr.log')",
    '    try {',
    "      $process = Start-Process -FilePath (Join-Path (Get-Location) 'dnscrypt-proxy.exe') -ArgumentList $arguments -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -ErrorAction Stop",
    '      $script:LastNativeExitCode = [int]$process.ExitCode',
    "      $output = @(); if (Test-Path -LiteralPath $stdoutPath) { $output += @([IO.File]::ReadAllLines($stdoutPath)) }; if (Test-Path -LiteralPath $stderrPath) { $output += @([IO.File]::ReadAllLines($stderrPath)) }",
    "      if ($script:LastNativeExitCode -ne 0) { $detail = ([string]::Join(' ', @($output))).Trim(); if ($detail.Length -gt 500) { $detail = $detail.Substring(0,500) + '...' }; throw ($failureMessage + '（退出码 ' + $script:LastNativeExitCode + '）' + $(if ($detail) { '：' + $detail } else { '' })) }",
    '    } finally { Remove-Item -LiteralPath $stdoutPath,$stderrPath -Force -ErrorAction SilentlyContinue }',
    '  }',
    '  function Wait-DnscryptService([bool]$present,[string]$requiredState,[int]$seconds) {',
    '    $deadline = [DateTime]::UtcNow.AddSeconds($seconds)',
    '    do {',
    "      $candidate = Get-CimInstance Win32_Service -Filter \"Name='dnscrypt-proxy'\" -ErrorAction SilentlyContinue",
    '      if (-not $present -and $null -eq $candidate) { return $null }',
    "      if ($present -and $null -ne $candidate -and $candidate.PathName -like ('*' + $installDir + '*') -and ([string]::IsNullOrWhiteSpace($requiredState) -or [string]$candidate.State -eq $requiredState)) { return $candidate }",
    '      Start-Sleep -Milliseconds 250',
    '    } while ([DateTime]::UtcNow -lt $deadline)',
    "    if ($present) { throw ('Windows 未报告本助手 DNSCrypt 服务进入预期状态' + $(if ($requiredState) { '：' + $requiredState } else { '' })) }",
    "    throw 'Windows 仍报告 DNSCrypt 服务存在，无法安全重新安装。'",
    '  }',
    '  function Remove-OwnedDnscryptService {',
    "    $candidate = Get-CimInstance Win32_Service -Filter \"Name='dnscrypt-proxy'\" -ErrorAction SilentlyContinue",
    '    if ($null -eq $candidate) { return }',
    "    if ($candidate.PathName -notlike ('*' + $installDir + '*')) { throw '检测到其他软件安装的 dnscrypt-proxy 服务，已停止以避免覆盖。' }",
    '    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue',
    "    $exe = Join-Path $installDir 'dnscrypt-proxy.exe'",
    "    if (Test-Path -LiteralPath $exe) { Push-Location $installDir; try { Invoke-Dnscrypt @('-service','uninstall') '旧 DNSCrypt 服务卸载失败' } finally { Pop-Location } } else {",
    "      $scOut = Join-Path $env:TEMP ('kelaude-sc-' + [Guid]::NewGuid().ToString('N') + '.stdout.log'); $scErr = Join-Path $env:TEMP ('kelaude-sc-' + [Guid]::NewGuid().ToString('N') + '.stderr.log')",
    "      try { $sc = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\\sc.exe') -ArgumentList @('delete',$serviceName) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $scOut -RedirectStandardError $scErr -ErrorAction Stop; $script:LastNativeExitCode = [int]$sc.ExitCode; if ($script:LastNativeExitCode -ne 0) { throw ('Windows 服务删除失败（退出码 ' + $script:LastNativeExitCode + '）') } } finally { Remove-Item -LiteralPath $scOut,$scErr -Force -ErrorAction SilentlyContinue }",
    '    }',
    '    Wait-DnscryptService $false $null 10 | Out-Null',
    '  }',
    "  function Save-NetworkState($networkState) { $tempState = $statePath + '.' + $PID + '.tmp'; [IO.File]::WriteAllText($tempState,($networkState | ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding($false))); Move-Item -LiteralPath $tempState -Destination $statePath -Force }",
    '  function Read-NetworkStateFile {',
    '    try {',
    "      $rawState = [IO.File]::ReadAllText($statePath,[Text.Encoding]::UTF8).TrimStart([char]0xFEFF)",
    "      if ([string]::IsNullOrWhiteSpace($rawState) -or $rawState.Length -gt 5242880) { throw 'empty-or-oversized' }",
    '      $parsedState = $rawState | ConvertFrom-Json -ErrorAction Stop',
    "      if ($parsedState -is [string]) { $nestedState = ([string]$parsedState).TrimStart([char]0xFEFF); $parsedState = $nestedState | ConvertFrom-Json -ErrorAction Stop }",
    "      $schema = [int]$parsedState.Schema; if ($schema -ne 1 -and $schema -ne 2) { throw 'unsupported-schema' }",
    "      if ($null -eq $parsedState.PSObject.Properties['Adapters']) { $parsedState | Add-Member -NotePropertyName Adapters -NotePropertyValue @() }",
    '      return $parsedState',
    "    } catch { throw '无法读取 DNS 备份状态（文件损坏或版本不支持），已停止网卡恢复以避免误修改。' }",
    '  }',
    '  function Get-SafeLocalHttpProxyUri([string]$proxyServer) {',
    '    if ([string]::IsNullOrWhiteSpace($proxyServer)) { return $null }',
    '    $directEndpoint = $null; $httpEndpoint = $null; $httpsEndpoint = $null',
    "    foreach ($rawPart in @($proxyServer -split ';')) { $part = $rawPart.Trim(); if (-not $part) { continue }; if ($part -match '(?i)^http=(.+)$') { $httpEndpoint = $Matches[1].Trim(); continue }; if ($part -match '(?i)^https=(.+)$') { $httpsEndpoint = $Matches[1].Trim(); continue }; if ($part -notmatch '=') { $directEndpoint = $part } }",
    '    $endpoint = if ($httpEndpoint) { $httpEndpoint } elseif ($httpsEndpoint) { $httpsEndpoint } else { $directEndpoint }',
    "    if ([string]::IsNullOrWhiteSpace($endpoint) -or $endpoint -notmatch '^(?:(?:https?)://)?(?<host>127\\.0\\.0\\.1|localhost|\\[::1\\]):(?<port>[0-9]{1,5})/?$') { return $null }",
    '    $port = 0; if (-not [int]::TryParse($Matches.port,[ref]$port) -or $port -lt 1 -or $port -gt 65535) { return $null }',
    "    return ('http://' + $Matches.host.ToLowerInvariant() + ':' + $port)",
    '  }',
    '  function Set-DnscryptHttpProxy([string]$configPath,[string]$proxyUri) {',
    "    $content = [IO.File]::ReadAllText($configPath,[Text.Encoding]::UTF8); $lines = @($content -split \"`r?`n\")",
    "    $filtered = @($lines | Where-Object { $_ -notmatch '^\\s*http_proxy\\s*=' })",
    "    if (-not [string]::IsNullOrWhiteSpace($proxyUri)) { $insertAt = $filtered.Count; for ($i = 0; $i -lt $filtered.Count; $i++) { if ($filtered[$i] -match '^\\s*\\[') { $insertAt = $i; break } }; $before = if ($insertAt -gt 0) { @($filtered[0..($insertAt - 1)]) } else { @() }; $after = if ($insertAt -lt $filtered.Count) { @($filtered[$insertAt..($filtered.Count - 1)]) } else { @() }; $filtered = @($before + @(\"http_proxy = '$proxyUri'\") + $after) }",
    "    [IO.File]::WriteAllText($configPath,([string]::Join(\"`r`n\",$filtered)),(New-Object Text.UTF8Encoding($false)))",
    '  }',
    "  $chromePath = 'HKCU:\\Software\\Policies\\Google\\Chrome'",
    "  $edgePath = 'HKCU:\\Software\\Policies\\Microsoft\\Edge'",
    "  $stage = 'inspect-service'; $stageLabel = '检查现有 DNSCrypt 服务'",
    "  $existingService = Get-CimInstance Win32_Service -Filter \"Name='dnscrypt-proxy'\" -ErrorAction SilentlyContinue",
    "  if ($null -ne $existingService -and $existingService.PathName -notlike ('*' + $installDir + '*')) { throw '检测到其他软件安装的 dnscrypt-proxy 服务，已停止以避免覆盖。' }",
    "  $ownedServicePid = if ($null -ne $existingService) { [int]$existingService.ProcessId } else { 0 }",
    "  $stage = 'preflight-port-53'; $stageLabel = '检查本机 53 端口'",
    '  $port53 = @()',
    "  if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) { $port53 += @(Get-NetTCPConnection -State Listen -LocalPort 53 -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Protocol='TCP'; LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort; OwningProcess=$_.OwningProcess } }) }",
    "  if (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) { $port53 += @(Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Protocol='UDP'; LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort; OwningProcess=$_.OwningProcess } }) }",
    '  $conflictingPids = @($port53 | Where-Object { [int]$_.OwningProcess -gt 0 -and [int]$_.OwningProcess -ne $ownedServicePid } | Select-Object -ExpandProperty OwningProcess -Unique)',
    '  if ($conflictingPids.Count -gt 0) {',
    '    $owners = @()',
    '    foreach ($processId in $conflictingPids) {',
    "      $processName = try { (Get-Process -Id $processId -ErrorAction Stop).ProcessName } catch { '未知进程' }",
    "      $serviceNames = @(Get-CimInstance Win32_Service -Filter ('ProcessId=' + [int]$processId) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)",
    "      $serviceText = if ($serviceNames.Count -gt 0) { '；服务 ' + [string]::Join(',', $serviceNames) } else { '' }",
    "      $bindings = @($port53 | Where-Object { [int]$_.OwningProcess -eq [int]$processId } | ForEach-Object { $_.Protocol + ' ' + $_.LocalAddress + ':' + $_.LocalPort })",
    "      $owners += ('PID ' + $processId + ' (' + $processName + $serviceText + ') [' + [string]::Join(', ', $bindings) + ']')",
    '    }',
    "    throw ('本机 53 端口已被占用，DNSCrypt 无法启动。请先退出或停用占用者：' + [string]::Join('；', $owners))",
    '  }',
    "  $stage = 'backup-network-state'; $stageLabel = '备份原 DNS 配置'",
  '  if (Test-Path -LiteralPath $statePath) {',
    '    $state = Read-NetworkStateFile',
    '  } else {',
    "    $adapters = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' } | ForEach-Object { $netAdapter = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue | Select-Object -First 1; [ordered]@{ InterfaceIndex = $_.InterfaceIndex; InterfaceAlias = $_.InterfaceAlias; InterfaceGuid = if ($null -ne $netAdapter) { [string]$netAdapter.InterfaceGuid } else { $null }; ServerAddresses = @($_.ServerAddresses) } })",
    "    $state = [ordered]@{ Schema = 2; CreatedAtUtc = [DateTime]::UtcNow.ToString('o'); Adapters = $adapters; Mutations = [ordered]@{ Service = $false; AdapterDnsIndexes = @(); Firewall = $false; BrowserDns = $false }; ChromeMode = Read-RegValue $chromePath 'DnsOverHttpsMode'; ChromeTemplate = Read-RegValue $chromePath 'DnsOverHttpsTemplates'; EdgeMode = Read-RegValue $edgePath 'DnsOverHttpsMode'; EdgeTemplate = Read-RegValue $edgePath 'DnsOverHttpsTemplates' }",
    '    Save-NetworkState $state',
    '  }',
    "  $hasMutationJournal = ($null -ne $state.PSObject.Properties['Mutations'])",
    "  if (-not $hasMutationJournal) { $legacyAdapterDnsIndexes = @($state.Adapters | Where-Object { $savedAdapter = $_; $currentDns = Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex ([int]$savedAdapter.InterfaceIndex) -ErrorAction SilentlyContinue | Select-Object -First 1; @($currentDns.ServerAddresses) -contains '127.0.0.1' } | ForEach-Object { [int]$_.InterfaceIndex }); $legacyFirewall = (@(Get-NetFirewallRule -Name 'KelaudeStudio-DnsLeakGuard-UDP','KelaudeStudio-DnsLeakGuard-TCP' -ErrorAction SilentlyContinue).Count -gt 0); $currentChromeMode = Read-RegValue $chromePath 'DnsOverHttpsMode'; $currentEdgeMode = Read-RegValue $edgePath 'DnsOverHttpsMode'; $legacyBrowserDns = (($currentChromeMode.Present -and $currentChromeMode.Value -eq 'off') -or ($currentEdgeMode.Present -and $currentEdgeMode.Value -eq 'off')); $state | Add-Member -NotePropertyName Mutations -NotePropertyValue ([pscustomobject]@{ Service = ($null -ne $existingService); AdapterDnsIndexes = @($legacyAdapterDnsIndexes); Firewall = $legacyFirewall; BrowserDns = $legacyBrowserDns }); Save-NetworkState $state }",
    '  $adapterDnsModified = @($state.Mutations.AdapterDnsIndexes | ForEach-Object { [int]$_ })',
    '  $mutationStarted = $true',
    "  $mutationStage = 'service-files'",
    '  $state.Mutations.Service = $true; Save-NetworkState $state',
    "  $stage = 'replace-service'; $stageLabel = '替换 DNSCrypt 系统服务'",
    '  if ($null -ne $existingService) { Remove-OwnedDnscryptService }',
    '  if (Test-Path -LiteralPath $installDir) { Remove-Item -LiteralPath $installDir -Recurse -Force -ErrorAction Stop }',
    '  New-Item -ItemType Directory -Path $installDir -Force | Out-Null',
    "  foreach ($name in @('dnscrypt-proxy.exe','dnscrypt-proxy.toml','public-resolvers.md','public-resolvers.md.minisig','LICENSE')) { Copy-Item -LiteralPath (Join-Path $sourceDir $name) -Destination (Join-Path $installDir $name) -Force }",
    "  # DNSCrypt 作为 LocalSystem 服务直接连接多个 DoH 上游，不绑定 Clash、v2rayN 或其他可能随时退出的本机代理端口。",
    "  Set-DnscryptHttpProxy (Join-Path $installDir 'dnscrypt-proxy.toml') $null",
    '  Push-Location $installDir',
    '  try {',
    "    $stage = 'validate-dnscrypt-config'; $stageLabel = '验证 DNSCrypt 配置'",
    "    $mutationStage = 'validate-config'",
    "    Invoke-Dnscrypt @('-config','.\\dnscrypt-proxy.toml','-check') '加密 DNS 配置检查失败'",
    "    $stage = 'install-dnscrypt-service'; $stageLabel = '安装 DNSCrypt 服务'",
    "    $mutationStage = 'install-service'",
    '    # dnscrypt-proxy.exe -service install',
    "    Invoke-Dnscrypt @('-service','install') '加密 DNS 服务安装失败'",
    "    $installedService = Wait-DnscryptService $true $null 10; if ($null -eq $installedService -or $installedService.PathName -notlike ('*' + $installDir + '*')) { throw '加密 DNS 服务安装后未通过 Windows 服务验证。' }",
    "    $stage = 'start-dnscrypt-service'; $stageLabel = '启动 DNSCrypt 服务'",
    "    $mutationStage = 'start-service'",
    "    Invoke-Dnscrypt @('-service','start') '加密 DNS 服务启动失败'",
    '  } finally { Pop-Location }',
    "  $service = Get-Service -Name $serviceName -ErrorAction Stop; $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(15)); $service.Refresh(); if ($service.Status -ne 'Running') { throw '加密 DNS 服务未进入 Running 状态。' }; Wait-DnscryptService $true 'Running' 5 | Out-Null",
    "  $scExe = Join-Path $env:SystemRoot 'System32\\sc.exe'",
    "  & $scExe failure $serviceName reset= 60 actions= 'restart/5000/restart/10000/restart/30000' | Out-Null; if ($LASTEXITCODE -ne 0) { throw '无法配置 DNSCrypt 服务自动重启。' }",
    "  & $scExe failureflag $serviceName 1 | Out-Null; if ($LASTEXITCODE -ne 0) { throw '无法启用 DNSCrypt 服务失败恢复。' }",
    "  $stage = 'verify-local-resolver-before-network-change'; $stageLabel = '变更前验证本地加密 DNS'",
    "  $preflightResolved = Resolve-DnsName -Name 'cloudflare.com' -Server '127.0.0.1' -DnsOnly -Type A -ErrorAction Stop",
    "  if (@($preflightResolved | Where-Object IPAddress).Count -eq 0) { throw '本地加密 DNS 在修改网卡前未能解析测试域名。' }",
    "  $stage = 'set-adapter-dns'; $stageLabel = '设置网卡 DNS'",
    "  $virtualPattern = '(?i)loopback|tunnel|tun|tap|wintun|wireguard|clash|v2ray|sing-box|tailscale|zerotier|hyper-v|vmware|virtualbox|docker|wsl|vethernet'",
    "  $connectedAdapters = @(Get-NetIPInterface -AddressFamily IPv4 -ConnectionState Connected | ForEach-Object { $ipInterface = $_; $adapter = Get-NetAdapter -InterfaceIndex $ipInterface.InterfaceIndex -ErrorAction SilentlyContinue | Select-Object -First 1; if ($null -ne $adapter -and $adapter.Status -eq 'Up' -and $adapter.HardwareInterface -eq $true -and $adapter.InterfaceAlias -notmatch $virtualPattern) { [pscustomobject]@{ InterfaceIndex=[int]$ipInterface.InterfaceIndex; InterfaceAlias=[string]$adapter.InterfaceAlias } } } | Sort-Object InterfaceIndex -Unique)",
    "  if ($connectedAdapters.Count -eq 0) { throw '没有检测到可安全接管的已连接物理 IPv4 网卡；为避免代理/TUN 断网，本次未修改网络。' }",
    "  $connected = @($connectedAdapters | Select-Object -ExpandProperty InterfaceIndex)",
    "  $connectedAliases = @($connectedAdapters | Select-Object -ExpandProperty InterfaceAlias)",
    "  $mutationStage = 'adapter-dns'",
    "  foreach ($index in $connected) { $adapterDnsModified = @($adapterDnsModified + [int]$index | Select-Object -Unique); $state.Mutations.AdapterDnsIndexes = @($adapterDnsModified); Save-NetworkState $state; Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses @('127.0.0.1') -ErrorAction Stop }",
    "  $stage = 'install-firewall-rules'; $stageLabel = '安装 DNS 防泄漏防火墙规则'",
    "  $mutationStage = 'firewall'",
    '  $state.Mutations.Firewall = $true; Save-NetworkState $state',
    "  Remove-NetFirewallRule -Name 'KelaudeStudio-DnsLeakGuard-UDP','KelaudeStudio-DnsLeakGuard-TCP' -ErrorAction SilentlyContinue",
    "  New-NetFirewallRule -Name 'KelaudeStudio-DnsLeakGuard-UDP' -DisplayName 'Kelaude Studio DNS Leak Guard UDP' -Group 'Kelaude Studio Cleaner' -Direction Outbound -Action Block -Protocol UDP -RemotePort 53 -InterfaceAlias $connectedAliases -Profile Any | Out-Null",
    "  New-NetFirewallRule -Name 'KelaudeStudio-DnsLeakGuard-TCP' -DisplayName 'Kelaude Studio DNS Leak Guard TCP' -Group 'Kelaude Studio Cleaner' -Direction Outbound -Action Block -Protocol TCP -RemotePort 53 -InterfaceAlias $connectedAliases -Profile Any | Out-Null",
    "  $stage = 'configure-browser-dns'; $stageLabel = '设置浏览器使用系统 DNS'",
    "  $mutationStage = 'browser-dns'",
    '  $state.Mutations.BrowserDns = $true; Save-NetworkState $state',
    '  New-Item -Path $chromePath -Force | Out-Null; New-Item -Path $edgePath -Force | Out-Null',
    "  New-ItemProperty -Path $chromePath -Name 'DnsOverHttpsMode' -PropertyType String -Value 'off' -Force | Out-Null; Remove-ItemProperty -Path $chromePath -Name 'DnsOverHttpsTemplates' -ErrorAction SilentlyContinue",
    "  New-ItemProperty -Path $edgePath -Name 'DnsOverHttpsMode' -PropertyType String -Value 'off' -Force | Out-Null; Remove-ItemProperty -Path $edgePath -Name 'DnsOverHttpsTemplates' -ErrorAction SilentlyContinue",
    "  $stage = 'verify-local-resolver'; $stageLabel = '验证本地加密 DNS'",
    "  $resolved = Resolve-DnsName -Name 'cloudflare.com' -Server '127.0.0.1' -DnsOnly -Type A -ErrorAction Stop",
    "  if (@($resolved | Where-Object IPAddress).Count -eq 0) { throw '本地加密 DNS 服务未能解析测试域名。' }",
    "  $defaultResolved = Resolve-DnsName -Name 'cloudflare.com' -DnsOnly -Type A -ErrorAction Stop",
    "  if (@($defaultResolved | Where-Object IPAddress).Count -eq 0) { throw '网卡切换后系统默认 DNS 未能解析测试域名。' }",
    "  $verifiedRules = @(Get-NetFirewallRule -Name 'KelaudeStudio-DnsLeakGuard-UDP','KelaudeStudio-DnsLeakGuard-TCP' | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block' })",
    "  if ($verifiedRules.Count -ne 2) { throw '系统未报告预期的 DNS 防火墙规则。' }",
    '  Clear-DnsClientCache',
    "  Write-Output 'DNS_LEAK_PROTECTION_OK'",
    ...operationEpilogue('DNS 防泄漏已成功启用。'),
  ].join('\r\n');
}

function buildWindowsRestoreScript(statePath, operation = {}) {
  const resolvedOperation = {
    operationId: operation.operationId || 'standalone-restore',
    resultPath: operation.resultPath || `${statePath}.restore-result.json`,
  };
  return [
    "$ErrorActionPreference = 'Stop'",
    "$ProgressPreference = 'SilentlyContinue'",
    '[Console]::OutputEncoding = [Text.Encoding]::UTF8',
    `$statePath = ${quotePowerShell(statePath)}`,
    "$installDir = Join-Path $env:ProgramData 'KelaudeStudio\\DnsCryptProxy'",
    "$serviceName = 'dnscrypt-proxy'",
    ...operationPrelude(resolvedOperation, 'restore'),
    'try {',
    "  $stage = 'prepare-diagnostics'; $stageLabel = '准备诊断记录'",
    '  New-Item -ItemType Directory -Path (Split-Path -Parent $resultPath) -Force | Out-Null',
    "  function Invoke-Dnscrypt([string[]]$arguments,[string]$failureMessage) {",
    "    $stdoutPath = Join-Path $env:TEMP ('kelaude-dnscrypt-' + [Guid]::NewGuid().ToString('N') + '.stdout.log')",
    "    $stderrPath = Join-Path $env:TEMP ('kelaude-dnscrypt-' + [Guid]::NewGuid().ToString('N') + '.stderr.log')",
    '    try {',
    "      $process = Start-Process -FilePath (Join-Path (Get-Location) 'dnscrypt-proxy.exe') -ArgumentList $arguments -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -ErrorAction Stop",
    '      $script:LastNativeExitCode = [int]$process.ExitCode',
    "      $output = @(); if (Test-Path -LiteralPath $stdoutPath) { $output += @([IO.File]::ReadAllLines($stdoutPath)) }; if (Test-Path -LiteralPath $stderrPath) { $output += @([IO.File]::ReadAllLines($stderrPath)) }",
    "      if ($script:LastNativeExitCode -ne 0) { $detail = ([string]::Join(' ', @($output))).Trim(); if ($detail.Length -gt 500) { $detail = $detail.Substring(0,500) + '...' }; throw ($failureMessage + '（退出码 ' + $script:LastNativeExitCode + '）' + $(if ($detail) { '：' + $detail } else { '' })) }",
    '    } finally { Remove-Item -LiteralPath $stdoutPath,$stderrPath -Force -ErrorAction SilentlyContinue }',
    '  }',
    '  function Wait-DnscryptServiceRemoved([int]$seconds) {',
    '    $deadline = [DateTime]::UtcNow.AddSeconds($seconds)',
    "    do { if ($null -eq (Get-CimInstance Win32_Service -Filter \"Name='dnscrypt-proxy'\" -ErrorAction SilentlyContinue)) { return }; Start-Sleep -Milliseconds 250 } while ([DateTime]::UtcNow -lt $deadline)",
    "    throw 'Windows 仍报告 DNSCrypt 服务存在。'",
    '  }',
    '  function Read-NetworkStateFile {',
    '    try {',
    "      $rawState = [IO.File]::ReadAllText($statePath,[Text.Encoding]::UTF8).TrimStart([char]0xFEFF)",
    "      if ([string]::IsNullOrWhiteSpace($rawState) -or $rawState.Length -gt 5242880) { throw 'empty-or-oversized' }",
    '      $parsedState = $rawState | ConvertFrom-Json -ErrorAction Stop',
    "      if ($parsedState -is [string]) { $nestedState = ([string]$parsedState).TrimStart([char]0xFEFF); $parsedState = $nestedState | ConvertFrom-Json -ErrorAction Stop }",
    "      $schema = [int]$parsedState.Schema; if ($schema -ne 1 -and $schema -ne 2) { throw 'unsupported-schema' }",
    "      if ($null -eq $parsedState.PSObject.Properties['Adapters']) { $parsedState | Add-Member -NotePropertyName Adapters -NotePropertyValue @() }",
    '      return $parsedState',
    "    } catch { throw '无法读取 DNS 备份状态（文件损坏或版本不支持），已停止网卡恢复以避免误修改。' }",
    '  }',
    "  $stage = 'load-network-state'; $stageLabel = '读取原 DNS 备份'",
    "  if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) { throw '未找到启用防泄漏前的网络状态，未执行恢复。' }",
    '  $state = Read-NetworkStateFile',
    "  $hasMutationJournal = ($null -ne $state.PSObject.Properties['Mutations'])",
    "  $restoreService = (-not $hasMutationJournal -or [bool]$state.Mutations.Service)",
    "  $restoreFirewall = (-not $hasMutationJournal -or [bool]$state.Mutations.Firewall)",
    "  $restoreBrowserDns = (-not $hasMutationJournal -or [bool]$state.Mutations.BrowserDns)",
    "  $adapterIndexesToRestore = if ($hasMutationJournal) { @($state.Mutations.AdapterDnsIndexes | ForEach-Object { [int]$_ }) } else { @($state.Adapters | ForEach-Object { [int]$_.InterfaceIndex }) }",
    '  $mutationStarted = $true',
    '  $restoreErrors = @()',
    "  $stage = 'remove-firewall-rules'; $stageLabel = '删除 DNS 防泄漏防火墙规则'",
    "  $mutationStage = 'restore-firewall'",
    "  if ($restoreFirewall) { try { Remove-NetFirewallRule -Name 'KelaudeStudio-DnsLeakGuard-UDP','KelaudeStudio-DnsLeakGuard-TCP' -ErrorAction SilentlyContinue } catch { $restoreErrors += ('防火墙规则：' + $_.Exception.Message) } }",
    "  $stage = 'restore-adapter-dns'; $stageLabel = '恢复网卡 DNS'",
    "  $mutationStage = 'restore-adapter-dns'",
    '  foreach ($adapter in @($state.Adapters)) {',
    '    $index = [int]$adapter.InterfaceIndex',
    '    if ($adapterIndexesToRestore -notcontains $index) { continue }',
    "    $currentInterface = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $index -ErrorAction SilentlyContinue | Select-Object -First 1",
    '    if ($null -eq $currentInterface -or [string]$currentInterface.InterfaceAlias -ne [string]$adapter.InterfaceAlias) { continue }',
    "    if (-not [string]::IsNullOrWhiteSpace([string]$adapter.InterfaceGuid)) { $currentAdapter = Get-NetAdapter -InterfaceIndex $index -ErrorAction SilentlyContinue | Select-Object -First 1; if ($null -eq $currentAdapter -or [string]$currentAdapter.InterfaceGuid -ne [string]$adapter.InterfaceGuid) { continue } }",
    '    try {',
    "      $currentDns = Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $index -ErrorAction Stop | Select-Object -First 1",
    "      $requiresRestore = (@($currentDns.ServerAddresses) -contains '127.0.0.1')",
    '      if (-not $requiresRestore) { continue }',
    "      if (@($adapter.ServerAddresses).Count -gt 0) { Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses @($adapter.ServerAddresses) -ErrorAction Stop } else { Set-DnsClientServerAddress -InterfaceIndex $index -ResetServerAddresses -ErrorAction Stop }",
    '      $adapterDnsModified = @($adapterDnsModified + $index | Select-Object -Unique)',
    "    } catch { $restoreErrors += ('网卡 ' + $index + '：' + $_.Exception.Message) }",
    '  }',
    "  $stage = 'restore-legacy-doh'; $stageLabel = '恢复系统 DoH'",
    "  try { if ($null -ne $state.Doh -and (Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue)) { foreach ($entry in @($state.Doh)) { $current = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | Where-Object ServerAddress -eq $entry.ServerAddress | Select-Object -First 1; if ($entry.Present) { if ($null -eq $current) { Add-DnsClientDohServerAddress -ServerAddress $entry.ServerAddress -DohTemplate $entry.DohTemplate -AutoUpgrade ([bool]$entry.AutoUpgrade) -AllowFallbackToUdp ([bool]$entry.AllowFallbackToUdp) | Out-Null } else { Set-DnsClientDohServerAddress -ServerAddress $entry.ServerAddress -DohTemplate $entry.DohTemplate -AutoUpgrade ([bool]$entry.AutoUpgrade) -AllowFallbackToUdp ([bool]$entry.AllowFallbackToUdp) | Out-Null } } elseif ($null -ne $current) { Remove-DnsClientDohServerAddress -ServerAddress $entry.ServerAddress -ErrorAction SilentlyContinue } } } } catch { $restoreErrors += ('DoH：' + $_.Exception.Message) }",
    "  $stage = 'remove-dnscrypt-service'; $stageLabel = '删除 DNSCrypt 服务'",
    "  $mutationStage = 'restore-service'",
    '  # dnscrypt-proxy.exe -service uninstall',
    '  if ($restoreService) { try {',
    "    $service = Get-CimInstance Win32_Service -Filter \"Name='dnscrypt-proxy'\" -ErrorAction SilentlyContinue",
    "    if ($null -ne $service -and $service.PathName -like ('*' + $installDir + '*')) {",
    '      Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue',
    "      $exe = Join-Path $installDir 'dnscrypt-proxy.exe'",
    "      if (Test-Path -LiteralPath $exe) { Push-Location $installDir; try { Invoke-Dnscrypt @('-service','uninstall') 'DNSCrypt 服务卸载失败' } finally { Pop-Location } } else {",
    "        $scOut = Join-Path $env:TEMP ('kelaude-sc-' + [Guid]::NewGuid().ToString('N') + '.stdout.log'); $scErr = Join-Path $env:TEMP ('kelaude-sc-' + [Guid]::NewGuid().ToString('N') + '.stderr.log')",
    "        try { $sc = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\\sc.exe') -ArgumentList @('delete',$serviceName) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $scOut -RedirectStandardError $scErr -ErrorAction Stop; $script:LastNativeExitCode = [int]$sc.ExitCode; if ($script:LastNativeExitCode -ne 0) { throw ('sc.exe 返回退出码 ' + $script:LastNativeExitCode) } } finally { Remove-Item -LiteralPath $scOut,$scErr -Force -ErrorAction SilentlyContinue }",
    '      }',
    '      Wait-DnscryptServiceRemoved 10',
    '    }',
    "  } catch { $restoreErrors += ('DNSCrypt 服务：' + $_.Exception.Message) } }",
    "  $stage = 'restore-browser-dns'; $stageLabel = '恢复浏览器 DNS 配置'",
    "  $mutationStage = 'restore-browser-dns'",
    "  function Restore-RegValue([string]$regPath,[string]$name,$saved) { if ($null -ne $saved -and $saved.Present) { New-Item -Path $regPath -Force | Out-Null; New-ItemProperty -Path $regPath -Name $name -PropertyType String -Value ([string]$saved.Value) -Force | Out-Null } else { Remove-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue } }",
    "  if ($restoreBrowserDns) { try { $chromePath = 'HKCU:\\Software\\Policies\\Google\\Chrome'; $edgePath = 'HKCU:\\Software\\Policies\\Microsoft\\Edge'; Restore-RegValue $chromePath 'DnsOverHttpsMode' $state.ChromeMode; Restore-RegValue $chromePath 'DnsOverHttpsTemplates' $state.ChromeTemplate; Restore-RegValue $edgePath 'DnsOverHttpsMode' $state.EdgeMode; Restore-RegValue $edgePath 'DnsOverHttpsTemplates' $state.EdgeTemplate } catch { $restoreErrors += ('浏览器 DNS：' + $_.Exception.Message) } }",
    "  try { Clear-DnsClientCache } catch { $restoreErrors += ('DNS 缓存：' + $_.Exception.Message) }",
    "  if ($restoreService) { try { Remove-Item -LiteralPath $installDir -Recurse -Force -ErrorAction Stop } catch { if (Test-Path -LiteralPath $installDir) { $restoreErrors += ('服务目录：' + $_.Exception.Message) } } }",
    "  if ($restoreErrors.Count -gt 0) { $stage = 'rollback-incomplete'; $stageLabel = '回滚未完全完成'; throw ([string]::Join('；', $restoreErrors)) }",
    '  Remove-Item -LiteralPath $statePath -Force',
    "  Write-Output 'DNS_LEAK_PROTECTION_RESTORED'",
    ...operationEpilogue('DNS 防泄漏配置已完整恢复。'),
  ].join('\r\n');
}

function buildWindowsEmergencyRestoreScript(operation = {}, statePath = '') {
  const resolvedOperation = {
    operationId: operation.operationId || 'standalone-emergency-restore',
    resultPath: operation.resultPath || path.join(process.cwd(), 'dns-emergency-restore-result.json'),
  };
  return [
    "$ErrorActionPreference = 'Stop'",
    "$ProgressPreference = 'SilentlyContinue'",
    '[Console]::OutputEncoding = [Text.Encoding]::UTF8',
    "$installDir = Join-Path $env:ProgramData 'KelaudeStudio\\DnsCryptProxy'",
    "$serviceName = 'dnscrypt-proxy'",
    `$statePath = ${quotePowerShell(statePath)}`,
    `$expectedExeHash = '${DNSCRYPT_EXE_SHA256}'`,
    ...operationPrelude(resolvedOperation, 'emergency-restore'),
    'try {',
    "  $stage = 'prepare-diagnostics'; $stageLabel = '准备应急恢复诊断'",
    '  New-Item -ItemType Directory -Path (Split-Path -Parent $resultPath) -Force | Out-Null',
    "  $stage = 'inspect-owned-state'; $stageLabel = '核对本助手网络改动'",
    "  $ownedRules = @()",
    "  foreach ($candidateRule in @(Get-NetFirewallRule -Name 'KelaudeStudio-DnsLeakGuard-UDP','KelaudeStudio-DnsLeakGuard-TCP' -ErrorAction SilentlyContinue)) {",
    "    $expectedProtocol = if ($candidateRule.Name -eq 'KelaudeStudio-DnsLeakGuard-UDP') { 'UDP' } elseif ($candidateRule.Name -eq 'KelaudeStudio-DnsLeakGuard-TCP') { 'TCP' } else { '' }",
    "    $expectedProtocolNumber = if ($expectedProtocol -eq 'UDP') { '17' } elseif ($expectedProtocol -eq 'TCP') { '6' } else { '' }",
    "    $expectedPortSets = if ($expectedProtocol -eq 'UDP') { @('53','137,53,5353,5355,853') } else { @('53','53,853') }",
    "    $portFilter = $candidateRule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | Select-Object -First 1; $actualPorts = @(@($portFilter.RemotePort) | ForEach-Object { @([string]$_ -split ',') } | ForEach-Object { $_.Trim() } | Sort-Object -Unique)",
    "    $protocolText = [string]$portFilter.Protocol; $protocolMatches = ($protocolText -eq $expectedProtocol -or $protocolText -eq $expectedProtocolNumber)",
    "    $actualPortText = [string]::Join(',', $actualPorts)",
    "    if ($candidateRule.Direction -eq 'Outbound' -and $candidateRule.Action -eq 'Block' -and [string]$candidateRule.Group -eq 'Kelaude Studio Cleaner' -and $protocolMatches -and $expectedPortSets -contains $actualPortText) { $ownedRules += $candidateRule }",
    "  }",
    "  $service = Get-CimInstance Win32_Service -Filter \"Name='dnscrypt-proxy'\" -ErrorAction SilentlyContinue",
    "  $ownedBinary = $false; $ownedExe = Join-Path $installDir 'dnscrypt-proxy.exe'",
    "  if (Test-Path -LiteralPath $ownedExe -PathType Leaf) { try { $ownedBinary = ((Get-FileHash -LiteralPath $ownedExe -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -eq $expectedExeHash) } catch { $ownedBinary = $false } }",
    "  $serviceExe = ''; if ($null -ne $service) { $serviceCommand = [Environment]::ExpandEnvironmentVariables([string]$service.PathName).Trim(); if ($serviceCommand.StartsWith([char]34)) { $closingQuote = $serviceCommand.IndexOf([char]34,1); if ($closingQuote -gt 1) { $serviceExe = $serviceCommand.Substring(1,$closingQuote-1) } } else { $serviceExe = @($serviceCommand -split '\\s+',2)[0] } }",
    "  $ownedService = ($ownedBinary -and -not [string]::IsNullOrWhiteSpace($serviceExe) -and [IO.Path]::GetFullPath($serviceExe) -eq [IO.Path]::GetFullPath($ownedExe))",
    "  $lockedAdapters = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $values = @($_.ServerAddresses | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }); $values.Count -eq 1 -and [string]$values[0] -eq '127.0.0.1' })",
    '  $trustedAdapters = @(); $trustedIndexes = @()',
    '  if (-not [string]::IsNullOrWhiteSpace($statePath) -and (Test-Path -LiteralPath $statePath -PathType Leaf)) { try {',
    '    $stateInfo = Get-Item -LiteralPath $statePath -ErrorAction Stop; if ($stateInfo.Length -gt 1048576) { throw \'备份状态文件过大\' }',
    "    $stateRaw = [IO.File]::ReadAllText($statePath,[Text.Encoding]::UTF8).TrimStart([char]0xFEFF); $state = $stateRaw | ConvertFrom-Json -ErrorAction Stop",
    "    if ($null -eq $state.PSObject.Properties['Mutations'] -or $null -eq $state.Mutations.PSObject.Properties['AdapterDnsIndexes']) { throw '备份状态不含可信的网卡变更清单' }",
    '    $mutatedIndexes = @($state.Mutations.AdapterDnsIndexes | ForEach-Object { [int]$_ })',
    '    foreach ($saved in @($state.Adapters)) {',
    '      $index = [int]$saved.InterfaceIndex; if ($mutatedIndexes -notcontains $index) { continue }',
    "      $currentInterface = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $index -ErrorAction SilentlyContinue | Select-Object -First 1; if ($null -eq $currentInterface -or [string]$currentInterface.InterfaceAlias -ne [string]$saved.InterfaceAlias) { continue }",
    "      if (-not [string]::IsNullOrWhiteSpace([string]$saved.InterfaceGuid)) { $currentAdapter = Get-NetAdapter -InterfaceIndex $index -ErrorAction SilentlyContinue | Select-Object -First 1; if ($null -eq $currentAdapter -or [string]$currentAdapter.InterfaceGuid -ne [string]$saved.InterfaceGuid) { continue } }",
    '      $currentDns = Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $index -ErrorAction SilentlyContinue | Select-Object -First 1; $currentValues = @($currentDns.ServerAddresses | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })',
    "      if ($currentValues.Count -eq 1 -and [string]$currentValues[0] -eq '127.0.0.1') { $trustedAdapters += $currentDns; $trustedIndexes += $index }",
    '    }',
    '  } catch { $trustedAdapters = @(); $trustedIndexes = @() } }',
    '  $untrustedLockedAdapters = @($lockedAdapters | Where-Object { $trustedIndexes -notcontains [int]$_.InterfaceIndex })',
    '  $safeToDisableService = ($ownedService -and $trustedAdapters.Count -gt 0 -and $untrustedLockedAdapters.Count -eq 0)',
    '  $hasRecoverableMutation = ($ownedRules.Count -gt 0 -or $trustedAdapters.Count -gt 0 -or $safeToDisableService)',
    '  if (-not $hasRecoverableMutation) {',
    "    Write-Output 'KELAUDE_EMERGENCY_NO_OWNED_CHANGES'",
    '  } else {',
    '    $mutationStarted = $true',
    "    $stage = 'remove-firewall-rules'; $stageLabel = '移除本助手 DNS 防火墙规则'; $mutationStage = 'restore-firewall'",
    "    if ($ownedRules.Count -gt 0) { $ownedRules | Remove-NetFirewallRule -ErrorAction Stop }",
    "    $stage = 'restore-adapter-dns'; $stageLabel = '恢复被锁定的网卡 DNS'; $mutationStage = 'restore-adapter-dns'",
    '    foreach ($adapter in $trustedAdapters) {',
    '      $index = [int]$adapter.InterfaceIndex',
    '      Set-DnsClientServerAddress -InterfaceIndex $index -ResetServerAddresses -ErrorAction Stop',
    '      $adapterDnsModified = @($adapterDnsModified + $index | Select-Object -Unique)',
    '    }',
    "    $stage = 'disable-owned-service'; $stageLabel = '停用本助手 DNSCrypt 服务'; $mutationStage = 'restore-service'",
    '    if ($safeToDisableService) { Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue; Set-Service -Name $serviceName -StartupType Disabled -ErrorAction Stop }',
    "    $stage = 'flush-dns-cache'; $stageLabel = '刷新 DNS 缓存'; $mutationStage = 'flush-dns-cache'",
    '    Clear-DnsClientCache',
    "    Write-Output 'KELAUDE_EMERGENCY_NETWORK_RESTORED'",
    '  }',
    ...operationEpilogue('网络应急恢复检查已完成。'),
  ].join('\r\n');
}

async function createDiagnosticOperation(context, action) {
  const operationId = crypto.randomUUID().replace(/-/g, '');
  const directory = context.pathApi.join(context.userDataDir, DNS_DIAGNOSTIC_DIR);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  return {
    operationId,
    resultPath: context.pathApi.join(directory, `${timestamp}-${action}-${operationId}.json`),
  };
}

async function readDiagnosticResult(operation) {
  try {
    const raw = (await fs.readFile(operation.resultPath, 'utf8')).replace(/^\uFEFF/, '');
    const result = JSON.parse(raw);
    if (result.Schema !== 1 || result.OperationId !== operation.operationId) return null;
    return result;
  } catch {
    return null;
  }
}

async function writeNodeDiagnostic(operation, action, fields) {
  const payload = {
    Schema: 1,
    OperationId: operation.operationId,
    Action: action,
    Success: false,
    Stage: fields.stage,
    StageLabel: fields.stageLabel,
    Message: fields.message,
    HResult: fields.hresult || 0,
    ExitCode: fields.exitCode || 1,
    MutationStarted: false,
    DnscryptVersion: DNSCRYPT_VERSION,
    TimestampUtc: new Date().toISOString(),
  };
  const temporary = `${operation.resultPath}.${process.pid}.tmp`;
  await fs.writeFile(temporary, JSON.stringify(payload), { encoding: 'utf8', mode: 0o600 });
  await fs.rename(temporary, operation.resultPath);
  return payload;
}

function diagnosticMessage(result, resultPath) {
  const details = [];
  if (Number(result.ExitCode)) details.push(`退出码 ${result.ExitCode}`);
  if (Number(result.HResult)) details.push(`HRESULT ${result.HResult}`);
  const suffix = details.length ? `（${details.join('，')}）` : '';
  const stage = String(result.Stage || '');
  let message = String(result.Message || '未知错误').replace(/[\r\n\t]+/g, ' ').replace(/\s{2,}/g, ' ').trim();
  if (stage === 'load-network-state' && /[\[{].{40,}/.test(message)) {
    message = 'DNS 备份状态无法解析，已停止网卡恢复以避免误修改。';
  } else if (message.length > 600) {
    message = `${message.slice(0, 600)}...`;
  }
  return `${result.StageLabel || result.Stage || '未知阶段'}：${message}${suffix}。诊断记录：${resultPath}`;
}

function compressedPowerShellCommand(script) {
  const compressed = zlib.gzipSync(Buffer.from(script, 'utf8')).toString('base64');
  const loader = `$b=[Convert]::FromBase64String('${compressed}');$m=New-Object IO.MemoryStream(,$b);$g=New-Object IO.Compression.GZipStream($m,[IO.Compression.CompressionMode]::Decompress);$r=New-Object IO.StreamReader($g,[Text.Encoding]::UTF8);& ([ScriptBlock]::Create($r.ReadToEnd()))`;
  return Buffer.from(loader, 'utf16le').toString('base64');
}

async function runElevatedWindowsScript(context, script, commandRunner, operation, action) {
  const powershell = context.pathApi.join(context.env.SystemRoot || context.env.WINDIR || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const encoded = compressedPowerShellCommand(script);
  const cancelWriter = [
    `$resultPath=${quotePowerShell(operation.resultPath)}`,
    `$operationId=${quotePowerShell(operation.operationId)}`,
    'try {',
    `  $p=Start-Process -FilePath ${quotePowerShell(powershell)} -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand','${encoded}') -Verb RunAs -Wait -PassThru`,
    '  exit $p.ExitCode',
    '} catch {',
    '  $h=[int64]$_.Exception.HResult',
    "  $cancelled=($h -eq -2147023673 -or $_.Exception.NativeErrorCode -eq 1223 -or $_.Exception.Message -match 'cancel|canceled|cancelled|取消')",
    "  $message=if($cancelled){'用户取消了 Windows 管理员授权。'}else{'无法启动 Windows 管理员操作：'+$_.Exception.Message}",
    "  $payload=[ordered]@{Schema=1;OperationId=$operationId;Action='${action}';Success=$false;Stage='authorization';StageLabel='Windows 管理员授权';Message=$message;HResult=$h;ExitCode=$(if($cancelled){1223}else{125});MutationStarted=$false;DnscryptVersion='${DNSCRYPT_VERSION}';TimestampUtc=[DateTime]::UtcNow.ToString('o')}",
    '  try{[IO.File]::WriteAllText($resultPath,($payload|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)))}catch{}',
    '  if($cancelled){exit 1223}else{exit 125}',
    '}',
  ].join(';');
  const result = await commandRunner(
    powershell,
    ['-NoProfile', '-NonInteractive', '-Command', cancelWriter],
    { timeoutMs: 5 * 60 * 1000 },
  );
  let diagnostic = await readDiagnosticResult(operation);
  if (result.code !== 0) {
    if (!diagnostic) {
      const uacCancelled = result.code === 1223 || result.code === 199;
      diagnostic = await writeNodeDiagnostic(operation, action, {
        stage: 'authorization-or-elevated-process',
        stageLabel: uacCancelled ? 'Windows 管理员授权' : '管理员子进程',
        message: uacCancelled ? '用户取消了 Windows 管理员授权。' : `管理员子进程异常结束，未返回详细结果（外层退出码 ${result.code}）。`,
        exitCode: result.code,
      });
    }
    const error = new Error(diagnosticMessage(diagnostic, operation.resultPath));
    error.diagnostic = diagnostic;
    error.diagnosticPath = operation.resultPath;
    throw error;
  }
  return { ...result, diagnostic };
}

async function verifyDnsConnectivity(fetchImpl) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetchImpl(DNS_PROBE_URL, { cache: 'no-store', signal: controller.signal });
    if (!response || !response.ok) throw new Error(`HTTPS 探测返回 ${response?.status || '未知状态'}`);
    const body = await response.text();
    if (!/(^|\n)ip=/.test(body)) throw new Error('HTTPS 探测响应格式无效');
  } finally {
    clearTimeout(timer);
  }
}

async function isRegularFile(filePath) {
  try {
    const stat = await fs.lstat(filePath);
    return stat.isFile() && !stat.isSymbolicLink();
  } catch {
    return false;
  }
}

async function rollbackAfterFailure(context, statePath, commandRunner, originalError, reasonPrefix, options = {}) {
  const hasState = await isRegularFile(statePath);
  const mutationStarted = originalError.diagnostic?.MutationStarted;
  if ((!hasState && !options.attemptWithoutState) || mutationStarted === false) {
    throw new Error(`${reasonPrefix}（未更改网络配置）：${originalError.message}`);
  }
  const restoreOperation = await createDiagnosticOperation(context, 'auto-restore');
  try {
    await runElevatedWindowsScript(
      context,
      buildWindowsRestoreScript(statePath, restoreOperation),
      commandRunner,
      restoreOperation,
      'auto-restore',
    );
  } catch (restoreError) {
    if (!hasState && restoreError.diagnostic?.Stage === 'load-network-state') {
      throw new Error(`${reasonPrefix}（未找到可恢复的网络备份，未执行回滚）：${originalError.message}；${restoreError.message}`);
    }
    throw new Error(`${reasonPrefix}，自动恢复也未完成：${originalError.message}；恢复错误：${restoreError.message}`);
  }
  throw new Error(`${reasonPrefix}，已恢复原网络配置：${originalError.message}`);
}

async function enableWindowsDnsLeakProtection(context, options = {}) {
  if (context.platform !== 'win32') throw new Error('系统级 DNS 强制防泄漏当前仅支持 Windows；macOS 需要签名的 Network Extension 系统扩展。');
  const commandRunner = options.commandRunner;
  if (typeof commandRunner !== 'function') throw new Error('DNS 防泄漏命令执行器不可用。');
  const sourceDir = options.sourceDir || context.dnscryptRoot;
  await verifyDnscryptAssets(sourceDir);
  const statePath = backupPath(context);
  await fs.mkdir(path.dirname(statePath), { recursive: true });
  const enableOperation = await createDiagnosticOperation(context, 'enable');
  try {
    await runElevatedWindowsScript(
      context,
      buildWindowsEnableScript(statePath, sourceDir, enableOperation),
      commandRunner,
      enableOperation,
      'enable',
    );
  } catch (error) {
    return rollbackAfterFailure(context, statePath, commandRunner, error, 'DNS 防泄漏未能完成');
  }
  try {
    await verifyDnsConnectivity(options.fetchImpl || globalThis.fetch);
  } catch (error) {
    const connectivityError = new Error(`启用后 HTTPS 连通性验证失败：${error.message}`);
    connectivityError.diagnostic = { MutationStarted: true };
    return rollbackAfterFailure(context, statePath, commandRunner, connectivityError, '网络验证失败', { attemptWithoutState: true });
  }
  return {
    changed: 1,
    message: `已启用兼容 Windows 10/11 的 DNSCrypt-Proxy ${DNSCRYPT_VERSION} 多上游加密 DNS；仅接管已连接物理网卡并阻断其明文 53 端口，服务已启用自动重启，系统解析与 HTTPS 连通性验证通过。`,
  };
}

async function restoreWindowsDns(context, options = {}) {
  if (context.platform !== 'win32') throw new Error('恢复 DNS 网络配置当前仅支持 Windows。');
  if (typeof options.commandRunner !== 'function') throw new Error('DNS 恢复命令执行器不可用。');
  const operation = await createDiagnosticOperation(context, 'restore');
  await runElevatedWindowsScript(
    context,
    buildWindowsRestoreScript(backupPath(context), operation),
    options.commandRunner,
    operation,
    'restore',
  );
  return { changed: 1, message: '已移除加密 DNS 服务和防泄漏规则，并恢复启用前的网卡 DNS 与浏览器 DNS 配置。' };
}

async function emergencyRestoreWindowsDns(context, options = {}) {
  if (context.platform !== 'win32') {
    return {
      changed: 0,
      mode: 'unsupported',
      message: '当前无需执行 Windows DNS 网络急救；macOS 版本不会安装此 Windows DNSCrypt 服务。',
    };
  }
  const commandRunner = options.commandRunner;
  if (typeof commandRunner !== 'function') throw new Error('网络急救命令执行器不可用。');

  const statePath = backupPath(context);
  const operation = await createDiagnosticOperation(context, 'emergency-restore');
  const result = await runElevatedWindowsScript(
    context,
    buildWindowsEmergencyRestoreScript(operation, statePath),
    commandRunner,
    operation,
    'emergency-restore',
  );
  const changed = result.diagnostic?.MutationStarted ? 1 : 0;
  return {
    changed,
    mode: changed ? 'emergency' : 'no-owned-changes',
    message: changed
      ? '已根据本助手保存的可信网卡变更清单撤销 DNS 锁定并恢复自动 DNS；代理软件、节点、订阅和浏览器代理地址均未删除。'
      : '未检测到可确认属于本助手的 DNS 网络改动，因此未修改系统网络配置。',
    diagnosticPath: operation.resultPath,
  };
}

module.exports = {
  DNSCRYPT_EXE_SHA256,
  DNSCRYPT_VERSION,
  FIREWALL_RULES,
  backupPath,
  buildWindowsEnableScript,
  buildWindowsEmergencyRestoreScript,
  buildWindowsRestoreScript,
  emergencyRestoreWindowsDns,
  enableWindowsDnsLeakProtection,
  readDiagnosticResult,
  restoreWindowsDns,
  verifyDnsConnectivity,
  verifyDnscryptAssets,
};
