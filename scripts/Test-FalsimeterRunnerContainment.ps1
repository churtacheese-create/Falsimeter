[CmdletBinding()]
param(
  [string[]]$RunnerExecutable,
  [string]$OutputDirectory = (Join-Path $env:LOCALAPPDATA 'Falsimeter\Results')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run from an elevated Administrator PowerShell session.'
}

if (-not $RunnerExecutable) {
  $RunnerExecutable = @(Get-Process -Name ollama,lms -ErrorAction SilentlyContinue |
    ForEach-Object { $_.Path } |
    Where-Object { $_ } |
    Select-Object -Unique)
}
if (-not $RunnerExecutable) {
  throw 'Start the local runner first or pass -RunnerExecutable with its executable path.'
}

$checks = foreach ($path in $RunnerExecutable) {
  $fullPath = [IO.Path]::GetFullPath($path)
  $name = 'Falsimeter Containment - ' + [IO.Path]::GetFileNameWithoutExtension($fullPath)
  $rule = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Select-Object -First 1

  if (-not $rule) {
    [ordered]@{
      runner = $fullPath
      rule = $name
      found = $false
      passed = $false
      detail = 'Containment rule was not found.'
    }
    continue
  }

  $app = $rule | Get-NetFirewallApplicationFilter
  $address = $rule | Get-NetFirewallAddressFilter
  $programMatches = $app.Program -and ([IO.Path]::GetFullPath($app.Program) -eq $fullPath)
  $blocksInternet = @($address.RemoteAddress) -contains 'Internet'
  $active = $rule.Enabled -eq 'True' -and $rule.Direction -eq 'Outbound' -and $rule.Action -eq 'Block'

  [ordered]@{
    runner = $fullPath
    rule = $name
    found = $true
    enabled = $rule.Enabled.ToString()
    direction = $rule.Direction.ToString()
    action = $rule.Action.ToString()
    program = $app.Program
    remoteAddress = @($address.RemoteAddress)
    passed = ($active -and $programMatches -and $blocksInternet)
    detail = if ($active -and $programMatches -and $blocksInternet) {
      'An active program-specific outbound block rule covers Internet destinations.'
    } else {
      'The rule exists but does not match the expected Falsimeter containment configuration.'
    }
  }
}

$result = [ordered]@{
  generatedAt = (Get-Date).ToUniversalTime().ToString('o')
  checks = @($checks)
  passed = (@($checks).Count -gt 0 -and -not (@($checks) | Where-Object { -not $_.passed }))
  scope = 'Configuration evidence only. This confirms the local Windows Firewall rule; it does not prove enforcement by an independent network gateway.'
  nextStep = 'Keep this output with the qualification report. For a security qualification, collect matching evidence from an independently administered gateway or egress control.'
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMddTHHmmssZ'
$evidencePath = Join-Path $OutputDirectory "containment-control-$stamp.json"
$result.evidencePath = $evidencePath
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $evidencePath -Encoding utf8
$result | ConvertTo-Json -Depth 6
