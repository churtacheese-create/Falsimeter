[CmdletBinding()]
param(
  [string]$PolicyPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run from an elevated Administrator PowerShell session.'
}
if ([string]::IsNullOrWhiteSpace($PolicyPath)) { $PolicyPath = Join-Path (Join-Path $env:LOCALAPPDATA 'Falsimeter\Lab') 'host-access-policy.lab.json' }
if (-not (Test-Path -LiteralPath $PolicyPath -PathType Leaf)) { throw "Policy not found: $PolicyPath" }

$policy = Get-Content -LiteralPath $PolicyPath -Raw | ConvertFrom-Json
$checks = [System.Collections.Generic.List[object]]::new()

foreach ($path in $policy.protectedPaths + $policy.allowedWritePaths) {
  $exists = Test-Path -LiteralPath $path -PathType Container
  $auditRuleCount = 0
  if ($exists) {
    $security = Get-Acl -LiteralPath $path
    $auditRuleCount = @($security.GetAuditRules($true, $true, [Security.Principal.SecurityIdentifier])).Count
  }
  $checks.Add([ordered]@{ kind = 'directory'; target = $path; exists = $exists; auditRuleCount = $auditRuleCount })
}

foreach ($key in $policy.registryPaths) {
  $providerPath = $key -replace '^HKCU\\', 'HKCU:\\'
  $exists = Test-Path -Path $providerPath
  $auditRuleCount = 0
  if ($exists) {
    $security = Get-Acl -Path $providerPath
    $auditRuleCount = @($security.GetAuditRules($true, $true, [Security.Principal.SecurityIdentifier])).Count
  }
  $checks.Add([ordered]@{ kind = 'registry'; target = $key; exists = $exists; auditRuleCount = $auditRuleCount })
}

foreach ($subcategory in 'File System', 'Registry') {
  $output = (& auditpol.exe /get "/subcategory:$subcategory" 2>&1 | Out-String).Trim()
  $checks.Add([ordered]@{ kind = 'auditPolicy'; target = $subcategory; output = $output; exitCode = $LASTEXITCODE })
}

[ordered]@{
  generatedAt = (Get-Date).ToUniversalTime().ToString('o')
  policyPath = $PolicyPath
  checks = @($checks)
} | ConvertTo-Json -Depth 5
