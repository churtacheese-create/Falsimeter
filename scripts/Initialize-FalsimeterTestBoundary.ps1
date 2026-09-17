[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
  [string]$Root = (Join-Path $env:LOCALAPPDATA 'Falsimeter\Lab'),
  [string]$PolicyPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run from an elevated Administrator PowerShell session.'
}

$rootPath = [IO.Path]::GetFullPath($Root)
if ($rootPath -eq [IO.Path]::GetPathRoot($rootPath)) { throw 'Root must be a dedicated folder, not a drive root.' }
if ([string]::IsNullOrWhiteSpace($PolicyPath)) { $PolicyPath = Join-Path $rootPath 'host-access-policy.lab.json' }
$protectedPath = Join-Path $rootPath 'ProtectedData'
$outputPath = Join-Path $rootPath 'ApprovedOutput'
$registryPath = 'HKCU:\Software\FalsimeterLab\Protected'

foreach ($path in @($rootPath, $protectedPath, $outputPath)) {
  if (-not (Test-Path -LiteralPath $path) -and $PSCmdlet.ShouldProcess($path, 'Create dedicated Falsimeter lab directory')) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
  }
}

if (-not (Test-Path -LiteralPath $registryPath) -and $PSCmdlet.ShouldProcess($registryPath, 'Create dedicated Falsimeter protected registry key')) {
  New-Item -Path $registryPath -Force | Out-Null
}

# Audit only the lab resources. These rules record access; they do not change permissions.
# Use a separate test account or VM when testing access denial.
$fileRule = New-Object Security.AccessControl.FileSystemAuditRule(
  'Everyone', [Security.AccessControl.FileSystemRights]::FullControl,
  [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
  [Security.AccessControl.PropagationFlags]::None,
  [Security.AccessControl.AuditFlags]'Success, Failure')
if (((Test-Path -LiteralPath $protectedPath) -or $WhatIfPreference) -and $PSCmdlet.ShouldProcess($protectedPath, 'Add scoped success/failure file-access audit rule')) {
  $acl = Get-Acl -LiteralPath $protectedPath
  $acl.AddAuditRule($fileRule)
  Set-Acl -LiteralPath $protectedPath -AclObject $acl
}

$registryRule = New-Object Security.AccessControl.RegistryAuditRule(
  'Everyone', [Security.AccessControl.RegistryRights]::FullControl,
  [Security.AccessControl.InheritanceFlags]'ContainerInherit',
  [Security.AccessControl.PropagationFlags]::None,
  [Security.AccessControl.AuditFlags]'Success, Failure')
if (((Test-Path -LiteralPath $registryPath) -or $WhatIfPreference) -and $PSCmdlet.ShouldProcess($registryPath, 'Add scoped success/failure registry-access audit rule')) {
  $acl = Get-Acl -Path $registryPath
  $acl.AddAuditRule($registryRule)
  Set-Acl -Path $registryPath -AclObject $acl
}

foreach ($subcategory in 'File System', 'Registry') {
  if ($PSCmdlet.ShouldProcess($subcategory, 'Enable success and failure object-access auditing')) {
    & auditpol.exe /set "/subcategory:$subcategory" /success:enable /failure:enable
    if ($LASTEXITCODE -ne 0) { throw "auditpol failed while enabling $subcategory auditing." }
  }
}

$policy = [ordered]@{
  protectedPaths = @($protectedPath)
  allowedWritePaths = @($outputPath)
  registryPaths = @($registryPath.Replace('HKCU:', 'HKCU'))
  serviceNames = @()
}
if ($PSCmdlet.ShouldProcess($PolicyPath, 'Write Falsimeter host-access policy for the dedicated lab')) {
  $parent = Split-Path -Parent $PolicyPath
  if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
  $policy | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $PolicyPath -Encoding utf8NoBOM
}

if ($WhatIfPreference) { Write-Output "Test boundary previewed. Policy: $PolicyPath" }
else { Write-Output "Test boundary prepared. Policy: $PolicyPath" }
Write-Output "Protected path: $protectedPath"
Write-Output "Approved output path: $outputPath"
