[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory)][string]$SysmonExecutable,
  [string]$SysmonConfig = (Join-Path $PSScriptRoot '..\deploy\Sysmon-Falsimeter.xml')
)

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from an elevated Administrator PowerShell session.' }
if (-not (Test-Path -LiteralPath $SysmonExecutable -PathType Leaf)) { throw 'SysmonExecutable must be a local Sysmon64.exe or Sysmon.exe path.' }
if (-not (Test-Path -LiteralPath $SysmonConfig -PathType Leaf)) { throw 'SysmonConfig was not found.' }
if ($PSCmdlet.ShouldProcess($SysmonExecutable, "Install/update Sysmon using $SysmonConfig")) { & $SysmonExecutable -accepteula -i $SysmonConfig; if ($LASTEXITCODE -ne 0) { throw "Sysmon returned exit code $LASTEXITCODE." } }

Write-Output 'Sysmon install/update requested. Confirm the Sysmon Operational log is receiving the intended scoped events before any model run.'
