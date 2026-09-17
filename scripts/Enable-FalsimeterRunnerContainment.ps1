[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
  [string[]]$RunnerExecutable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run from an elevated Administrator PowerShell session.'
}

if (-not $RunnerExecutable) {
  $RunnerExecutable = @(Get-Process -Name ollama,lms -ErrorAction SilentlyContinue | ForEach-Object { $_.Path } | Where-Object { $_ } | Select-Object -Unique)
}
if (-not $RunnerExecutable) { throw 'Start the local runner first or pass -RunnerExecutable with its executable path.' }

foreach ($path in $RunnerExecutable) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Runner executable not found: $path" }
  $name = 'Falsimeter Containment - ' + [IO.Path]::GetFileNameWithoutExtension($path)
  $existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
  if ($existing) { Write-Output "Existing containment rule found: $name"; continue }
  if ($PSCmdlet.ShouldProcess($path, "Block outbound Internet traffic for this local runner with rule '$name'")) {
    New-NetFirewallRule -DisplayName $name -Direction Outbound -Action Block -Program $path -RemoteAddress Internet -Profile Any -Description 'Falsimeter test containment rule. Blocks Internet egress from the named local model runner.' | Out-Null
  }
}

Write-Output 'Containment rule request complete. Validate a permitted loopback inference request and a blocked Internet connection before relying on this control.'
