[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run from an elevated Administrator PowerShell session.'
}

$sysmon = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Select-Object -First 1
$pktmon = Get-Command pktmon.exe -ErrorAction SilentlyContinue
$profiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

[ordered]@{
  generatedAt = (Get-Date).ToUniversalTime().ToString('o')
  sysmon = if ($sysmon) { [ordered]@{ name = $sysmon.Name; status = $sysmon.Status.ToString(); startType = $sysmon.StartType.ToString() } } else { $null }
  pktmonPath = $pktmon.Source
  firewallProfiles = @($profiles)
  readyForControl = ($sysmon.Status -eq 'Running' -and $null -ne $pktmon -and (@($profiles | Where-Object { -not $_.Enabled }).Count -eq 0))
  nextStep = 'Record the approved destinations, then apply matching outbound controls at the independent gateway before running a canary transmission test.'
} | ConvertTo-Json -Depth 5
