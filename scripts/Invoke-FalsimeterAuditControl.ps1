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
$protectedPath = @($policy.protectedPaths | Where-Object { Test-Path -LiteralPath $_ -PathType Container } | Select-Object -First 1)[0]
if (-not $protectedPath) { throw 'No existing protected directory was found in the policy.' }

$controlFile = Join-Path $protectedPath ("falsimeter-audit-control-{0}.txt" -f [Guid]::NewGuid().ToString('N'))
$start = (Get-Date).AddSeconds(-2)
try {
  [IO.File]::WriteAllText($controlFile, 'Falsimeter synthetic audit control. No user data.')
  [void][IO.File]::ReadAllText($controlFile)
}
finally {
  if (Test-Path -LiteralPath $controlFile) { Remove-Item -LiteralPath $controlFile -Force }
}

Start-Sleep -Seconds 2
$matches = foreach ($event in Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663; StartTime = $start } -MaxEvents 200) {
  $xml = [xml]$event.ToXml()
  $fields = @{}
  foreach ($data in $xml.Event.EventData.Data) { $fields[$data.Name] = [string]$data.'#text' }
  if ($fields['ObjectName'] -eq $controlFile) {
    [ordered]@{
      timeCreated = $event.TimeCreated.ToUniversalTime().ToString('o')
      processName = $fields['ProcessName']
      accessMask = $fields['AccessMask']
      accessList = $fields['AccessList']
    }
  }
}

[ordered]@{
  generatedAt = (Get-Date).ToUniversalTime().ToString('o')
  protectedPath = $protectedPath
  controlFile = $controlFile
  securityEvent4663Count = @($matches).Count
  passed = @($matches).Count -gt 0
  evidence = @($matches)
} | ConvertTo-Json -Depth 5
