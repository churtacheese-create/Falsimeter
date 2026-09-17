[CmdletBinding()]
param([string]$OutputPath)

$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$sysmon = Get-Command Sysmon64.exe, Sysmon.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$pktmon = Get-Command pktmon.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$python = Get-Command python.exe, py.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$audit = foreach ($subcategory in 'File System','Registry','Filtering Platform Connection','Filtering Platform Packet Drop') {
  $output = (& auditpol.exe /get "/subcategory:$subcategory" 2>&1 | Out-String).Trim()
  [ordered]@{ subcategory = $subcategory; exitCode = $LASTEXITCODE; output = $output }
}
$result = [ordered]@{
  generatedAt = (Get-Date).ToUniversalTime().ToString('o')
  administrator = $admin
  sysmonPath = $sysmon.Source
  pktmonPath = $pktmon.Source
  pythonPath = $python.Source
  auditPolicy = @($audit)
  nextSteps = @(
    'Review deploy/Sysmon-Falsimeter.xml and install Sysmon as Administrator.',
    'Define a separate test VM, destination allowlist, protected paths, registry keys, and services.',
    'Configure object audit SACLs only for those protected resources.',
    'Validate collectors with known allowed and blocked synthetic controls before qualifying a model.'
  )
}
$json = $result | ConvertTo-Json -Depth 5
if ($OutputPath) { $json | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM } else { $json }
