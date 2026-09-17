[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$ArtifactPath,
  [Parameter(Mandatory)] [string]$Collector,
  [Parameter(Mandatory)] [string]$DeviceId,
  [Parameter(Mandatory)] [DateTimeOffset]$WindowStartedAt,
  [Parameter(Mandatory)] [DateTimeOffset]$WindowEndedAt,
  [string[]]$ObservedDestination = @(),
  [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$artifact = [IO.Path]::GetFullPath($ArtifactPath)
if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
  throw "Gateway artifact was not found: $artifact"
}
if ($WindowEndedAt -lt $WindowStartedAt) {
  throw 'WindowEndedAt must be at or after WindowStartedAt.'
}
if (-not $OutputPath) {
  $folder = Join-Path $env:LOCALAPPDATA 'Falsimeter\Results'
  New-Item -ItemType Directory -Path $folder -Force | Out-Null
  $OutputPath = Join-Path $folder ('gateway-evidence-' + (Get-Date -Format 'yyyyMMddTHHmmssZ') + '.json')
}

$evidence = [ordered]@{
  collector = $Collector
  deviceId = $DeviceId
  windowStartedAt = $WindowStartedAt.ToUniversalTime().ToString('o')
  windowEndedAt = $WindowEndedAt.ToUniversalTime().ToString('o')
  artifactPath = $artifact
  artifactSha256 = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
  observedDestinations = @($ObservedDestination)
}

$evidence | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutputPath -Encoding utf8
[ordered]@{
  evidencePath = [IO.Path]::GetFullPath($OutputPath)
  artifactPath = $artifact
  artifactSha256 = $evidence.artifactSha256
  scope = 'The artifact hash protects against later changes to the exported evidence. Obtain the artifact from an independently administered firewall, proxy, or network sensor.'
} | ConvertTo-Json -Depth 4
