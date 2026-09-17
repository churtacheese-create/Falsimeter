[CmdletBinding(SupportsShouldProcess)] param([string]$Root = (Join-Path $env:LOCALAPPDATA 'Falsimeter'))
$folders = 'Registry','TestCases','CanarySets','Results','Baselines','Reports','Logs','Quarantine'
foreach ($folder in $folders) { $path = Join-Path $Root $folder; if ($PSCmdlet.ShouldProcess($path, 'Create directory')) { New-Item -ItemType Directory -Path $path -Force | Out-Null } }
"Falsimeter data root initialized: $Root"
