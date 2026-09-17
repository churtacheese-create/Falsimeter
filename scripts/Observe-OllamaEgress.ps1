[CmdletBinding()] param([int]$DurationSeconds = 30, [string]$OutputPath)
$processes = Get-Process ollama -ErrorAction SilentlyContinue
if (-not $processes) { throw 'Ollama is not running.' }
$start = Get-Date; $observations = [System.Collections.Generic.List[object]]::new()
while (((Get-Date) - $start).TotalSeconds -lt $DurationSeconds) { foreach ($process in $processes) { Get-NetTCPConnection -OwningProcess $process.Id -State Established -ErrorAction SilentlyContinue | ForEach-Object { $observations.Add([pscustomobject]@{ Time=(Get-Date).ToUniversalTime().ToString('o'); Pid=$process.Id; Local="$($_.LocalAddress):$($_.LocalPort)"; Remote="$($_.RemoteAddress):$($_.RemotePort)" }) } }; Start-Sleep -Milliseconds 500 }
$json = [pscustomobject]@{ Method='Get-NetTCPConnection sampling'; Caveat='Observation is not prevention; enforce a firewall egress block.'; Observations=$observations } | ConvertTo-Json -Depth 5
if ($OutputPath) { $json | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM } else { $json }
