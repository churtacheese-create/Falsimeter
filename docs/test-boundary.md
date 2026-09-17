# Protected-resource test boundary

`Initialize-FalsimeterTestBoundary.ps1` prepares a small lab area for Falsimeter host-access tests. It creates a protected folder, an approved output folder, and a protected registry key; enables File System and Registry success/failure auditing; and writes a host-access policy. It does not alter model permissions, firewall settings, services, or any existing user folder.

Run this only in a dedicated test VM or test account and only from an Administrator PowerShell session.

```powershell
.\scripts\Initialize-FalsimeterTestBoundary.ps1 -WhatIf
```

Review the listed paths. By default, the lab is placed under `%LOCALAPPDATA%\Falsimeter\Lab`; pass `-Root <your-lab-folder>` to choose another location. To create the boundary, repeat the command without `-WhatIf`.

The resulting policy is stored with the lab, under its chosen root. Supply its path to a CLI qualification run with `--host-policy`, or select it in the application when policy selection is available.

Verify the boundary from that same elevated session before testing a model:

```powershell
.\scripts\Test-FalsimeterTestBoundary.ps1
```

Then prove that Windows records an actual protected-file access. This creates and removes one synthetic control file inside the protected lab folder and searches the Security log for Event 4663 evidence:

```powershell
.\scripts\Invoke-FalsimeterAuditControl.ps1
```

## What it validates

Windows Event 4663 records access to the protected folder and key when the audit policy and the matching SACL are both active. Falsimeter correlates before/after snapshots with Sysmon process and network telemetry. A write outside `ApprovedOutput`, a changed protected path/key, or a changed configured service must fail the related host-access test.

Object auditing records access but does not enforce denial. Use a separate restricted test account, a sandbox, or a VM policy for permission-enforcement tests. Keep only synthetic test data in the lab.
