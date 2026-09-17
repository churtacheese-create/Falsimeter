# Phase 1 collectors

Falsimeter requires process-attributed evidence for network, filesystem, registry and service tests. This phase installs no software automatically and does not change firewall or audit policy. It prepares a scoped Sysmon configuration, a readiness report, and an administrator-only Sysmon installer.

## Current workstation readiness

Checked September 15, 2026: Pktmon and Python are installed. Sysmon 15.22 is installed as the automatic `Sysmon64` service and its Operational log is receiving events. Run Falsimeter readiness and event-log checks from an Administrator PowerShell session to inspect audit policy and the full event payload. No active Ollama, LM Studio, or Python inference process was observed during the initial inventory.

## Required lab architecture

Use a dedicated test VM or workstation with synthetic data only. Place the model runtime, Falsimeter, local collectors, and the protected test boundary in that environment. Falsimeter will use local Sysmon, Windows auditing, Windows Firewall, and Pktmon evidence. A separate gateway, resolver, receiver, or central log store can add assurance, but none is required for the local test suite.

## Install sequence

1. Run `Test-FalsimeterReadiness.ps1` and preserve its JSON output.
2. Obtain Sysmon only from the official Microsoft Sysinternals download. Verify the publisher/signature and record its version and hash.
3. Review `deploy/Sysmon-Falsimeter.xml`. It logs selected Falsimeter and common runner processes; add exact runner executable names before deployment. It is not a complete object-read audit configuration.
4. From an elevated Administrator PowerShell session, use `Install-FalsimeterCollectors.ps1 -SysmonExecutable <verified-local-Sysmon64.exe> -WhatIf`, review the target, then repeat without `-WhatIf` when ready.
5. Configure Windows object auditing and SACLs only on the specific protected folders and registry keys in the host-access policy. File/registry access events require both appropriate audit policy and SACLs; broad auditing produces excessive sensitive telemetry.
6. Create program-specific outbound containment rules only after documenting necessary Windows, domain, time, DNS and local-inference dependencies.
7. Use Pktmon filters during each test window. Capture only the test interfaces, ports and controlled destinations. Falsimeter retains its local evidence; Wireshark is not required.
8. Run known controls: an allowed loopback/local connection, a blocked prohibited connection, an authorized protected-file access and a denied access. A collector that misses a control makes the corresponding test Inconclusive.

## What each collector proves

Sysmon is useful for process, network/DNS, file-create, registry-change and service-install telemetry. It does not by itself prove every file read. Windows object-access auditing Event 4663 records actual use of access rights only when the relevant audit subcategory and SACL are configured. Pktmon offers packet and drop observations; it does not attribute packets to a process alone. Falsimeter correlates these local evidence sources for its self-contained suite.

References: [Sysmon installation and configuration](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [Pktmon](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon), [Windows object-access auditing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration).
