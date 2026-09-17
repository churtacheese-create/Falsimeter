# Selected model and test runs

All checkboxes start unchecked. Choose tests opens a searchable catalog with individual descriptions and requirements. Use checked tests applies the selection; closing without applying discards edits. Search does not change selections. Run checked freezes only checked models and tests. Empty selections do nothing. Stop cancels further requests and preserves partial evidence. A subset never grants or overwrites full qualification.

## Coverage

Implemented: original seven synthetic prompts, thirteen new deterministic accuracy/reliability probes, and static package inspection. These are limited probes, not complete benchmarks. New probes use exact-answer scoring; original prompts retain contains/absent checks.

Network, host-access, permission, operational and recognized-benchmark entries are itemized, but their full local collectors, agent harnesses, offline benchmark packs and reference evaluators are not bundled yet. They return NeedsSetup until the corresponding Falsimeter local component is installed and configured. Each requirement is shown in the test selector before the user chooses the test. Catalog presence is not evidence of implemented coverage. NIST and ISO governance standards are not executable model certification tests.

## Local harness contract

`<data-root>/test-runners.json` maps an exact test ID to a locally installed Falsimeter harness component with an executable (absolute trusted path), arguments (array), and timeoutSeconds (positive integer). The executable receives `--falsimeter-request <request-file>`. The request contains test, model, allowedTestIds (exactly one) and resultPath. The harness runs only that test and writes a CheckEvidence object with testId, outcome, detail and durationMs. Outcomes: Passed, Failed, NeedsSetup, Unsupported, Error, Cancelled. Mismatched IDs, invalid outcomes, missing results and nonzero exits are errors. Cancellation terminates the launched process tree. Local benchmark packs and scorers use the same contract and can run offline.

## Evidence

`Results/SelectedRuns/<unique-run-id>/report.json` records selected IDs and individual outcomes; report.sha256 provides a checksum, not a digital signature or proof of collection accuracy. Row menus show selected results from the current session. Reports remain on disk after closing. Existing qualification reports are unchanged.

Falsimeter schedules only selected checks. This cannot constrain untrusted runtime behavior internally. Network containment, unauthorized-read detection and permission enforcement require their corresponding locally installed collector and lab-harness components.

Verified: warning-free build, selection freeze/exclusion, empty-selection behavior, no implicit inventory/metadata calls, cancellation, missing benchmark setup and prevention of subset approval.
