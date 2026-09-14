# security_scan

OWASP Top 10 (2025) scanner that uses `pi -p` as a vulnerability analyst, in a
three-phase pipeline: discovery → per-file scan → optional verification.

## Language

**Finding**:
One vulnerability report emitted by the phase-2 scan for one file (line, code,
severity, explanation, fix). A finding exists regardless of whether it is real.
_Avoid_: vulnerability, issue, alert

**False Positive (FP)**:
A Finding a human rejects — either a misread (the flagged code is actually safe)
or real-but-not-actionable (dead code, test-only, defense-in-depth, unreachable).
_Avoid_: noise, bogus finding

**Misread**:
A Finding where the scanner misidentified a safe pattern as vulnerable (e.g. a
parameterized query flagged as SQL injection). The proper fate is permanent
Suppression.
_Avoid_: wrong finding

**Not-Actionable Finding**:
A Finding whose issue is technically real but not reachable/exploitable in this
codebase (dead code, test-only caller, defense-in-depth wrapper). The proper
fate is re-bucketing out of the main report, not permanent Suppression.
_Avoid_: false positive (when precision matters — it is only "positive" on a
technicality)

**Triage Burden**:
The set of Findings a human must manually read in the report. The primary
metric this project optimizes: every mechanism below exists to shrink it.
_Avoid_: false positives (as a count — Triage Burden is what the human feels)

**Refuted Finding**:
A Finding the phase-3 refuter has dismissed with cited evidence (the sanitizer,
parameterization, dead path, or test-only caller it found). Refuted Findings
leave the Vulnerable Files and heatmap buckets and appear in the report's
"Refuted" section — skimmed as reasons, not read as code. Refutation is
machine-made and never becomes a Suppression.
_Avoid_: false positive (as a verdict), auto-suppressed

**Verdict**:
The phase-3 verifier's judgment on a Finding: confidence (High/Medium/Low) +
exploitability (yes/no/conditional) + reason, with citations.
_Avoid_: review result, annotation

**Suppression**:
An entry in `allowlist.json` that removes matching Findings from the active
report (with audit trail). Meant for Misreads, confirmed by a human.
_Avoid_: whitelist, ignore, exception

**Allowlist**:
The `.security_scan/allowlist.json` file holding Suppressions.
_Avoid_: exclusions file
