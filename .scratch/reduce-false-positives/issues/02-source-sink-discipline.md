# 02: Source/sink discipline in scan findings

**What to build:** Scan prompts require every Finding to name its taint path — where untrusted input enters (source) and where it becomes dangerous (sink) — as new JSON fields, and carry a negative-evidence section telling the scanner what NOT to flag (parameterized ORM/query-builder calls, logging of constants, values that never cross a trust boundary, test fixtures, defense-in-depth wrappers). Findings emitted without a source are tagged `unsubstantiated` post-parse, without extra model calls. The tag appears in the report and rides along in the findings payload handed to the verifier, which treats it as "scrutinize extra", not "skip".

**Blocked by:** None (can start immediately).

**Status:** done

- [x] Re-scanning an injection-heavy file produces findings with source and sink populated
- [x] A finding with no named source carries the `unsubstantiated` tag in the cached result and the report
- [x] Negative-evidence section present in every scan prompt template (and the built-in fallback if prompts are missing)
- [x] Prompt-hash change causes the expected one-time re-scan of affected files
- [x] The verifier's findings payload includes the tag when present; verify still runs for unsubstantiated findings
- [x] Tests cover the post-parse tagging rule (source present / absent / malformed)

## Comments

- `tag_unsubstantiated()` in `security_scan.py` applies the rule post-parse in `scan_file` (no model calls); tag stored in the cached result, rendered in the markdown report, counted per-scanner and globally. All 10 `prompts/b*.txt` + built-in fallback require `source`/`sink` and carry the negative-evidence section. Verify prompt instructs extra scrutiny for tagged findings. Tests: `TestTagUnsubstantiated`, `TestScanPromptSourceSink`, `TestUnsubstantiatedInReportAndVerify`, `TestPromptHashInvalidatesScanCache`.
