# 05: Export allowlist candidates from refuted findings

**What to build:** A flag that turns the human-approval flow into a glance instead of a chore: it emits *candidate* suppression entries derived from Refuted Findings into the allowlist file, each marked with a candidate status (never auto-applied). Suppression remains human-confirmed only — candidates match nothing until a person approves them (flips status to confirmed); the report's audit trail distinguishes confirmed suppressions from still-candidate ones. This preserves the ADR's rule that machine refutations are reported, never silently allowlisted.

**Blocked by:** 04 (refuted re-bucketing — the refuted findings and their evidence must flow through the report first).

**Status:** done

- [x] Flag exports candidate suppression entries from refuted findings (scanner, file, line, reason) into the allowlist file
- [x] Candidate entries never suppress anything until approved (status flipped to confirmed by a human)
- [x] Report's suppressed-findings audit trail separates confirmed suppressions from pending candidates
- [x] Re-export is idempotent: an already-candidate or already-confirmed finding is not duplicated
- [x] Tests cover export, idempotency, and the candidate-matches-nothing rule

## Comments

- `export_allowlist_candidates(state_dir, refuted_findings)` appends `status: candidate` entries (scanner, file, line, cited reason, exported_at) atomically, skipping any (scanner, file, line) that already has a candidate or confirmed entry. `find_suppression` skips candidate entries — legacy entries with no status still suppress. `--export-allowlist-candidates` in main: export after the report build, then rebuild the report (cache reads only, no model calls) so the audit trail shows a separate "Pending candidate suppressions" section distinct from "Suppressed Findings (allowlist)". Works for both md and csv/tsv report formats via the shared stats `refuted_findings`. Tests: `TestCandidateSuppressions`.
- Also fixed a pre-existing bug found by the end-to-end smoke test: `load_verification_for_file` computed its cache key without the `thinking` dimension, so real runs (verify default `thinking=medium`) never overlaid cached verdicts into the report. `build_report`/`build_csv_report` now take `verify_thinking` and main passes `--verify-thinking`; regression test added.
