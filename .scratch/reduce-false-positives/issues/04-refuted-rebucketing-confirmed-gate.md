# 04: Refuted/not-actionable re-bucketing and confirmed-only CI gate

**What to build:** The report consumes verdicts under refutation-first semantics. Refuted Findings leave Vulnerable Files, the Risk Heatmap, and the CI gate, and appear in a new skim-only "Refuted" section showing each refutation's cited evidence — read as reasons, not code. Not-actionable findings (real but unreachable: dead code, test-only, defense-in-depth) are re-bucketed below the line without being suppressed — they are real, so they resurrect if the code path wakes up; the content-hash cache invalidation handles that naturally. `--fail-on-confidence` counts only confirmed findings, making the gate more trustworthy. A per-scanner summary (confirmed / refuted / unsubstantiated / suppressed) lands in the report so precision changes are measurable across runs.

**Blocked by:** 03 (refutation-first verifier prompt — the new verdict semantics must exist first).

**Status:** done

- [x] Refuted findings appear only in the Refuted section, with their evidence; absent from Vulnerable Files, heatmap, and overall risk counts
- [x] Not-actionable findings (exploitable: no/conditional) are re-bucketed below the line, not suppressed, and never written to the allowlist
- [x] `--fail-on-confidence` gate counts only confirmed findings; CI exit codes reflect this
- [x] Per-scanner summary shows confirmed / refuted / unsubstantiated / suppressed counts
- [x] Suppressed (allowlisted) findings continue to work unchanged alongside the new buckets
- [x] Tests cover bucket placement for each verdict combination

## Comments

- `verdict_bucket()` maps each verification record to a bucket: explicit `verdict: refuted` → Refuted section (with cited evidence); confirmed + `exploitable: no|conditional` → Not-Actionable (below the line, never suppressed/allowlisted); confirmed + `yes` → active; no verdict → unverified (legacy raw counting). Legacy cached verdicts without a `verdict` field derive the bucket from exploitable/confidence. `--fail-on-confidence` (exit 3) counts only gated = confirmed-at/above-cutoff findings. Per-scanner + global summaries gained Confirmed/Refuted/Not-Actionable/Unsubstantiated rows; CSV gained `refuted`/`not_actionable` statuses plus source/sink/tags/verdict columns. Tests: `TestRefutationBuckets`, updated `TestBuildReportWithVerification`, `test_csv_refuted_and_not_actionable_statuses`.
