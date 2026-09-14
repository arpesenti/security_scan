# Refutation-first verification

Manual triage of scan findings was the dominant cost of using this scanner, and
most false positives were injection findings from the phase-2 scan's single-file
blindness (no callers, no sanitizers in view). We decided to optimize for
precision over recall, with three mutually reinforcing choices:

1. **The verifier's job is to refute, not to rate.** The phase-3 prompt was
   rewritten from "rate each finding's confidence" to "assume every finding is
   wrong; hunt for the sanitizer, parameterization, allowlist, or dead path
   that proves it safe, using your tools." Findings the refuter cannot kill are
   *confirmed*; the rest are *Refuted Findings*, reported with their evidence in
   a separate section but removed from Vulnerable Files, the heatmap, and the
   CI gate.

2. **Suppression is human-confirmed only.** Machine refutations are never
   auto-written to `allowlist.json`. Not-actionable findings (real but
   unreachable: dead code, test-only, defense-in-depth) are re-bucketed, not
   suppressed — they resurrect if the code path wakes up, and the content-hash
   cache invalidation handles that naturally.

3. **Scanning runs with read-only tools by default** (`--scan-tools` as the
   default, `--no-scan-tools` to opt out). Accepting ~2–3× scan cost to give
   the scanner cross-file context at scan time, for all scanners, attacks the
   root cause instead of filtering afterwards.

The scan prompts also demand a named source and sink per finding; a finding
without a source is tagged `unsubstantiated` and still sent to the refuter
(the refuter is better at constructing taint paths than the scanner is at
articulating them — pre-filtering on the scanner's own articulation would
discard exactly the cases the refuter exists for).

## Considered Options

- A phase-4 independent refutation pass on top of the reworked phase-3
  (rejected for now: ~2× verify cost; revisit if precision is still lacking).
- A deterministic context prepass feeding call-graph/sanitizer data into scan
  prompts (rejected for now: engineering cost; tools-mode achieves the same
  context and already exists).
- A static-analyzer second signal (semgrep/bandit) for consensus (rejected:
  new dependency; LLM-vs-LLM chosen instead).
- Auto-bucketing unsubstantiated findings without verification (rejected:
  see point above).

## Consequences

- Rewriting `verify_prompt.txt` changes its hash: one-time full re-verification
  of all cached verdicts.
- The CI gate (`--fail-on-confidence`) counts only confirmed findings.
- The allowlist schema gains a `status: candidate|confirmed` distinction for
  the human-approval flow.
